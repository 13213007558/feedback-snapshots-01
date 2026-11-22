# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

"""Bounded, field-limited summaries of streamed search results.

The helpers in this module are intentionally passive: they only observe
results that the application has already requested. They never call
``search``, ``scroll`` or ``clear_scroll`` themselves, never advance an
iterator ahead of the application and never retain complete documents.
"""

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional

DEFAULT_MAX_SAMPLES = 3
DEFAULT_MAX_ERRORS = 32
MAX_PROJECTION_DEPTH = 32


class _MissingField(Exception):
    """Raised internally when a configured field is not present."""


@dataclass(frozen=True)
class DiagnosticConfig:
    """Configuration for the summary attached to a diagnostic record.

    :arg fields: exact field paths that are allowed to leave the process.
        Dotted paths address nested values (``"request.user.name"``). No
        wildcard expansion is performed.
    :arg max_samples: maximum number of result samples retained.
    :arg max_errors: maximum number of decode errors retained. Error
        records only contain a record index, the field path and the
        exception class; they never contain the offending value.
    """

    fields: Sequence[str]
    max_samples: int = DEFAULT_MAX_SAMPLES
    max_errors: int = DEFAULT_MAX_ERRORS

    def __post_init__(self) -> None:
        if self.fields is None:
            raise ValueError("DiagnosticConfig.fields is required.")
        fields = (self.fields,) if isinstance(self.fields, str) else tuple(self.fields)
        if not fields:
            raise ValueError("DiagnosticConfig.fields must not be empty.")
        for name in fields:
            if not isinstance(name, str) or not name:
                raise ValueError("DiagnosticConfig.fields must contain field paths.")
            if name == "_source":
                raise ValueError("DiagnosticConfig.fields cannot expose '_source'.")
            if any(not part for part in name.split(".")):
                raise ValueError(
                    f"DiagnosticConfig field path is malformed: {name!r}."
                )

        for label in ("max_samples", "max_errors"):
            value = getattr(self, label)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"DiagnosticConfig.{label} must be an int >= 0.")

        object.__setattr__(self, "fields", fields)


@dataclass(frozen=True)
class SampleError:
    """A field that could not be copied into the diagnostic summary."""

    record: int
    field: str
    error: str

    def to_dict(self) -> Dict[str, Any]:
        return {"record": self.record, "field": self.field, "error": self.error}


class DiagnosticSummary:
    """Samples and decode errors collected from a result stream.

    Accessing :attr:`samples` returns copies of the stored dictionaries so
    callers cannot mutate the state of the sampler.
    """

    def __init__(self, config: DiagnosticConfig) -> None:
        self.config = config
        self._samples: List[Dict[str, Any]] = []
        self._errors: List[SampleError] = []
        self._seen = 0
        self._truncated = False

    @property
    def samples(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self._samples)

    @property
    def errors(self) -> List[Dict[str, Any]]:
        return [error.to_dict() for error in self._errors]

    @property
    def seen(self) -> int:
        """Number of results observed so far."""

        return self._seen

    @property
    def sampled(self) -> int:
        """Number of samples retained."""

        return len(self._samples)

    @property
    def truncated(self) -> bool:
        """Whether more results were observed than the sample limit."""

        return self._truncated

    def to_dict(self) -> Dict[str, Any]:
        """Return the summary that is safe to attach to an operational record."""

        return {"samples": self.samples, "errors": self.errors}

    def observe(self, result: Any, record: int) -> None:
        """Observe one result without modifying or retaining it."""

        self._seen += 1
        if len(self._samples) >= self.config.max_samples:
            self._truncated = True
            return

        try:
            sample = self._extract_sample(result, record)
        except _MissingField:
            return
        except Exception:
            # _extract_sample already recorded the field error. This
            # backstop guarantees diagnostics never fail the real stream.
            return

        # A result that carries none of the approved fields is not a useful
        # sample. Do not count it against the configured sample budget.
        if sample:
            self._samples.append(sample)

    def _extract_sample(self, result: Any, record: int) -> Dict[str, Any]:
        sample: Dict[str, Any] = {}
        for path in self.config.fields:
            try:
                value = _extract_field(result, path)
            except _MissingField:
                continue
            except Exception as exc:
                self._record_error(record, path, exc)
                # Do not retain a partially decoded record. The error entry
                # identifies the record without including any field value.
                raise

            try:
                sample[path] = _project_value(value)
            except Exception as exc:
                self._record_error(record, path, exc)
                raise
        return sample

    def _record_error(self, record: int, field: str, exc: Exception) -> None:
        if len(self._errors) >= self.config.max_errors:
            return
        # Only the exception type is recorded. Exception messages from
        # UnicodeDecodeError and similar include the original value.
        self._errors.append(
            SampleError(record=record, field=field, error=type(exc).__name__)
        )

    def __repr__(self) -> str:
        return (
            f"<DiagnosticSummary: {len(self._samples)} sample(s), "
            f"{len(self._errors)} error(s), {self._seen} seen>"
        )


def _lookup_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                raise _MissingField(path)
            current = current[part]
        elif isinstance(current, (str, bytes, bytearray)):
            raise _MissingField(path)
        elif isinstance(current, Sequence):
            if not part.isdigit():
                raise _MissingField(path)
            try:
                current = current[int(part)]
            except (IndexError, TypeError):
                raise _MissingField(path)
        elif hasattr(current, "__getitem__") and part.isdigit():
            # Support lists and AttrList, which are not Sequence subclasses.
            try:
                current = current[int(part)]
            except (IndexError, KeyError, TypeError):
                raise _MissingField(path)
        elif hasattr(current, "__contains__") and hasattr(current, "__getitem__"):
            # AttrDict and similar helper objects expose mapping access
            # without being registered as Mapping instances.
            try:
                if part not in current:
                    raise _MissingField(path)
                current = current[part]
            except (KeyError, TypeError, AttributeError):
                raise _MissingField(path)
        else:
            raise _MissingField(path)
    return current


def _extract_field(result: Any, path: str) -> Any:
    """Read an approved path from a raw hit or a ``Hit``-like object."""

    if isinstance(result, Mapping):
        source = result.get("_source")
        if isinstance(source, Mapping):
            try:
                return _lookup_path(source, path)
            except _MissingField:
                pass
        return _lookup_path(result, path)

    try:
        return _lookup_path(result, path)
    except _MissingField:
        meta = getattr(result, "meta", None)
        if meta is not None:
            if path.startswith("meta."):
                return _lookup_path(meta, path[len("meta.") :])
            return _lookup_path(meta, path)
        raise


def _project_value(value: Any, depth: int = 0) -> Any:
    """Copy an approved value into a JSON-friendly structure.

    Byte values are decoded so diagnostic records remain serializable. A
    decoding failure is reported through :class:`DiagnosticSummary` without
    interrupting the stream.
    """

    if depth > MAX_PROJECTION_DEPTH:
        raise ValueError("Field value is nested too deeply.")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8")
    if isinstance(value, Mapping):
        return {
            str(key): _project_value(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_project_value(item, depth + 1) for item in value]

    # Escape hatch for helper wrappers such as AttrList that wrap a sequence
    # but do not register as one of the built-in containers.
    inner = getattr(value, "_l_", None)
    if isinstance(inner, list):
        return [_project_value(item, depth + 1) for item in inner]

    # Unknown objects are intentionally not coerced with str(): their
    # __repr__ may include the original document. Use the type name only.
    return f"<{type(value).__name__}>"


class DiagnosticSampler(Iterator[Any]):
    """Wrap a sync result iterator and collect a bounded summary.

    The wrapper advances the underlying iterator exactly once for every call
    to :meth:`__next__`. It never peeks at the next page, so a logger or
    diagnostic consumer cannot cause additional requests.

    Example::

        results = helpers.scan(client, index="logs")
        stream = sample_results(results, fields=("title", "status"), max_samples=2)
        for hit in stream:
            ...  # the real, unmodified hit
        logger.info("search summary: %s", stream.summary.to_dict())
    """

    def __init__(
        self,
        results: Any,
        config: Optional[DiagnosticConfig] = None,
        *,
        fields: Optional[Sequence[str]] = None,
        max_samples: int = DEFAULT_MAX_SAMPLES,
        max_errors: int = DEFAULT_MAX_ERRORS,
    ) -> None:
        if config is not None and fields is not None:
            raise ValueError("Pass either config or fields, not both.")
        if config is None:
            if fields is None:
                raise ValueError("DiagnosticSampler requires fields.")
            config = DiagnosticConfig(
                fields=fields, max_samples=max_samples, max_errors=max_errors
            )

        self.config = config
        self.summary = DiagnosticSummary(config)
        self._results = iter(results)
        self._record = 0

    @property
    def samples(self) -> List[Dict[str, Any]]:
        return self.summary.samples

    @property
    def errors(self) -> List[Dict[str, Any]]:
        return self.summary.errors

    def __iter__(self) -> "DiagnosticSampler":
        return self

    def __next__(self) -> Any:
        result = next(self._results)
        record = self._record
        self._record += 1
        self.summary.observe(result, record)
        return result

    def close(self) -> None:
        """Close the wrapped iterator without consuming more results."""

        close = getattr(self._results, "close", None)
        if close is not None:
            close()


def sample_results(
    results: Any,
    *,
    fields: Sequence[str],
    max_samples: int = DEFAULT_MAX_SAMPLES,
    max_errors: int = DEFAULT_MAX_ERRORS,
) -> DiagnosticSampler:
    """Return a :class:`DiagnosticSampler` for a synchronous result stream."""

    return DiagnosticSampler(
        results, fields=fields, max_samples=max_samples, max_errors=max_errors
    )


class AsyncDiagnosticSampler(AsyncIterator[Any]):
    """Async equivalent of :class:`DiagnosticSampler`.

    It advances the wrapped async iterator one item at a time and never
    requests the next page on its own.
    """

    def __init__(
        self,
        results: Any,
        config: Optional[DiagnosticConfig] = None,
        *,
        fields: Optional[Sequence[str]] = None,
        max_samples: int = DEFAULT_MAX_SAMPLES,
        max_errors: int = DEFAULT_MAX_ERRORS,
    ) -> None:
        if config is not None and fields is not None:
            raise ValueError("Pass either config or fields, not both.")
        if config is None:
            if fields is None:
                raise ValueError("AsyncDiagnosticSampler requires fields.")
            config = DiagnosticConfig(
                fields=fields, max_samples=max_samples, max_errors=max_errors
            )

        self.config = config
        self.summary = DiagnosticSummary(config)
        self._results = results.__aiter__()
        self._record = 0

    @property
    def samples(self) -> List[Dict[str, Any]]:
        return self.summary.samples

    @property
    def errors(self) -> List[Dict[str, Any]]:
        return self.summary.errors

    def __aiter__(self) -> "AsyncDiagnosticSampler":
        return self

    async def __anext__(self) -> Any:
        result = await self._results.__anext__()
        record = self._record
        self._record += 1
        self.summary.observe(result, record)
        return result

    async def aclose(self) -> None:
        """Close the wrapped async iterator when it supports ``aclose``."""

        close = getattr(self._results, "aclose", None)
        if close is not None:
            await close()


def async_sample_results(
    results: Any,
    *,
    fields: Sequence[str],
    max_samples: int = DEFAULT_MAX_SAMPLES,
    max_errors: int = DEFAULT_MAX_ERRORS,
) -> AsyncDiagnosticSampler:
    """Return an :class:`AsyncDiagnosticSampler` for an async result stream."""

    return AsyncDiagnosticSampler(
        results, fields=fields, max_samples=max_samples, max_errors=max_errors
    )


def scan_with_summary(
    client: Any,
    *,
    fields: Sequence[str],
    max_samples: int = DEFAULT_MAX_SAMPLES,
    max_errors: int = DEFAULT_MAX_ERRORS,
    **scan_kwargs: Any,
) -> DiagnosticSampler:
    """Run :func:`~opensearchpy.helpers.scan` with a diagnostic summary.

    ``scan_kwargs`` are passed to :func:`~opensearchpy.helpers.scan`
    unchanged. The returned sampler yields the real hits and exposes the
    bounded summary as :attr:`~DiagnosticSampler.summary`.
    """

    from .actions import scan

    return DiagnosticSampler(
        scan(client, **scan_kwargs),
        fields=fields,
        max_samples=max_samples,
        max_errors=max_errors,
    )


def async_scan_with_summary(
    client: Any,
    *,
    fields: Sequence[str],
    max_samples: int = DEFAULT_MAX_SAMPLES,
    max_errors: int = DEFAULT_MAX_ERRORS,
    **scan_kwargs: Any,
) -> AsyncDiagnosticSampler:
    """Async version of :func:`scan_with_summary`."""

    from .._async.helpers.actions import async_scan

    return AsyncDiagnosticSampler(
        async_scan(client, **scan_kwargs),
        fields=fields,
        max_samples=max_samples,
        max_errors=max_errors,
    )


__all__ = [
    "DEFAULT_MAX_ERRORS",
    "DEFAULT_MAX_SAMPLES",
    "AsyncDiagnosticSampler",
    "DiagnosticConfig",
    "DiagnosticSampler",
    "DiagnosticSummary",
    "SampleError",
    "async_sample_results",
    "async_scan_with_summary",
    "sample_results",
    "scan_with_summary",
]
