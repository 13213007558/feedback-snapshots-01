"""Field-level provenance for deserialization.

Provenance is recorded while a schema maps raw input to fields, separately from
the deserialized data. It is opt-in: pass ``provenance=True`` (or a
`LoadProvenance` collector) to :meth:`Schema.load <marshmallow.Schema.load>`.

The deserialized data itself is never modified. This matters for audit logs:
the business object keeps its original shape while value sources can be queried
by external alias or by nested output path.
"""

from __future__ import annotations

import contextvars
import dataclasses
import enum
import typing
from collections.abc import Mapping

__all__ = ["FieldSource", "LoadProvenance"]


class FieldSource(enum.StrEnum):
    """Where a deserialized field value came from.

    .. attribute:: INPUT

        The value was present in the original input passed to ``load``. In an
        HTTP API this means the value came from the external caller, even if a
        ``pre_load`` processor changed it afterwards.

    .. attribute:: DEFAULT

        The value was produced because the input did not contain the field and
        the field had a ``load_default`` (or a nested field defaulted to a
        value).

    .. attribute:: PROCESSOR

        The value was not present in the original input and was added by a
        schema or field processor (for example ``pre_load`` or ``post_load``).
    """

    INPUT = "input"
    DEFAULT = "default"
    PROCESSOR = "processor"

    #: Alias for `INPUT`.
    EXTERNAL = "input"
    #: Alias for `INPUT`, naming the original request payload.
    ORIGINAL = "input"
    #: Alias for `PROCESSOR`.
    SERVER = "processor"


#: Sentinel for "the original value is not known at this level".
_UNKNOWN = object()
#: Sentinel returned by lookups when a path is not registered.
_MISSING = object()


_current_context: contextvars.ContextVar[_ProvenanceContext | None] = (
    contextvars.ContextVar("marshmallow_provenance", default=None)
)


@dataclasses.dataclass(frozen=True)
class _ProvenanceContext:
    """Provenance context for the field currently being deserialized."""

    collector: LoadProvenance
    path: tuple[typing.Any, ...]
    alias: tuple[typing.Any, ...]
    source: FieldSource
    original: typing.Any = _UNKNOWN

    def child(
        self,
        path: tuple[typing.Any, ...],
        alias: tuple[typing.Any, ...],
        *,
        source: FieldSource | None = None,
        original: typing.Any = _UNKNOWN,
    ) -> _ProvenanceContext:
        return _ProvenanceContext(
            collector=self.collector,
            path=self.path + tuple(path),
            alias=self.alias + tuple(alias),
            source=source or self.source,
            original=original,
        )

    def index(self, index: int) -> _ProvenanceContext:
        """Return the context for one item of a collection field."""
        original = _UNKNOWN
        if isinstance(self.original, (list, tuple)) and index < len(self.original):
            original = self.original[index]
        return _ProvenanceContext(
            collector=self.collector,
            path=(*self.path, index),
            alias=(*self.alias, index),
            source=self.source,
            original=original,
        )

    def key(self, key: typing.Any) -> _ProvenanceContext:
        """Return the context for one value of a mapping field."""
        original = _UNKNOWN
        if isinstance(self.original, Mapping) and key in self.original:
            original = self.original[key]
        return _ProvenanceContext(
            collector=self.collector,
            path=(*self.path, key),
            alias=(*self.alias, key),
            source=self.source,
            original=original,
        )


def _push_context(ctx: _ProvenanceContext | None) -> contextvars.Token | None:
    if ctx is None:
        return None
    return _current_context.set(ctx)


def _pop_context(token: contextvars.Token | None) -> None:
    if token is not None:
        _current_context.reset(token)


def _current() -> _ProvenanceContext | None:
    return _current_context.get()


class LoadProvenance:
    """Collects :class:`FieldSource` values for one ``Schema.load`` call.

    Pass an instance to ``Schema.load`` to read sources afterwards::

        provenance = LoadProvenance()
        data = schema.load(payload, provenance=provenance)
        provenance.get("homeAddress.zipCode")  # FieldSource.INPUT
        provenance.by_alias("UserName")  # FieldSource.INPUT

    Alternatively use ``provenance=True``, in which case ``load`` returns
    ``(data, provenance)``.

    Lookups accept a dotted path relative to the schema that was loaded. Both
    the external alias path (keys in the request payload, including nested
    ``data_key`` names) and the output path (keys of the business dict,
    including ``attribute`` names) are registered.
    """

    def __init__(self) -> None:
        self._by_path: dict[tuple[typing.Any, ...], FieldSource] = {}
        self._by_alias: dict[tuple[typing.Any, ...], FieldSource] = {}
        self._path_base: tuple[typing.Any, ...] = ()
        self._alias_base: tuple[typing.Any, ...] = ()
        self._original: typing.Any = _UNKNOWN
        self._root_original: typing.Any = _UNKNOWN
        self._parent: LoadProvenance | None = None

    def _scoped(
        self,
        path: tuple[typing.Any, ...],
        alias: tuple[typing.Any, ...],
        original: typing.Any = _UNKNOWN,
    ) -> LoadProvenance:
        """Return a view of this collector with absolute bases ``path``/``alias``.

        ``path`` and ``alias`` are complete paths, not relative segments, so
        callers must include any existing base themselves.
        """
        child = object.__new__(LoadProvenance)
        child._by_path = self._by_path
        child._by_alias = self._by_alias
        child._path_base = tuple(path)
        child._alias_base = tuple(alias)
        child._original = original
        child._root_original = self._root_original
        child._parent = self
        return child

    def _context(
        self,
        path: tuple[typing.Any, ...],
        alias: tuple[typing.Any, ...],
        source: FieldSource,
        original: typing.Any = _UNKNOWN,
    ) -> _ProvenanceContext:
        """Build a context for paths relative to this view's base."""
        return _ProvenanceContext(
            collector=self,
            path=self._path_base + tuple(path),
            alias=self._alias_base + tuple(alias),
            source=source,
            original=original,
        )

    def _record(
        self,
        output_path: tuple[typing.Any, ...],
        alias_path: tuple[typing.Any, ...],
        source: FieldSource,
    ) -> None:
        # A more specific record (a nested child) must not be overwritten by a
        # later, broader one (its parent field).
        self._by_path.setdefault(output_path, source)
        self._by_alias.setdefault(alias_path, source)

    def _record_context(
        self,
        ctx: _ProvenanceContext,
        source: FieldSource | None = None,
    ) -> None:
        self._record(ctx.path, ctx.alias, source or ctx.source)

    def _bind_root(self, original: typing.Any) -> LoadProvenance:
        """Attach the root input used to resolve nested originals.

        Nested views share the root collector's input by reference.
        """
        if self._root_original is _UNKNOWN:
            self._root_original = original
        return self

    def _root_view(self) -> LoadProvenance:
        """Return the collector that holds the root input."""
        root = self
        while root._parent is not None:
            root = root._parent
        return root

    def _lookup_original(
        self, path: tuple[typing.Any, ...], default: typing.Any = _UNKNOWN
    ) -> typing.Any:
        """Walk ``path`` through the root input; return ``default`` if absent."""
        current = self._root_original
        for part in path:
            if current is _UNKNOWN:
                return default
            if isinstance(current, Mapping):
                try:
                    current = current[part]
                except (KeyError, TypeError):
                    return default
            elif (
                isinstance(current, (list, tuple))
                and isinstance(part, int)
                and 0 <= part < len(current)
            ):
                current = current[part]
            else:
                return default
        return current

    def _record_added(
        self,
        data: typing.Any,
        before: typing.Any,
        source: FieldSource = FieldSource.PROCESSOR,
    ) -> None:
        """Record keys added to ``data`` by post-load processors."""
        if isinstance(data, Mapping):
            old = before if isinstance(before, Mapping) else {}
            for key in set(data) - set(old):
                path = tuple(str(key).split("."))
                self._record(self._path_base + path, self._alias_base + path, source)
        elif isinstance(data, (list, tuple)) and isinstance(before, (list, tuple)):
            for index, (item, old) in enumerate(zip(data, before, strict=False)):
                if isinstance(item, Mapping) and isinstance(old, Mapping):
                    for key in set(item) - set(old):
                        path = (index, *tuple(str(key).split(".")))
                        self._record(
                            self._path_base + path,
                            self._alias_base + path,
                            source,
                        )

    @staticmethod
    def _candidates(
        path: str | typing.Sequence[typing.Any],
    ) -> typing.Iterator[tuple[typing.Any, ...]]:
        if isinstance(path, str):
            # A data_key may legitimately contain a dot. Try it as one segment
            # before interpreting it as a nested path.
            yield (path,)
            parts = path.split(".")
            yield tuple(parts)
            converted = tuple(int(part) if part.isdigit() else part for part in parts)
            if converted != tuple(parts):
                yield converted
        else:
            parts = tuple(path)
            yield parts
            converted = tuple(
                int(part) if isinstance(part, str) and part.isdigit() else part
                for part in parts
            )
            if converted != parts:
                yield converted

    def _lookup(
        self,
        mapping: dict[tuple[typing.Any, ...], FieldSource],
        path: str | typing.Sequence[typing.Any],
    ) -> FieldSource | object:
        for candidate in self._candidates(path):
            try:
                return mapping[candidate]
            except KeyError:
                pass
        return _MISSING

    def by_alias(
        self, path: str | typing.Sequence[typing.Any], default: typing.Any = None
    ) -> FieldSource | typing.Any:
        """Look up a source by external alias path (for example ``"UserName"``)."""
        source = self._lookup(self._by_alias, path)
        return default if source is _MISSING else source

    def by_path(
        self, path: str | typing.Sequence[typing.Any], default: typing.Any = None
    ) -> FieldSource | typing.Any:
        """Look up a source by output/business-dict path."""
        source = self._lookup(self._by_path, path)
        return default if source is _MISSING else source

    def get(
        self, path: str | typing.Sequence[typing.Any], default: typing.Any = None
    ) -> FieldSource | typing.Any:
        """Look up a source, preferring alias paths then output paths."""
        source = self._lookup(self._by_alias, path)
        if source is _MISSING:
            source = self._lookup(self._by_path, path)
        return default if source is _MISSING else source

    def __getitem__(self, path: str | typing.Sequence[typing.Any]) -> FieldSource:
        source = self.get(path, _MISSING)
        if source is _MISSING:
            raise KeyError(path)
        return typing.cast("FieldSource", source)

    def __contains__(self, path: object) -> bool:
        if not isinstance(path, (str, list, tuple)):
            return False
        return (
            self._lookup(self._by_alias, path) is not _MISSING
            or self._lookup(self._by_path, path) is not _MISSING
        )

    def __len__(self) -> int:
        return len(self._by_path)

    @staticmethod
    def _render(path: tuple[typing.Any, ...]) -> str:
        return ".".join(str(part) for part in path)

    @property
    def paths(self) -> dict[str, FieldSource]:
        """Sources keyed by output/business-dict path."""
        return {self._render(path): source for path, source in self._by_path.items()}

    @property
    def aliases(self) -> dict[str, FieldSource]:
        """Sources keyed by external alias path."""
        return {
            self._render(path): source for path, source in self._by_alias.items()
        }

    def items(self) -> typing.Iterator[tuple[str, FieldSource]]:
        """Iterate over ``(output_path, source)`` pairs."""
        return iter(self.paths.items())

    def as_dict(
        self, *, by: typing.Literal["path", "alias"] = "path"
    ) -> dict[str, str]:
        """Return sources as a JSON-serializable mapping of path to source."""
        if by == "alias":
            return {path: str(source) for path, source in self.aliases.items()}
        return {path: str(source) for path, source in self.paths.items()}

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}({self.as_dict()!r})>"
