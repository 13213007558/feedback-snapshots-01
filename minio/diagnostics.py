# -*- coding: utf-8 -*-
"""Controlled, correlation-preserving diagnostics for replication traffic.

The objects in this module never replace request data.  The HTTP transport and
signer continue to see the original headers and payloads.  Diagnostics retain
correlation identifiers, request stages and safe material categories while
redacting actual key material and other protected markers.
"""

# pylint: disable=too-many-arguments,too-many-lines,too-many-public-methods

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import threading
import uuid
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping, Optional, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SOURCE_SSE_MATERIAL = "source_sse_material"
TARGET_SSE_MATERIAL = "target_sse_material"
DESTINATION_SSE_MATERIAL = TARGET_SSE_MATERIAL
SSE_MATERIAL = "sse_material"
SYNTHETIC_RESPONSE_MATERIAL = "synthetic_response_material"
RESPONSE_INTERNAL_MARKER = SYNTHETIC_RESPONSE_MATERIAL
SIGNATURE_MATERIAL = "signature_material"
CREDENTIAL_MATERIAL = "credential_material"
CUSTOM_MATERIAL = "protected_material"

MATERIAL_CATEGORIES = frozenset(
    {
        SOURCE_SSE_MATERIAL,
        TARGET_SSE_MATERIAL,
        SSE_MATERIAL,
        SYNTHETIC_RESPONSE_MATERIAL,
        SIGNATURE_MATERIAL,
        CREDENTIAL_MATERIAL,
        CUSTOM_MATERIAL,
    },
)

SOURCE_ENCRYPTION_MATERIAL = SOURCE_SSE_MATERIAL
TARGET_ENCRYPTION_MATERIAL = TARGET_SSE_MATERIAL
DESTINATION_ENCRYPTION_MATERIAL = TARGET_SSE_MATERIAL
MATERIAL_SOURCE_SSE = SOURCE_SSE_MATERIAL
MATERIAL_TARGET_SSE = TARGET_SSE_MATERIAL
MATERIAL_RESPONSE_MARKER = SYNTHETIC_RESPONSE_MATERIAL

REDACTED = "[REDACTED]"

_CURRENT_RECORDER: ContextVar[
    Optional["DiagnosticRecorder"]
] = ContextVar("minio_diagnostic_recorder", default=None)
_CURRENT_SCOPE: ContextVar[
    Optional["DiagnosticScope"]
] = ContextVar("minio_diagnostic_scope", default=None)
_CURRENT_HTTP_ID: ContextVar[Optional[str]] = ContextVar(
    "minio_diagnostic_http_id", default=None,
)

_DEFAULT_RECORDER: Optional["DiagnosticRecorder"] = None
_DEFAULT_RECORDER_LOCK = threading.Lock()


class DiagnosticRecord(dict):
    """A JSON-like dictionary that also exposes fields as attributes."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


@dataclass(frozen=True)
class DiagnosticScope:
    """Job, chain and attempt correlation for diagnostic records."""

    job_id: str = "-"
    chain_id: str = "-"
    attempt: int = 0
    attempt_id: str = "-"
    stage: str = "-"
    operation: str = "-"

    def as_dict(self) -> dict[str, Any]:
        """Return the correlation fields as a dictionary."""
        return {
            "job_id": self.job_id,
            "chain_id": self.chain_id,
            "attempt": self.attempt,
            "attempt_id": self.attempt_id,
            "stage": self.stage,
            "operation": self.operation,
        }


def _new_id(prefix: str) -> str:
    """Generate a short random identifier."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _as_text(value: Any) -> str:
    """Decode bytes for redaction while tolerating binary header values."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1", errors="replace")
    return str(value)


def classify_material_header(
        name: str,
        stage: Optional[str] = None,
) -> Optional[str]:
    """Return the safe material category for an HTTP header name."""
    lowered = name.lower()
    is_customer_key = (
        "server-side-encryption-customer-key" in lowered
        or "sse-customer-key" in lowered
    )
    if "copy-source" in lowered and is_customer_key:
        return SOURCE_SSE_MATERIAL
    if is_customer_key:
        if stage in {"head_source", "get_source", "read_source"}:
            return SOURCE_SSE_MATERIAL
        return TARGET_SSE_MATERIAL
    if "kms-key-id" in lowered or "sse-aws-kms" in lowered:
        return TARGET_SSE_MATERIAL
    if lowered == "authorization":
        return SIGNATURE_MATERIAL
    if lowered in {"x-amz-security-token", "cookie", "set-cookie"}:
        return CREDENTIAL_MATERIAL
    return None


def infer_wire_stage(
        method: str,
        query: Optional[Mapping[str, Any] | str] = None,
        headers: Optional[Mapping[str, Any]] = None,
) -> str:
    """Infer the S3 replication stage from a wire request."""
    if isinstance(query, str):
        params = dict(parse_qsl(query, keep_blank_values=True))
    else:
        params = {
            key: str(value) for key, value in (query or {}).items()
        }

    method_upper = method.upper()
    headers = headers or {}
    lower_headers = {key.lower(): value for key, value in headers.items()}

    if "uploads" in params and method_upper == "POST":
        return "create_multipart_upload"
    if "uploadid" in {key.lower() for key in params}:
        if method_upper == "DELETE":
            return "abort_multipart_upload"
        if method_upper == "POST":
            return "complete_multipart_upload"
        if method_upper == "PUT":
            if "partnumber" in {key.lower() for key in params}:
                if "x-amz-copy-source" in lower_headers:
                    return "upload_part_copy"
                return "upload_part"
    if method_upper == "HEAD":
        return "head_source"
    if method_upper == "PUT" and "x-amz-copy-source" in lower_headers:
        return "copy_object"
    if method_upper == "GET" and "location" in {
            key.lower() for key in params}:
        return "get_bucket_region"
    return f"{method_upper.lower()}_request"


class MaterialGuard:
    """Private value registry used to redact actual material values."""

    def __init__(self) -> None:
        self._values: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    def protect(
            self,
            value: Any,
            category: str = CUSTOM_MATERIAL,
    ) -> str:
        """Protect a value and return its safe placeholder."""
        if value is None:
            return f"{REDACTED}:{category}"
        candidates = self._candidate_values(value)
        with self._lock:
            for candidate in candidates:
                if len(candidate) >= 4:
                    self._values.setdefault(candidate, set()).add(category)
        return f"{REDACTED}:{category}"

    @staticmethod
    def _candidate_values(value: Any) -> list[str]:
        """Return raw, base64 and checksum forms that may appear in text."""
        candidates: list[str] = []
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            candidates.append(raw.decode("latin-1", errors="replace"))
            candidates.append(base64.b64encode(raw).decode("ascii"))
            digest = hashlib.md5(  # noqa: S324 - S3 header compatibility
                raw, usedforsecurity=False,
            ).digest()
            candidates.append(base64.b64encode(digest).decode("ascii"))
        else:
            text = str(value)
            candidates.append(text)
            try:
                decoded = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                decoded = None
            if decoded is not None:
                candidates.append(
                    decoded.decode("utf-8", errors="ignore"),
                )
                candidates.append(
                    base64.b64encode(decoded).decode("ascii"),
                )
        return [item for item in candidates if item]

    def categories_for(self, value: str) -> set[str]:
        """Return categories registered for an exact value."""
        with self._lock:
            return set(self._values.get(value, set()))

    def redact(self, text: Any) -> str:
        """Redact all protected values from ``text``."""
        if text is None:
            return ""
        result = _as_text(text)
        with self._lock:
            values = sorted(
                self._values.items(),
                key=lambda item: len(item[0]),
                reverse=True,
            )
            for value, categories in values:
                if value and value in result:
                    category = (
                        next(iter(categories))
                        if len(categories) == 1
                        else CUSTOM_MATERIAL
                    )
                    result = result.replace(
                        value, f"{REDACTED}:{category}",
                    )
        return result

    def merge(self, other: "MaterialGuard") -> None:
        """Copy protected values from another guard."""
        # pylint: disable=protected-access
        with self._lock, other._lock:
            for value, categories in other._values.items():
                self._values.setdefault(value, set()).update(categories)


class DisclosurePolicy:
    """What a shareable diagnostic view is allowed to retain."""

    def __init__(
            self,
            *,
            allowed_categories: Optional[Sequence[str]] = None,
            allow_categories: Optional[Sequence[str]] = None,
            include_headers: bool = True,
            include_url: bool = True,
            include_message: bool = True,
            include_response_body: bool = False,
            include_body: bool = False,
            max_text_length: int = 4096,
            markers: Optional[Mapping[str, Any] | Sequence[Any]] = None,
            protected_values: Optional[Sequence[Any]] = None,
            secrets: Optional[Mapping[str, Any] | Sequence[Any]] = None,
    ) -> None:
        allowed = allowed_categories
        if allowed is None:
            allowed = allow_categories
        self.allowed_categories = (
            None if allowed is None else frozenset(allowed)
        )
        self.include_headers = include_headers
        self.include_url = include_url
        self.include_message = include_message
        self.include_response_body = include_response_body
        self.include_body = include_body
        self.max_text_length = max_text_length
        self.guard = MaterialGuard()

        for item in protected_values or ():
            self.protect(item)
        for item in secrets or ():
            if isinstance(item, Mapping):
                for category, value in item.items():
                    self.protect(value, str(category))
            else:
                self.protect(item)
        if isinstance(markers, Mapping):
            for category, value in markers.items():
                self.protect(value, str(category))
        elif markers is not None:
            for marker in markers:
                self.protect(marker, SYNTHETIC_RESPONSE_MATERIAL)

    @classmethod
    def strict(cls, **kwargs: Any) -> "DisclosurePolicy":
        """Return a conservative policy that omits free-text messages/bodies."""
        kwargs.setdefault("include_message", False)
        kwargs.setdefault("include_response_body", False)
        kwargs.setdefault("include_body", False)
        return cls(**kwargs)

    @classmethod
    def shareable_categories(
            cls,
            categories: Sequence[str],
            **kwargs: Any,
    ) -> "DisclosurePolicy":
        """Return a policy allowing only the named material categories."""
        return cls(allowed_categories=categories, **kwargs)

    def protect(
            self,
            value: Any,
            category: str = CUSTOM_MATERIAL,
    ) -> str:
        """Protect a marker using this policy's guard."""
        return self.guard.protect(value, category)

    def category_allowed(self, category: str) -> bool:
        """Return whether a material category may be published."""
        if self.allowed_categories is None:
            return True
        return category in self.allowed_categories

    def materials(
            self,
            materials: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Filter material descriptors by allowed category."""
        result = []
        for material in materials:
            category = str(material.get("category", CUSTOM_MATERIAL))
            if self.category_allowed(category):
                item = dict(material)
                item["redacted"] = True
                result.append(item)
        return result

    def redact(self, value: Any) -> str:
        """Redact protected material and truncate long text."""
        result = self.guard.redact(value)
        if len(result) > self.max_text_length:
            result = result[:self.max_text_length] + "...[truncated]"
        return result

    def redact_headers(
            self,
            headers: Optional[Mapping[str, Any]],
            *,
            register: bool = True,
            stage: Optional[str] = None,
    ) -> dict[str, str]:
        """Return a copy of headers with material values redacted."""
        safe: dict[str, str] = {}
        for key, value in (headers or {}).items():
            text = _as_text(value)
            category = classify_material_header(key, stage)
            if category:
                if register:
                    self.protect(text, category)
                safe[key] = f"{REDACTED}:{category}"
            else:
                safe[key] = self.redact(text)
        return safe

    def redact_url(self, url: str) -> str:
        """Redact signed-URL credentials and protected markers."""
        parts = urlsplit(url)
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            category = classify_material_header(key)
            lowered = key.lower()
            if category or "signature" in lowered or "credential" in lowered:
                category = category or SIGNATURE_MATERIAL
                self.protect(value, category)
                query.append((key, f"{REDACTED}:{category}"))
            else:
                query.append((key, value))
        redacted_query = urlencode(query)
        redacted_url = urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                redacted_query,
                parts.fragment,
            ),
        )
        return self.redact(redacted_url)


def redact_headers(
        headers: Optional[Mapping[str, Any]],
        policy: Optional[DisclosurePolicy] = None,
        *,
        stage: Optional[str] = None,
) -> dict[str, str]:
    """Redact sensitive headers with an optional shared policy."""
    policy = policy or DisclosurePolicy()
    return policy.redact_headers(headers, stage=stage)


def redact_text(
        value: Any,
        policy: Optional[DisclosurePolicy] = None,
        *,
        markers: Optional[Sequence[Any]] = None,
        allowed_categories: Optional[Sequence[str]] = None,
) -> str:
    """Redact text using a policy and optional one-off markers."""
    if policy is None:
        policy = DisclosurePolicy(
            markers=markers,
            allowed_categories=allowed_categories,
        )
    elif markers:
        for marker in markers:
            policy.protect(marker, SYNTHETIC_RESPONSE_MATERIAL)
    return policy.redact(value)


class DiagnosticRecorder:
    """Thread-safe store for correlation records and attempt chains."""

    def __init__(
            self,
            policy: Optional[DisclosurePolicy] = None,
            redaction_policy: Optional[DisclosurePolicy] = None,
            disclosure_policy: Optional[DisclosurePolicy] = None,
            *,
            name: str = "minio-replication",
            markers: Optional[Sequence[Any]] = None,
            protected_markers: Optional[Sequence[Any]] = None,
            protected_values: Optional[Sequence[Any]] = None,
            sensitive_values: Optional[Sequence[Any]] = None,
            allowed_categories: Optional[Sequence[str]] = None,
    ) -> None:
        self.name = name
        policy = policy or redaction_policy or disclosure_policy
        if policy is None:
            values = list(protected_values or ())
            values.extend(protected_markers or ())
            values.extend(sensitive_values or ())
            policy = DisclosurePolicy(
                markers=list(markers or ()) + values,
                allowed_categories=allowed_categories,
            )
        self.policy = policy
        self._records: list[DiagnosticRecord] = []
        self._attempt_counts: dict[str, int] = {}
        self._lock = threading.RLock()

    @contextmanager
    def job(
            self,
            job_id: Optional[str] = None,
            *,
            chain_id: Optional[str] = None,
            operation: str = "replication",
            stage: str = "job",
            **metadata: Any,
    ) -> Iterator[DiagnosticScope]:
        """Bind all nested records to one replication job and chain."""
        job_id = job_id or _new_id("job")
        chain_id = chain_id or job_id
        scope = DiagnosticScope(
            job_id=job_id,
            chain_id=chain_id,
            operation=operation,
            stage=stage,
        )
        recorder_token = _CURRENT_RECORDER.set(self)
        scope_token = _CURRENT_SCOPE.set(scope)
        try:
            self.emit("job_started", metadata=metadata or None)
            yield scope
            self.emit("job_completed", metadata=metadata or None)
        except BaseException as exc:  # noqa: BLE001
            with suppress(Exception):
                self.record_error(exc, phase="job_failed")
            raise
        finally:
            _CURRENT_SCOPE.reset(scope_token)
            _CURRENT_RECORDER.reset(recorder_token)

    @contextmanager
    def attempt(
            self,
            number: Optional[int] = None,
            *,
            stage: Optional[str] = None,
            attempt_id: Optional[str] = None,
            retry: bool = False,
    ) -> Iterator[DiagnosticScope]:
        """Bind nested wire records to one numbered retry attempt."""
        parent = self._scope()
        if number is None:
            with self._lock:
                number = self._attempt_counts.get(parent.chain_id, 0) + 1
                self._attempt_counts[parent.chain_id] = number
        else:
            with self._lock:
                self._attempt_counts[parent.chain_id] = max(
                    self._attempt_counts.get(parent.chain_id, 0), number,
                )
        scope = DiagnosticScope(
            job_id=parent.job_id,
            chain_id=parent.chain_id,
            attempt=number,
            attempt_id=attempt_id or f"{parent.chain_id}:attempt-{number}",
            stage=stage or parent.stage,
            operation=parent.operation,
        )
        token = _CURRENT_SCOPE.set(scope)
        try:
            self.emit(
                "attempt_started",
                metadata={"retry": retry or number > 1},
            )
            yield scope
            self.emit("attempt_completed")
        except BaseException as exc:  # noqa: BLE001
            with suppress(Exception):
                self.record_error(exc, phase="attempt_failed")
            raise
        finally:
            _CURRENT_SCOPE.reset(token)

    @contextmanager
    def stage(self, stage: str) -> Iterator[DiagnosticScope]:
        """Set the stage for nested diagnostic records."""
        parent = self._scope()
        scope = DiagnosticScope(
            job_id=parent.job_id,
            chain_id=parent.chain_id,
            attempt=parent.attempt,
            attempt_id=parent.attempt_id,
            stage=stage,
            operation=parent.operation,
        )
        token = _CURRENT_SCOPE.set(scope)
        try:
            yield scope
        finally:
            _CURRENT_SCOPE.reset(token)

    def protect(
            self,
            value: Any,
            category: str = CUSTOM_MATERIAL,
    ) -> str:
        """Protect an internal marker from shareable output."""
        return self.policy.protect(value, category)

    def protect_headers(
            self,
            headers: Optional[Mapping[str, Any]],
            *,
            stage: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Register material header values and return category descriptors."""
        materials: list[dict[str, Any]] = []
        for key, value in (headers or {}).items():
            category = classify_material_header(key, stage)
            if not category:
                continue
            self.policy.protect(_as_text(value), category)
            materials.append(
                {
                    "category": category,
                    "field": key.lower(),
                    "scope": (
                        "source"
                        if category == SOURCE_SSE_MATERIAL
                        else "target"
                        if category == TARGET_SSE_MATERIAL
                        else "signature"
                        if category == SIGNATURE_MATERIAL
                        else "credential"
                    ),
                },
            )
        return materials

    @staticmethod
    def _scope() -> DiagnosticScope:
        """Return the active scope or a safe unscoped placeholder."""
        return _CURRENT_SCOPE.get() or DiagnosticScope()

    def emit(
            self,
            phase: str,
            *,
            stage: Optional[str] = None,
            **fields: Any,
    ) -> DiagnosticRecord:
        """Create and store one safe diagnostic record."""
        scope_data = self._scope().as_dict()
        scope_stage = scope_data.pop("stage")
        effective_stage = stage or scope_stage
        with self._lock:
            sequence = len(self._records) + 1
        materials = list(fields.pop("materials", []) or [])
        headers = fields.pop("headers", None)
        safe_headers = None
        if headers is not None and self.policy.include_headers:
            safe_headers = self.policy.redact_headers(
                headers, stage=effective_stage,
            )
            materials.extend(
                self.protect_headers(headers, stage=effective_stage),
            )
        url = fields.pop("url", None)
        safe_url = self.policy.redact_url(url) if (
            url and self.policy.include_url
        ) else None
        error = fields.pop("error", None)
        if error is not None and not isinstance(error, dict):
            error = build_error_summary(error, self.policy)
        metadata = fields.pop("metadata", None) or {}
        extra = {}
        for key, value in fields.items():
            if key.startswith("_"):
                continue
            extra[key] = self.policy.redact(value) if isinstance(
                value, str,
            ) else value

        unique_materials = []
        seen_materials = set()
        for material in materials:
            material_key = (
                material.get("category"),
                material.get("field"),
                material.get("scope"),
            )
            if material_key not in seen_materials:
                seen_materials.add(material_key)
                unique_materials.append(material)

        record = DiagnosticRecord(
            sequence=sequence,
            recorder=self.name,
            **scope_data,
            job=scope_data["job_id"],
            chain=scope_data["chain_id"],
            attempt_number=scope_data["attempt"],
            phase=phase,
            stage=effective_stage,
            shareable=True,
            disclosure="redacted-material-values",
            materials=self.policy.materials(unique_materials),
            headers=safe_headers,
            url=safe_url,
            error=error,
            metadata=metadata,
            **extra,
        )
        with self._lock:
            self._records.append(record)
        return record

    def record_http_request(
            self,
            *,
            method: str,
            url: str,
            headers: Optional[Mapping[str, Any]] = None,
            body: Any = None,
            wire_stage: Optional[str] = None,
            correlation_id: Optional[str] = None,
            query_params: Optional[Mapping[str, Any]] = None,
    ) -> DiagnosticRecord:
        """Record an about-to-be-sent HTTP request without material values."""
        stage_name = wire_stage or infer_wire_stage(
            method, query_params or url, headers,
        )
        materials = self.protect_headers(headers, stage=stage_name)
        correlation_id = correlation_id or _new_id("http")
        safe_body = None
        if self.policy.include_body and body is not None:
            safe_body = self.policy.redact(body)
        return self.emit(
            "request",
            stage=stage_name,
            method=method.upper(),
            url=url,
            headers=headers,
            materials=materials,
            correlation_id=correlation_id,
            body=safe_body,
        )

    def record_http_response(
            self,
            *,
            correlation_id: str,
            status: int,
            headers: Optional[Mapping[str, Any]] = None,
            stage: Optional[str] = None,
    ) -> DiagnosticRecord:
        """Record HTTP response status and safe headers."""
        return self.emit(
            "response",
            stage=stage,
            correlation_id=correlation_id,
            status=status,
            headers=headers,
        )

    def record_error(
            self,
            error: BaseException,
            *,
            phase: str = "error",
            correlation_id: Optional[str] = None,
            stage: Optional[str] = None,
    ) -> DiagnosticRecord:
        """Record a shareable error summary."""
        summary = build_error_summary(error, self.policy)
        context = getattr(error, "_diagnostic_context", None)
        if (
                not correlation_id
                and isinstance(context, Mapping)
                and context.get("correlation_id")
        ):
            correlation_id = context["correlation_id"]
        fields: dict[str, Any] = {"error": summary}
        if correlation_id:
            fields["correlation_id"] = correlation_id
        if isinstance(context, Mapping) and not stage:
            stage = context.get("stage")
        return self.emit(phase, stage=stage, **fields)

    def shareable_error(
            self,
            error: BaseException,
            **kwargs: Any,
    ) -> ShareableError:
        """Return an error summary redacted with this recorder's policy."""
        return shareable_error(error, self.policy, **kwargs)

    public_error = shareable_error

    @property
    def records(self) -> list[DiagnosticRecord]:
        """Return stored records."""
        with self._lock:
            return list(self._records)

    events = records

    def for_job(self, job_id: str) -> list[DiagnosticRecord]:
        """Return all records for a job."""
        return [item for item in self.records if item.job_id == job_id]

    def for_chain(self, chain_id: str) -> list[DiagnosticRecord]:
        """Return all records for an attempt chain."""
        return [item for item in self.records if item.chain_id == chain_id]

    def chain(self, chain_id: str) -> "AttemptChain":
        """Build the attempt chain for ``chain_id``."""
        records = self.for_chain(chain_id)
        attempts = sorted({
            int(item.attempt) for item in records if item.attempt
        })
        raw_failures = [
            item for item in records
            if item.phase in {"error", "attempt_failed", "job_failed"}
            or item.get("error")
        ]
        failed = []
        seen_failures = set()
        for item in raw_failures:
            dedupe_key = item.get("correlation_id") or (
                item.attempt,
                item.get("error", {}).get("request_id")
                if isinstance(item.get("error"), Mapping) else None,
                item.get("error", {}).get("code")
                if isinstance(item.get("error"), Mapping) else None,
                item.sequence,
            )
            if dedupe_key in seen_failures:
                continue
            seen_failures.add(dedupe_key)
            failed.append(item)
        recovered = bool(failed) and any(
            item.phase in {
                "response", "attempt_completed", "recovery", "job_completed",
            }
            and (
                item.get("status") is None
                or int(item.get("status", 200)) < 400
            )
            and item.attempt > min(
                (record.attempt for record in failed if record.attempt),
                default=0,
            )
            for item in records
        )
        return AttemptChain(
            chain_id=chain_id,
            job_id=records[0].job_id if records else "-",
            attempts=attempts,
            records=records,
            events=records,
            failures=failed,
            recovery_records=[
                item for item in records if item.phase == "recovery"
            ],
            recovered=recovered,
        )

    get_chain = chain

    def attempt_chain(self, chain_id: str) -> "AttemptChain":
        """Return the attempt chain for ``chain_id``."""
        return self.chain(chain_id)

    def records_for_job(self, job_id: str) -> list[DiagnosticRecord]:
        """Alias for :meth:`for_job`."""
        return self.for_job(job_id)

    def records_for_chain(self, chain_id: str) -> list[DiagnosticRecord]:
        """Alias for :meth:`for_chain`."""
        return self.for_chain(chain_id)

    @property
    def chains(self) -> dict[str, "AttemptChain"]:
        """Return all known attempt chains."""
        return {
            chain_id: self.chain(chain_id)
            for chain_id in {record.chain_id for record in self.records}
            if chain_id != "-"
        }

    def shareable(self) -> list[dict[str, Any]]:
        """Return JSON-safe shareable records."""
        return [record_to_shareable(item, self.policy) for item in self.records]

    snapshot = shareable

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary containing records and chains."""
        return {
            "records": self.shareable(),
            "chains": {
                chain_id: {
                    "job_id": chain.job_id,
                    "attempts": chain.attempts,
                    "recovered": chain.recovered,
                    "record_count": len(chain.records),
                }
                for chain_id, chain in self.chains.items()
            },
        }

    as_dict = to_dict

    def to_json(self, **kwargs: Any) -> str:
        """Serialize shareable records as JSON."""
        kwargs.setdefault("ensure_ascii", False)
        return json.dumps(self.shareable(), **kwargs)


class AttemptChain(DiagnosticRecord):
    """Records belonging to one job's failure/retry chain."""

    @property
    def attempt_chain(self) -> list[int]:
        """Alias for ordered attempt numbers."""
        return list(self.get("attempts", []))

    @property
    def failure(self) -> Optional[DiagnosticRecord]:
        """Return the first failure record, if any."""
        failures = self.get("failures", [])
        return failures[0] if failures else None

    @property
    def recovery(self) -> Optional[DiagnosticRecord]:
        """Return the explicit recovery record, if one was emitted."""
        records = self.get("recovery_records", [])
        return records[0] if records else None


def record_to_shareable(
        record: Mapping[str, Any],
        policy: Optional[DisclosurePolicy] = None,
) -> dict[str, Any]:
    """Convert a record to a plain JSON-safe dictionary."""
    result: dict[str, Any] = {}
    for key, value in dict(record).items():
        if key == "headers" and not (
                policy is None or policy.include_headers):
            continue
        if key == "url" and not (policy is None or policy.include_url):
            continue
        if key == "materials" and policy is not None:
            value = policy.materials(value or [])
        result[key] = value
    return json.loads(json.dumps(result, default=str, ensure_ascii=False))


class ShareableError(DiagnosticRecord):
    """A redacted exception summary safe for shared logs."""

    def __str__(self) -> str:
        return json.dumps(dict(self), ensure_ascii=False, sort_keys=True)

    @property
    def summary(self) -> dict[str, Any]:
        """Return the dictionary summary."""
        return dict(self)

    @classmethod
    def from_exception(
            cls,
            error: BaseException,
            policy: Optional[DisclosurePolicy] = None,
            **kwargs: Any,
    ) -> "ShareableError":
        """Build a safe summary from an exception."""
        return shareable_error(error, policy, **kwargs)


def _policy_chain(
        policy: Optional[DisclosurePolicy],
        error: Optional[BaseException] = None,
) -> list[DisclosurePolicy]:
    """Collect explicit and exception-attached redaction policies."""
    policies: list[DisclosurePolicy] = []
    attached = getattr(error, "_diagnostic_policy", None)
    extra = getattr(error, "_diagnostic_extra_policies", None) or []
    for candidate in [policy, attached, *extra]:
        if (
            isinstance(candidate, DisclosurePolicy)
            and candidate not in policies
        ):
            policies.append(candidate)
    if not policies:
        policies.append(DisclosurePolicy())
    return policies


def build_error_summary(
        error: BaseException,
        policy: Optional[DisclosurePolicy] = None,
        *,
        markers: Optional[Sequence[Any]] = None,
        protected_values: Optional[Sequence[Any]] = None,
) -> dict[str, Any]:
    """Build a shareable, redacted summary of an exception."""
    local_policy = DisclosurePolicy(
        markers=markers,
        protected_values=protected_values,
        include_message=policy.include_message if policy else True,
        include_response_body=(
            policy.include_response_body if policy else False
        ),
    )
    policies = _policy_chain(policy, error) + [local_policy]
    message_allowed = (
        policy.include_message
        if policy is not None
        else any(candidate.include_message for candidate in policies)
    )

    def redact(value: Any) -> str:
        text = _as_text(value)
        for candidate in policies:
            text = candidate.redact(text)
        return text

    status = getattr(error, "status_code", None)
    if status is None:
        response = getattr(error, "response", None)
        status = getattr(response, "status", None)
    context = getattr(error, "_diagnostic_context", None)
    summary = ShareableError(
        error_type=type(error).__name__,
        type=type(error).__name__,
        code=getattr(error, "code", None),
        status_code=status,
        request_id=getattr(error, "request_id", None),
        resource=redact(getattr(error, "resource", None)) or None,
        bucket_name=getattr(error, "bucket_name", None),
        object_name=getattr(error, "object_name", None),
        diagnostic=True,
    )
    if message_allowed:
        summary["message"] = redact(str(error))
    if isinstance(context, Mapping):
        for key in (
                "job_id", "chain_id", "attempt", "attempt_id", "stage",
                "correlation_id",
        ):
            if context.get(key) is not None:
                summary[key] = context[key]

    response = getattr(error, "response", None)
    response_headers = getattr(response, "headers", None)
    if response_headers:
        safe_headers: dict[str, str] = {}
        for key, value in response_headers.items():
            category = classify_material_header(key)
            if category:
                safe_headers[key] = f"{REDACTED}:{category}"
            else:
                safe_headers[key] = redact(value)
        summary["response_headers"] = safe_headers
    if policy is not None and policy.include_response_body:
        data = getattr(response, "data", None)
        if data is not None:
            summary["response_body"] = redact(data)
    return {key: value for key, value in summary.items() if value is not None}


def shareable_error(
        error: BaseException,
        policy: Optional[DisclosurePolicy] = None,
        **kwargs: Any,
) -> ShareableError:
    """Return a :class:`ShareableError` for an exception."""
    return ShareableError(build_error_summary(error, policy, **kwargs))


safe_error_summary = build_error_summary
public_error = shareable_error
redacted_error = shareable_error


def get_current_recorder() -> Optional[DiagnosticRecorder]:
    """Return the recorder bound to the current context, if any."""
    return _CURRENT_RECORDER.get()


def current_http_correlation_id() -> Optional[str]:
    """Return the HTTP correlation identifier bound to this call."""
    return _CURRENT_HTTP_ID.get()


def get_default_recorder() -> DiagnosticRecorder:
    """Return the process-wide default diagnostic recorder."""
    global _DEFAULT_RECORDER  # pylint: disable=global-statement
    with _DEFAULT_RECORDER_LOCK:
        if _DEFAULT_RECORDER is None:
            _DEFAULT_RECORDER = DiagnosticRecorder(name="default")
        return _DEFAULT_RECORDER


@contextmanager
def diagnostic_job(
        job_id: Optional[str] = None,
        *,
        recorder: Optional[DiagnosticRecorder] = None,
        **kwargs: Any,
) -> Iterator[DiagnosticScope]:
    """Open a job on the supplied or process-wide recorder."""
    recorder = recorder or get_default_recorder()
    with recorder.job(job_id, **kwargs) as scope:
        yield scope


@contextmanager
def diagnostic_attempt(
        number: Optional[int] = None,
        *,
        recorder: Optional[DiagnosticRecorder] = None,
        **kwargs: Any,
) -> Iterator[DiagnosticScope]:
    """Open an attempt on the supplied or contextual/default recorder."""
    recorder = recorder or _CURRENT_RECORDER.get() or get_default_recorder()
    with recorder.attempt(number, **kwargs) as scope:
        yield scope


@contextmanager
def diagnostic_stage(
        stage: str,
        *,
        recorder: Optional[DiagnosticRecorder] = None,
) -> Iterator[DiagnosticScope]:
    """Set the current diagnostic stage."""
    recorder = recorder or _CURRENT_RECORDER.get() or get_default_recorder()
    with recorder.stage(stage) as scope:
        yield scope


class ReplicationDiagnostics:
    """Retry replication calls while preserving one diagnostic chain."""

    def __init__(
            self,
            client: Any = None,
            *,
            recorder: Optional[DiagnosticRecorder] = None,
            policy: Optional[DisclosurePolicy] = None,
            max_attempts: int = 2,
            retry_on: Any = Exception,
    ) -> None:
        self.client = client
        self.recorder = recorder or DiagnosticRecorder(policy)
        self.max_attempts = max_attempts
        self.retry_on = retry_on
        self.attempt_errors: dict[str, list[BaseException]] = {}

    def run(
            self,
            job_id: Optional[str],
            operation: Callable[..., Any],
            *args: Any,
            max_attempts: Optional[int] = None,
            stage: str = "replication",
            **kwargs: Any,
    ) -> Any:
        """Run ``operation`` with job/attempt correlation and one retry."""
        attempts = max_attempts or self.max_attempts
        with self.recorder.job(job_id, stage=stage):
            for number in range(1, attempts + 1):
                try:
                    with self.recorder.attempt(number):
                        result = operation(*args, **kwargs)
                # pylint: disable-next=broad-exception-caught
                except self.retry_on as error:
                    self.attempt_errors.setdefault(
                        job_id or "-", [],
                    ).append(error)
                    if number >= attempts:
                        raise
                    self.recorder.emit(
                        "retry_scheduled",
                        reason=type(error).__name__,
                    )
                    continue
                if number > 1:
                    self.recorder.emit(
                        "recovery",
                        recovered=True,
                        failed_attempt=1,
                    )
                return result
        raise RuntimeError("replication diagnostic loop exited unexpectedly")

    def copy(self, *args: Any, **kwargs: Any) -> Any:
        """Run ``client.copy_object`` under a diagnostic attempt chain."""
        job_id = kwargs.pop("job_id", None)
        max_attempts = kwargs.pop("max_attempts", None)
        if self.client is None:
            raise ValueError("client is required for copy diagnostics")
        return self.run(
            job_id,
            self.client.copy_object,
            *args,
            max_attempts=max_attempts,
            stage="copy_object",
            **kwargs,
        )

    copy_object = copy
    replicate = run


class DiagnosticView:
    """Read-only shareable view over a diagnostic recorder."""

    def __init__(
            self,
            target: Any = None,
            *,
            recorder: Optional[DiagnosticRecorder] = None,
            policy: Optional[DisclosurePolicy] = None,
            allowed_categories: Optional[Sequence[str]] = None,
            markers: Optional[Sequence[Any]] = None,
    ) -> None:
        if policy is None and (
                allowed_categories is not None or markers is not None
        ):
            policy = DisclosurePolicy(
                allowed_categories=allowed_categories,
                markers=markers,
            )
        if recorder is not None:
            self.recorder = recorder
        elif isinstance(target, DiagnosticRecorder):
            self.recorder = target
        elif isinstance(target, DiagnosticView):
            self.recorder = target.recorder
        elif target is not None and hasattr(target, "diagnostic_view"):
            view = target.diagnostic_view()
            self.recorder = view.recorder
        else:
            self.recorder = target or get_default_recorder()
        if policy is not None:
            self.recorder.policy = policy

    @property
    def records(self) -> list[dict[str, Any]]:
        """Return shareable records."""
        return self.recorder.shareable()

    @property
    def chains(self) -> dict[str, AttemptChain]:
        """Return attempt chains."""
        return self.recorder.chains

    def chain(self, chain_id: str) -> AttemptChain:
        """Return one attempt chain."""
        return self.recorder.chain(chain_id)

    def for_job(self, job_id: str) -> list[dict[str, Any]]:
        """Return shareable records for one job."""
        return [
            record_to_shareable(item, self.recorder.policy)
            for item in self.recorder.for_job(job_id)
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary containing shareable records and chains."""
        return self.recorder.to_dict()

    as_dict = to_dict

    def to_json(self) -> str:
        """Serialize the view as JSON."""
        return self.recorder.to_json()


ControlledDiagnosticView = DiagnosticView
ShareableDiagnosticView = DiagnosticView
RedactionPolicy = DisclosurePolicy
DiagnosticPolicy = DisclosurePolicy
SafeError = ShareableError


class RecordedRequest(DiagnosticRecord):
    """One raw HTTP request captured by :class:`RecordingTransport`."""


class SafeTraceStream:
    """Redact material from trace text before writing to an output stream."""

    def __init__(
            self,
            stream: Any = None,
            policy: Optional[DisclosurePolicy] = None,
    ) -> None:
        self.policy = policy or DisclosurePolicy()
        self._output = stream if stream is not None else io.StringIO()

    def write(self, text: str) -> int:
        """Write redacted text to the wrapped stream."""
        return self._output.write(self.policy.redact(text))

    def flush(self) -> None:
        """Flush the wrapped stream when supported."""
        flush = getattr(self._output, "flush", None)
        if callable(flush):
            # pylint: disable-next=not-callable
            flush()

    def getvalue(self) -> str:
        """Return text from an in-memory wrapped stream."""
        return self._output.getvalue()


RedactingTraceStream = SafeTraceStream
ControlledTraceStream = SafeTraceStream


class RecordingTransport:
    """Transport decorator that records the exact outgoing request.

    The record intentionally contains original headers.  It is the test/
    transport evidence channel; shareable diagnostics must be produced by a
    :class:`DiagnosticRecorder` or :class:`DiagnosticView`.
    """

    def __init__(
            self,
            delegate: Any = None,
            *,
            inner: Any = None,
            wrapped: Any = None,
            handler: Optional[Callable[[RecordedRequest], Any]] = None,
            responses: Optional[Sequence[Any]] = None,
    ) -> None:
        self.delegate = delegate or inner or wrapped
        self.handler = handler
        self._responses = list(responses or [])
        self.requests: list[RecordedRequest] = []
        self._lock = threading.RLock()

    def urlopen(
            self,
            method: str,
            url: str,
            body: Any = None,
            headers: Optional[Mapping[str, Any]] = None,
            **kwargs: Any,
    ) -> Any:
        """Record a request and dispatch it to handler, script or delegate."""
        request = RecordedRequest(
            sequence=len(self.requests) + 1,
            method=method,
            url=url,
            body=body,
            headers=dict(headers or {}),
            kwargs=kwargs,
        )
        with self._lock:
            request["sequence"] = len(self.requests) + 1
            self.requests.append(request)
        if self.handler is not None:
            response = self.handler(request)
        elif self._responses:
            response = self._responses.pop(0)
        elif self.delegate is not None:
            response = self.delegate.urlopen(
                method, url, body=body, headers=headers, **kwargs,
            )
        else:
            raise RuntimeError(
                "RecordingTransport requires a handler, responses, or delegate",
            )
        request["response"] = response
        return response

    def clear(self) -> None:
        """Compatibility hook used by :class:`minio.Minio` finalization."""

    def reset(self) -> None:
        """Clear recorded requests."""
        with self._lock:
            self.requests.clear()

    @property
    def raw_requests(self) -> list[RecordedRequest]:
        """Explicit alias emphasizing that values are not redacted."""
        return self.requests

    @property
    def calls(self) -> list[RecordedRequest]:
        """Alias for recorded requests."""
        return self.requests

    recorded_requests = raw_requests


RecordingHTTPTransport = RecordingTransport


def get_current_scope() -> DiagnosticScope:
    """Return the current job/attempt scope or an unscoped placeholder."""
    return _CURRENT_SCOPE.get() or DiagnosticScope()


@contextmanager
def bind_http_correlation(correlation_id: str) -> Iterator[None]:
    """Bind a wire request correlation id to the current call context."""
    token = _CURRENT_HTTP_ID.set(correlation_id)
    try:
        yield
    finally:
        _CURRENT_HTTP_ID.reset(token)


def new_correlation_id(prefix: str = "http") -> str:
    """Generate a correlation identifier."""
    return _new_id(prefix)
