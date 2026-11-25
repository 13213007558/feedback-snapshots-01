"""Privacy-preserving public status and short-lived admin diagnostics."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from pydantic import AliasChoices, BaseModel, Field

from taskiq.abc.result_backend import AsyncResultBackend
from taskiq.exceptions import NoResultError, SecurityError
from taskiq.failure_categories import (
    FailureCategory,
    FailureClassifier,
    classify_failure,
    resolve_failure_category,
)
from taskiq.result import TaskiqResult

if TYPE_CHECKING:
    from taskiq.depends.progress_tracker import TaskProgress

PUBLIC_COLLECTION = "public_statuses"
DIAGNOSTIC_COLLECTION = "diagnostics"

__all__ = [
    "DIAGNOSTIC_COLLECTION",
    "PUBLIC_COLLECTION",
    "DiagnosticGrant",
    "FailureCategory",
    "InMemoryRecordSink",
    "PublicTaskFailure",
    "PublicTaskFailureError",
    "PublicTaskStatus",
    "RecordSink",
    "SecureResultBackend",
    "TaskDiagnostic",
]

StatusValue = Literal["pending", "retrying", "success", "failure"]


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _result_attempt(result: TaskiqResult[Any]) -> int:
    """Extract the retry generation from result labels."""
    raw_attempt = result.labels.get("_retries", 0)
    try:
        return max(0, int(raw_attempt))
    except (TypeError, ValueError):
        return 0


def _original_error(result: TaskiqResult[Any]) -> BaseException | None:
    """Return the task error behind a retry-suppression marker."""
    hidden_error = result.get_original_error()
    if hidden_error is not None:
        return hidden_error

    error = result.error
    if isinstance(error, NoResultError):
        return error.__cause__ or error.__context__ or error
    return error


class PublicTaskStatus(BaseModel):
    """Task state that is safe to persist and show to ordinary consumers."""

    schema_version: int = 1
    task_id: str
    status: StatusValue
    is_ready: bool = True
    is_err: bool = False
    failure_category: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "failure_category",
            "error_category",
            "category",
            "failure_kind",
        ),
    )
    retryable: bool | None = None
    attempt: int = 0
    execution_time: float = 0.0
    updated_at: datetime = Field(default_factory=utc_now)

    @property
    def state(self) -> StatusValue:
        """Alias for ``status``."""
        return self.status

    @property
    def failure_kind(self) -> str | None:
        """Alias for ``failure_category``."""
        return self.failure_category

    @property
    def error_category(self) -> str | None:
        """Alias for ``failure_category``."""
        return self.failure_category

    @property
    def category(self) -> str | None:
        """Alias for ``failure_category``."""
        return self.failure_category

    @classmethod
    def from_result(
        cls,
        task_id: str,
        result: TaskiqResult[Any],
        *,
        status: StatusValue | None = None,
        category: str | None = None,
        now: datetime | None = None,
    ) -> PublicTaskStatus:
        """
        Build a public status from a full result.

        :param task_id: Task id.
        :param result: Original task result.
        :param status: Optional explicit status.
        :param category: Optional resolved category.
        :param now: Optional timestamp for deterministic tests.
        :return: Safe public status.
        """
        error = _original_error(result)
        resolved_category = category or resolve_failure_category(result)
        suppressed = isinstance(result.error, NoResultError)
        has_original_error = suppressed and error is not result.error
        terminal_failure = result.is_err and not suppressed
        if status is None:
            if terminal_failure:
                status = "failure"
            elif suppressed:
                status = "retrying" if has_original_error else "pending"
            else:
                status = "success"

        return cls(
            task_id=task_id,
            status=status,
            is_ready=status == "success" or terminal_failure,
            is_err=terminal_failure or has_original_error,
            failure_category=(
                resolved_category if terminal_failure or has_original_error else None
            ),
            attempt=_result_attempt(result),
            retryable=getattr(error, "retryable", None),
            execution_time=result.execution_time,
            updated_at=now or utc_now(),
        )

    def to_result(self) -> TaskiqResult[None]:
        """Convert this status to a redacted Taskiq result."""
        error: BaseException | None = None
        if self.is_err and self.failure_category:
            error = PublicTaskFailureError(self.failure_category)
        return TaskiqResult(
            is_err=self.is_err,
            return_value=None,
            execution_time=self.execution_time,
            failure_category=self.failure_category,
            error=error,
        )


class PublicTaskFailureError(Exception):
    """Exception containing only a safe failure category."""

    def __init__(self, failure_category: str) -> None:
        self.failure_category = failure_category
        super().__init__(f"Task failed with category {failure_category!r}.")


PublicTaskFailure = PublicTaskFailureError


class TaskDiagnostic(BaseModel):
    """Authorized-only diagnostic details for a failure."""

    schema_version: int = 1
    task_id: str
    failure_category: str
    error_type: str | None = None
    error_message: str | None = None
    result: TaskiqResult[Any] | None = None
    attempt: int = 0
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    @property
    def error_category(self) -> str:
        """Alias for ``failure_category``."""
        return self.failure_category

    @classmethod
    def from_result(
        cls,
        task_id: str,
        result: TaskiqResult[Any],
        *,
        category: str,
        now: datetime,
        expires_at: datetime | None,
    ) -> TaskDiagnostic:
        """Build a diagnostic record while retaining necessary error details."""
        error = _original_error(result)
        diagnostic_result = result
        if error is not None and error is not result.error:
            diagnostic_result = result.model_copy(update={"error": error})
        return cls(
            task_id=task_id,
            failure_category=category,
            error_type=type(error).__name__ if error is not None else None,
            error_message=str(error) if error is not None else None,
            result=diagnostic_result,
            attempt=_result_attempt(result),
            created_at=now,
            expires_at=expires_at,
        )


class DiagnosticGrant(BaseModel):
    """Short-lived credential for the diagnostic API."""

    token: str
    task_id: str | None = None
    expires_at: datetime


@runtime_checkable
class RecordSink(Protocol):
    """Minimal persistence boundary used by the secure result backend."""

    async def write_record(
        self,
        collection: str,
        key: str,
        record: dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> None:
        """Write a JSON-safe record."""

    async def read_record(
        self,
        collection: str,
        key: str,
    ) -> dict[str, Any] | None:
        """Read a record."""

    async def delete_record(self, collection: str, key: str) -> None:
        """Delete a record."""


class InMemoryRecordSink:
    """In-memory :class:`RecordSink` useful for tests and local jobs."""

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], dict[str, Any]] = {}
        self.writes: list[tuple[str, str, dict[str, Any], float | None]] = []
        self.deletes: list[tuple[str, str]] = []

    async def write_record(
        self,
        collection: str,
        key: str,
        record: dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> None:
        """Persist a record in memory."""
        payload = dict(record)
        self.records[(collection, key)] = payload
        self.writes.append((collection, key, payload, ttl_seconds))

    async def read_record(
        self,
        collection: str,
        key: str,
    ) -> dict[str, Any] | None:
        """Return a record if present."""
        record = self.records.get((collection, key))
        return dict(record) if record is not None else None

    async def delete_record(self, collection: str, key: str) -> None:
        """Remove a record."""
        self.records.pop((collection, key), None)
        self.deletes.append((collection, key))


class _PublicResultBackendSink:
    """Expose a classic result backend through the record-sink interface."""

    def __init__(self, backend: AsyncResultBackend[Any]) -> None:
        self.backend = backend

    async def write_record(
        self,
        collection: str,
        key: str,
        record: dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> None:
        del collection, ttl_seconds
        status = PublicTaskStatus.model_validate(record)
        result = status.to_result()
        result.labels["_retries"] = status.attempt
        await self.backend.set_result(key, result)

    async def read_record(
        self,
        collection: str,
        key: str,
    ) -> dict[str, Any] | None:
        del collection
        try:
            result = await self.backend.get_result(key)
        except KeyError:
            return None
        return PublicTaskStatus.from_result(key, result).model_dump(mode="json")

    async def delete_record(self, collection: str, key: str) -> None:
        del collection
        deleter = getattr(self.backend, "delete_result", None) or getattr(
            self.backend,
            "delete",
            None,
        )
        if callable(deleter):
            removed = deleter(key)
            if hasattr(removed, "__await__"):
                await removed


class _DiagnosticResultBackendSink:
    """Store full diagnostic results in a classic result backend."""

    def __init__(self, backend: AsyncResultBackend[Any]) -> None:
        self.backend = backend

    async def write_record(
        self,
        collection: str,
        key: str,
        record: dict[str, Any],
        ttl_seconds: float | None = None,
    ) -> None:
        del collection, ttl_seconds
        diagnostic = TaskDiagnostic.model_validate(record)
        if diagnostic.result is None:
            return
        diagnostic.result.labels["_diagnostic_expires_at"] = record.get("expires_at")
        await self.backend.set_result(key, diagnostic.result)

    async def read_record(
        self,
        collection: str,
        key: str,
    ) -> dict[str, Any] | None:
        del collection
        try:
            result = await self.backend.get_result(key)
        except KeyError:
            return None
        expires_raw = result.labels.get("_diagnostic_expires_at")
        expires_at = (
            datetime.fromisoformat(expires_raw)
            if isinstance(expires_raw, str)
            else None
        )
        diagnostic = TaskDiagnostic.from_result(
            key,
            result,
            category=result.failure_category or classify_failure(result.error),
            now=utc_now(),
            expires_at=expires_at,
        )
        return diagnostic.model_dump(mode="json")

    async def delete_record(self, collection: str, key: str) -> None:
        del collection
        deleter = getattr(self.backend, "delete_result", None) or getattr(
            self.backend,
            "delete",
            None,
        )
        if callable(deleter):
            removed = deleter(key)
            if hasattr(removed, "__await__"):
                await removed


class SecureResultBackend(AsyncResultBackend[Any]):
    """
    Result backend separating public status from sensitive diagnostics.

    Ordinary reads return a redacted :class:`TaskiqResult`. Admin reads require
    credentials and return the original result only while its diagnostic TTL is
    valid. A successful retry overwrites public state and deletes diagnostics.
    """

    def __init__(
        self,
        persistence: AsyncResultBackend[Any] | RecordSink | None = None,
        *,
        sink: AsyncResultBackend[Any] | RecordSink | None = None,
        public_sink: AsyncResultBackend[Any] | RecordSink | None = None,
        public_backend: AsyncResultBackend[Any] | None = None,
        backend: AsyncResultBackend[Any] | None = None,
        diagnostic_sink: AsyncResultBackend[Any] | RecordSink | None = None,
        diagnostic_backend: AsyncResultBackend[Any] | None = None,
        admin_token: str | None = None,
        authorizer: Callable[..., Any] | None = None,
        diagnostic_ttl_seconds: float | None = 300.0,
        classifier: FailureClassifier = classify_failure,
        clock: Callable[[], datetime] = utc_now,
        allow_anonymous_admin: bool = False,
        purge_diagnostics_on_success: bool = False,
    ) -> None:
        public_source = (
            public_sink
            or public_backend
            or backend
            or persistence
            or sink
            or InMemoryRecordSink()
        )
        self.public_backend = (
            public_source if isinstance(public_source, AsyncResultBackend) else None
        )
        self.public_sink: RecordSink = (
            _PublicResultBackendSink(public_source)
            if isinstance(public_source, AsyncResultBackend)
            else public_source
        )

        diagnostic_source = diagnostic_sink or diagnostic_backend
        self.diagnostic_backend = (
            diagnostic_source
            if isinstance(diagnostic_source, AsyncResultBackend)
            else None
        )
        if self.diagnostic_backend is not None:
            self.diagnostic_sink: RecordSink = _DiagnosticResultBackendSink(
                self.diagnostic_backend,
            )
        elif diagnostic_source is not None and not isinstance(
            diagnostic_source,
            AsyncResultBackend,
        ):
            self.diagnostic_sink = diagnostic_source
        elif isinstance(persistence, RecordSink):
            self.diagnostic_sink = persistence
        elif isinstance(sink, RecordSink):
            self.diagnostic_sink = sink
        else:
            self.diagnostic_sink = InMemoryRecordSink()
        self.admin_token = admin_token
        self.authorizer = authorizer
        self.diagnostic_ttl_seconds = diagnostic_ttl_seconds
        self.classifier = classifier
        self.clock = clock
        self.allow_anonymous_admin = allow_anonymous_admin
        self.purge_diagnostics_on_success = purge_diagnostics_on_success
        self._grants: dict[str, DiagnosticGrant] = {}
        self._progress: dict[str, TaskProgress[Any]] = {}

    async def startup(self) -> None:
        """Start wrapped result backends."""
        if self.public_backend is not None:
            await self.public_backend.startup()
        if self.diagnostic_backend is not None:
            await self.diagnostic_backend.startup()

    async def shutdown(self) -> None:
        """Shut down wrapped result backends."""
        if self.public_backend is not None:
            await self.public_backend.shutdown()
        if self.diagnostic_backend is not None:
            await self.diagnostic_backend.shutdown()

    async def set_progress(
        self,
        task_id: str,
        progress: TaskProgress[Any],
    ) -> None:
        """Delegate progress storage or keep it in memory."""
        if self.public_backend is not None:
            await self.public_backend.set_progress(task_id, progress)
        else:
            self._progress[task_id] = progress

    async def get_progress(self, task_id: str) -> TaskProgress[Any] | None:
        """Read progress from the wrapped backend or local memory."""
        if self.public_backend is not None:
            return await self.public_backend.get_progress(task_id)
        return self._progress.get(task_id)

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None:
            return now.replace(tzinfo=timezone.utc)
        return now

    def _denied(self) -> SecurityError:
        return SecurityError(
            description="Valid admin credentials are required for diagnostics.",
        )

    def _hash_token(self, token: str) -> str:
        return sha256(token.encode("utf-8")).hexdigest()

    def _extract_token(
        self,
        token: str | None,
        credentials: dict[str, Any],
    ) -> str | None:
        candidates = [
            token,
            credentials.get("admin_token"),
            credentials.get("diagnostic_token"),
            credentials.get("secret"),
            credentials.get("key"),
        ]
        authorization = credentials.get("authorization")
        if isinstance(authorization, str):
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer" and value:
                candidates.append(value)
            elif authorization:
                candidates.append(authorization)
        for candidate in candidates:
            if candidate:
                return str(candidate)
        return None

    async def _authorize(
        self,
        task_id: str | None,
        token: str | None = None,
        **credentials: Any,
    ) -> None:
        presented = self._extract_token(token, credentials)

        if self.authorizer is not None:
            allowed = self.authorizer(presented, task_id=task_id, **credentials)
            if hasattr(allowed, "__await__"):
                allowed = await allowed
            if allowed:
                return
            raise self._denied()

        if (
            self.admin_token is not None
            and presented is not None
            and compare_digest(presented, self.admin_token)
        ):
            return

        if presented is not None:
            grant = self._grants.get(self._hash_token(presented))
            now = self._now()
            if (
                grant is not None
                and grant.expires_at > now
                and (grant.task_id is None or grant.task_id == task_id)
            ):
                return

        if self.admin_token is None and self.allow_anonymous_admin:
            return
        raise self._denied()

    def _check_admin_token(self, admin_token: str | None) -> None:
        if self.authorizer is not None:
            allowed = self.authorizer(admin_token)
            if hasattr(allowed, "__await__"):
                raise TypeError(
                    "Async authorizers must be awaited before issuing a grant.",
                )
            if allowed:
                return
            raise self._denied()
        if (
            self.admin_token is not None
            and admin_token is not None
            and compare_digest(admin_token, self.admin_token)
        ):
            return
        if self.admin_token is None and self.allow_anonymous_admin:
            return
        raise self._denied()

    async def create_diagnostic_grant(
        self,
        admin_token: str | None = None,
        *,
        task_id: str | None = None,
        ttl_seconds: float | None = None,
    ) -> DiagnosticGrant:
        """Exchange a long-lived admin credential for a short-lived token."""
        self._check_admin_token(admin_token)
        ttl = self.diagnostic_ttl_seconds if ttl_seconds is None else ttl_seconds
        expires_at = self._now() + timedelta(seconds=ttl or 300)
        token = f"diag_{token_urlsafe(32)}"
        grant = DiagnosticGrant(
            token=token,
            task_id=task_id,
            expires_at=expires_at,
        )
        self._grants[self._hash_token(token)] = grant
        return grant

    async def _current_status(self, task_id: str) -> PublicTaskStatus | None:
        record = await self.public_sink.read_record(PUBLIC_COLLECTION, task_id)
        if record is None:
            return None
        return PublicTaskStatus.model_validate(record)

    async def set_result(
        self,
        task_id: str,
        result: TaskiqResult[Any],
    ) -> None:
        """Persist public status and authorized diagnostics for a terminal result."""
        await self.set_attempt_result(task_id, result)

    async def set_attempt_result(
        self,
        task_id: str,
        result: TaskiqResult[Any],
    ) -> None:
        """Persist an intermediate attempt without exposing it publicly."""
        current = await self._current_status(task_id)
        attempt = _result_attempt(result)
        if current is not None and attempt < current.attempt:
            return

        category = result.failure_category or resolve_failure_category(
            result,
            self.classifier,
        )
        status = PublicTaskStatus.from_result(
            task_id,
            result,
            category=category,
            now=self._now(),
        )
        if current is not None and attempt == current.attempt:
            status.updated_at = self._now()

        await self.public_sink.write_record(
            PUBLIC_COLLECTION,
            task_id,
            status.model_dump(mode="json"),
        )

        if status.failure_category and status.status in {"failure", "retrying"}:
            ttl = self.diagnostic_ttl_seconds
            expires_at = (
                self._now() + timedelta(seconds=ttl)
                if ttl is not None and ttl > 0
                else None
            )
            diagnostic = TaskDiagnostic.from_result(
                task_id,
                result,
                category=category,
                now=self._now(),
                expires_at=expires_at,
            )
            await self.diagnostic_sink.write_record(
                DIAGNOSTIC_COLLECTION,
                task_id,
                diagnostic.model_dump(mode="json"),
                ttl_seconds=ttl,
            )
        elif status.status == "success" and self.purge_diagnostics_on_success:
            await self.diagnostic_sink.delete_record(
                DIAGNOSTIC_COLLECTION,
                task_id,
            )

    async def is_result_ready(self, task_id: str) -> bool:
        """Return whether a terminal public status is available."""
        status = await self._current_status(task_id)
        return status is not None and status.is_ready

    async def get_public_status(self, task_id: str) -> PublicTaskStatus:
        """Get the non-sensitive public status."""
        status = await self._current_status(task_id)
        if status is None:
            raise KeyError(task_id)
        return status

    async def get_public_state(self, task_id: str) -> PublicTaskStatus:
        """Alias for :meth:`get_public_status`."""
        return await self.get_public_status(task_id)

    async def get_result(
        self,
        task_id: str,
        with_logs: bool = False,
    ) -> TaskiqResult[None]:
        """Get a redacted result safe for ordinary query callers."""
        del with_logs
        status = await self.get_public_status(task_id)
        return status.to_result()

    async def get_admin_diagnostic(
        self,
        task_id: str,
        token: str | None = None,
        **credentials: Any,
    ) -> TaskDiagnostic:
        """Get authorized diagnostic details if the short-lived record exists."""
        await self._authorize(task_id, token, **credentials)
        record = await self.diagnostic_sink.read_record(
            DIAGNOSTIC_COLLECTION,
            task_id,
        )
        if record is None:
            raise SecurityError(
                description="Diagnostic details are unavailable or were purged.",
            )
        diagnostic = TaskDiagnostic.model_validate(record)
        now = self._now()
        if diagnostic.expires_at is not None and diagnostic.expires_at <= now:
            await self.diagnostic_sink.delete_record(
                DIAGNOSTIC_COLLECTION,
                task_id,
            )
            raise SecurityError(
                description="Diagnostic details have expired.",
            )
        return diagnostic

    async def get_admin_result(
        self,
        task_id: str,
        token: str | None = None,
        **credentials: Any,
    ) -> TaskiqResult[Any]:
        """Get the original result through the authorized diagnostic path."""
        diagnostic = await self.get_admin_diagnostic(task_id, token, **credentials)
        if diagnostic.result is None:
            raise SecurityError(description="Diagnostic result is unavailable.")
        return diagnostic.result

    async def purge_diagnostics(self, task_id: str) -> None:
        """Delete restricted details for a task."""
        await self.diagnostic_sink.delete_record(DIAGNOSTIC_COLLECTION, task_id)

    get_diagnostic = get_admin_diagnostic
    get_diagnostics = get_admin_diagnostic
    admin_get_result = get_admin_result
    get_restricted_result = get_admin_result
    save_attempt_result = set_attempt_result


RedactingResultBackend = SecureResultBackend
PrivacyAwareResultBackend = SecureResultBackend
PublicStatusResultBackend = SecureResultBackend
ErrorCategory = FailureCategory
PublicState = PublicTaskStatus
PublicTaskState = PublicTaskStatus
TaskPublicStatus = PublicTaskStatus
DiagnosticDetails = TaskDiagnostic
AdminDiagnostic = TaskDiagnostic
RedactedTaskError = PublicTaskFailureError
SafeTaskFailure = PublicTaskFailureError
InMemoryPersistence = InMemoryRecordSink
RecordingRecordSink = InMemoryRecordSink
