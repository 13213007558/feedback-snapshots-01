# -*- coding: utf-8 -*-
"""Retention-aware composition of versioned MinIO/S3 objects.

The module intentionally depends on a small gateway protocol.  Applications can
adapt :class:`minio.Minio` to that protocol while tests can provide local,
stateful responses without a network or a running MinIO server.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from typing_extensions import Protocol

from .models import Retention

# pylint: disable=too-many-branches,too-many-statements,broad-except

DEFAULT_MULTIPART_THRESHOLD = 8 * 1024 * 1024
DEFAULT_PART_SIZE = 8 * 1024 * 1024


def _as_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime, treating naive values as UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def retention_sort_key(retention: Retention) -> tuple[int, datetime]:
    """Order retention by strictness of mode and expiry."""
    mode_rank = {
        Retention.GOVERNANCE: 1,
        Retention.COMPLIANCE: 2,
    }
    return mode_rank[retention.mode], _as_utc(
        retention.retain_until_date,
    )


def retention_covers(
        candidate: Optional[Retention],
        requirement: Optional[Retention],
) -> bool:
    """Return whether ``candidate`` satisfies ``requirement``.

    COMPLIANCE is stricter than GOVERNANCE and therefore covers either mode.
    A later retain-until date also covers an earlier requirement.
    """
    if requirement is None:
        return True
    if candidate is None:
        return False

    candidate_rank = {
        Retention.GOVERNANCE: 1,
        Retention.COMPLIANCE: 2,
    }[candidate.mode]
    required_rank = {
        Retention.GOVERNANCE: 1,
        Retention.COMPLIANCE: 2,
    }[requirement.mode]
    return (
        candidate_rank >= required_rank and
        _as_utc(candidate.retain_until_date) >=
        _as_utc(requirement.retain_until_date)
    )


class ArchiveError(Exception):
    """Base class for archive composition failures."""

    category = "archive_error"
    code = "ArchiveError"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.details = details

    def __str__(self) -> str:
        if not self.details:
            return super().__str__()
        return f"{super().__str__()} [{self.code}: {self.details}]"


class SourceRetentionConflict(ArchiveError):
    """Request override is weaker than an actually used source version."""

    category = "source_constraint_conflict"
    code = "SOURCE_RETENTION_CONFLICT"


# Descriptive alias for callers that prefer the broader “source constraint”
# vocabulary used by archive orchestration.
SourceConstraintConflict = SourceRetentionConflict


class TargetCapabilityError(ArchiveError):
    """Destination bucket cannot enforce the required retention."""

    category = "target_capability_insufficient"
    code = "TARGET_RETENTION_CAPABILITY_INSUFFICIENT"


TargetCapabilityInsufficient = TargetCapabilityError


class SourceVersionChanged(ArchiveError):
    """A source response does not match the preflight version."""

    category = "source_version_changed"
    code = "SOURCE_VERSION_CHANGED"

    def __init__(
            self,
            message: str,
            *,
            changes: Sequence["VersionChange"] | None = None,
            read_versions: Sequence["ReadVersion"] | None = None,
            **details: Any,
    ) -> None:
        super().__init__(
            message,
            changes=tuple(changes or ()),
            read_versions=tuple(read_versions or ()),
            **details,
        )
        self.changes = tuple(changes or ())
        self.read_versions = tuple(read_versions or ())


VersionChangedDuringTransfer = SourceVersionChanged


class ArchiveCleanupError(ArchiveError):
    """One or more multipart abort calls failed after the primary error."""

    category = "archive_cleanup_error"
    code = "ARCHIVE_CLEANUP_ERROR"


@dataclass(frozen=True)
class ArchiveSource:
    """A source object reference.

    Omitting ``version_id`` means the preflight resolves the current version.
    That resolved version is then treated as the expected version during
    delivery.  Supplying ``version_id`` pins reads to an approved version.
    """

    bucket_name: str
    object_name: str
    version_id: Optional[str] = None
    etag: Optional[str] = None


@dataclass(frozen=True)
class SourceVersion:
    """Metadata and retention observed for one source version."""

    bucket_name: str
    object_name: str
    version_id: str
    size: int
    etag: Optional[str] = None
    retention: Optional[Retention] = None
    requested_version_id: Optional[str] = None

    @property
    def qualified_version(self) -> str:
        """Return a stable bucket/key@version identifier."""
        return f"{self.bucket_name}/{self.object_name}@{self.version_id}"

    def as_source(self) -> ArchiveSource:
        """Return the reference used to read this source during delivery."""
        return ArchiveSource(
            bucket_name=self.bucket_name,
            object_name=self.object_name,
            version_id=self.requested_version_id,
        )


@dataclass(frozen=True)
class TargetCapabilities:
    """Object-lock capabilities exposed by a destination bucket."""

    versioning_enabled: bool = True
    object_lock_enabled: bool = True
    supported_modes: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {Retention.GOVERNANCE, Retention.COMPLIANCE},
        ),
    )


@dataclass(frozen=True)
class ArchiveRequest:
    """Input for a retention-aware archive composition."""

    target_bucket_name: str
    target_object_name: str
    sources: Sequence[ArchiveSource]
    retention_override: Optional[Retention] = None
    multipart: Optional[bool] = None
    part_size: int = DEFAULT_PART_SIZE
    multipart_threshold: int = DEFAULT_MULTIPART_THRESHOLD


@dataclass(frozen=True)
class ArchivePlan:
    """Validated preflight result used by :meth:`ArchiveComposer.deliver`."""

    request: ArchiveRequest
    source_versions: tuple[SourceVersion, ...]
    target_capabilities: TargetCapabilities
    retention: Optional[Retention]
    use_multipart: bool
    total_size: int


@dataclass(frozen=True)
class ReadVersion:
    """Version identity returned by an actual source read."""

    bucket_name: str
    object_name: str
    version_id: str
    requested_version_id: Optional[str] = None
    etag: Optional[str] = None

    @property
    def qualified_version(self) -> str:
        """Return a stable bucket/key@version identifier."""
        return f"{self.bucket_name}/{self.object_name}@{self.version_id}"


@dataclass(frozen=True)
class VersionChange:
    """Difference between a preflight version and the read version."""

    bucket_name: str
    object_name: str
    expected_version_id: str
    actual_version_id: str
    expected_etag: Optional[str] = None
    actual_etag: Optional[str] = None


@dataclass(frozen=True)
class PartToken:
    """Opaque information needed to complete an uploaded part."""

    part_number: int
    etag: str


@dataclass(frozen=True)
class SourceRead:
    """Bytes and identity returned by reading a source."""

    version_id: str
    data: bytes
    etag: Optional[str] = None
    retention: Optional[Retention] = None


@dataclass(frozen=True)
class TargetWrite:
    """Identity of a created target object version."""

    version_id: Optional[str] = None
    etag: Optional[str] = None


@dataclass(frozen=True)
class ArchiveResult:
    """Outcome and audit trail for a successful composition."""

    bucket_name: str
    object_name: str
    target_version_id: Optional[str]
    retention: Optional[Retention]
    read_versions: tuple[ReadVersion, ...]
    created_upload_ids: tuple[str, ...] = ()
    completed_upload_ids: tuple[str, ...] = ()
    aborted_upload_ids: tuple[str, ...] = ()

    @property
    def upload_id(self) -> Optional[str]:
        """Return the completed upload ID for the common one-job case."""
        if not self.completed_upload_ids:
            return None
        return self.completed_upload_ids[0]

    @property
    def read_version_ids(self) -> tuple[str, ...]:
        """Return only the actual read source version IDs."""
        return tuple(item.version_id for item in self.read_versions)


class ArchiveGateway(Protocol):
    """Storage operations required by :class:`ArchiveComposer`.

    A production implementation can adapt :class:`minio.Minio`; tests can
    provide a stateful local implementation with versioning and retention.
    """

    def target_capabilities(
            self, bucket_name: str,
    ) -> TargetCapabilities:
        """Return destination versioning and object-lock capabilities."""

    def stat_source(self, source: ArchiveSource) -> SourceVersion:
        """Resolve source metadata and its current retention state."""

    def read_source(self, source: ArchiveSource) -> SourceRead:
        """Read source bytes and the version identity returned by storage."""

    def put_archive(
            self,
            *,
            bucket_name: str,
            object_name: str,
            data: bytes,
            retention: Optional[Retention],
    ) -> TargetWrite:
        """Create a small target object."""

    def create_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            retention: Optional[Retention],
    ) -> str:
        """Create one multipart upload and return its upload ID."""

    def upload_part(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            part: PartToken,
            data: bytes,
    ) -> PartToken:
        """Upload one part and return its completion token."""

    def complete_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            parts: Sequence[PartToken],
    ) -> TargetWrite:
        """Complete the multipart upload."""

    def abort_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
    ) -> None:
        """Abort one multipart upload created by this composer."""


def resolve_retention(
        sources: Sequence[SourceVersion],
        override: Optional[Retention] = None,
) -> Optional[Retention]:
    """Resolve target retention from source constraints and an override.

    The required date is the maximum retained-until date across all actual
    source versions.  The required mode is the strictest source mode.  An
    override is accepted only when it tightens both dimensions.
    """
    source_retentions = [
        source.retention for source in sources
        if source.retention is not None
    ]
    required: Optional[Retention] = None
    if source_retentions:
        required = max(source_retentions, key=retention_sort_key)
        strictest_mode = max(
            source_retentions,
            key=lambda item: retention_sort_key(item)[0],
        ).mode
        required = Retention(
            mode=strictest_mode,
            retain_until_date=required.retain_until_date,
        )

    if override is None:
        if required is None:
            return None
        return Retention(
            mode=required.mode,
            retain_until_date=_as_utc(required.retain_until_date),
        )

    violations: list[str] = []
    if required is not None:
        if not retention_covers(override, required):
            if (
                {
                    Retention.GOVERNANCE: 1,
                    Retention.COMPLIANCE: 2,
                }[override.mode] <
                {
                    Retention.GOVERNANCE: 1,
                    Retention.COMPLIANCE: 2,
                }[required.mode]
            ):
                violations.append("mode_is_weaker")
            if _as_utc(override.retain_until_date) < _as_utc(
                    required.retain_until_date,
            ):
                violations.append("retain_until_date_is_too_early")

    if violations:
        raise SourceRetentionConflict(
            "retention override cannot loosen source requirements",
            violations=tuple(violations),
            required_mode=required.mode if required else None,
            required_until=(
                _as_utc(required.retain_until_date) if required else None
            ),
            override_mode=override.mode,
            override_until=_as_utc(override.retain_until_date),
            source_versions=tuple(
                source.qualified_version for source in sources
            ),
        )

    return Retention(
        mode=override.mode,
        retain_until_date=_as_utc(override.retain_until_date),
    )


def ensure_target_capability(
        capabilities: TargetCapabilities,
        retention: Optional[Retention],
        bucket_name: str,
) -> None:
    """Reject destinations that cannot enforce the resolved retention."""
    if retention is None:
        return

    missing: list[str] = []
    if not capabilities.versioning_enabled:
        missing.append("versioning")
    if not capabilities.object_lock_enabled:
        missing.append("object_lock")
    if retention.mode not in capabilities.supported_modes:
        missing.append(f"retention_mode:{retention.mode}")

    if missing:
        raise TargetCapabilityError(
            "target bucket cannot enforce archive retention",
            bucket_name=bucket_name,
            missing_capabilities=tuple(missing),
            required_mode=retention.mode,
        )


class ArchiveComposer:
    """Compose sources and enforce retention through preflight and delivery."""

    def __init__(
            self,
            gateway: ArchiveGateway,
            *,
            multipart_threshold: int = DEFAULT_MULTIPART_THRESHOLD,
            part_size: int = DEFAULT_PART_SIZE,
    ) -> None:
        if multipart_threshold < 0:
            raise ValueError("multipart_threshold must not be negative")
        if part_size <= 0:
            raise ValueError("part_size must be greater than zero")
        self.gateway = gateway
        self.multipart_threshold = multipart_threshold
        self.part_size = part_size

    def preflight(self, request: ArchiveRequest) -> ArchivePlan:
        """Read target capability and every current source retention."""
        if not request.target_bucket_name or not request.target_object_name:
            raise ValueError("target bucket and object names are required")
        if not request.sources:
            raise ValueError("at least one source is required")
        if request.part_size <= 0:
            raise ValueError("part_size must be greater than zero")
        if request.multipart_threshold < 0:
            raise ValueError("multipart_threshold must not be negative")

        capabilities = self.gateway.target_capabilities(
            request.target_bucket_name,
        )
        observed = tuple(
            self.gateway.stat_source(source) for source in request.sources
        )
        retention = resolve_retention(
            observed, request.retention_override,
        )
        ensure_target_capability(
            capabilities, retention, request.target_bucket_name,
        )

        total_size = sum(source.size for source in observed)
        use_multipart = (
            request.multipart
            if request.multipart is not None
            else total_size > request.multipart_threshold
        )
        return ArchivePlan(
            request=request,
            source_versions=observed,
            target_capabilities=capabilities,
            retention=retention,
            use_multipart=use_multipart,
            total_size=total_size,
        )

    def compose(self, request: ArchiveRequest) -> ArchiveResult:
        """Run preflight and delivery in one call."""
        return self.deliver(self.preflight(request))

    #: Descriptive alias for callers modeling this as an archive transfer.
    compose_archive = compose

    def deliver(self, plan: ArchivePlan) -> ArchiveResult:
        """Transfer a preflighted plan and reconfirm actual source versions."""
        request = plan.request
        read_versions: list[ReadVersion] = []
        actual_versions: list[SourceVersion] = []
        created: list[str] = []
        completed: list[str] = []
        aborted: list[str] = []

        try:
            if not plan.use_multipart:
                chunks: list[bytes] = []
                for expected in plan.source_versions:
                    read, actual = self._read_and_check(
                        expected, read_versions,
                    )
                    chunks.append(read.data)
                    actual_versions.append(actual)

                final_retention = resolve_retention(
                    actual_versions, request.retention_override,
                )
                if not retention_covers(plan.retention, final_retention):
                    raise SourceRetentionConflict(
                        "actual source retention exceeds preflight decision",
                        planned_retention=plan.retention,
                        actual_retention=final_retention,
                        read_versions=tuple(read_versions),
                    )

                write = self.gateway.put_archive(
                    bucket_name=request.target_bucket_name,
                    object_name=request.target_object_name,
                    data=b"".join(chunks),
                    retention=final_retention,
                )
                return ArchiveResult(
                    bucket_name=request.target_bucket_name,
                    object_name=request.target_object_name,
                    target_version_id=write.version_id,
                    retention=final_retention,
                    read_versions=tuple(read_versions),
                )

            upload_id = self.gateway.create_multipart(
                bucket_name=request.target_bucket_name,
                object_name=request.target_object_name,
                retention=plan.retention,
            )
            created.append(upload_id)
            parts: list[PartToken] = []
            part_number = 1
            buffer = bytearray()

            def flush_buffer() -> None:
                nonlocal part_number
                if not buffer:
                    return
                payload = bytes(buffer)
                token = PartToken(part_number=part_number, etag="")
                uploaded = self.gateway.upload_part(
                    bucket_name=request.target_bucket_name,
                    object_name=request.target_object_name,
                    upload_id=upload_id,
                    part=token,
                    data=payload,
                )
                if not uploaded.etag:
                    uploaded = replace(
                        uploaded,
                        etag=f"etag-{upload_id}-{part_number}",
                    )
                parts.append(uploaded)
                part_number += 1
                buffer.clear()

            for expected in plan.source_versions:
                read, actual = self._read_and_check(
                    expected, read_versions,
                )
                actual_versions.append(actual)
                buffer.extend(read.data)
                part_size = request.part_size or self.part_size
                while len(buffer) >= part_size:
                    payload = bytes(buffer[:part_size])
                    del buffer[:part_size]
                    token = PartToken(part_number=part_number, etag="")
                    uploaded = self.gateway.upload_part(
                        bucket_name=request.target_bucket_name,
                        object_name=request.target_object_name,
                        upload_id=upload_id,
                        part=token,
                        data=payload,
                    )
                    if not uploaded.etag:
                        uploaded = replace(
                            uploaded,
                            etag=f"etag-{upload_id}-{part_number}",
                        )
                    parts.append(uploaded)
                    part_number += 1

            flush_buffer()

            final_retention = resolve_retention(
                actual_versions, request.retention_override,
            )
            if not retention_covers(plan.retention, final_retention):
                raise SourceRetentionConflict(
                    "actual source retention exceeds preflight decision",
                    planned_retention=plan.retention,
                    actual_retention=final_retention,
                    read_versions=tuple(read_versions),
                    created_upload_ids=tuple(created),
                )

            write = self.gateway.complete_multipart(
                bucket_name=request.target_bucket_name,
                object_name=request.target_object_name,
                upload_id=upload_id,
                parts=tuple(parts),
            )
            completed.append(upload_id)
            return ArchiveResult(
                bucket_name=request.target_bucket_name,
                object_name=request.target_object_name,
                target_version_id=write.version_id,
                retention=final_retention,
                read_versions=tuple(read_versions),
                created_upload_ids=tuple(created),
                completed_upload_ids=tuple(completed),
            )
        except Exception as primary_error:
            cleanup_errors: list[Exception] = []
            for upload_id in created:
                if upload_id in completed or upload_id in aborted:
                    continue
                try:
                    self.gateway.abort_multipart(
                        bucket_name=request.target_bucket_name,
                        object_name=request.target_object_name,
                        upload_id=upload_id,
                    )
                    aborted.append(upload_id)
                except Exception as cleanup_error:
                    cleanup_errors.append(cleanup_error)

            if hasattr(primary_error, "details"):
                primary_error.details.setdefault(
                    "created_upload_ids", tuple(created),
                )
                primary_error.details.setdefault(
                    "aborted_upload_ids", tuple(aborted),
                )
                if isinstance(primary_error, SourceVersionChanged):
                    primary_error.read_versions = tuple(read_versions)
                    primary_error.details["read_versions"] = tuple(
                        read_versions,
                    )

            if cleanup_errors:
                raise ArchiveCleanupError(
                    "archive failed and one or more aborts also failed",
                    primary_error=primary_error,
                    cleanup_errors=tuple(cleanup_errors),
                    created_upload_ids=tuple(created),
                    aborted_upload_ids=tuple(aborted),
                ) from primary_error
            raise

    def _read_and_check(
            self,
            expected: SourceVersion,
            read_versions: list[ReadVersion],
    ) -> tuple[SourceRead, SourceVersion]:
        """Read one source and compare its actual version with preflight."""
        source_ref = expected.as_source()
        read = self.gateway.read_source(source_ref)
        read_version = ReadVersion(
            bucket_name=expected.bucket_name,
            object_name=expected.object_name,
            requested_version_id=expected.requested_version_id,
            version_id=read.version_id,
            etag=read.etag,
        )
        read_versions.append(read_version)

        changes: list[VersionChange] = []
        if read.version_id != expected.version_id:
            changes.append(
                VersionChange(
                    bucket_name=expected.bucket_name,
                    object_name=expected.object_name,
                    expected_version_id=expected.version_id,
                    actual_version_id=read.version_id,
                    expected_etag=expected.etag,
                    actual_etag=read.etag,
                ),
            )

        actual = self.gateway.stat_source(
            ArchiveSource(
                bucket_name=expected.bucket_name,
                object_name=expected.object_name,
                version_id=read.version_id,
                etag=read.etag,
            ),
        )
        if changes:
            raise SourceVersionChanged(
                "source version changed after retention preflight",
                changes=changes,
                read_versions=tuple(read_versions),
                expected_version_id=expected.version_id,
                actual_version_id=read.version_id,
                source=expected.qualified_version,
            )
        return read, actual


def compose_archive(
        gateway: ArchiveGateway,
        request: ArchiveRequest,
) -> ArchiveResult:
    """Plan and execute one retention-aware archive composition."""
    return ArchiveComposer(gateway).compose(request)
