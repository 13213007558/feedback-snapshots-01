"""Minimum-permission contract for MinIO upload grants.

An :class:`UploadRequest` is what the business application asks for and an
:class:`Approval` is what the security review registered.  Only the scope
allowed by both sides may ever be handed to a signer; see
:func:`resolve_scope`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional
from urllib.parse import quote, urlencode

PRESIGN_MAX_TTL = timedelta(days=7)


class ScopeConflict(ValueError):
    """The application asks for something the approval does not allow."""


def utcnow() -> datetime:
    """Return current UTC time without microseconds.

    Truncating microseconds makes the absolute POST policy expiration
    round-trip exactly through S3's millisecond ISO-8601 formatting.
    """
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class SizeRange:
    """Inclusive ``content-length-range`` bounds in bytes."""

    min_bytes: int = 0
    max_bytes: int = 5 * 1024 ** 3

    def __post_init__(self) -> None:
        if self.min_bytes < 0:
            raise ValueError("min_bytes cannot be negative")
        if self.max_bytes < 0:
            raise ValueError("max_bytes cannot be negative")
        if self.min_bytes > self.max_bytes:
            raise ValueError("min_bytes cannot be greater than max_bytes")

    def intersect(self, other: "SizeRange") -> "SizeRange":
        """Return the range allowed by both sides."""
        lower = max(self.min_bytes, other.min_bytes)
        upper = min(self.max_bytes, other.max_bytes)
        if lower > upper:
            raise ScopeConflict(
                f"size ranges do not overlap: "
                f"[{self.min_bytes}, {self.max_bytes}] vs "
                f"[{other.min_bytes}, {other.max_bytes}]",
            )
        return SizeRange(lower, upper)

    def as_condition(self) -> list[int]:
        return ["content-length-range", self.min_bytes, self.max_bytes]


def canonical_tags(tags: Mapping[str, str]) -> str:
    """Encode tags the same way ``minio`` does for ``x-amz-tagging``."""
    return urlencode(list(sorted(tags.items())), quote_via=quote)


def merge_tags(
        requested: Mapping[str, str],
        required: Mapping[str, str],
) -> dict[str, str]:
    """Merge two exact tag requirements, rejecting conflicting values."""
    merged: dict[str, str] = {}
    for source in (required, requested):
        for key, value in source.items():
            if not key:
                raise ValueError("tag keys cannot be empty")
            if key in merged and merged[key] != value:
                raise ScopeConflict(
                    f"tag {key!r} required as {merged[key]!r} and {value!r}",
                )
            merged[key] = value
    return dict(sorted(merged.items()))


def intersect_prefixes(requested: str, allowed: str) -> str:
    """Return the narrower prefix covered by both prefixes."""
    if requested.startswith(allowed):
        return requested
    if allowed.startswith(requested):
        return allowed
    raise ScopeConflict(
        f"requested prefix {requested!r} is outside approved prefix "
        f"{allowed!r}",
    )


@dataclass(frozen=True)
class UploadRequest:
    """Business application for one upload grant."""

    request_id: str
    bucket: str
    object_key: Optional[str] = None
    key_prefix: Optional[str] = None
    size_range: Optional[SizeRange] = None
    tags: Mapping[str, str] = field(default_factory=dict)
    ttl: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id is required")
        if not self.object_key and not self.key_prefix:
            raise ValueError("either object_key or key_prefix is required")
        if self.object_key and self.key_prefix:
            raise ValueError(
                "object_key and key_prefix are mutually exclusive",
            )
        if self.ttl.total_seconds() < 1:
            raise ValueError("ttl must be at least one second")


@dataclass(frozen=True)
class Approval:
    """Registered security approval."""

    approval_id: str
    bucket: str
    allowed_prefix: str
    max_ttl: timedelta = timedelta(minutes=15)
    size_range: Optional[SizeRange] = None
    required_tags: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.approval_id:
            raise ValueError("approval_id is required")
        if not self.allowed_prefix:
            raise ValueError("allowed_prefix is required")
        if self.max_ttl.total_seconds() < 1:
            raise ValueError("max_ttl must be at least one second")


@dataclass(frozen=True)
class GrantScope:
    """The common, minimum scope that may be expressed by a credential."""

    request_id: str
    approval_id: str
    bucket: str
    ttl_seconds: int
    issued_at: datetime
    expires_at: datetime
    key: Optional[str] = None
    key_prefix: Optional[str] = None
    size_range: Optional[SizeRange] = None
    tags: Mapping[str, str] = field(default_factory=dict)
    approved_prefix: str = ""

    def __post_init__(self) -> None:
        if self.key is None and self.key_prefix is None:
            raise ValueError("scope must pin a key or a prefix")

    @property
    def tagging_value(self) -> Optional[str]:
        return canonical_tags(self.tags) if self.tags else None

    def snapshot(self) -> dict:
        """JSON-safe view used by the signature journal."""
        return {
            "request_id": self.request_id,
            "approval_id": self.approval_id,
            "bucket": self.bucket,
            "key": self.key,
            "key_prefix": self.key_prefix,
            "approved_prefix": self.approved_prefix,
            "size_range": (
                [self.size_range.min_bytes, self.size_range.max_bytes]
                if self.size_range else None
            ),
            "tags": dict(self.tags),
            "tagging_condition": self.tagging_value,
            "ttl_seconds": self.ttl_seconds,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


def resolve_scope(
        request: UploadRequest,
        approval: Approval,
        *,
        now: Optional[datetime] = None,
) -> GrantScope:
    """Compute the range jointly allowed by application and approval.

    Raises :class:`ScopeConflict` when the two sides have no common range.
    The function never widens the result: prefixes are narrowed, size ranges
    are intersected, tags are merged with conflict detection, and the TTL is
    capped by the approval maximum and the SigV4 seven-day limit.
    """
    if request.bucket != approval.bucket:
        raise ScopeConflict(
            f"bucket {request.bucket!r} does not match approval bucket "
            f"{approval.bucket!r}",
        )

    key: Optional[str] = None
    key_prefix: Optional[str] = None
    if request.object_key:
        if not request.object_key.startswith(approval.allowed_prefix):
            raise ScopeConflict(
                f"object {request.object_key!r} is outside approved prefix "
                f"{approval.allowed_prefix!r}",
            )
        key = request.object_key
    else:
        assert request.key_prefix is not None
        key_prefix = intersect_prefixes(
            request.key_prefix, approval.allowed_prefix,
        )

    size_range = approval.size_range
    if request.size_range is not None:
        size_range = (
            request.size_range
            if size_range is None
            else size_range.intersect(request.size_range)
        )

    tags = merge_tags(request.tags, approval.required_tags)

    ttl = min(request.ttl, approval.max_ttl, PRESIGN_MAX_TTL)
    ttl_seconds = int(ttl.total_seconds())
    if ttl_seconds < 1:
        raise ScopeConflict("effective ttl is below one second")

    issued_at = now or utcnow()
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)

    return GrantScope(
        request_id=request.request_id,
        approval_id=approval.approval_id,
        bucket=request.bucket,
        key=key,
        key_prefix=key_prefix,
        approved_prefix=approval.allowed_prefix,
        size_range=size_range,
        tags=tags,
        ttl_seconds=ttl_seconds,
        issued_at=issued_at,
        expires_at=expires_at,
    )
