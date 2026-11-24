# -*- coding: utf-8 -*-
"""Tests for retention-aware archive composition.

The local gateway models versioned objects, per-version retention, target
object-lock capability, and multipart upload IDs.  It is intentionally stateful
so a source can be changed between preflight and delivery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence

import pytest

from minio.archive_retention import (ArchiveComposer, ArchiveRequest,
                                     ArchiveSource, PartToken, SourceRead,
                                     SourceRetentionConflict, SourceVersion,
                                     SourceVersionChanged,
                                     TargetCapabilityError, TargetWrite)
from minio.models import Retention

NOW = datetime(2026, 11, 24, 9, 0, tzinfo=timezone.utc)
IN_TEN_DAYS = NOW + timedelta(days=10)
IN_TWENTY_DAYS = NOW + timedelta(days=20)
IN_THIRTY_DAYS = NOW + timedelta(days=30)
IN_FORTY_DAYS = NOW + timedelta(days=40)


@dataclass
class FakeVersion:
    """One immutable object version and its retention state."""

    data: bytes
    etag: str
    retention: Optional[Retention] = None


@dataclass
class FakeObject:
    """All versions and the current version pointer for one key."""

    current_version_id: str
    versions: dict[str, FakeVersion] = field(default_factory=dict)


@dataclass
class FakeBucket:
    """Versioning and object-lock capability state."""

    versioning_enabled: bool = True
    object_lock_enabled: bool = True
    supported_modes: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {Retention.GOVERNANCE, Retention.COMPLIANCE},
        ),
    )


@dataclass
class FakeMultipart:
    """A local in-progress multipart upload."""

    bucket_name: str
    object_name: str
    retention: Optional[Retention]
    parts: dict[int, bytes] = field(default_factory=dict)


class LocalVersionedMinioResponses:
    """Stateful gateway used in place of HTTP MinIO responses."""

    def __init__(self) -> None:
        self.buckets: dict[str, FakeBucket] = {}
        self.objects: dict[tuple[str, str], FakeObject] = {}
        self.multipart: dict[str, FakeMultipart] = {}
        self.read_log: list[tuple[str, str, Optional[str], str]] = []
        self.put_log: list[tuple[str, str, Optional[Retention]]] = []
        self.create_log: list[str] = []
        self.upload_part_log: list[tuple[str, int]] = []
        self.complete_log: list[str] = []
        self.abort_log: list[tuple[str, str, str]] = []
        self._upload_counter = 0
        self._target_version_counter = 0

    def add_bucket(
            self,
            name: str,
            *,
            versioning_enabled: bool = True,
            object_lock_enabled: bool = True,
            supported_modes: Optional[frozenset[str]] = None,
    ) -> None:
        """Create a local bucket with advertised lock capabilities."""
        self.buckets[name] = FakeBucket(
            versioning_enabled=versioning_enabled,
            object_lock_enabled=object_lock_enabled,
            supported_modes=supported_modes or frozenset(
                {Retention.GOVERNANCE, Retention.COMPLIANCE},
            ),
        )

    def add_version(
            self,
            bucket_name: str,
            object_name: str,
            version_id: str,
            data: bytes,
            retention: Optional[Retention] = None,
            *,
            current: bool = True,
            etag: Optional[str] = None,
    ) -> None:
        """Add an object version and optionally make it current."""
        key = (bucket_name, object_name)
        obj = self.objects.setdefault(
            key, FakeObject(current_version_id=version_id),
        )
        obj.versions[version_id] = FakeVersion(
            data=data,
            etag=etag or f"etag-{version_id}",
            retention=retention,
        )
        if current:
            obj.current_version_id = version_id

    def seed_multipart(
            self,
            upload_id: str,
            bucket_name: str = "archive",
            object_name: str = "joined",
    ) -> None:
        """Seed an unrelated upload that cleanup must not abort."""
        self.multipart[upload_id] = FakeMultipart(
            bucket_name=bucket_name,
            object_name=object_name,
            retention=None,
        )

    def target_capabilities(self, bucket_name: str) -> FakeBucket:
        return self.buckets[bucket_name]

    def stat_source(self, source: ArchiveSource) -> SourceVersion:
        obj = self.objects[(source.bucket_name, source.object_name)]
        version_id = source.version_id or obj.current_version_id
        version = obj.versions[version_id]
        return SourceVersion(
            bucket_name=source.bucket_name,
            object_name=source.object_name,
            version_id=version_id,
            size=len(version.data),
            etag=version.etag,
            retention=version.retention,
            requested_version_id=source.version_id,
        )

    def read_source(self, source: ArchiveSource) -> SourceRead:
        obj = self.objects[(source.bucket_name, source.object_name)]
        version_id = source.version_id or obj.current_version_id
        version = obj.versions[version_id]
        self.read_log.append(
            (
                source.bucket_name,
                source.object_name,
                source.version_id,
                version_id,
            ),
        )
        return SourceRead(
            version_id=version_id,
            data=version.data,
            etag=version.etag,
            retention=version.retention,
        )

    def put_archive(
            self,
            *,
            bucket_name: str,
            object_name: str,
            data: bytes,
            retention: Optional[Retention],
    ) -> TargetWrite:
        self._target_version_counter += 1
        version_id = f"target-v{self._target_version_counter}"
        self.add_version(
            bucket_name,
            object_name,
            version_id,
            data,
            retention,
        )
        self.put_log.append((bucket_name, object_name, retention))
        return TargetWrite(version_id=version_id, etag=f"etag-{version_id}")

    def create_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            retention: Optional[Retention],
    ) -> str:
        self._upload_counter += 1
        upload_id = f"upload-{self._upload_counter}"
        self.multipart[upload_id] = FakeMultipart(
            bucket_name=bucket_name,
            object_name=object_name,
            retention=retention,
        )
        self.create_log.append(upload_id)
        return upload_id

    def upload_part(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            part: PartToken,
            data: bytes,
    ) -> PartToken:
        upload = self.multipart[upload_id]
        assert upload.bucket_name == bucket_name
        assert upload.object_name == object_name
        upload.parts[part.part_number] = data
        etag = f"etag-{upload_id}-part-{part.part_number}"
        self.upload_part_log.append((upload_id, part.part_number))
        return PartToken(part_number=part.part_number, etag=etag)

    def complete_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
            parts: Sequence[PartToken],
    ) -> TargetWrite:
        upload = self.multipart.pop(upload_id)
        assert upload.bucket_name == bucket_name
        assert upload.object_name == object_name
        data = b"".join(
            upload.parts[part.part_number] for part in sorted(
                parts, key=lambda item: item.part_number,
            )
        )
        self._target_version_counter += 1
        version_id = f"target-v{self._target_version_counter}"
        self.add_version(
            bucket_name,
            object_name,
            version_id,
            data,
            upload.retention,
        )
        self.complete_log.append(upload_id)
        return TargetWrite(version_id=version_id)

    def abort_multipart(
            self,
            *,
            bucket_name: str,
            object_name: str,
            upload_id: str,
    ) -> None:
        self.multipart.pop(upload_id, None)
        self.abort_log.append((bucket_name, object_name, upload_id))

    def target_retention(self) -> Optional[Retention]:
        obj = self.objects[("archive", "joined")]
        return obj.versions[obj.current_version_id].retention

    def target_data(self) -> bytes:
        obj = self.objects[("archive", "joined")]
        return obj.versions[obj.current_version_id].data

    def actual_read_versions(self) -> list[str]:
        return [item[3] for item in self.read_log]


def build_gateway() -> LocalVersionedMinioResponses:
    """Create two legal source versions and a lock-capable target."""
    gateway = LocalVersionedMinioResponses()
    gateway.add_bucket("archive")
    gateway.add_bucket("sources")
    gateway.add_version(
        "sources", "report-a", "a-v1", b"AAAA-first-block-",
        Retention(Retention.GOVERNANCE, IN_TEN_DAYS),
    )
    gateway.add_version(
        "sources", "report-b", "b-v1", b"BBBB-second-block",
        Retention(Retention.COMPLIANCE, IN_TWENTY_DAYS),
    )
    gateway.seed_multipart("upload-preexisting")
    return gateway


def build_request(**overrides) -> ArchiveRequest:
    """Build the standard two-source request."""
    values = {
        "target_bucket_name": "archive",
        "target_object_name": "joined",
        "sources": [
            ArchiveSource("sources", "report-a"),
            ArchiveSource("sources", "report-b"),
        ],
        "retention_override": Retention(
            Retention.COMPLIANCE, IN_THIRTY_DAYS,
        ),
        "part_size": 16,
    }
    values.update(overrides)
    return ArchiveRequest(**values)


@pytest.mark.parametrize(
    ("use_multipart", "expected_create_count"),
    [(False, 0), (True, 1)],
    ids=["small_object", "multipart_object"],
)
def test_legal_version_combination_sets_tightened_retention(
        use_multipart: bool,
        expected_create_count: int,
) -> None:
    gateway = build_gateway()
    composer = ArchiveComposer(gateway)
    request = build_request(multipart=use_multipart)

    result = composer.compose(request)

    assert result.read_version_ids == ("a-v1", "b-v1")
    assert gateway.actual_read_versions() == ["a-v1", "b-v1"]
    assert gateway.target_data() == (
        b"AAAA-first-block-BBBB-second-block"
    )
    retention = gateway.target_retention()
    assert retention is not None
    assert retention.mode == Retention.COMPLIANCE
    assert retention.retain_until_date == IN_THIRTY_DAYS

    assert len(gateway.create_log) == expected_create_count
    if use_multipart:
        assert result.created_upload_ids == ("upload-1",)
        assert result.completed_upload_ids == ("upload-1",)
        assert result.aborted_upload_ids == ()
        assert gateway.complete_log == ["upload-1"]
        assert "upload-1" not in gateway.multipart
        assert [number for _, number in gateway.upload_part_log] == [
            1, 2, 3,
        ]
    else:
        assert result.created_upload_ids == ()
        assert gateway.put_log[0][2] == retention

    assert gateway.abort_log == []
    assert "upload-preexisting" in gateway.multipart


def test_without_override_uses_strictest_mode_and_latest_date() -> None:
    gateway = build_gateway()
    composer = ArchiveComposer(gateway)

    result = composer.compose(
        build_request(retention_override=None, multipart=False),
    )

    assert result.retention == Retention(
        Retention.COMPLIANCE, IN_TWENTY_DAYS,
    )
    assert gateway.target_retention() == result.retention


@pytest.mark.parametrize(
    "override",
    [
        Retention(Retention.GOVERNANCE, IN_THIRTY_DAYS),
        Retention(Retention.COMPLIANCE, IN_TEN_DAYS),
    ],
    ids=["weaker_mode", "earlier_date"],
)
def test_override_cannot_loosen_source_constraints(
        override: Retention,
) -> None:
    gateway = build_gateway()
    composer = ArchiveComposer(gateway)

    with pytest.raises(SourceRetentionConflict) as exc_info:
        composer.compose(
            build_request(retention_override=override, multipart=True),
        )

    assert exc_info.value.category == "source_constraint_conflict"
    assert "violations" in exc_info.value.details
    assert gateway.create_log == []
    assert gateway.abort_log == []


def test_target_without_object_lock_is_capability_error() -> None:
    gateway = build_gateway()
    gateway.add_bucket("archive", object_lock_enabled=False)
    composer = ArchiveComposer(gateway)

    with pytest.raises(TargetCapabilityError) as exc_info:
        composer.compose(build_request(multipart=True))

    assert exc_info.value.category == "target_capability_insufficient"
    assert exc_info.value.details["missing_capabilities"] == (
        "object_lock",
    )
    assert gateway.create_log == []


def test_target_that_cannot_enforce_compliance_is_capability_error() -> None:
    gateway = build_gateway()
    gateway.add_bucket(
        "archive",
        supported_modes=frozenset({Retention.GOVERNANCE}),
    )
    composer = ArchiveComposer(gateway)

    with pytest.raises(TargetCapabilityError) as exc_info:
        composer.compose(build_request(multipart=False))

    assert f"retention_mode:{Retention.COMPLIANCE}" in (
        exc_info.value.details["missing_capabilities"]
    )


def test_pinned_version_reads_same_id_after_source_update() -> None:
    gateway = build_gateway()
    pinned_sources = [
        ArchiveSource("sources", "report-a", version_id="a-v1"),
        ArchiveSource("sources", "report-b", version_id="b-v1"),
    ]
    composer = ArchiveComposer(gateway)
    plan = composer.preflight(
        build_request(sources=pinned_sources, multipart=True),
    )

    gateway.add_version(
        "sources", "report-a", "a-v2", b"new-current-version",
        Retention(Retention.COMPLIANCE, IN_FORTY_DAYS),
    )
    result = composer.deliver(plan)

    assert result.read_version_ids == ("a-v1", "b-v1")
    assert gateway.actual_read_versions() == ["a-v1", "b-v1"]
    assert gateway.abort_log == []
    assert result.completed_upload_ids == ("upload-1",)


def test_version_change_reports_reads_and_aborts_only_own_upload() -> None:
    gateway = build_gateway()
    composer = ArchiveComposer(gateway)
    plan = composer.preflight(build_request(multipart=True))

    # The floating second source is updated after preflight.
    gateway.add_version(
        "sources",
        "report-b",
        "b-v2",
        b"BBBB-changed-after-preflight",
        Retention(Retention.COMPLIANCE, IN_FORTY_DAYS),
    )

    with pytest.raises(SourceVersionChanged) as exc_info:
        composer.deliver(plan)

    error = exc_info.value
    assert error.category == "source_version_changed"
    assert len(error.changes) == 1
    change = error.changes[0]
    assert change.object_name == "report-b"
    assert change.expected_version_id == "b-v1"
    assert change.actual_version_id == "b-v2"

    # The first source was read at v1 and the changed second source was
    # actually returned at v2.
    assert tuple(item.version_id for item in error.read_versions) == (
        "a-v1", "b-v2",
    )
    assert gateway.actual_read_versions() == ["a-v1", "b-v2"]

    assert gateway.create_log == ["upload-1"]
    assert gateway.abort_log == [("archive", "joined", "upload-1")]
    assert error.details["aborted_upload_ids"] == ("upload-1",)
    assert "upload-1" not in gateway.multipart
    assert "upload-preexisting" in gateway.multipart
    assert ("archive", "joined") not in gateway.objects


def test_final_check_rejects_retention_tightened_after_preflight() -> None:
    gateway = build_gateway()
    request = build_request(
        retention_override=None, multipart=True,
    )
    composer = ArchiveComposer(gateway)
    plan = composer.preflight(request)

    # Same version ID, but its legal retention state is extended after the
    # preflight response.
    obj = gateway.objects[("sources", "report-b")]
    obj.versions["b-v1"].retention = Retention(
        Retention.COMPLIANCE, IN_FORTY_DAYS,
    )

    with pytest.raises(SourceRetentionConflict) as exc_info:
        composer.deliver(plan)

    assert exc_info.value.category == "source_constraint_conflict"
    assert gateway.abort_log == [("archive", "joined", "upload-1")]
    assert "upload-1" not in gateway.multipart
    assert "upload-preexisting" in gateway.multipart


def test_unrelated_transfer_failure_still_aborts_only_own_upload() -> None:
    gateway = build_gateway()

    def fail_part(*args, **kwargs):
        raise RuntimeError("part transport failed")

    gateway.upload_part = fail_part  # type: ignore[method-assign]
    composer = ArchiveComposer(gateway)

    with pytest.raises(RuntimeError, match="part transport failed"):
        composer.compose(build_request(multipart=True, part_size=4))

    assert gateway.create_log == ["upload-1"]
    assert gateway.abort_log == [("archive", "joined", "upload-1")]
    assert "upload-preexisting" in gateway.multipart
