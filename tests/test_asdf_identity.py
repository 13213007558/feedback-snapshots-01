from __future__ import annotations

import io
import uuid
from io import BytesIO

import pytest

from dissect.evidence.asdf.asdf import IDX_MEMORY, IDX_METADATA, MAX_IDX, AsdfSnapshot, AsdfWriter
from dissect.evidence.asdf.identity import (
    DECLARED,
    KIND_DISK,
    KIND_MEMORY,
    KIND_METADATA,
    KIND_VOLUME,
    MANIFEST_PATH,
    STRUCTURAL,
    VERIFIED,
    IdentityError,
    IdentityManifest,
    IdentityReader,
    attach_manifest,
    stream_sha256,
)

BLOCK = 4096
VOLUME_BASE = 1024 * 1024


@pytest.fixture
def buffered_writer() -> AsdfWriter:
    fh = BytesIO()
    fh.close = lambda: None  # type: ignore[method-assign]
    return AsdfWriter(fh, guid=uuid.UUID("11111111-2222-3333-4444-555555555555"))


def _populate(writer: AsdfWriter) -> None:
    writer.copy_bytes(BytesIO(b"\x01" * BLOCK), 0, BLOCK, idx=0, base=0)
    writer.copy_bytes(BytesIO(b"\x02" * BLOCK), 0, BLOCK, idx=1, base=0)
    writer.copy_bytes(BytesIO(b"\x03" * BLOCK), 0, BLOCK, idx=2, base=VOLUME_BASE)
    writer.copy_bytes(BytesIO(b"\xcc" * BLOCK), 0, BLOCK, idx=IDX_MEMORY)


def _snapshot(writer: AsdfWriter) -> AsdfSnapshot:
    writer.close()
    writer._fh.seek(0)
    return AsdfSnapshot(writer._fh)


def test_legacy_snapshot_falls_back_to_structural(buffered_writer: AsdfWriter) -> None:
    buffered_writer.add_bytes(b"\x09" * BLOCK, idx=0, base=0)
    reader = IdentityReader(_snapshot(buffered_writer))

    assert reader.manifest is None
    identity = reader.identity(0)
    assert identity.confidence == STRUCTURAL
    assert identity.source == "structure"
    assert identity.kind == KIND_DISK
    assert "must not be merged" in reader.strongest_conclusion(0)


def test_reserved_stream_kinds_are_structural(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    reader = IdentityReader(_snapshot(buffered_writer))

    assert reader.identity(IDX_MEMORY).kind == KIND_MEMORY
    assert reader.identity(IDX_METADATA).kind == KIND_METADATA
    assert reader.identity(IDX_MEMORY).is_reserved
    assert "memory" in reader.strongest_conclusion(IDX_MEMORY)


def test_manifest_drives_verified_declared_and_volume(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.acquisition = {"group_id": "run-1"}
    manifest.declare_disk(0, serial="SERIAL-A", device="/dev/sda", label="disk A")
    manifest.declare_disk(1, device="/dev/sdb", label="disk B", extra={"group_id": "run-1"})
    manifest.declare_volume(2, parent_idx=0, volume_base=VOLUME_BASE, filesystem="ntfs")
    attach_manifest(buffered_writer, manifest)

    reader = IdentityReader(_snapshot(buffered_writer))
    assert reader.manifest is not None

    disk0 = reader.identity(0)
    disk1 = reader.identity(1)
    volume = reader.identity(2)

    assert disk0.confidence == VERIFIED
    assert disk0.serial == "SERIAL-A"
    assert disk1.confidence == DECLARED
    assert disk1.serial is None
    assert volume.kind == KIND_VOLUME
    assert volume.parent_idx == 0
    assert volume.volume_base == VOLUME_BASE


def test_equal_offsets_on_different_disks_never_merge(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.declare_disk(0)
    manifest.declare_disk(1)
    attach_manifest(buffered_writer, manifest)
    reader = IdentityReader(_snapshot(buffered_writer))

    # Both streams hold a block at absolute offset 0.
    assert reader.snapshot.table[0][0][0] == 0
    assert reader.snapshot.table[1][0][0] == 0

    decision = reader.can_merge(0, 1)
    assert decision.same_device is False
    assert decision.confidence == STRUCTURAL


def test_matching_serial_verifies_same_device(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.declare_disk(0, serial="DUP-SERIAL")
    manifest.declare_disk(1, serial="DUP-SERIAL")
    attach_manifest(buffered_writer, manifest)
    reader = IdentityReader(_snapshot(buffered_writer))

    decision = reader.can_merge(0, 1)
    assert decision.same_device is True
    assert decision.confidence == VERIFIED


def test_distinct_serials_reject_merge(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.declare_disk(0, serial="SERIAL-A")
    manifest.declare_disk(1, serial="SERIAL-B")
    attach_manifest(buffered_writer, manifest)
    reader = IdentityReader(_snapshot(buffered_writer))

    decision = reader.can_merge(0, 1)
    assert decision.same_device is False
    assert decision.confidence == VERIFIED


def test_acquisition_group_declares_same_device(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.acquisition = {"group_id": "run-9"}
    manifest.declare_disk(0, extra={"group_id": "run-9"})
    manifest.declare_disk(1, extra={"group_id": "run-9"})
    attach_manifest(buffered_writer, manifest)
    reader = IdentityReader(_snapshot(buffered_writer))

    decision = reader.can_merge(0, 1)
    assert decision.same_device is True
    assert decision.confidence == DECLARED


def test_locator_scopes_offset_by_stream(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.declare_disk(0)
    manifest.declare_disk(1)
    manifest.declare_volume(2, parent_idx=0, volume_base=VOLUME_BASE)
    attach_manifest(buffered_writer, manifest)
    reader = IdentityReader(_snapshot(buffered_writer))

    loc0 = reader.locator(0, 0, BLOCK)
    loc1 = reader.locator(1, 0, BLOCK)
    loc2 = reader.locator(2, 0, BLOCK)
    assert loc0 != loc1
    assert "stream/0/disk" in loc0
    assert "stream/1/disk" in loc1
    assert "stream/2/volume" in loc2
    assert "stream/254/memory" in reader.locator(IDX_MEMORY, 0, 1)
    with pytest.raises(IndexError):
        reader.locator(99)


def test_disk_extent_adds_volume_base(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.declare_volume(2, parent_idx=0, volume_base=VOLUME_BASE)
    attach_manifest(buffered_writer, manifest)
    reader = IdentityReader(_snapshot(buffered_writer))

    parent_idx, disk_offset = reader.disk_extent(2, 0x2000, 0x100)
    assert parent_idx == 0
    assert disk_offset == VOLUME_BASE + 0x2000

    # A whole-disk stream maps through unchanged.
    assert reader.disk_extent(0, 0x1234, 16) == (0, 0x1234)


def test_attach_manifest_rejects_foreign_guid(buffered_writer: AsdfWriter) -> None:
    manifest = IdentityManifest(writer_guid=str(uuid.uuid4()))
    with pytest.raises(IdentityError):
        attach_manifest(buffered_writer, manifest)


def test_manifest_validation() -> None:
    with pytest.raises(IdentityError):
        IdentityManifest.from_dict({"schema": "asdf-identity/v1"})
    with pytest.raises(IdentityError):
        IdentityManifest.from_dict({"schema": "other", "writer_guid": "x"})

    manifest = IdentityManifest(writer_guid="g")
    with pytest.raises(IdentityError):
        manifest.declare_disk(MAX_IDX + 1)
    with pytest.raises(IdentityError):
        manifest.declare_volume(0, parent_idx=0, volume_base=-1)


def test_manifest_round_trips_through_metadata_tar(buffered_writer: AsdfWriter) -> None:
    _populate(buffered_writer)
    manifest = IdentityManifest(writer_guid=str(buffered_writer.guid))
    manifest.declare_disk(0, serial="SERIAL-A")
    attach_manifest(buffered_writer, manifest)

    snapshot = _snapshot(buffered_writer)
    assert MANIFEST_PATH in snapshot.metadata.names()
    reader = IdentityReader(snapshot)
    assert reader.identity(0).serial == "SERIAL-A"
    # Existing metadata API and old block reading stay intact.
    assert snapshot.open(0).read(BLOCK) == b"\x01" * BLOCK


def test_content_hash_is_correlation_only(buffered_writer: AsdfWriter) -> None:
    buffered_writer.add_bytes(b"\x07" * BLOCK, idx=0, base=0)
    snapshot = _snapshot(buffered_writer)
    digest = stream_sha256(snapshot.open(0))
    assert digest == stream_sha256(io.BytesIO(b"\x07" * BLOCK))
    # A content hash never upgrades the structural confidence by itself.
    reader = IdentityReader(snapshot)
    assert reader.identity(0).confidence == STRUCTURAL
