from __future__ import annotations

import json
import uuid
from io import BytesIO

import pytest

from dissect.evidence.asdf import (
    AsdfSnapshot,
    AsdfWriter,
    EvidenceIndex,
    IdentityStrength,
    SourceClaim,
    StreamDeclaration,
    StreamRole,
    write_identity_manifest,
)
from dissect.evidence.asdf.identity import IDENTITY_FORMAT, IDENTITY_MANIFEST, IDENTITY_VERSION
from dissect.evidence.exception import InvalidEvidence


def make_writer() -> AsdfWriter:
    fh = BytesIO()
    fh.close = lambda: None
    return AsdfWriter(fh)


def reopen(writer: AsdfWriter) -> AsdfSnapshot:
    writer.close()
    writer._fh.seek(0)
    return AsdfSnapshot(writer._fh)


def sample_snapshot() -> AsdfSnapshot:
    """Build the two-disk, one-volume and one-memory-stream sample."""
    writer = make_writer()

    # Disk A, stream 0, captured at two ranges.
    writer.add_bytes(b"A" * 0x1000, idx=0, base=0x0000)
    writer.add_bytes(b"a" * 0x1000, idx=0, base=0x4000)

    # Volume A1 is captured in its own relative stream.  Its base is the
    # offset of the volume inside disk A; the ASDF block offsets stay relative.
    # Only part of the volume was captured in this example.
    writer.add_bytes(b"V" * 0x200, idx=1, base=0x0000)
    writer.add_bytes(b"W" * 0x200, idx=1, base=0x0600)

    # Disk B, stream 2, deliberately uses the same offsets as disk A.
    writer.add_bytes(b"B" * 0x1000, idx=2, base=0x0000)
    writer.add_bytes(b"b" * 0x1000, idx=2, base=0x4000)

    # Memory capture, reserved stream 254.
    writer.add_bytes(b"M" * 0x200, idx=254)

    write_identity_manifest(
        writer,
        [
            StreamDeclaration(
                0,
                StreamRole.DISK,
                source=SourceClaim(serial="DISK-A", serial_source="acquisition", model="Example"),
                label="Disk A",
            ),
            StreamDeclaration(1, StreamRole.VOLUME, base=0x4000, parent_idx=0, label="Volume A1"),
            StreamDeclaration(
                2,
                StreamRole.DISK,
                source=SourceClaim(serial="DISK-B", serial_source="acquisition"),
                label="Disk B",
            ),
            StreamDeclaration(254, StreamRole.MEMORY, label="Memory"),
        ],
    )

    return reopen(writer)


def test_identity_sample_locate_two_disks_volume_and_memory() -> None:
    snapshot = sample_snapshot()
    evidence = snapshot.evidence

    assert evidence.manifest_present
    assert not evidence.manifest_ignored
    assert evidence.warnings == ()
    assert evidence.container == snapshot.guid

    disk_a = evidence.get(0)
    volume = evidence.get(1)
    disk_b = evidence.get(2)
    memory = evidence.get(254)

    assert disk_a.role == StreamRole.DISK
    assert disk_a.identity_strength == IdentityStrength.DECLARED_SERIAL
    assert disk_a.source_key == "serial:DISK-A"
    assert disk_a.display_name == "Disk A [stream 0]"

    assert volume.role == StreamRole.VOLUME
    assert volume.base == 0x4000
    assert volume.parent_idx == 0
    assert volume.identity_strength == IdentityStrength.DECLARED_ROLE
    assert volume.source_key is None

    # Same byte offsets in two disks are distinct evidence extents.
    extent_a = disk_a.locate(0x4000, 0x1000)
    extent_b = disk_b.locate(0x4000, 0x1000)
    assert extent_a.identifier == f"asdf:{snapshot.guid}/stream/0@0x4000+0x1000"
    assert extent_b.identifier == f"asdf:{snapshot.guid}/stream/2@0x4000+0x1000"
    assert extent_a.identifier != extent_b.identifier
    assert not extent_a.same_stream(extent_b)
    assert not extent_a.overlaps(extent_b)

    # A volume-relative extent translates to its parent disk, but keeps its
    # own stream identifier for provenance.
    volume_extent = volume.locate(0x100, 0x200)
    assert volume_extent.identifier == f"asdf:{snapshot.guid}/stream/1@0x100+0x200"
    assert volume_extent.source_offset == 0x4100
    assert volume_extent.to_parent() == (0, 0x4100, 0x200)

    # A partially captured volume reports that fact; the address and parent
    # translation remain available.
    partial = volume.locate(0x0, 0x800)
    assert not partial.captured
    assert volume.locate(0x0, 0x200).captured
    assert partial.to_parent() == (0, 0x4000, 0x800)

    # Memory has no parent-disk coordinate system.
    memory_extent = memory.locate(0x20, 0x40)
    assert memory_extent.identifier == f"asdf:{snapshot.guid}/stream/254@0x20+0x40"
    assert memory_extent.source_offset is None
    assert memory_extent.to_parent() is None

    # Human-facing identifiers round-trip.
    assert evidence.resolve(extent_b.identifier) == extent_b
    assert evidence.resolve(volume_extent.identifier).to_parent() == (0, 0x4100, 0x200)

    with pytest.raises(ValueError):
        evidence.resolve("asdf:not-a-guid/stream/0@0x0+0x1")

    with pytest.raises(ValueError):
        evidence.resolve(f"asdf:{uuid.uuid4()}/stream/0@0x0+0x1")

    # A range crossing a sparse gap is addressable but not fully captured.
    assert not disk_a.locate(0x0800, 0x0900).captured
    assert disk_a.locate(0x4000, 0x1000).captured

    with pytest.raises(ValueError):
        disk_a.locate(0x4000, 0x1001)  # Exceeds the stream size.

    # Old read interfaces are unchanged.
    assert snapshot.open(0).read(0x1000) == b"A" * 0x1000
    assert snapshot.open(2).read(0x1000) == b"B" * 0x1000
    assert [stream.idx for stream in snapshot.disks()] == [0, 1, 2]
    assert IDENTITY_MANIFEST in snapshot.metadata.names()


def test_identity_without_manifest_only_claims_container_stream() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0)
    writer.add_bytes(b"\x02" * 0x1000, idx=1, base=0x4000)
    writer.add_bytes(b"\x03" * 0x1000, idx=254)
    snapshot = reopen(writer)

    evidence = snapshot.evidence
    assert not evidence.manifest_present
    assert not evidence.manifest_ignored
    assert evidence.metadata_names == ()

    for idx in (0, 1):
        stream = evidence.get(idx)
        assert stream.role == StreamRole.STREAM
        assert stream.identity_strength == IdentityStrength.CONTAINER_STREAM
        assert stream.source_key is None
        assert stream.base is None
        assert stream.parent_idx is None
        assert stream.display_name == f"stream stream {idx}"

    assert evidence.get(254).role == StreamRole.MEMORY
    assert evidence.get(254).identity_strength == IdentityStrength.CONTAINER_STREAM

    # Only the container GUID, stream index and ranges are known.
    assert evidence.get(0).identifier == f"asdf:{snapshot.guid}/stream/0"
    assert evidence.get(0).locate(0, 0x1000).identifier == f"asdf:{snapshot.guid}/stream/0@0x0+0x1000"

    # There is no basis to say streams 0 and 1 are the same device.
    assert evidence.get(0).source_key is None
    assert evidence.get(1).source_key is None


def test_identity_serial_without_provenance_is_declared_but_not_verified() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x00" * 0x100, idx=0)
    write_identity_manifest(writer, [StreamDeclaration(0, StreamRole.DISK, SourceClaim(serial="X"))])
    snapshot = reopen(writer)

    stream = snapshot.evidence.get(0)
    assert stream.source_key == "serial:X"
    assert stream.identity_strength == IdentityStrength.DECLARED_SERIAL
    assert stream.source is not None
    assert not stream.source.serial_verified
    assert stream.source.display() == "serial='X' (provenance unknown)"


def test_identity_label_only_does_not_identify_a_device() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x00" * 0x100, idx=0)
    writer.add_bytes(b"\x00" * 0x100, idx=1)
    write_identity_manifest(
        writer,
        [
            StreamDeclaration(0, StreamRole.DISK, SourceClaim(serial="Evidence-01", serial_source="label")),
            StreamDeclaration(1, StreamRole.DISK, SourceClaim(serial="Evidence-01", serial_source="label")),
        ],
    )
    snapshot = reopen(writer)
    evidence = snapshot.evidence

    for idx in (0, 1):
        stream = evidence.get(idx)
        assert stream.identity_strength == IdentityStrength.DECLARED_ROLE
        assert stream.source_key is None
        assert stream.source.display() == "label='Evidence-01' (label)"
        assert stream.source is not None and stream.source.serial_verified is False

    assert evidence.warnings == ()


def test_identity_same_declared_serial_does_not_merge_ranges() -> None:
    writer = make_writer()
    writer.add_bytes(b"A" * 0x1000, idx=0, base=0x4000)
    writer.add_bytes(b"A" * 0x1000, idx=1, base=0x4000)
    write_identity_manifest(
        writer,
        [
            StreamDeclaration(0, StreamRole.DISK, SourceClaim(serial="SAME", serial_source="acquisition")),
            StreamDeclaration(1, StreamRole.DISK, SourceClaim(serial="SAME", serial_source="acquisition")),
        ],
    )
    snapshot = reopen(writer)
    evidence = snapshot.evidence

    first = evidence.get(0).locate(0x4000, 0x1000)
    second = evidence.get(1).locate(0x4000, 0x1000)

    # The source claim is shared, but the addresses and extents are not.
    assert first.source_key == second.source_key == "serial:SAME"
    assert not first.same_stream(second)
    assert not first.overlaps(second)
    assert first.identifier != second.identifier


def test_identity_role_only_is_declared_not_identified() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x00" * 0x100, idx=0)
    write_identity_manifest(writer, [StreamDeclaration(0, StreamRole.DISK)])
    snapshot = reopen(writer)

    stream = snapshot.evidence.get(0)
    assert stream.role == StreamRole.DISK
    assert stream.identity_strength == IdentityStrength.DECLARED_ROLE
    assert stream.source_key is None


def test_identity_invalid_manifest_degrades_and_strict_raises() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x00" * 0x100, idx=0)
    writer.add_metadata_file(IDENTITY_MANIFEST, BytesIO(b"not json"))
    snapshot = reopen(writer)

    evidence = snapshot.evidence
    assert evidence.manifest_present
    assert evidence.manifest_ignored
    assert len(evidence.warnings) == 1
    assert evidence.get(0).identity_strength == IdentityStrength.CONTAINER_STREAM

    with pytest.raises(InvalidEvidence):
        EvidenceIndex.from_snapshot(snapshot, strict=True)


def test_identity_guid_mismatch_is_not_trusted() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x00" * 0x100, idx=0)
    manifest = {
        "format": IDENTITY_FORMAT,
        "version": IDENTITY_VERSION,
        "container_guid": str(uuid.uuid4()),
        "streams": [{"idx": 0, "role": "disk", "base": 0}],
    }
    data = json.dumps(manifest).encode()
    writer.add_metadata_file(IDENTITY_MANIFEST, BytesIO(data), len(data))
    snapshot = reopen(writer)

    evidence = snapshot.evidence
    assert evidence.manifest_present
    assert evidence.manifest_ignored
    assert evidence.get(0).role == StreamRole.STREAM
    assert evidence.get(0).identity_strength == IdentityStrength.CONTAINER_STREAM
    assert any("does not match" in warning for warning in evidence.warnings)

    with pytest.raises(InvalidEvidence):
        EvidenceIndex.from_snapshot(snapshot, strict=True)


def test_identity_unknown_and_absent_streams_are_warnings() -> None:
    writer = make_writer()
    writer.add_bytes(b"\x00" * 0x100, idx=0)
    write_identity_manifest(
        writer,
        [
            StreamDeclaration(0, StreamRole.DISK, SourceClaim(serial="A", serial_source="acquisition")),
            StreamDeclaration(7, StreamRole.DISK, SourceClaim(serial="B", serial_source="acquisition")),
        ],
    )
    snapshot = reopen(writer)

    evidence = snapshot.evidence
    assert any("absent stream 7" in warning for warning in evidence.warnings)
    with pytest.raises(IndexError):
        evidence.get(7)

    # Absent streams are not invented, but the existing stream stays readable.
    assert snapshot.open(0).read(0x100) == b"\x00" * 0x100


def test_identity_manifest_rejects_duplicate_and_bad_declarations() -> None:
    writer = make_writer()

    with pytest.raises(ValueError):
        StreamDeclaration(255, StreamRole.DISK)

    with pytest.raises(ValueError):
        StreamDeclaration(0, StreamRole.DISK, base=0x4000)

    with pytest.raises(ValueError):
        StreamDeclaration(0, StreamRole.DISK, parent_idx=1)

    with pytest.raises(ValueError):
        StreamDeclaration(0, StreamRole.MEMORY)

    with pytest.raises(ValueError):
        StreamDeclaration(254, StreamRole.DISK)

    with pytest.raises(ValueError):
        write_identity_manifest(
            writer,
            [
                StreamDeclaration(0, StreamRole.DISK),
                StreamDeclaration(0, StreamRole.DISK),
            ],
        )


def test_identity_legacy_reader_ignores_manifest() -> None:
    """A caller that only knows the old API still sees the same streams."""
    snapshot = sample_snapshot()

    assert snapshot.contains(0)
    assert snapshot.contains(1)
    assert snapshot.contains(2)
    assert snapshot.contains(254)
    assert snapshot.contains(255)
    assert sorted(snapshot.table) == [0, 1, 2, 254, 255]

    # The metadata stream is still a tar and only gained one member.
    assert IDENTITY_MANIFEST in snapshot.metadata.names()
    assert snapshot.metadata.open(IDENTITY_MANIFEST).read().startswith(b"{")
