"""End-to-end, fully in-memory demonstration of the ASDF identity layer.

Scenario:
    - Two physical disks captured as streams idx=0 and idx=1.
    - A partition/volume captured as a relative stream idx=2, with its byte
      offset (base) on disk idx=0 recorded in the identity manifest.
    - A memory capture on the reserved stream idx=254.
    - The metadata TAR occupies the reserved stream idx=255 automatically.

The script never touches a real disk: every source and the ASDF container
itself live in ``io.BytesIO``. Run it with::

    .venv/bin/python examples/asdf_identity_demo.py
"""

from __future__ import annotations

import io
import uuid

from dissect.evidence.asdf.asdf import IDX_MEMORY, AsdfSnapshot, AsdfWriter
from dissect.evidence.asdf.identity import (
    STRUCTURAL,
    IdentityManifest,
    IdentityReader,
    attach_manifest,
)

BLOCK = 4096
# Volume starts 1 MiB into disk 0.
VOLUME_BASE = 1024 * 1024


def build_snapshot() -> io.BytesIO:
    buf = io.BytesIO()
    # Keep the buffer alive after writer.close().
    buf.close = lambda: None  # type: ignore[method-assign]
    writer = AsdfWriter(buf, guid=uuid.UUID("11111111-2222-3333-4444-555555555555"))

    # --- Disk 0: a disk whose serial is known -------------------------------
    disk0 = io.BytesIO(b"\x01" * (8 * BLOCK))
    writer.copy_bytes(disk0, 0, 4 * BLOCK, idx=0, base=0)
    # A second, non-contiguous extent of the *same* disk.
    writer.copy_bytes(disk0, 4 * BLOCK, 4 * BLOCK, idx=0, base=8 * BLOCK)

    # --- Disk 1: a different disk, deliberately at a colliding offset -------
    disk1 = io.BytesIO(b"\x02" * (4 * BLOCK))
    # Same absolute offset (0) as disk 0's first block, but another idx.
    writer.copy_bytes(disk1, 0, 4 * BLOCK, idx=1, base=0)

    # --- Volume: relative stream of a partition on disk 0 ------------------
    # The volume source reads from offset 0; on the disk it sits at VOLUME_BASE.
    volume = io.BytesIO(b"\x03" * (4 * BLOCK))
    writer.copy_bytes(volume, 0, 4 * BLOCK, idx=2, base=VOLUME_BASE)

    # --- Reserved memory stream --------------------------------------------
    memory = io.BytesIO(b"\xcc" * (4 * BLOCK))
    writer.copy_bytes(memory, 0, 4 * BLOCK, idx=IDX_MEMORY)

    # --- Identity manifest carried in the metadata TAR (idx=255) -----------
    manifest = IdentityManifest(writer_guid=str(writer.guid))
    manifest.acquisition = {
        "case_id": "CASE-2026-0001",
        "acquirer": "acquire-agent/3.1",
        "group_id": "run-7f3a",
    }
    # Disk 0 carries a real hardware serial -> strongest (verified) identity.
    manifest.declare_disk(0, serial="S1AXNS0AA90001", device="/dev/sda", label="evidence-disk-A")
    # Disk 1 has no serial: an acquisition declaration only, never "verified".
    manifest.declare_disk(1, device="/dev/sdb", label="evidence-disk-B", extra={"group_id": "run-7f3a"})
    # Volume maps back to disk 0 at the recorded byte base.
    manifest.declare_volume(
        2,
        parent_idx=0,
        volume_base=VOLUME_BASE,
        filesystem="ntfs",
        label="disk-A partition 1",
    )
    attach_manifest(writer, manifest)

    writer.close()
    buf.seek(0)
    return buf


def build_legacy_snapshot() -> io.BytesIO:
    """An old-style ASDF with block data but no identity manifest."""
    buf = io.BytesIO()
    buf.close = lambda: None  # type: ignore[method-assign]
    writer = AsdfWriter(buf, guid=uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    writer.add_bytes(b"\x09" * BLOCK, idx=0, base=0)
    writer.close()
    buf.seek(0)
    return buf


def main() -> None:
    snapshot = AsdfSnapshot(build_snapshot())
    reader = IdentityReader(snapshot)

    print("== container ==")
    print(f"writer GUID        : {snapshot.guid}")
    print(f"streams in table   : {sorted(snapshot.table.keys())}")
    print()

    print("== per-stream identity ==")
    for idx, identity in reader.identities().items():
        print(
            f"idx={idx:<3} kind={identity.kind:<8} confidence={identity.confidence:<10} "
            f"source={identity.source:<9} label={identity.display()!r}"
        )
    print()

    print("== canonical locators (offset alone never implies a device) ==")
    loc_disk0 = reader.locator(0, offset=0, size=BLOCK)
    loc_disk1 = reader.locator(1, offset=0, size=BLOCK)
    loc_volume = reader.locator(2, offset=0, size=BLOCK)
    loc_memory = reader.locator(IDX_MEMORY, offset=0, size=BLOCK)
    print(f"disk0  @0x0       : {loc_disk0}")
    print(f"disk1  @0x0 (same offset, different disk): {loc_disk1}")
    print(f"volume @0x0       : {loc_volume}")
    print(f"memory @0x0       : {loc_memory}")
    assert loc_disk0 != loc_disk1, "equal offsets on different disks must not share a locator"
    print()

    print("== mapping a volume byte back to the physical disk ==")
    in_volume_offset = 0x2000
    parent_idx, disk_offset = reader.disk_extent(2, in_volume_offset, 0x100)
    print(
        f"volume idx=2 offset 0x{in_volume_offset:x} -> disk idx={parent_idx} "
        f"absolute offset 0x{disk_offset:x} (base 0x{VOLUME_BASE:x})"
    )
    assert disk_offset == VOLUME_BASE + in_volume_offset
    print()

    print("== same-device merge decisions ==")
    # Two ranges of the same idx are one device by construction; disk 0 vs
    # disk 1 are not, even at identical offsets.
    same_stream = reader.can_merge(0, 0)
    cross_disk = reader.can_merge(0, 1)
    declared_group = reader.can_merge(1, 2)

    def show(title: str, decision: object) -> None:
        print(f"{title:<34}: merge={decision.same_device} ({decision.confidence}) - {decision.reason}")

    show("two extents of idx=0", same_stream)
    show("idx=0 vs idx=1, identical offset", cross_disk)
    show("idx=1 vs idx=2, no binding claim", declared_group)
    assert same_stream.same_device
    assert not cross_disk.same_device
    assert not declared_group.same_device
    print()

    print("== legacy file without any metadata ==")
    legacy = AsdfSnapshot(build_legacy_snapshot())
    legacy_reader = IdentityReader(legacy)
    legacy_identity = legacy_reader.identity(0)
    print(f"manifest present   : {legacy_reader.manifest is not None}")
    print(f"confidence         : {legacy_identity.confidence}")
    print(f"strongest conclusion: {legacy_reader.strongest_conclusion(0)}")
    assert legacy_identity.confidence == STRUCTURAL
    print()
    print("OK: all identity assertions held.")


if __name__ == "__main__":
    main()
