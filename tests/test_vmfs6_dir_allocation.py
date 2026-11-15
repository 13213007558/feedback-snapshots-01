from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

import pytest

from dissect.vmfs.c_vmfs import FS3_DescriptorType, FS6_DirBlockType, c_vmfs
from dissect.vmfs.descriptor import (
    FileDescriptor6,
    StaleEntryReason,
    _iter_dir_allocation_map,
    _iter_dir_ent_blocks,
)
from dissect.vmfs.exception import NotADirectoryError

BLOCK_SIZE = 0x1000
HEADER_SIZE = c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE
BLOCK_HEADER_SIZE = len(c_vmfs.FS6_DirBlockHeader)
DIRENT_SIZE = len(c_vmfs.FS6_DirEntry)
BLOCK_CAPACITY = (BLOCK_SIZE - BLOCK_HEADER_SIZE) // DIRENT_SIZE

# Directory block layout used by the synthetic fixture
ALLOC_MAP_BLOCK = 0
ACTIVE_BLOCK = 1
FREE_SLOT_BLOCK = 2
NOT_WRITTEN_BLOCK = 3
BOGUS_COUNT_BLOCK = 4


@dataclass
class FakeVMFS:
    """Minimal stand-in for a VMFS instance, only exposing what directory traversal needs."""

    md_alignment: int = BLOCK_SIZE

    def file_descriptor(self, address: int) -> object:
        return object()


class FakeDirectory(FileDescriptor6):
    """A VMFS6 directory descriptor backed by an in-memory directory buffer."""

    def __init__(self, buf: bytes):
        super().__init__(FakeVMFS(), c_vmfs.rootDirDescAddr)
        self._buf = buf

    def is_dir(self) -> bool:
        return True

    def open(self) -> BytesIO:
        return BytesIO(self._buf)


def _make_dirent(address: int, name: str, type: FS3_DescriptorType = FS3_DescriptorType.REGFILE) -> bytes:
    return c_vmfs.FS6_DirEntry(
        type=type,
        address=address,
        generation=1,
        hashIndex=0,
        linkHash=0,
        offset=0,
        name=name.encode() + b"\x00" * (256 - len(name)),
        _unk1=0,
    ).dumps()


def _make_block_header(type: int, total_slots: int, free_slots: int, free_bitmap: int = 0) -> bytes:
    bitmap = free_bitmap.to_bytes(56, "little")
    return c_vmfs.FS6_DirBlockHeader(
        version=1,
        type=type,
        totalSlots=total_slots,
        freeSlots=free_slots,
        bitmap=bitmap,
    ).dumps()


def _pack_nibble(entry_type: int, free: bool, not_written: bool) -> int:
    return entry_type | (0b0100 if free else 0) | (0b1000 if not_written else 0)


def _build_directory(
    *,
    num_entries: int | None = None,
    bogus_total_slots: int | None = None,
    corrupt_free_slots: bool = False,
) -> bytes:
    """Build a synthetic VMFS6 directory buffer.

    The fixture deliberately mixes live and residual data:
        - block 1: a fully active directory entry block.
        - block 2: an active block with a free slot that still holds a parseable residual entry.
        - block 3: a block past the ``notWritten`` boundary that still holds parseable residual entries.
        - block 4: an active block whose ``totalSlots`` count is corrupt (claims more slots than fit).
    """
    total_blocks = 5
    buf = bytearray(HEADER_SIZE + total_blocks * BLOCK_SIZE)

    def block_offset(block: int) -> int:
        return HEADER_SIZE + block * BLOCK_SIZE

    def write_dirent(block: int, slot: int, data: bytes) -> None:
        offset = block_offset(block) + BLOCK_HEADER_SIZE + slot * DIRENT_SIZE
        buf[offset : offset + DIRENT_SIZE] = data

    # Directory header
    header = c_vmfs.FS6_DirHeader(
        version=c_vmfs.FS6_DIR_HEADER_VERSION,
        numEntries=num_entries if num_entries is not None else 999,
        numAllocated=999,
        numAllocationMapBlocks=1,
    )
    header.allocationMapBlocks[0] = ALLOC_MAP_BLOCK
    header.selfEntry = c_vmfs.FS6_DirEntry(
        type=FS3_DescriptorType.DIRECTORY,
        address=c_vmfs.rootDirDescAddr,
        name=b"." + b"\x00" * 255,
    )
    header.parentEntry = c_vmfs.FS6_DirEntry(
        type=FS3_DescriptorType.DIRECTORY,
        address=c_vmfs.rootDirDescAddr,
        name=b".." + b"\x00" * 254,
    )
    buf[: len(header.dumps())] = header.dumps()

    # Allocation map block (block 0). Nibbles encode the state of each directory block.
    nibbles = {
        ALLOC_MAP_BLOCK: _pack_nibble(FS6_DirBlockType.ALLOCATION_MAP, False, False),
        ACTIVE_BLOCK: _pack_nibble(FS6_DirBlockType.DIRENT, False, False),
        FREE_SLOT_BLOCK: _pack_nibble(FS6_DirBlockType.DIRENT, True, False),
        NOT_WRITTEN_BLOCK: _pack_nibble(FS6_DirBlockType.DIRENT, False, True),
        BOGUS_COUNT_BLOCK: _pack_nibble(FS6_DirBlockType.DIRENT, False, False),
    }
    map_offset = block_offset(ALLOC_MAP_BLOCK)
    buf[map_offset : map_offset + BLOCK_HEADER_SIZE] = _make_block_header(
        FS6_DirBlockType.ALLOCATION_MAP, 0, 0
    )
    for idx, nibble in nibbles.items():
        byte_offset = map_offset + BLOCK_HEADER_SIZE + idx // 2
        if idx % 2 == 0:
            buf[byte_offset] = nibble << 4
        else:
            buf[byte_offset] |= nibble

    # Block 1: fully active block
    active_offset = block_offset(ACTIVE_BLOCK)
    buf[active_offset : active_offset + BLOCK_HEADER_SIZE] = _make_block_header(
        FS6_DirBlockType.DIRENT, 2, 0, free_bitmap=0
    )
    write_dirent(ACTIVE_BLOCK, 0, _make_dirent(0x100, "active1"))
    write_dirent(ACTIVE_BLOCK, 1, _make_dirent(0x104, "active2"))

    # Block 2: active block with one free slot. The free slot keeps a well formed residual entry.
    free_slot_offset = block_offset(FREE_SLOT_BLOCK)
    # The bitmap proves only slot 1 is free; the freeSlots count can lie but must not be trusted
    free_slots_count = 0 if corrupt_free_slots else 1
    buf[free_slot_offset : free_slot_offset + BLOCK_HEADER_SIZE] = _make_block_header(
        FS6_DirBlockType.DIRENT, 3, free_slots_count, free_bitmap=0b0000_0010
    )
    write_dirent(FREE_SLOT_BLOCK, 0, _make_dirent(0x200, "active3"))
    write_dirent(FREE_SLOT_BLOCK, 1, _make_dirent(0xDEAD, "deleted_in_free_slot"))
    write_dirent(FREE_SLOT_BLOCK, 2, _make_dirent(0x208, "active4"))

    # Block 3: a freed block (notWritten in the allocation map) whose previous content is still on disk.
    # It keeps a parseable directory entry block header and well formed residual directory entries.
    stale_offset = block_offset(NOT_WRITTEN_BLOCK)
    buf[stale_offset : stale_offset + BLOCK_HEADER_SIZE] = _make_block_header(
        FS6_DirBlockType.DIRENT, 2, 2, free_bitmap=0b0000_0011
    )
    write_dirent(NOT_WRITTEN_BLOCK, 0, _make_dirent(0xBEEF, "stale_unwritten_a"))
    write_dirent(NOT_WRITTEN_BLOCK, 1, _make_dirent(0xBEEF + 4, "stale_unwritten_b"))

    # Block 4: active block with a corrupt totalSlots count claiming far more slots than fit
    bogus_offset = block_offset(BOGUS_COUNT_BLOCK)
    bogus_total = bogus_total_slots if bogus_total_slots is not None else 0xFFFF
    buf[bogus_offset : bogus_offset + BLOCK_HEADER_SIZE] = _make_block_header(
        FS6_DirBlockType.DIRENT, bogus_total, 0, free_bitmap=0
    )
    write_dirent(BOGUS_COUNT_BLOCK, 0, _make_dirent(0x400, "active5"))

    return bytes(buf)


def _open_dir(**kwargs: object) -> FakeDirectory:
    return FakeDirectory(_build_directory(**kwargs))


def test_allocation_map_nibble_states() -> None:
    """The allocation map must expose type, free and notWritten state separately."""
    buf = _build_directory()
    fs = FakeVMFS()
    directory = FakeDirectory(buf)
    with directory.open() as fh:
        fh.seek(HEADER_SIZE + ALLOC_MAP_BLOCK * BLOCK_SIZE)
        map_block = memoryview(fh.read(BLOCK_SIZE))[BLOCK_HEADER_SIZE:]

    states = dict(enumerate(_iter_dir_allocation_map(map_block)))

    assert states[ALLOC_MAP_BLOCK] == (FS6_DirBlockType.ALLOCATION_MAP, False, False)
    assert states[ACTIVE_BLOCK] == (FS6_DirBlockType.DIRENT, False, False)
    # A partially filled block is flagged free, but that does not mean its allocated slots are inactive
    assert states[FREE_SLOT_BLOCK] == (FS6_DirBlockType.DIRENT, True, False)
    assert states[NOT_WRITTEN_BLOCK] == (FS6_DirBlockType.DIRENT, False, True)
    assert states[BOGUS_COUNT_BLOCK] == (FS6_DirBlockType.DIRENT, False, False)
    # Unused map space past the directory is a zero nibble: no type, not flagged as written
    assert states[max(states)] == (0, False, False)
    assert fs.md_alignment == BLOCK_SIZE


def test_iterdir_only_returns_allocated_entries() -> None:
    """A complete name structure is not enough: free slots and notWritten blocks stay out of iterdir."""
    directory = _open_dir()
    names = {entry.name for entry in directory.iterdir()}

    assert names == {".", "..", "active1", "active2", "active3", "active4", "active5"}
    assert "deleted_in_free_slot" not in names
    assert "stale_unwritten_a" not in names
    assert "stale_unwritten_b" not in names


def test_stale_entries_are_separate_and_justified() -> None:
    """Residual entries are exposed through iterdir_stale with their location and exclusion reason."""
    directory = _open_dir()
    stale = list(directory.iterdir_stale())
    stale_by_name = {entry.entry.name: entry for entry in stale}

    assert set(stale_by_name) == {
        "deleted_in_free_slot",
        "stale_unwritten_a",
        "stale_unwritten_b",
    }

    free_slot_residual = stale_by_name["deleted_in_free_slot"]
    assert free_slot_residual.block == FREE_SLOT_BLOCK
    assert free_slot_residual.slot == 1
    assert free_slot_residual.reason == StaleEntryReason.FREE_SLOT
    assert free_slot_residual.entry.address == 0xDEAD

    for name in ("stale_unwritten_a", "stale_unwritten_b"):
        residual = stale_by_name[name]
        assert residual.block == NOT_WRITTEN_BLOCK
        assert residual.reason == StaleEntryReason.NOT_WRITTEN

    # Forensic evidence and the ordinary listing must never overlap
    active_names = {entry.name for entry in directory.iterdir()}
    assert not (active_names & set(stale_by_name))


def test_free_flag_does_not_hide_allocated_slots() -> None:
    """The allocation map free flag marks a partially filled block, not a fully deallocated one."""
    directory = _open_dir()
    names = {entry.name for entry in directory.iterdir()}

    # active3 and active4 live in the block that the allocation map flags as having free slots
    assert {"active3", "active4"} <= names


def test_free_slot_count_does_not_override_bitmap() -> None:
    """A corrupt freeSlots header count cannot resurrect a free slot or hide its residual status."""
    directory = FakeDirectory(_build_directory(corrupt_free_slots=True))

    # freeSlots claims 0 free slots, but the bitmap still marks slot 1 as free
    active_names = {entry.name for entry in directory.iterdir()}
    assert "active3" in active_names and "active4" in active_names
    assert "deleted_in_free_slot" not in active_names

    stale = {entry.entry.name: entry for entry in directory.iterdir_stale()}
    assert stale["deleted_in_free_slot"].reason == StaleEntryReason.FREE_SLOT


def test_corrupt_header_counts_do_not_control_traversal() -> None:
    """Corrupt numEntries and totalSlots counts cannot hide entries or read past the block boundary."""
    # numEntries claims there are no entries at all
    directory = _open_dir(num_entries=0)
    names = {entry.name for entry in directory.iterdir()}
    assert {"active1", "active2", "active3", "active4", "active5"} <= names

    # totalSlots claims an impossibly large number of slots; iteration must stay within the block
    directory = FakeDirectory(_build_directory(bogus_total_slots=0xFFFF))
    entries = list(directory.iterdir())
    assert any(entry.name == "active5" for entry in entries)
    # Only physically present, allocated slots are yielded from the corrupt block
    bogus_entries = [entry for entry in entries if entry.name == "active5"]
    assert len(bogus_entries) == 1


def test_block_capacity_caps_slot_scan() -> None:
    """The effective slot count is capped to the number of slots that physically fit in a block."""
    directory = _open_dir()
    with directory.open() as fh:
        header = c_vmfs.FS6_DirHeader(fh)
        for block, block_header, _block_entries, _not_written in _iter_dir_ent_blocks(fh, header, directory.vmfs):
            assert block_header.totalSlots <= BLOCK_CAPACITY or block == BOGUS_COUNT_BLOCK


def test_iterdir_requires_directory() -> None:
    """iterdir and iterdir_stale reject non-directory descriptors."""
    directory = _open_dir()
    directory.is_dir = lambda: False

    with pytest.raises(NotADirectoryError):
        list(directory.iterdir())

    with pytest.raises(NotADirectoryError):
        list(directory.iterdir_stale())


def test_invalid_directory_header_version() -> None:
    """An unrecognized directory header version is rejected rather than traversed."""
    buf = bytearray(_build_directory())
    buf[0:4] = (0x12345678).to_bytes(4, "little")
    directory = FakeDirectory(bytes(buf))

    with pytest.raises(NotADirectoryError):
        list(directory.iterdir())

    with pytest.raises(NotADirectoryError):
        list(directory.iterdir_stale())
