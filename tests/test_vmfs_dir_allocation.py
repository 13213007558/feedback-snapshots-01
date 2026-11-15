from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

from dissect.vmfs.c_vmfs import FS3_DescriptorType, FS6_DirBlockType, c_vmfs
from dissect.vmfs.descriptor import (
    DirEntryExclusionReason,
    FileDescriptor6,
    ResidualDirEntry,
    _iter_dir_allocation_map,
)

BLOCK_SIZE = 0x1000
DIR_HEADER_SIZE = c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE
BLOCK_HEADER_SIZE = len(c_vmfs.FS6_DirBlockHeader)
DIRENT_SIZE = len(c_vmfs.FS6_DirEntry)
SLOTS_PER_BLOCK = (BLOCK_SIZE - BLOCK_HEADER_SIZE) // DIRENT_SIZE

ALLOCATION_MAP_BLOCK = 0
NOT_WRITTEN_BLOCK = 2
MIXED_BLOCK = 4


class SyntheticDirectory(FileDescriptor6):
    """A VMFS6 file descriptor backed by an in-memory synthetic directory buffer."""

    def __init__(self, buffer: bytes, md_alignment: int = BLOCK_SIZE):
        super().__init__(SimpleNamespace(md_alignment=md_alignment), address=c_vmfs.rootDirDescAddr)
        self._buffer = buffer

    @property
    def size(self) -> int:
        return len(self._buffer)

    def is_dir(self) -> bool:
        return True

    def open(self):
        return io.BytesIO(self._buffer)


def _dirent(name: str, address: int) -> bytes:
    entry = c_vmfs.FS6_DirEntry()
    entry.type = FS3_DescriptorType.REGFILE
    entry.address = address
    entry.name = name.encode()
    return entry.dumps()


def _dirent_block(total_slots: int, free_slots: set[int], entries: dict[int, bytes]) -> bytes:
    header = c_vmfs.FS6_DirBlockHeader()
    header.version = 1
    header.type = FS6_DirBlockType.DIRENT
    header.totalSlots = total_slots
    header.freeSlots = len(free_slots)

    bitmap = bytearray(len(header.bitmap))
    for slot in free_slots:
        bitmap[slot >> 3] |= 1 << (slot & 7)
    header.bitmap = bytes(bitmap)

    block = bytearray(header.dumps())
    block += b"\x00" * (BLOCK_SIZE - BLOCK_HEADER_SIZE)
    for slot, payload in entries.items():
        start = BLOCK_HEADER_SIZE + slot * DIRENT_SIZE
        block[start : start + DIRENT_SIZE] = payload
    return bytes(block)


def _allocation_map_block(nibbles: dict[int, int]) -> bytes:
    # Each byte holds two nibbles; the high nibble is the even index and the low nibble the odd index
    payload = bytearray(BLOCK_SIZE - BLOCK_HEADER_SIZE)
    for index, value in nibbles.items():
        byte_index, is_low_nibble = divmod(index, 2)
        if is_low_nibble:
            payload[byte_index] |= value & 0x0F
        else:
            payload[byte_index] |= (value & 0x0F) << 4
    return BLOCK_HEADER_SIZE * b"\x00" + bytes(payload)


def _make_header(*, include_parent: bool = True) -> c_vmfs.FS6_DirHeader:
    # Construct from a zeroed buffer: cstruct reuses one shared default instance for nested structs, so mutating
    # selfEntry/parentEntry on a bare FS6_DirHeader() would leak into every subsequently constructed header.
    header = c_vmfs.FS6_DirHeader(bytearray(len(c_vmfs.FS6_DirHeader)))
    header.version = c_vmfs.FS6_DIR_HEADER_VERSION
    header.numAllocationMapBlocks = 1
    header.allocationMapBlocks[0] = ALLOCATION_MAP_BLOCK
    header.selfEntry.type = FS3_DescriptorType.DIRECTORY
    header.selfEntry.address = 0x4
    header.selfEntry.name = b"."
    if include_parent:
        header.parentEntry.type = FS3_DescriptorType.DIRECTORY
        header.parentEntry.address = 0x4
        header.parentEntry.name = b".."
    return header


def _build_directory(num_entries: int) -> bytes:
    """Build a directory with one not-written block and one partially free active block.

    Layout of the directory buffer:
        - block 0: allocation map block
        - block 1: fully active directory entry block
        - block 2: not-written block that still holds a fully parseable "ghost" entry
        - block 3: unused (not-written, empty)
        - block 4: active block with two free slots holding deleted names and two live entries
    """
    header = _make_header()
    # Deliberately caller controlled so tests can prove the counter cannot extend or shrink the listing
    header.numEntries = num_entries
    header.numAllocated = num_entries

    buffer = bytearray(DIR_HEADER_SIZE + 5 * BLOCK_SIZE)
    buffer[: len(header.dumps())] = header.dumps()

    full_block = _dirent_block(
        SLOTS_PER_BLOCK,
        free_slots=set(),
        entries={slot: _dirent(f"active-full-{slot}", 0x1000 + slot) for slot in range(3)},
    )

    # The not-written block still contains a structurally complete entry that must not be treated as live
    not_written_block = _dirent_block(
        SLOTS_PER_BLOCK,
        free_slots=set(),
        entries={0: _dirent("ghost-not-written", 0x9000)},
    )

    mixed_block = _dirent_block(
        4,
        free_slots={1, 3},
        entries={
            0: _dirent("active-mixed-0", 0x2000),
            1: _dirent("deleted-free-slot", 0x3000),
            2: _dirent("active-mixed-2", 0x2002),
            3: _dirent("another-deleted", 0x3003),
        },
    )

    allocation_map = _allocation_map_block(
        {
            ALLOCATION_MAP_BLOCK: FS6_DirBlockType.ALLOCATION_MAP,
            1: FS6_DirBlockType.DIRENT,
            NOT_WRITTEN_BLOCK: 0b1000,
            3: 0b1000,
            MIXED_BLOCK: FS6_DirBlockType.DIRENT | 0b0100,
        }
    )

    blocks = {
        ALLOCATION_MAP_BLOCK: allocation_map,
        1: full_block,
        NOT_WRITTEN_BLOCK: not_written_block,
        MIXED_BLOCK: mixed_block,
    }
    for block, payload in blocks.items():
        start = DIR_HEADER_SIZE + block * BLOCK_SIZE
        buffer[start : start + BLOCK_SIZE] = payload

    return bytes(buffer)


@pytest.fixture()
def synthetic_directory() -> SyntheticDirectory:
    # An absurdly large counter must not make the traversal walk past the real directory boundary
    return SyntheticDirectory(_build_directory(num_entries=0xFFFFFFFF))


def test_iterdir_only_yields_allocated_entries(synthetic_directory: SyntheticDirectory) -> None:
    names = [entry.name for entry in synthetic_directory.iterdir()]

    assert names == [
        ".",
        "..",
        "active-full-0",
        "active-full-1",
        "active-full-2",
        "active-mixed-0",
        "active-mixed-2",
    ]

    # Deleted names and leftovers from not-written blocks never appear in the normal listing
    joined = "\n".join(names)
    assert "ghost-not-written" not in joined
    assert "deleted-free-slot" not in joined
    assert "another-deleted" not in joined


def test_iterdir_ignores_corrupted_num_entries(synthetic_directory: SyntheticDirectory) -> None:
    inflated = [entry.name for entry in synthetic_directory.iterdir()]

    # A zeroed/under-counted header must not hide active entries either
    shrunk = SyntheticDirectory(_build_directory(num_entries=0))
    assert [entry.name for entry in shrunk.iterdir()] == inflated


def test_corrupted_total_slots_does_not_cross_block_boundary() -> None:
    # A block header claiming more slots than physically fit must not make the scan read past the block
    buffer = bytearray(_build_directory(num_entries=5))
    mixed_block_offset = DIR_HEADER_SIZE + MIXED_BLOCK * BLOCK_SIZE
    block_header = c_vmfs.FS6_DirBlockHeader(buffer[mixed_block_offset:])
    block_header.totalSlots = SLOTS_PER_BLOCK + 100
    buffer[mixed_block_offset : mixed_block_offset + BLOCK_HEADER_SIZE] = block_header.dumps()

    directory = SyntheticDirectory(bytes(buffer))

    # No EOFError and no phantom entries beyond the physical block boundary
    names = [entry.name for entry in directory.iterdir()]
    assert "active-mixed-0" in names
    assert "active-mixed-2" in names
    assert names.count("active-mixed-0") == 1
    assert "." in names
    assert ".." in names


def test_not_written_block_beyond_buffer_is_not_read() -> None:
    # The allocation map covers a fixed capacity and can mark blocks not-written that are not backed by the directory
    # buffer at all. The forensic scan must stay inside the real buffer instead of reading past its end.
    buffer = bytearray(DIR_HEADER_SIZE + 2 * BLOCK_SIZE)
    header = _make_header(include_parent=False)
    header.numEntries = 1
    buffer[: len(header.dumps())] = header.dumps()

    # Block 1 is a real dirent block; block 100 only exists in the map as not-written, not on disk
    buffer[DIR_HEADER_SIZE : DIR_HEADER_SIZE + BLOCK_SIZE] = _allocation_map_block(
        {
            ALLOCATION_MAP_BLOCK: FS6_DirBlockType.ALLOCATION_MAP,
            1: FS6_DirBlockType.DIRENT,
            100: 0b1000,
        }
    )
    buffer[DIR_HEADER_SIZE + BLOCK_SIZE : DIR_HEADER_SIZE + 2 * BLOCK_SIZE] = _dirent_block(
        1, free_slots=set(), entries={0: _dirent("in-buffer", 0x1)}
    )

    directory = SyntheticDirectory(bytes(buffer))

    active = [entry.name for entry in directory.iterdir()]
    assert active == [".", "in-buffer"]
    # No EOFError: the out-of-buffer not-written block is bounded by the directory size, not read at all
    assert list(directory.iterdir_residual()) == []


def test_iterdir_residual_keeps_location_and_reason(synthetic_directory: SyntheticDirectory) -> None:
    residual = list(synthetic_directory.iterdir_residual())

    assert all(isinstance(item, ResidualDirEntry) for item in residual)

    by_name = {item.entry.name: item for item in residual}
    assert set(by_name) == {"ghost-not-written", "deleted-free-slot", "another-deleted"}

    ghost = by_name["ghost-not-written"]
    assert ghost.block == NOT_WRITTEN_BLOCK
    assert ghost.slot == 0
    assert ghost.reason is DirEntryExclusionReason.BLOCK_NOT_WRITTEN
    # A complete-looking name still points at the parsed entry, but is flagged as inactive
    assert ghost.entry.address == 0x9000

    for name in ("deleted-free-slot", "another-deleted"):
        item = by_name[name]
        assert item.block == MIXED_BLOCK
        assert item.reason is DirEntryExclusionReason.FREE_SLOT
    assert by_name["deleted-free-slot"].slot == 1
    assert by_name["another-deleted"].slot == 3


def test_residual_entries_are_disjoint_from_active_listing(synthetic_directory: SyntheticDirectory) -> None:
    active = {entry.name for entry in synthetic_directory.iterdir()}
    residual = {item.entry.name for item in synthetic_directory.iterdir_residual()}

    assert active.isdisjoint(residual)


def test_zeroed_free_slots_are_not_reported_as_residual() -> None:
    # Free slots without any parseable name/address are empty, not forensic evidence
    buffer = bytearray(DIR_HEADER_SIZE + 2 * BLOCK_SIZE)
    header = _make_header(include_parent=False)
    header.numEntries = 1
    buffer[: len(header.dumps())] = header.dumps()

    buffer[DIR_HEADER_SIZE : DIR_HEADER_SIZE + BLOCK_SIZE] = _allocation_map_block(
        {ALLOCATION_MAP_BLOCK: FS6_DirBlockType.ALLOCATION_MAP, 1: FS6_DirBlockType.DIRENT}
    )
    buffer[DIR_HEADER_SIZE + BLOCK_SIZE : DIR_HEADER_SIZE + 2 * BLOCK_SIZE] = _dirent_block(
        4, free_slots={1, 2, 3}, entries={0: _dirent("only-active", 0x1)}
    )

    directory = SyntheticDirectory(bytes(buffer))
    assert [entry.name for entry in directory.iterdir()] == [".", "only-active"]
    assert list(directory.iterdir_residual()) == []


@pytest.mark.parametrize(
    ("nibble", "expected"),
    [
        (0b0000, (0, False, False)),
        (0b0001, (FS6_DirBlockType.DIRENT, False, False)),
        (0b0101, (FS6_DirBlockType.DIRENT, True, False)),
        (0b1000, (0, False, True)),
        (0b1110, (FS6_DirBlockType.LINK, True, True)),
    ],
)
def test_iter_dir_allocation_map_flags(nibble: int, expected: tuple[int, bool, bool]) -> None:
    # High nibble carries logical entry 0, low nibble entry 1
    packed = bytes([(nibble << 4) | nibble])
    parsed = list(_iter_dir_allocation_map(packed))
    assert parsed[0] == expected
    assert parsed[1] == expected
