from __future__ import annotations

import struct
from unittest.mock import Mock

import pytest

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk
from dissect.archive.vbk.vbk import (
    FibBlockDescriptor,
    FibMetaSparseTable,
    MetaBlob,
    MetaVector,
    MetaVector2,
    VBKError,
)

INT64S_PER_PAGE = PAGE_SIZE // 8
DESCS_PER_DATA_PAGE = PAGE_SIZE // len(c_vbk.FibBlockDescriptor)

# Hand-constructed MetaVector2 table page layout.
# The first table page has a 16 byte header, every third page after that a 32 byte header,
# all other pages an 8 byte header. Each (header_size, capacity) pair below is derived
# directly from that on-disk layout, not from the implementation under test.
TABLE_PAGE_LAYOUT = [
    (16, INT64S_PER_PAGE - 2),  # page 0: next page + root page
    (32, INT64S_PER_PAGE - 4),  # page 1: next page + 3 embedded page numbers
    (8, INT64S_PER_PAGE - 1),  # page 2: next page only
    (8, INT64S_PER_PAGE - 1),  # page 3: next page only
    (32, INT64S_PER_PAGE - 4),  # page 4: next group of 3 embedded page numbers
    (8, INT64S_PER_PAGE - 1),  # page 5: next page only
    (8, INT64S_PER_PAGE - 1),  # page 6: next page only
]
TABLE_PAGE_NUMBERS = list(range(100, 100 + len(TABLE_PAGE_LAYOUT)))
DATA_PAGE_BASE = 0x10000


def build_table_chain(page_numbers: list[int]) -> tuple[dict[int, bytes], list[int]]:
    """Build a MetaVector2 table chain and return its pages plus the slot boundaries.

    Every table slot points at a distinct data page, so a slot read at the wrong table
    offset can never accidentally return the descriptor of the expected data page.
    """
    pages = {}
    boundaries = []
    slot = 0

    for table_idx, page_no in enumerate(page_numbers):
        header_size, capacity = TABLE_PAGE_LAYOUT[table_idx]
        next_page = page_numbers[table_idx + 1] if table_idx + 1 < len(page_numbers) else -1

        if header_size == 32:
            next_1 = page_numbers[table_idx + 1] if table_idx + 1 < len(page_numbers) else -1
            next_2 = page_numbers[table_idx + 2] if table_idx + 2 < len(page_numbers) else -1
            header = struct.pack("<qqqq", next_page, page_no, next_1, next_2)
        elif header_size == 16:
            header = struct.pack("<qq", next_page, page_no)
        else:
            header = struct.pack("<q", next_page)

        boundaries.append((slot, capacity, page_no, header_size))
        pointers = struct.pack(f"<{capacity}q", *[DATA_PAGE_BASE + slot + i for i in range(capacity)])
        pages[page_no] = (header + pointers).ljust(PAGE_SIZE, b"\x00")
        slot += capacity

    return pages, boundaries


class SyntheticVBKPageStore:
    """An in-memory VBK page store backed by a hand-constructed page layout."""

    def __init__(self, table_pages: dict[int, bytes]):
        self.table_pages = table_pages
        self.data_pages: dict[int, bytes] = {}

    def add_data_page(self, slot: int) -> int:
        page_no = DATA_PAGE_BASE + slot
        records = b"".join(
            c_vbk.FibBlockDescriptor(
                BlockSize=0x10000,
                Type=c_vbk.BlockLocationType.Normal,
                BlockId=self._block_id(slot, offset),
            ).dumps()
            for offset in range(DESCS_PER_DATA_PAGE)
        )
        self.data_pages[page_no] = records.ljust(PAGE_SIZE, b"\x00")
        return page_no

    def add_subtable_data_page(self, table_id: int, local_slot: int, page_no: int) -> None:
        records = b"".join(
            c_vbk.FibBlockDescriptor(
                BlockSize=0x20000 + table_id,
                Type=c_vbk.BlockLocationType.Normal,
                BlockId=self._subtable_block_id(table_id, local_slot, offset),
            ).dumps()
            for offset in range(DESCS_PER_DATA_PAGE)
        )
        self.data_pages[page_no] = records.ljust(PAGE_SIZE, b"\x00")

    @staticmethod
    def _block_id(slot: int, offset: int) -> int:
        return (slot << 16) | offset

    @staticmethod
    def _subtable_block_id(table_id: int, local_slot: int, offset: int) -> int:
        return (table_id << 40) | (local_slot << 16) | offset

    def truncate_after(self, page_no: int) -> None:
        """Break the next-page pointer of a table page so the chain is truncated."""
        buf = bytearray(self.table_pages[page_no])
        buf[:8] = struct.pack("<q", 999_999)
        self.table_pages[page_no] = bytes(buf)

    def point_next_at(self, page_no: int, target: int) -> None:
        """Overwrite the next-page pointer of a table page."""
        buf = bytearray(self.table_pages[page_no])
        buf[:8] = struct.pack("<q", target)
        self.table_pages[page_no] = bytes(buf)

    def repoint_slot(self, page_no: int, header_size: int, slot_offset: int, target: int) -> None:
        """Overwrite a single table slot pointer."""
        position = header_size + slot_offset * 8
        buf = bytearray(self.table_pages[page_no])
        buf[position : position + 8] = struct.pack("<q", target)
        self.table_pages[page_no] = bytes(buf)

    def page(self, page_no: int) -> memoryview:
        if page_no not in self.table_pages and page_no not in self.data_pages:
            # A truncated chain runs off the end of the evidence file: no page is returned.
            return memoryview(b"")
        if page_no in self.table_pages:
            return memoryview(self.table_pages[page_no])
        return memoryview(self.data_pages[page_no])


def make_vbk(store: SyntheticVBKPageStore) -> Mock:
    vbk = Mock(spec=["format_version", "block_size", "page", "get_meta_blob", "is_v7"])
    vbk.format_version = 13
    vbk.block_size = 0x10000
    vbk.is_v7 = lambda: False
    vbk.page = store.page
    vbk.get_meta_blob = lambda page: MetaBlob(_SlotAdapter(store), page)
    return vbk


class _SlotAdapter:
    def __init__(self, store: SyntheticVBKPageStore):
        self.page = store.page


def first_descriptor_mismatch(vec: MetaVector2, total_slots: int) -> tuple[int, int, int, int] | None:
    """Return the first misaligned descriptor as (logical_index, physical_page, got_id, expected_id)."""
    for slot in range(total_slots):
        logical_index = slot * DESCS_PER_DATA_PAGE
        desc = vec.get(logical_index)
        expected_id = SyntheticVBKPageStore._block_id(slot, 0)
        if desc.block_id != expected_id or desc.block_size != 0x10000:
            return logical_index, vec._lookup_page(slot), desc.block_id, expected_id
    return None


def test_metavector2_table_layout_matches_hand_constructed_headers() -> None:
    """The table chain must expose exactly the header-derived slot boundaries."""
    table_pages, boundaries = build_table_chain(TABLE_PAGE_NUMBERS)
    total_slots = sum(capacity for _, capacity, _, _ in boundaries)

    assert boundaries == [
        (0, 510, 100, 16),
        (510, 508, 101, 32),
        (1018, 511, 102, 8),
        (1529, 511, 103, 8),
        (2040, 508, 104, 32),
        (2548, 511, 105, 8),
        (3059, 511, 106, 8),
    ]
    assert total_slots == 3570

    # Table slot values are real data page numbers, never small header integers.
    assert min(struct.unpack("<q", table_pages[100][16:24])) == DATA_PAGE_BASE


def test_metavector2_forward_reverse_and_cached_access() -> None:
    """Every slot must resolve to its own data page across all special header boundaries."""
    table_pages, boundaries = build_table_chain(TABLE_PAGE_NUMBERS)
    total_slots = sum(capacity for _, capacity, _, _ in boundaries)
    store = SyntheticVBKPageStore(table_pages)
    for slot in range(total_slots):
        store.add_data_page(slot)
    vbk = make_vbk(store)

    vec = MetaVector2(vbk, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], total_slots * DESCS_PER_DATA_PAGE)

    # Explicit boundary lookups derived from the hand-constructed layout.
    expected_first_slots = [0, 510, 1018, 1529, 2040, 2548, 3059]
    for table_idx, first_slot in enumerate(expected_first_slots):
        assert vec._lookup_page(first_slot) == DATA_PAGE_BASE + first_slot
        last_slot = first_slot + TABLE_PAGE_LAYOUT[table_idx][1] - 1
        assert vec._lookup_page(last_slot) == DATA_PAGE_BASE + last_slot

    # Forward access over every table slot, checking the first descriptor of each data page.
    forward = [vec.get(slot * DESCS_PER_DATA_PAGE) for slot in range(total_slots)]
    assert first_descriptor_mismatch(vec, total_slots) is None

    # Reverse access must land on the exact same descriptors.
    for slot in range(total_slots - 1, -1, -1):
        desc = vec.get(slot * DESCS_PER_DATA_PAGE)
        assert desc.block_id == SyntheticVBKPageStore._block_id(slot, 0)
        assert desc.block_id == forward[slot].block_id

    # Cache revisit: repeated and interleaved lookups stay pinned to their physical page.
    revisited = [0, 509, 510, 1017, 1018, 1528, 1529, 2039, 2040, 2547, 2548, 3058, 3059, 3569]
    for slot in revisited * 3:
        assert vec._lookup_page(slot) == DATA_PAGE_BASE + slot
        assert vec.get(slot * DESCS_PER_DATA_PAGE).block_id == SyntheticVBKPageStore._block_id(slot, 0)

    # The last descriptor on boundary data pages must not bleed into a neighbouring page.
    for first_slot, capacity, _, _ in boundaries:
        last_slot = first_slot + capacity - 1
        last_index = last_slot * DESCS_PER_DATA_PAGE + DESCS_PER_DATA_PAGE - 1
        desc = vec.get(last_index)
        assert desc.block_id == SyntheticVBKPageStore._block_id(last_slot, DESCS_PER_DATA_PAGE - 1)


def test_metavector2_reports_first_misaligned_slot_and_physical_page() -> None:
    """A corrupted slot pointer must be reported with its logical index and physical location."""
    table_pages, _ = build_table_chain(TABLE_PAGE_NUMBERS)
    total_slots = sum(capacity for _, capacity in TABLE_PAGE_LAYOUT)
    store = SyntheticVBKPageStore(table_pages)
    for slot in range(total_slots):
        store.add_data_page(slot)

    # Corrupt the first slot on the 32 byte header page (global slot 510) so it points at
    # the previous slot's data page, which still contains perfectly valid descriptors.
    store.repoint_slot(TABLE_PAGE_NUMBERS[1], 32, 0, DATA_PAGE_BASE + 509)
    vbk = make_vbk(store)
    vec = MetaVector2(vbk, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], total_slots * DESCS_PER_DATA_PAGE)

    mismatch = first_descriptor_mismatch(vec, total_slots)
    assert mismatch == (
        510 * DESCS_PER_DATA_PAGE,
        DATA_PAGE_BASE + 509,
        SyntheticVBKPageStore._block_id(509, 0),
        SyntheticVBKPageStore._block_id(510, 0),
    )


def test_metavector2_negative_and_over_count_indices_raise() -> None:
    """Out of range indices must raise instead of silently reading another descriptor."""
    table_pages, _ = build_table_chain(TABLE_PAGE_NUMBERS[:2])
    total_slots = sum(capacity for _, capacity in TABLE_PAGE_LAYOUT[:2])
    store = SyntheticVBKPageStore(table_pages)
    for slot in range(total_slots):
        store.add_data_page(slot)
    vbk = make_vbk(store)
    vec = MetaVector2(vbk, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], total_slots * DESCS_PER_DATA_PAGE)

    for bad_index in (-1, -DESCS_PER_DATA_PAGE, vec.count, vec.count + 1):
        with pytest.raises(IndexError):
            vec.get(bad_index)

    # The legacy single-header vector shares the same index guard.
    vbk_old = Mock(spec=["format_version", "block_size", "page", "get_meta_blob"])
    vbk_old.format_version = 9
    vbk_old.block_size = 0x10000
    vbk_old.page = store.page
    vbk_old.get_meta_blob = lambda page: MetaBlob(_SlotAdapter(store), page)
    old_vec = MetaVector(vbk_old, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], 4)
    with pytest.raises(IndexError):
        old_vec.get(-1)
    with pytest.raises(IndexError):
        old_vec.get(4)


def test_metavector2_truncated_page_chain_raises() -> None:
    """A chain that runs off the end of the file must fail rather than loop on empty pages."""
    table_pages, _ = build_table_chain(TABLE_PAGE_NUMBERS)
    store = SyntheticVBKPageStore(table_pages)
    store.truncate_after(TABLE_PAGE_NUMBERS[2])
    vbk = make_vbk(store)

    with pytest.raises(VBKError, match="Truncated meta blob page"):
        MetaVector2(vbk, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], 1)


def test_metavector2_circular_page_chain_raises() -> None:
    """A next-page pointer back into the chain must be detected instead of looping forever."""
    table_pages, _ = build_table_chain(TABLE_PAGE_NUMBERS)
    store = SyntheticVBKPageStore(table_pages)
    store.point_next_at(TABLE_PAGE_NUMBERS[3], TABLE_PAGE_NUMBERS[1])
    vbk = make_vbk(store)

    with pytest.raises(VBKError, match="Circular meta blob page chain"):
        MetaVector2(vbk, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], 1)

    # A self-referencing root page is a cycle as well.
    table_pages, _ = build_table_chain(TABLE_PAGE_NUMBERS)
    store = SyntheticVBKPageStore(table_pages)
    store.point_next_at(TABLE_PAGE_NUMBERS[0], TABLE_PAGE_NUMBERS[0])
    vbk = make_vbk(store)

    with pytest.raises(VBKError, match="Circular meta blob page chain"):
        MetaVector2(vbk, FibBlockDescriptor, TABLE_PAGE_NUMBERS[0], 1)


def test_fib_meta_sparse_table_routes_through_metavector2() -> None:
    """FibMetaSparseTable must resolve descriptors through the same table page machinery."""
    # Sub-table 2 is fully sparse. The populated sizes are exact multiples of the data page
    # capacity so every constructed descriptor is backed by an actual on-page record.
    subtable_sizes = [DESCS_PER_DATA_PAGE * 2, DESCS_PER_DATA_PAGE * 3, 0, DESCS_PER_DATA_PAGE + 5]
    subtable_roots = [200, 201, 202, 203]
    descriptor_page = 300
    next_free_page = [400]

    store = SyntheticVBKPageStore({})
    descriptors = []

    for table_id, (count, root_page) in enumerate(zip(subtable_sizes, subtable_roots)):
        if count == 0:
            descriptors.append(c_vbk.MetaTableDescriptor(RootPage=-1, BlockSize=0x10000, Count=0).dumps())
            continue

        slot_count = (count + DESCS_PER_DATA_PAGE - 1) // DESCS_PER_DATA_PAGE
        pointers = []
        for local_slot in range(slot_count):
            page_no = next_free_page[0]
            next_free_page[0] += 1
            store.add_subtable_data_page(table_id, local_slot, page_no)
            pointers.append(page_no)

        header = struct.pack("<qq", -1, root_page)
        store.table_pages[root_page] = (
            header + struct.pack(f"<{len(pointers)}q", *pointers)
        ).ljust(PAGE_SIZE, b"\x00")
        descriptors.append(
            c_vbk.MetaTableDescriptor(RootPage=root_page, BlockSize=0x10000, Count=count).dumps()
        )

    store.data_pages[descriptor_page] = b"".join(descriptors).ljust(PAGE_SIZE, b"\x00")
    outer_header = struct.pack("<qq", -1, 4000)
    outer_pointers = struct.pack("<4q", descriptor_page, descriptor_page, descriptor_page, descriptor_page)
    store.table_pages[4000] = (outer_header + outer_pointers).ljust(PAGE_SIZE, b"\x00")

    vbk = make_vbk(store)
    # Every sub-table occupies a full MAX_ENTRIES_PER_TABLE stride in the logical address space.
    total_count = FibMetaSparseTable.MAX_ENTRIES_PER_TABLE * len(subtable_sizes)
    sparse = FibMetaSparseTable(vbk, 4000, total_count)

    def expected_block_id(logical_index: int) -> int:
        table_id, entry_index = divmod(logical_index, FibMetaSparseTable.MAX_ENTRIES_PER_TABLE)
        local_slot, offset = divmod(entry_index, DESCS_PER_DATA_PAGE)
        return SyntheticVBKPageStore._subtable_block_id(table_id, local_slot, offset)

    def expected_block_size(logical_index: int) -> int:
        table_id = logical_index // FibMetaSparseTable.MAX_ENTRIES_PER_TABLE
        return 0x20000 + table_id

    third_start = FibMetaSparseTable.MAX_ENTRIES_PER_TABLE * 3
    populated_ranges = [
        range(0, subtable_sizes[0]),
        range(
            FibMetaSparseTable.MAX_ENTRIES_PER_TABLE,
            FibMetaSparseTable.MAX_ENTRIES_PER_TABLE + subtable_sizes[1],
        ),
        range(third_start, third_start + subtable_sizes[3]),
    ]
    populated = [idx for rng in populated_ranges for idx in rng]

    # Forward access through the directory/sparse-table reading path.
    for logical_index in populated:
        desc = sparse.get(logical_index)
        assert desc.is_normal()
        assert desc.block_id == expected_block_id(logical_index)
        assert desc.block_size == expected_block_size(logical_index)

    # Reverse access and cache revisits resolve identically, including every sub-table edge.
    for logical_index in reversed(populated):
        assert sparse.get(logical_index).block_id == expected_block_id(logical_index)
    edge_indices = [
        0,
        DESCS_PER_DATA_PAGE - 1,
        DESCS_PER_DATA_PAGE,
        subtable_sizes[0] - 1,
        FibMetaSparseTable.MAX_ENTRIES_PER_TABLE,
        FibMetaSparseTable.MAX_ENTRIES_PER_TABLE + subtable_sizes[1] - 1,
        third_start,
        third_start + subtable_sizes[3] - 1,
    ]
    for logical_index in edge_indices * 2:
        assert sparse.get(logical_index).block_id == expected_block_id(logical_index)

    # The fully sparse sub-table returns synthetic sparse descriptors, never page data.
    sparse_start = FibMetaSparseTable.MAX_ENTRIES_PER_TABLE * 2
    for logical_index in range(sparse_start, sparse_start + 100):
        assert sparse.get(logical_index).is_sparse()

    for bad_index in (-1, total_count, total_count + 10):
        with pytest.raises(IndexError):
            sparse.get(bad_index)
