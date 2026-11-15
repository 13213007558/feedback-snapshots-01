"""Structured regression tests for :class:`MetaVector2` table page chains.

A ``MetaVector2`` is a table of 64-bit page numbers spread over several table
pages. The table pages do not share a single header size:

* the first table page has a 16 byte header,
* every third table page (index 1, 4, 7, ...) has a 32 byte header,
* all other table pages have an 8 byte header.

When a forensic image is large enough that the index walks from the first table
page into later table pages, a header length miscalculation shifts every slot
that follows. The tests below build the page layout by hand so the expected
physical location of every slot is known independently of the implementation
under test.

Each data descriptor gets a unique, non-guessable marker (digest pattern plus a
``BlockId`` derived from the logical index). Decoy pages holding descriptors
from a fictional neighbouring file are placed right before the table chain so a
read that leaves the chain can never return something that happens to validate.
"""
from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.archive.vbk.c_vbk import PAGE_SIZE, c_vbk
from dissect.archive.vbk.vbk import (
    VBKError,
    FibBlockDescriptor,
    FibMetaSparseTable,
    MetaBlob,
    MetaVector2,
)

ENTRIES_PER_TABLE_PAGE = PAGE_SIZE // 8
FIB_ENTRY_SIZE = len(c_vbk.FibBlockDescriptor)
FIB_ENTRIES_PER_DATA_PAGE = PAGE_SIZE // FIB_ENTRY_SIZE
TABLE_ENTRY_SIZE = len(c_vbk.MetaTableDescriptor)
TABLE_ENTRIES_PER_DATA_PAGE = PAGE_SIZE // TABLE_ENTRY_SIZE

# Header size (in 64-bit words) for each table page. The first page always has
# a 16 byte (2 word) header; afterwards the 32 byte (4 word) header repeats on
# indices 1, 4, 7, ... and every other page has an 8 byte (1 word) header.
TABLE_HEADER_WORDS_FIRST = 2
TABLE_HEADER_WORDS_SPECIAL = 4
TABLE_HEADER_WORDS_NORMAL = 1


def table_header_words(table_idx: int) -> int:
    """Return the header size, in 64-bit words, of table page ``table_idx``."""
    if table_idx == 0:
        return TABLE_HEADER_WORDS_FIRST
    if table_idx % 3 == 1:
        return TABLE_HEADER_WORDS_SPECIAL
    return TABLE_HEADER_WORDS_NORMAL


# Markers used to tell our descriptors apart from neighbouring-file decoys.
MARKER_MAGIC = b"VBK"
DECOY_MAGIC = b"NBH"


def table_entries_on_page(table_idx: int) -> int:
    """Return the number of usable page-number slots on table page ``table_idx``."""
    return ENTRIES_PER_TABLE_PAGE - table_header_words(table_idx)


def expected_table_slot(flat_idx: int) -> tuple[int, int]:
    """Return the expected ``(table_page, word_offset)`` for a flat table index.

    This mirrors the hand-built layout, independently of ``MetaVector2``'s
    own arithmetic, so the two can be compared to locate the first mismatch.
    """
    if flat_idx < table_entries_on_page(0):
        return 0, table_header_words(0) + flat_idx

    remaining = flat_idx - table_entries_on_page(0)
    table_idx = 1
    while True:
        capacity = table_entries_on_page(table_idx)
        if remaining < capacity:
            return table_idx, table_header_words(table_idx) + remaining
        remaining -= capacity
        table_idx += 1


# The Digest field starts after BlockSize (uint32) + Type (uint8) inside a
# FibBlockDescriptor, which is where the unique marker is stored.
DIGEST_OFFSET = 4 + 1


def encode_fib_descriptor(logical_idx: int, magic: bytes = MARKER_MAGIC) -> bytes:
    """Encode a uniquely marked ``FibBlockDescriptor`` for ``logical_idx``."""
    digest = magic + struct.pack("<I", logical_idx) + b"\x00" * (16 - len(magic) - 4)
    return c_vbk.FibBlockDescriptor(
        BlockSize=PAGE_SIZE,
        Type=c_vbk.BlockLocationType.Normal,
        Digest=digest,
        BlockId=0xA0000000 + logical_idx,
        Flags=c_vbk.BlockFlags(0),
    ).dumps()


def decode_marker(buf: bytes) -> tuple[bytes, int]:
    """Return ``(magic, logical_idx)`` stored in a raw descriptor buffer."""
    digest = bytes(buf[DIGEST_OFFSET : DIGEST_OFFSET + 16])
    magic = digest[:3]
    logical_idx = struct.unpack("<I", digest[3:7])[0]
    return magic, logical_idx


class SyntheticVBK:
    """An in-memory VBK page store with a hand-constructed MetaVector2 chain."""

    def __init__(self, num_table_pages: int):
        self.format_version = 13
        self.block_size = PAGE_SIZE
        self.pages: dict[int, bytes] = {}
        self._next_free_page = 0
        self.decoy_pages = [self.alloc_page(), self.alloc_page()]
        for decoy_page in self.decoy_pages:
            self.pages[decoy_page] = self._build_decoy_page(decoy_page)

        self.table_pages = [self.alloc_page() for _ in range(num_table_pages)]
        self.num_table_pages = num_table_pages

        self.capacities = [table_entries_on_page(i) for i in range(num_table_pages)]
        self.table_capacity = sum(self.capacities)

        self.data_pages: list[int] = []
        self._build_table_chain()

    def alloc_page(self) -> int:
        page = self._next_free_page
        self._next_free_page += 1
        return page

    def _build_decoy_page(self, decoy_page: int) -> bytes:
        entry = c_vbk.FibBlockDescriptor(
            BlockSize=PAGE_SIZE,
            Type=c_vbk.BlockLocationType.Normal,
            Digest=DECOY_MAGIC + struct.pack("<I", decoy_page) + b"\x00" * 9,
            BlockId=0xDEAD0000 + decoy_page,
            Flags=c_vbk.BlockFlags(0),
        ).dumps()
        return (entry * (PAGE_SIZE // len(entry)))[:PAGE_SIZE]

    def _data_page_for(self, table_slot: int) -> int:
        # A table slot points at a whole data page holding
        # FIB_ENTRIES_PER_DATA_PAGE consecutive descriptors.
        data_page_idx = table_slot
        while len(self.data_pages) <= data_page_idx:
            self.data_pages.append(self.alloc_page())
        return self.data_pages[data_page_idx]

    def _build_data_page(self, data_page_idx: int) -> bytes:
        base = data_page_idx * FIB_ENTRIES_PER_DATA_PAGE
        return b"".join(
            encode_fib_descriptor(base + slot) for slot in range(FIB_ENTRIES_PER_DATA_PAGE)
        )

    def _build_table_chain(self) -> None:
        flat_idx = 0
        for table_idx, page_no in enumerate(self.table_pages):
            next_page = self.table_pages[table_idx + 1] if table_idx + 1 < self.num_table_pages else -1
            capacity = self.capacities[table_idx]
            pointers = [self._data_page_for(flat_idx + slot) for slot in range(capacity)]

            if table_idx == 0:
                header = struct.pack("<qq", next_page, self.table_pages[0])
            elif table_idx % 3 == 1:
                this_page = self.table_pages[table_idx]
                page_b = self.table_pages[table_idx + 1] if table_idx + 1 < self.num_table_pages else -1
                page_c = self.table_pages[table_idx + 2] if table_idx + 2 < self.num_table_pages else -1
                header = struct.pack("<qqqq", next_page, this_page, page_b, page_c)
            else:
                header = struct.pack("<q", next_page)

            body = struct.pack(f"<{capacity}q", *pointers)
            self.pages[page_no] = (header + body).ljust(PAGE_SIZE, b"\x00")
            flat_idx += capacity

    def page(self, page_no: int) -> bytes:
        if page_no not in self.pages:
            if page_no in self.data_pages:
                self.pages[page_no] = self._build_data_page(self.data_pages.index(page_no))
            else:
                raise IndexError(f"reference to page outside the constructed store: {page_no}")
        return self.pages[page_no]

    def is_v7(self) -> bool:
        return False

    def get_meta_blob(self, root_page: int) -> MetaBlob:
        return MetaBlob(_SlotAdapter(self), root_page)

    def vector(self, count: int | None = None, entry_type: type = FibBlockDescriptor) -> MetaVector2:
        return MetaVector2(self, entry_type, self.table_pages[0], count if count is not None else self.table_capacity)

    def truncate_chain(self, keep_pages: int) -> None:
        """Terminate the next-page pointer after ``keep_pages`` table pages."""
        last = self.table_pages[keep_pages - 1]
        buf = bytearray(self.pages[last])
        struct.pack_into("<q", buf, 0, -1)
        self.pages[last] = bytes(buf)

    def link_back(self, table_idx: int, target_table_idx: int) -> None:
        """Rewrite the next-page pointer of one table page to point backwards."""
        page = self.table_pages[table_idx]
        buf = bytearray(self.pages[page])
        struct.pack_into("<q", buf, 0, self.table_pages[target_table_idx])
        self.pages[page] = bytes(buf)


class _SlotAdapter:
    """Minimal slot-like object exposing ``page`` for :class:`MetaBlob`."""

    def __init__(self, store: SyntheticVBK):
        self._store = store

    def page(self, page_no: int) -> bytes:
        return self._store.page(page_no)


def first_misalignment(store: SyntheticVBK, table_slots: list[int]) -> tuple[int, int, int, int] | None:
    """Walk a freshly built vector and report the first slot read wrongly.

    Args are table-slot (flat page-number) indices. Returns
    ``(table_slot, expected_page, actual_page, word_offset)`` for the first
    mismatch, or ``None`` when every slot resolves to its hand-computed
    physical location. The vector is rebuilt on every call so callers can
    mutate the page store first to inject a structural defect.
    """
    vec = store.vector()
    for table_slot in table_slots:
        expected_page = store.data_pages[table_slot]
        _, word_offset = expected_table_slot(table_slot)

        actual_page = vec._lookup_page(table_slot)
        if actual_page != expected_page:
            return table_slot, expected_page, actual_page, word_offset

        # Every descriptor on the referenced data page must carry the marker
        # matching its logical index, so a shifted pointer cannot hide behind a
        # descriptor that merely happens to validate.
        first_logical = table_slot * FIB_ENTRIES_PER_DATA_PAGE
        for entry_idx in (0, FIB_ENTRIES_PER_DATA_PAGE - 1):
            raw = vec.data(first_logical + entry_idx)
            magic, marked_idx = decode_marker(raw)
            if magic != MARKER_MAGIC or marked_idx != first_logical + entry_idx:
                return table_slot, expected_page, actual_page, word_offset
    return None


# ---------------------------------------------------------------------------
# Layout construction: every special table header is exercised.
# ---------------------------------------------------------------------------


def test_table_layout_matches_hand_computed_slots() -> None:
    store = SyntheticVBK(num_table_pages=11)

    assert store.capacities == [510, 508, 511, 511, 508, 511, 511, 508, 511, 511, 508]
    assert store.table_capacity == sum(store.capacities)

    vec = store.vector()
    flat_idx = 0
    for table_idx, page_no in enumerate(store.table_pages):
        for slot in range(store.capacities[table_idx]):
            assert expected_table_slot(flat_idx) == (
                table_idx,
                table_header_words(table_idx) + slot,
            )
            assert vec._lookup_page(flat_idx) == store._data_page_for(flat_idx)
            flat_idx += 1


def test_header_word_offsets_skip_full_header() -> None:
    # The first word inside each table page is the next-page pointer and must
    # never be interpreted as a data page number.
    store = SyntheticVBK(num_table_pages=7)
    vec = store.vector()
    first_flat_per_page = []
    cumulative = 0
    for capacity in store.capacities:
        first_flat_per_page.append(cumulative)
        cumulative += capacity

    for table_idx, flat_idx in enumerate(first_flat_per_page):
        table_page, word_offset = expected_table_slot(flat_idx)
        assert table_page == table_idx
        assert word_offset == table_header_words(table_idx)
        raw_word = struct.unpack("<q", store.pages[store.table_pages[table_idx]][:8])[0]
        assert vec._lookup_page(flat_idx) != raw_word or raw_word == -1


# ---------------------------------------------------------------------------
# Forward, reverse and cached re-visit access over every header boundary.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("num_table_pages", [4, 7, 11])
def test_forward_reverse_and_cached_access(num_table_pages: int) -> None:
    store = SyntheticVBK(num_table_pages=num_table_pages)
    vec = store.vector()

    # Indices on, and immediately around, every table page boundary, plus the
    # transitions into the next repeating group of special headers.
    boundary_indices = [0]
    cumulative = 0
    for capacity in store.capacities:
        cumulative += capacity
        boundary_indices.extend(idx for idx in (cumulative - 1, cumulative) if idx < store.table_capacity)
    sampled = sorted(set(boundary_indices))

    for order_name, indices in (
        ("forward", sampled),
        ("reverse", list(reversed(sampled))),
        ("cached_revisit", sampled),
    ):
        for logical_idx in indices:
            descriptor = vec.get(logical_idx)
            magic, marked_idx = decode_marker(descriptor.buf)
            assert magic == MARKER_MAGIC, f"{order_name}: neighbour/decoy descriptor at logical {logical_idx}"
            assert marked_idx == logical_idx, (
                f"{order_name}: misaligned slot, expected marker {logical_idx} but read {marked_idx}"
            )
            assert descriptor.block_id == 0xA0000000 + logical_idx

    assert first_misalignment(store, sampled) is None


def test_full_scan_never_leaves_the_chain() -> None:
    store = SyntheticVBK(num_table_pages=7)
    vec = store.vector()
    # Scan every logical entry backed by the table; decoys must never appear.
    for logical_idx in range(store.table_capacity):
        magic, marked_idx = decode_marker(vec.data(logical_idx))
        assert magic == MARKER_MAGIC
        assert marked_idx == logical_idx


# ---------------------------------------------------------------------------
# A deliberately broken header shift is detected and located precisely.
# ---------------------------------------------------------------------------


def test_first_misalignment_is_reported_with_physical_location() -> None:
    store = SyntheticVBK(num_table_pages=4)
    first_slot_on_page_one = store.capacities[0]
    expected_table_page, expected_word = expected_table_slot(first_slot_on_page_one)
    assert expected_table_page == 1
    assert expected_word == table_header_words(1)

    # Simulate the historical header-length bug: a parser that believes the
    # second table page has an 8 byte header instead of its real 32 byte header
    # reads its first slot two words too early, landing on a header word rather
    # than the first data-page pointer.
    page_one = store.table_pages[1]
    parser_word_offset = 1  # The buggy header assumption (8 bytes / 8).
    actual_pointer_word = table_header_words(1)  # The correct 32 byte header.

    buggy_pointer = struct.unpack(
        "<q", store.pages[page_one][parser_word_offset * 8 : parser_word_offset * 8 + 8]
    )[0]
    correct_pointer = struct.unpack(
        "<q", store.pages[page_one][actual_pointer_word * 8 : actual_pointer_word * 8 + 8]
    )[0]
    assert buggy_pointer != correct_pointer

    # Drive the same arithmetic the implementation uses, but with the wrong
    # header assumption, and confirm the diagnostic locates this exact slot.
    flat_idx = first_slot_on_page_one - store.capacities[0]
    buggy_table_offset = 1 * ENTRIES_PER_TABLE_PAGE + parser_word_offset + flat_idx
    correct_table_offset = 1 * ENTRIES_PER_TABLE_PAGE + actual_pointer_word + flat_idx
    assert buggy_table_offset != correct_table_offset

    # The unmodified store must report no misalignment, proving the diagnostic
    # itself is sound; the corrupted read resolves to a different physical page.
    assert first_misalignment(store, list(range(store.table_capacity))) is None

    expected_data_page = store.data_pages[first_slot_on_page_one]
    assert correct_pointer == expected_data_page
    assert buggy_pointer != expected_data_page

    # Now physically corrupt the page so the correct header offset returns the
    # header word; the first mismatch must be this slot with its location.
    buf = bytearray(store.pages[page_one])
    struct.pack_into("<q", buf, actual_pointer_word * 8, buggy_pointer)
    store.pages[page_one] = bytes(buf)

    mismatch = first_misalignment(store, list(range(store.table_capacity)))
    assert mismatch is not None
    logical_idx, expected_page, actual_page, word_offset = mismatch
    assert logical_idx == first_slot_on_page_one
    assert expected_page == expected_data_page
    assert actual_page == buggy_pointer
    assert word_offset == actual_pointer_word


# ---------------------------------------------------------------------------
# Truncated chains, negative indices, over-count and back-links.
# ---------------------------------------------------------------------------


def test_truncated_page_chain_raises_instead_of_reading_neighbour() -> None:
    store = SyntheticVBK(num_table_pages=5)
    store.truncate_chain(keep_pages=2)
    surviving_table_slots = sum(store.capacities[:2])
    first_missing_logical = surviving_table_slots * FIB_ENTRIES_PER_DATA_PAGE
    # Declare a count that reaches into the truncated region so the failure is
    # driven by the broken page chain, not by the count bounds check.
    vec = store.vector(count=first_missing_logical + FIB_ENTRIES_PER_DATA_PAGE)

    # The last table slot that still belongs to the surviving chain resolves.
    last_data_page_idx = surviving_table_slots - 1
    last_logical = last_data_page_idx * FIB_ENTRIES_PER_DATA_PAGE
    magic, marked_idx = decode_marker(vec.data(last_logical))
    assert magic == MARKER_MAGIC and marked_idx == last_logical

    # A data page index beyond the surviving table chain must fail instead of
    # walking into a decoy page or a stale next-page word.
    with pytest.raises(IndexError):
        vec._lookup_page(surviving_table_slots)
    with pytest.raises(IndexError):
        vec.data(first_missing_logical)
    with pytest.raises(IndexError):
        vec.get(first_missing_logical)

    # Decoy pages sit before the chain and must never be reached instead.
    for decoy_page in store.decoy_pages:
        assert decode_marker(store.page(decoy_page))[0] == DECOY_MAGIC


@pytest.mark.parametrize("negative_idx", [-1, -2, -510, -1019, -1020, -5000])
def test_negative_index_is_rejected(negative_idx: int) -> None:
    store = SyntheticVBK(num_table_pages=4)
    vec = store.vector()

    with pytest.raises(IndexError):
        vec.get(negative_idx)


def test_index_at_and_above_count_is_rejected() -> None:
    store = SyntheticVBK(num_table_pages=4)
    vec = store.vector(count=100)

    with pytest.raises(IndexError):
        vec.get(100)
    with pytest.raises(IndexError):
        vec.get(101)
    # The last valid index still works and is not a decoy descriptor.
    magic, marked_idx = decode_marker(vec.data(99))
    assert magic == MARKER_MAGIC and marked_idx == 99


def test_back_link_cannot_loop_into_a_valid_descriptor() -> None:
    store = SyntheticVBK(num_table_pages=5)
    store.link_back(table_idx=4, target_table_idx=1)

    with pytest.raises(VBKError, match="Circular meta blob page chain"):
        store.vector()


def test_self_referencing_table_page_is_rejected() -> None:
    store = SyntheticVBK(num_table_pages=3)
    store.link_back(table_idx=1, target_table_idx=1)

    with pytest.raises(VBKError, match="Circular meta blob page chain"):
        store.vector()


# ---------------------------------------------------------------------------
# End-to-end impact through the FibMetaSparseTable / directory read path.
# ---------------------------------------------------------------------------


def _build_sub_table_chain(store: SyntheticVBK, count: int) -> int:
    """Lay out a sub table reached from a FibMetaSparseTable.

    On format version 13 every :class:`MetaVector` is constructed as a
    :class:`MetaVector2`: the root chain is a table of page numbers with the
    special 16/32/8 byte table headers, while the referenced data pages hold
    full ``FibBlockDescriptor`` records with no header of their own.

    Returns the root page number of the sub table's table-of-pages chain.
    """
    num_data_pages = (count + FIB_ENTRIES_PER_DATA_PAGE - 1) // FIB_ENTRIES_PER_DATA_PAGE
    data_pages = [store.alloc_page() for _ in range(num_data_pages)]

    for data_idx, page_no in enumerate(data_pages):
        base = data_idx * FIB_ENTRIES_PER_DATA_PAGE
        capacity = min(FIB_ENTRIES_PER_DATA_PAGE, count - base)
        store.pages[page_no] = b"".join(
            encode_fib_descriptor(base + slot) for slot in range(capacity)
        ).ljust(PAGE_SIZE, b"\x00")

    # Allocate the whole table-of-pages chain in one contiguous, non-overlapping
    # span; its first page is the sub table root.
    num_table_pages = 1
    while sum(table_entries_on_page(i) for i in range(num_table_pages)) < num_data_pages:
        num_table_pages += 1
    table_pages = [store.alloc_page() for _ in range(num_table_pages)]
    flat_idx = 0
    for table_idx, table_page in enumerate(table_pages):
        capacity = table_entries_on_page(table_idx)
        pointers = []
        for slot in range(capacity):
            pointers.append(data_pages[flat_idx + slot] if flat_idx + slot < num_data_pages else -1)
        flat_idx += capacity

        next_page = table_pages[table_idx + 1] if table_idx + 1 < num_table_pages else -1
        if table_idx == 0:
            header = struct.pack("<qq", next_page, table_pages[0])
        elif table_idx % 3 == 1:
            header = struct.pack(
                "<qqqq",
                next_page,
                table_pages[table_idx],
                table_pages[table_idx + 1] if table_idx + 1 < num_table_pages else -1,
                table_pages[table_idx + 2] if table_idx + 2 < num_table_pages else -1,
            )
        else:
            header = struct.pack("<q", next_page)
        store.pages[table_page] = (header + struct.pack(f"<{capacity}q", *pointers)).ljust(PAGE_SIZE, b"\x00")

    return table_pages[0]


def _build_sparse_store(num_sub_tables: int) -> tuple[SyntheticVBK, int]:
    """Build a sparse table whose outer descriptor vector is a MetaVector2.

    The outer MetaVector2 maps one table slot to one data page holding
    ``MetaTableDescriptor`` records. Only the first ``num_sub_tables`` slots are
    populated; each opens a sub table of marked ``FibBlockDescriptor`` pages.
    """
    entries_per_sub_table = FibMetaSparseTable.MAX_ENTRIES_PER_TABLE
    total = entries_per_sub_table * num_sub_tables

    store = SyntheticVBK(num_table_pages=4)

    sub_table_roots: list[int] = []
    for _ in range(num_sub_tables):
        sub_table_roots.append(_build_sub_table_chain(store, entries_per_sub_table))

    # Pack the sub table descriptors into data pages; one descriptor data page
    # holds TABLE_ENTRIES_PER_DATA_PAGE MetaTableDescriptor records.
    num_descriptor_pages = (
        num_sub_tables + TABLE_ENTRIES_PER_DATA_PAGE - 1
    ) // TABLE_ENTRIES_PER_DATA_PAGE
    descriptor_pages = [store.alloc_page() for _ in range(num_descriptor_pages)]
    for page_idx, page_no in enumerate(descriptor_pages):
        buf = bytearray(PAGE_SIZE)
        base = page_idx * TABLE_ENTRIES_PER_DATA_PAGE
        for slot in range(TABLE_ENTRIES_PER_DATA_PAGE):
            sub_idx = base + slot
            if sub_idx >= num_sub_tables:
                break
            record = c_vbk.MetaTableDescriptor(
                RootPage=sub_table_roots[sub_idx],
                BlockSize=PAGE_SIZE,
                Count=entries_per_sub_table,
            ).dumps()
            buf[slot * TABLE_ENTRY_SIZE : (slot + 1) * TABLE_ENTRY_SIZE] = record
        store.pages[page_no] = bytes(buf)

    # Each outer table slot references one descriptor data page.
    flat_idx = 0
    for table_idx, table_page in enumerate(store.table_pages):
        capacity = store.capacities[table_idx]
        pointers = []
        for slot in range(capacity):
            descriptor_page_idx = (flat_idx + slot) // TABLE_ENTRIES_PER_DATA_PAGE
            pointers.append(
                descriptor_pages[descriptor_page_idx]
                if descriptor_page_idx < num_descriptor_pages
                else -1
            )
        flat_idx += capacity

        next_page = store.table_pages[table_idx + 1] if table_idx + 1 < store.num_table_pages else -1
        if table_idx == 0:
            header = struct.pack("<qq", next_page, store.table_pages[0])
        elif table_idx % 3 == 1:
            header = struct.pack(
                "<qqqq",
                next_page,
                store.table_pages[table_idx],
                store.table_pages[table_idx + 1] if table_idx + 1 < store.num_table_pages else -1,
                store.table_pages[table_idx + 2] if table_idx + 2 < store.num_table_pages else -1,
            )
        else:
            header = struct.pack("<q", next_page)
        store.pages[table_page] = (header + struct.pack(f"<{capacity}q", *pointers)).ljust(PAGE_SIZE, b"\x00")

    return store, total


def test_fib_meta_sparse_table_resolves_every_descriptor() -> None:
    num_sub_tables = 3
    store, total = _build_sparse_store(num_sub_tables)
    table = FibMetaSparseTable(store, store.table_pages[0], total)

    check_indices = [
        0,
        1,
        FibMetaSparseTable.MAX_ENTRIES_PER_TABLE - 1,
        FibMetaSparseTable.MAX_ENTRIES_PER_TABLE,
        FibMetaSparseTable.MAX_ENTRIES_PER_TABLE + 7,
        2 * FibMetaSparseTable.MAX_ENTRIES_PER_TABLE - 1,
        total - 1,
    ]
    for logical_idx in reversed(check_indices):
        descriptor = table.get(logical_idx)
        magic, local_idx = decode_marker(descriptor.buf)
        assert magic == MARKER_MAGIC
        # Markers are local to each sub table, so each sub table restarts at 0.
        assert local_idx == logical_idx % FibMetaSparseTable.MAX_ENTRIES_PER_TABLE

    # Cached re-visit must return the same descriptor, never a decoy.
    cached = table.get(total - 1)
    assert decode_marker(cached.buf) == (
        MARKER_MAGIC,
        (total - 1) % FibMetaSparseTable.MAX_ENTRIES_PER_TABLE,
    )

    with pytest.raises(IndexError):
        table.get(-1)
    with pytest.raises(IndexError):
        table.get(total)


def test_fib_meta_sparse_table_back_link_is_rejected() -> None:
    num_sub_tables = 2
    store, total = _build_sparse_store(num_sub_tables)
    store.link_back(table_idx=2, target_table_idx=0)

    with pytest.raises(VBKError, match="Circular meta blob page chain"):
        FibMetaSparseTable(store, store.table_pages[0], total).get(0)


def test_directory_read_path_uses_sparse_table() -> None:
    """Exercise the same public read path an opened internal file relies on.

    ``FibStream._read`` resolves every block through ``FibMetaSparseTable.get``,
    so driving that entry point covers the directory/open-file read path.
    """
    num_sub_tables = 2
    store, total = _build_sparse_store(num_sub_tables)

    table = FibMetaSparseTable(store, store.table_pages[0], total)
    stream_like = BytesIO()
    for block_idx in (0, total // 2, total - 1):
        descriptor = table.get(block_idx)
        assert descriptor.is_normal()
        stream_like.write(descriptor.buf)

    assert stream_like.tell() == 3 * FIB_ENTRY_SIZE
