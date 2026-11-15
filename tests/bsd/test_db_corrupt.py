from __future__ import annotations

import struct
from io import BytesIO

import pytest

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.db import DB, overflow_data

PAGE_SIZE = 512
PAGE_OVERHEAD = len(c_db.PAGE)

MARKER_KEYS = [f"key-{i:02d}-MARKER".encode() for i in range(12)]
MARKER_VALUES = [f"value-{i:02d}-MARKER".encode() for i in range(12)]


def _pack_page(page_type: int, level: int, items: list[bytes]) -> bytes:
    page = bytearray(PAGE_SIZE)
    index = []
    offset = PAGE_SIZE
    for item in items:
        offset -= len(item)
        page[offset : offset + len(item)] = item
        index.append(offset)

    header = c_db.PAGE()
    header.entries = len(items)
    header.hf_offset = offset
    header.level = level
    header.type = page_type
    page[:PAGE_OVERHEAD] = bytes(header)
    struct.pack_into(f"<{len(index)}H", page, PAGE_OVERHEAD, *index)
    return bytes(page)


def _set_header(page: bytes, **kwargs: int) -> bytes:
    page = bytearray(page)
    header = c_db.PAGE(page)
    for key, value in kwargs.items():
        setattr(header, key, value)
    page[:PAGE_OVERHEAD] = bytes(header)
    return bytes(page)


def _set_byte(page: bytes, offset: int, value: int) -> bytes:
    page = bytearray(page)
    page[offset] = value
    return bytes(page)


def _hash_item(data: bytes) -> bytes:
    return bytes([c_db.H_KEYDATA]) + data


def _hash_overflow(pgno: int, length: int) -> bytes:
    entry = c_db.HOFFPAGE()
    entry.type = c_db.H_OFFPAGE
    entry.pgno = pgno
    entry.tlen = length
    return bytes(entry)


def _btree_item(data: bytes, type_: int = c_db.B_KEYDATA) -> bytes:
    entry = c_db.BKEYDATA()
    entry.len = len(data)
    entry.type = type_
    return bytes(entry) + data


def _btree_internal(pgno: int, nrecs: int, key: bytes = b"") -> bytes:
    entry = c_db.BINTERNAL()
    entry.len = len(key)
    entry.type = c_db.B_KEYDATA
    entry.pgno = pgno
    entry.nrecs = nrecs
    return bytes(entry) + key


def _btree_overflow(pgno: int, length: int) -> bytes:
    entry = c_db.BOVERFLOW()
    entry.type = c_db.B_OVERFLOW
    entry.pgno = pgno
    entry.tlen = length
    return bytes(entry)


def _overflow_pages(data: bytes) -> list[bytes]:
    pages = []
    for start in range(0, len(data), PAGE_SIZE - PAGE_OVERHEAD):
        chunk = data[start : start + (PAGE_SIZE - PAGE_OVERHEAD)]
        header = c_db.PAGE()
        header.pgno = 0
        header.entries = 1
        header.hf_offset = len(chunk)
        header.type = c_db.P_OVERFLOW
        page = bytearray(PAGE_SIZE)
        page[:PAGE_OVERHEAD] = bytes(header)
        page[PAGE_OVERHEAD : PAGE_OVERHEAD + len(chunk)] = chunk
        pages.append(bytes(page))
    return pages


def _hash_meta(max_bucket: int) -> bytes:
    meta = c_db.HMETA()
    meta.dbmeta.magic = c_db.DB_HASHMAGIC
    meta.dbmeta.version = c_db.DB_HASHVERSION
    meta.dbmeta.pagesize = PAGE_SIZE
    meta.dbmeta.type = c_db.P_HASHMETA
    meta.dbmeta.flags = 0
    meta.max_bucket = max_bucket
    meta.high_mask = 0
    meta.low_mask = 0
    meta.spares = [1, 1, 2, 3, 5, 8, 0, 0, 0, 0] + [0] * 22
    return bytes(meta)


def _hash_db(pages: list[bytes], max_bucket: int = 0) -> BytesIO:
    return BytesIO(b"".join([_hash_meta(max_bucket), *pages]))


def _btree_meta(root: int, recno: bool = False) -> bytes:
    meta = c_db.BTMETA()
    meta.dbmeta.magic = c_db.DB_BTREEMAGIC
    meta.dbmeta.version = c_db.DB_BTREEVERSION
    meta.dbmeta.pagesize = PAGE_SIZE
    meta.dbmeta.type = c_db.P_BTREEMETA
    meta.dbmeta.flags = c_db.BTM_RECNO if recno else 0
    meta.root = root
    return bytes(meta)


def _btree_db(root: int, pages: list[bytes], recno: bool = False) -> BytesIO:
    return BytesIO(b"".join([_btree_meta(root, recno), *pages]))


def _hash_records(pairs: list[tuple[bytes, bytes]]) -> tuple[bytes, list[bytes]]:
    items = []
    pages = []
    for key, value in pairs:
        items.append(_hash_item(key))
        items.append(_hash_item(value))
    pages.append(_pack_page(c_db.P_HASH, 0, items[:8]))
    pages[0] = _set_header(pages[0], pgno=1, next_pgno=2 if len(items) > 8 else 0)
    if len(items) > 8:
        pages.append(_pack_page(c_db.P_HASH, 0, items[8:]))
        pages[1] = _set_header(pages[1], pgno=2)
    return _hash_db(pages), pages


def _slot_offset(page: bytes, slot: int) -> int:
    return struct.unpack_from("<H", page, PAGE_OVERHEAD + slot * 2)[0]


def _corrupt_marker_page(pairs: list[tuple[bytes, bytes]], index: int, page: bytes) -> bytes:
    return _set_byte(page, _slot_offset(page, index * 2), 0xFF)


def _btree_pairs(pairs: list[tuple[bytes, bytes]]) -> tuple[int, list[bytes]]:
    items = []
    for key, value in pairs:
        items.append(_btree_item(key))
        items.append(_btree_item(value))
    leaf = _set_header(_pack_page(c_db.P_LBTREE, 1, items), pgno=1)
    return 1, [leaf]


def test_hash_chain_cross_page_pairs() -> None:
    """Hash chains that continue on another page keep key/value pairing intact."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(8)]
    db = DB(_hash_db(_hash_records(pairs)[1]))
    records = list(db.iter_records())

    assert [(r.key, r.value) for r in records] == pairs
    assert all(r.complete for r in records)
    assert all(r.key_location.pgno in (1, 2) for r in records)
    assert len({r.key_location.pgno for r in records}) == 2


def test_hash_each_marker_is_independent() -> None:
    """Corrupting one marker never shifts later key/value pairs."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(10)]
    _, pages = _hash_records(pairs)

    for index in range(10):
        target_page = pages[0] if index < 4 else pages[1]
        local_index = index if index < 4 else index - 4
        corrupted = _corrupt_marker_page(pairs, local_index, target_page)
        db = DB(_hash_db([corrupted, pages[1]])) if index < 4 else DB(_hash_db([pages[0], corrupted]))

        records = list(db.iter_records(recover=True))
        assert len(records) == len(pairs)

        for i, (record, (key, value)) in enumerate(zip(records, pairs, strict=True)):
            if i == index:
                assert not record.complete
                assert record.key_page is not None
                assert record.key_slot is not None
            else:
                assert record.complete
                assert record.key == key
                assert record.value == value


def test_hash_odd_slot_isolated_to_its_page() -> None:
    """An odd number of slots must not borrow a key from the next page."""
    pairs = [(MARKER_KEYS[0], MARKER_VALUES[0]), (MARKER_KEYS[1], MARKER_VALUES[1])]
    first = _pack_page(c_db.P_HASH, 0, [_hash_item(pairs[0][0]), _hash_item(pairs[0][1])])
    second = _pack_page(c_db.P_HASH, 0, [_hash_item(pairs[1][0])])
    db = DB(_hash_db([_set_header(first, pgno=1, next_pgno=2), _set_header(second, pgno=2)]))

    records = list(db.iter_records(recover=True))
    assert [(r.key, r.value, r.complete) for r in records] == [
        (pairs[0][0], pairs[0][1], True),
        (pairs[1][0], b"", False),
    ]
    assert records[1].key_slot == 0
    assert any(issue.kind == "orphan-key" and issue.slot == 0 for issue in db.issues)
    assert list(db.records()) == [pairs[0]]


def test_hash_key_overflow_only() -> None:
    """A key can use overflow while its value stays on the page."""
    pair = (MARKER_KEYS[0], MARKER_VALUES[0])
    overflow_pages = _overflow_pages(b"K" * 900)
    first_overflow = 2
    for i, page in enumerate(overflow_pages, first_overflow):
        next_pgno = i + 1 if i < first_overflow + len(overflow_pages) - 1 else 0
        overflow_pages[i - first_overflow] = _set_header(page, pgno=i, next_pgno=next_pgno)

    data_page = _pack_page(c_db.P_HASH, 0, [_hash_overflow(first_overflow, 900), _hash_item(pair[1])])
    db = DB(_hash_db([_set_header(data_page, pgno=1), *overflow_pages]))

    [record] = list(db.iter_records())
    assert record.key == b"K" * 900
    assert record.value == pair[1]
    assert record.complete
    assert record.key_location.slot == 0
    assert record.value_location.slot == 1


def test_hash_value_overflow_only() -> None:
    """A value can use overflow while its key stays on the page."""
    pair = (MARKER_KEYS[0], b"V" * 900)
    overflow_pages = _overflow_pages(pair[1])
    first_overflow = 2
    for i in range(len(overflow_pages)):
        pgno = first_overflow + i
        next_pgno = pgno + 1 if i < len(overflow_pages) - 1 else 0
        overflow_pages[i] = _set_header(overflow_pages[i], pgno=pgno, next_pgno=next_pgno)

    data_page = _pack_page(c_db.P_HASH, 0, [_hash_item(pair[0]), _hash_overflow(first_overflow, 900)])
    db = DB(_hash_db([_set_header(data_page, pgno=1), *overflow_pages]))

    [record] = list(db.iter_records())
    assert record.key == pair[0]
    assert record.value == pair[1]
    assert record.complete
    assert record.value_location.slot == 1


def test_hash_broken_overflow_chain_reports_owner() -> None:
    """A broken overflow chain yields only its proven prefix and points at its slot."""
    pairs = [(MARKER_KEYS[0], b"V" * 900), (MARKER_KEYS[1], MARKER_VALUES[1])]
    overflow_pages = _overflow_pages(pairs[0][1])
    first_overflow = 2
    overflow_pages[0] = _set_header(overflow_pages[0], pgno=first_overflow, next_pgno=0)

    data_page = _pack_page(
        c_db.P_HASH,
        0,
        [
            _hash_item(pairs[0][0]),
            _hash_overflow(first_overflow, 900),
            _hash_item(pairs[1][0]),
            _hash_item(pairs[1][1]),
        ],
    )
    db = DB(_hash_db([_set_header(data_page, pgno=1), *overflow_pages]))

    records = list(db.iter_records(recover=True))
    assert len(records) == 2

    broken, intact = records
    assert not broken.complete
    assert broken.pgno == 1
    assert broken.slot == 0
    assert broken.key == pairs[0][0]
    assert broken.value == pairs[0][1][: PAGE_SIZE - PAGE_OVERHEAD]
    assert (intact.key, intact.value, intact.complete) == (*pairs[1], True)

    assert any(issue.kind == "overflow-chain-truncated" and issue.pgno == 1 and issue.slot == 1 for issue in db.issues)


def test_hash_truncated_overflow_page_does_not_borrow_next_chain() -> None:
    """A short overflow page must not be filled from the following item's bytes."""
    pairs = [(MARKER_KEYS[0], b"V" * 2000), (MARKER_KEYS[1], b"W" * 2000)]
    first_overflow = 2
    first_pages = _overflow_pages(pairs[0][1])
    second_pages = _overflow_pages(pairs[1][1])
    second_start = first_overflow + len(first_pages)
    for i in range(len(first_pages)):
        pgno = first_overflow + i
        next_pgno = pgno + 1 if i < len(first_pages) - 1 else 0
        first_pages[i] = _set_header(first_pages[i], pgno=pgno, next_pgno=next_pgno)
    for i in range(len(second_pages)):
        pgno = second_start + i
        next_pgno = pgno + 1 if i < len(second_pages) - 1 else 0
        second_pages[i] = _set_header(second_pages[i], pgno=pgno, next_pgno=next_pgno)

    data_page = _pack_page(
        c_db.P_HASH,
        0,
        [
            _hash_item(pairs[0][0]),
            _hash_overflow(first_overflow, len(pairs[0][1])),
            _hash_item(pairs[1][0]),
            _hash_overflow(second_start, len(pairs[1][1])),
        ],
    )
    db = DB(_hash_db([_set_header(data_page, pgno=1), *first_pages, *second_pages], max_bucket=0))

    records = list(db.iter_records(recover=True))
    assert len(records) == 2
    assert records[0].complete
    assert records[1].complete
    assert records[0].value == pairs[0][1]
    assert records[1].value == pairs[1][1]
    assert records[0].value != records[1].value


def test_btree_leaf_each_marker_is_independent() -> None:
    """Corrupting one btree leaf slot does not shift any later pair."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(6)]
    root, pages = _btree_pairs(pairs)
    leaf = pages[0]

    for index in range(6):
        slot = index * 2
        offset = _slot_offset(leaf, slot)
        corrupted = _set_byte(leaf, offset + 2, c_db.B_OVERFLOW)
        db = DB(_btree_db(root, [corrupted]))

        records = list(db.iter_records(recover=True))
        assert len(records) == len(pairs)
        for i, (record, (key, value)) in enumerate(zip(records, pairs, strict=True)):
            if i == index:
                assert not record.complete
                assert record.key_page == 1
                assert record.key_slot == slot
            else:
                assert record.complete
                assert (record.key, record.value) == (key, value)
        assert list(db.records()) == [pair for i, pair in enumerate(pairs) if i != index]


def test_btree_truncated_slot_isolated() -> None:
    """A btree slot whose declared length exceeds its space is reported in place."""
    pairs = [(MARKER_KEYS[0], MARKER_VALUES[0]), (MARKER_KEYS[1], MARKER_VALUES[1])]
    root, pages = _btree_pairs(pairs)
    leaf = pages[0]
    offset = _slot_offset(leaf, 3)
    corrupted = bytearray(leaf)
    struct.pack_into("<H", corrupted, offset, 200)
    db = DB(_btree_db(root, [bytes(corrupted)]))

    records = list(db.iter_records(recover=True))
    assert len(records) == 2
    assert records[0].complete
    assert (records[0].key, records[0].value) == pairs[0]
    assert not records[1].complete
    assert records[1].key == pairs[1][0]
    assert records[1].value == pairs[1][1]
    assert any(issue.kind == "truncated-entry" and issue.slot == 3 for issue in db.issues)


def test_btree_overflow_value_only() -> None:
    """A btree value can be stored entirely on overflow pages."""
    key = MARKER_KEYS[0]
    value = b"V" * 900
    overflow_pages = _overflow_pages(value)
    first_overflow = 2
    for i in range(len(overflow_pages)):
        pgno = first_overflow + i
        next_pgno = pgno + 1 if i < len(overflow_pages) - 1 else 0
        overflow_pages[i] = _set_header(overflow_pages[i], pgno=pgno, next_pgno=next_pgno)

    leaf = _set_header(
        _pack_page(c_db.P_LBTREE, 1, [_btree_item(key), _btree_overflow(first_overflow, len(value))]), pgno=1
    )
    db = DB(_btree_db(1, [leaf, *overflow_pages]))

    [record] = list(db.iter_records())
    assert record.key == key
    assert record.value == value
    assert record.complete
    assert record.value_location.slot == 1


def test_btree_overflow_key_only() -> None:
    """A btree key can be stored entirely on overflow pages."""
    key = b"K" * 900
    value = MARKER_VALUES[0]
    overflow_pages = _overflow_pages(key)
    first_overflow = 2
    for i in range(len(overflow_pages)):
        pgno = first_overflow + i
        next_pgno = pgno + 1 if i < len(overflow_pages) - 1 else 0
        overflow_pages[i] = _set_header(overflow_pages[i], pgno=pgno, next_pgno=next_pgno)

    leaf = _set_header(
        _pack_page(c_db.P_LBTREE, 1, [_btree_overflow(first_overflow, len(key)), _btree_item(value)]), pgno=1
    )
    db = DB(_btree_db(1, [leaf, *overflow_pages]))

    [record] = list(db.iter_records())
    assert record.key == key
    assert record.value == value
    assert record.complete
    assert record.key_location.slot == 0


def test_btree_broken_overflow_key_isolated() -> None:
    """A broken overflow key keeps the proven prefix and does not consume the value slot."""
    key = b"K" * 900
    value = MARKER_VALUES[0]
    overflow_pages = _overflow_pages(key)
    first_overflow = 2
    overflow_pages[0] = _set_header(overflow_pages[0], pgno=first_overflow, next_pgno=0)

    leaf = _set_header(
        _pack_page(c_db.P_LBTREE, 1, [_btree_overflow(first_overflow, len(key)), _btree_item(value)]), pgno=1
    )
    db = DB(_btree_db(1, [leaf, *overflow_pages]))

    [record] = list(db.iter_records(recover=True))
    assert not record.complete
    assert record.key == key[: PAGE_SIZE - PAGE_OVERHEAD]
    assert record.value == value
    assert record.key_slot == 0
    assert record.value_slot == 1
    assert any(issue.kind == "overflow-chain-truncated" and issue.slot == 0 for issue in db.issues)


def test_overflow_data_strict_and_partial() -> None:
    """The low level overflow helper returns the proven prefix or raises with it."""
    value = b"V" * 900
    pages = _overflow_pages(value)
    pages[0] = _set_header(pages[0], pgno=1, next_pgno=0)
    db = DB(_hash_db([_pack_page(c_db.P_HASH, 0, []), pages[0]]))

    partial = overflow_data(db, 2, len(value), strict=False)
    assert partial == value[: PAGE_SIZE - PAGE_OVERHEAD]

    with pytest.raises(ValueError, match="overflow-chain-truncated") as exc:
        overflow_data(db, 2, len(value))
    assert exc.value.partial == partial


def test_walk_is_read_only() -> None:
    """Walking a corrupt database must not modify the underlying file."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(4)]
    fh = _hash_db(_hash_records(pairs)[1])
    db_bytes = fh.getvalue()
    db = DB(fh)
    list(db.iter_records(recover=True))
    assert fh.getvalue() == db_bytes


def test_corrupt_marker_never_contains_neighbour_bytes() -> None:
    """A corrupt record's proven prefix must not contain any neighbour marker."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(8)]
    _, pages = _hash_records(pairs)
    leaf = pages[0]

    for index in range(4):
        slot = index * 2
        offset = _slot_offset(leaf, slot)
        corrupted = _set_byte(leaf, offset, 0xFF)
        db = DB(_hash_db([corrupted, pages[1]]))
        records = list(db.iter_records(recover=True))
        record = records[index]

        assert not record.complete
        for other_key, other_value in pairs:
            if other_key == pairs[index][0]:
                continue
            assert other_key not in record.key
            assert other_value not in record.value


def test_btree_corrupt_marker_never_contains_neighbour_bytes() -> None:
    """Same neighbour isolation check for a btree leaf page."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(6)]
    root, pages = _btree_pairs(pairs)
    leaf = pages[0]

    for index in range(6):
        slot = index * 2
        offset = _slot_offset(leaf, slot)
        corrupted = _set_byte(leaf, offset + 2, c_db.B_OVERFLOW)
        db = DB(_btree_db(root, [corrupted]))
        records = list(db.iter_records(recover=True))
        record = records[index]

        assert not record.complete
        for other_key, other_value in pairs:
            if other_key == pairs[index][0]:
                continue
            assert other_key not in record.key
            assert other_value not in record.value


def test_btree_internal_corruption_localizes_leaf() -> None:
    """A corrupt internal entry must not silently drop or shift unrelated leaves."""
    pairs_a = [(MARKER_KEYS[0], MARKER_VALUES[0]), (MARKER_KEYS[1], MARKER_VALUES[1])]
    pairs_b = [(MARKER_KEYS[2], MARKER_VALUES[2]), (MARKER_KEYS[3], MARKER_VALUES[3])]
    leaf_a = _set_header(
        _pack_page(
            c_db.P_LBTREE, 1, [item for pair in pairs_a for item in (_btree_item(pair[0]), _btree_item(pair[1]))]
        ),
        pgno=2,
    )
    leaf_b = _set_header(
        _pack_page(
            c_db.P_LBTREE, 1, [item for pair in pairs_b for item in (_btree_item(pair[0]), _btree_item(pair[1]))]
        ),
        pgno=3,
    )

    internal = _set_header(
        _pack_page(c_db.P_IBTREE, 2, [_btree_internal(2, len(pairs_a)), _btree_internal(3, len(pairs_b))]),
        pgno=1,
    )

    db = DB(_btree_db(1, [internal, leaf_a, leaf_b]))
    records = list(db.iter_records())
    assert [(r.key, r.value) for r in records] == [*pairs_a, *pairs_b]
    assert all(r.complete for r in records)

    corrupted = bytearray(internal)
    struct.pack_into("<I", corrupted, _slot_offset(internal, 1) + 4, 99)
    db = DB(_btree_db(1, [bytes(corrupted), leaf_a, leaf_b]))
    records = list(db.iter_records())
    assert [(r.key, r.value) for r in records] == pairs_a
    assert any(issue.kind == "invalid-child-page" and issue.slot == 1 for issue in db.issues)


def test_issues_available_after_partial_iteration() -> None:
    """Diagnostics collected before a generator is stopped remain available."""
    pairs = [(MARKER_KEYS[i], MARKER_VALUES[i]) for i in range(10)]
    _, pages = _hash_records(pairs)
    leaf = pages[0]
    offset = _slot_offset(leaf, 2)
    corrupted = _set_byte(leaf, offset, 0xFF)

    db = DB(_hash_db([corrupted, pages[1]]))
    iterator = db.iter_records(recover=True)

    first = next(iterator)
    assert first.complete
    second = next(iterator)
    assert not second.complete
    assert any(issue.kind == "unknown-entry-type" and issue.slot == 2 for issue in db.issues)

    iterator.close()


def test_recno_record_numbers_stable_under_corruption() -> None:
    """A corrupt RECNO payload keeps its record number and does not shift later numbers."""
    slots = [b"alpha", b"broken", b"gamma"]
    items = []
    for data in slots:
        entry = c_db.BKEYDATA()
        entry.len = len(data)
        entry.type = c_db.B_KEYDATA
        items.append(bytes(entry) + data)

    leaf = bytearray(_set_header(_pack_page(c_db.P_LRECNO, 1, items), pgno=1))
    broken_offset = _slot_offset(bytes(leaf), 1)
    struct.pack_into("<H", leaf, broken_offset, 0xDEAD)

    db = DB(_btree_db(1, [bytes(leaf)], recno=True))
    assert db.is_recno
    records = list(db.iter_records(recover=True))
    assert [(r.key, r.complete) for r in records] == [(1, True), (2, False), (3, True)]
    assert records[0].value == b"alpha"
    assert records[1].value == b"broken"
    assert b"gamma" not in records[1].value
    assert records[2].value == b"gamma"
    assert list(db.records()) == [(1, b"alpha"), (3, b"gamma")]

    # A corrupt slot keeps a stable record number, so later numbers do not shift.
    assert [record.key for record in records] == [1, 2, 3]


def test_truncated_page_does_not_mark_items_complete() -> None:
    """A file ending mid-page must not produce a "complete" record from clipped bytes."""
    pairs = [(MARKER_KEYS[0], MARKER_VALUES[0]), (MARKER_KEYS[1], MARKER_VALUES[1])]
    _, pages = _hash_records(pairs)
    page = pages[0]
    offset = _slot_offset(page, 1)
    truncated = page[: offset + 4]

    db = DB(BytesIO(_hash_meta(0) + truncated))
    records = list(db.iter_records(recover=True))

    # Items are stored from the end of the page downwards, so the first pair is
    # clipped while the second pair lies entirely inside the readable prefix.
    assert len(records) == 2
    assert not records[0].complete
    assert records[0].value == b"val"
    assert records[0].value == MARKER_VALUES[0][: len(records[0].value)]
    assert records[1].complete
    assert (records[1].key, records[1].value) == pairs[1]
    assert any(issue.kind == "truncated-page" and issue.pgno == 1 for issue in db.issues)
