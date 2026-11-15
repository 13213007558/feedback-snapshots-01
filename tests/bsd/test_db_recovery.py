"""Tests for recovering corrupted Berkeley DB files.

Each record gets its own distinct marker so tests can prove that corrupted
records never borrow bytes from their neighbours and that unaffected records
are still parsed correctly.
"""

from __future__ import annotations

import io
import struct
from typing import BinaryIO

import pytest

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.db import DB
from dissect.database.bsd.exception import InvalidEntryError

PAGE_SIZE = 512
OVERHEAD = 26  # SIZEOF_PAGE
OVERFLOW_CAPACITY = PAGE_SIZE - OVERHEAD


def header(pgno: int, ptype: int, entries: int, hf_offset: int, next_pgno: int = 0) -> bytes:
    return struct.pack("<IIIIIHHBB", 0, 0, pgno, 0, next_pgno, entries, hf_offset, 1, ptype)


def leaf_page(pgno: int, ptype: int, items: list[bytes], next_pgno: int = 0) -> bytes:
    """Build a hash/btree leaf page. Item 0 ends up at the highest page offset."""
    page = bytearray(PAGE_SIZE)
    cursor = PAGE_SIZE
    offsets = []
    for item in items:
        cursor -= len(item)
        page[cursor : cursor + len(item)] = item
        offsets.append(cursor)
    page[:OVERHEAD] = header(pgno, ptype, len(items), cursor, next_pgno)
    struct.pack_into(f"<{len(offsets)}H", page, OVERHEAD, *offsets)
    return bytes(page)


def overflow_page(pgno: int, data: bytes, next_pgno: int = 0) -> bytes:
    page = bytearray(PAGE_SIZE)
    page[:OVERHEAD] = header(pgno, c_db.P_OVERFLOW, 0, len(data), next_pgno)
    page[OVERHEAD : OVERHEAD + len(data)] = data
    return bytes(page)


def hkeydata(data: bytes) -> bytes:
    return bytes([c_db.H_KEYDATA]) + data


def hoffpage(pgno: int, tlen: int) -> bytes:
    return struct.pack("<B3xII", c_db.H_OFFPAGE, pgno, tlen)


def bkeydata(data: bytes, claimed_len: int | None = None) -> bytes:
    return struct.pack("<HB", len(data) if claimed_len is None else claimed_len, c_db.B_KEYDATA) + data


def boverflow(pgno: int, tlen: int) -> bytes:
    return struct.pack("<HBBII", 0, c_db.B_OVERFLOW, 0, pgno, tlen)


def meta_page(magic: int, ptype: int, last_pgno: int) -> bytearray:
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<I", page, 12, magic)
    struct.pack_into("<I", page, 16, 9)  # version
    struct.pack_into("<I", page, 20, PAGE_SIZE)
    struct.pack_into("<B", page, 25, ptype)
    struct.pack_into("<I", page, 32, last_pgno)
    return page


def hash_meta(last_pgno: int, max_bucket: int = 0, spares: list[int] | None = None) -> bytes:
    page = meta_page(c_db.DB_HASHMAGIC, c_db.P_HASHMETA, last_pgno)
    struct.pack_into("<I", page, 72, max_bucket)
    struct.pack_into("<32I", page, 96, *(spares or [1] + [0] * 31))
    return bytes(page)


def btree_meta(last_pgno: int, root: int) -> bytes:
    page = meta_page(c_db.DB_BTREEMAGIC, c_db.P_BTREEMETA, last_pgno)
    struct.pack_into("<I", page, 88, root)
    return bytes(page)


def build_db(meta: bytes, pages: dict[int, bytes]) -> bytes:
    buf = bytearray((max(pages) + 1) * PAGE_SIZE)
    buf[:PAGE_SIZE] = meta
    for pgno, page in pages.items():
        buf[pgno * PAGE_SIZE : (pgno + 1) * PAGE_SIZE] = page
    return bytes(buf)


# Distinct markers per record: key-N / val-N, long values span overflow pages
KEYS = [f"key-{i:02d}".encode() for i in range(4)]
VALS = [f"val-{i:02d}".encode() for i in range(4)]
LONG_KEY = b"key-01-" + b"K" * 300
LONG_VAL = b"val-02-" + b"V" * (OVERFLOW_CAPACITY + 100)


def build_hash_db(*, chain_next: int = 5, odd: bool = False) -> bytes:
    """Hash database with a bucket chain spanning two pages.

    Page 1: record 0 (inline), record 1 (key-only overflow on page 3)
    Page 2: record 2 (value-only overflow chained over pages 4 and 5)
    """
    items_page1 = [
        hkeydata(KEYS[0]),
        hkeydata(VALS[0]),
        hoffpage(3, len(LONG_KEY)),
        hkeydata(VALS[1]),
    ]
    items_page2 = [
        hkeydata(KEYS[2]),
        hoffpage(4, len(LONG_VAL)),
    ]
    if odd:
        items_page2.append(hkeydata(KEYS[3]))
    return build_db(
        hash_meta(last_pgno=5),
        {
            1: leaf_page(1, c_db.P_HASH, items_page1, next_pgno=2),
            2: leaf_page(2, c_db.P_HASH, items_page2),
            3: overflow_page(3, LONG_KEY),
            4: overflow_page(4, LONG_VAL[:OVERFLOW_CAPACITY], next_pgno=chain_next),
            5: overflow_page(5, LONG_VAL[OVERFLOW_CAPACITY:]),
        },
    )


def build_btree_db(*, corrupt_key_len: bool = False, odd: bool = False, value_tlen: int | None = None) -> bytes:
    """Btree database with a single leaf page. Record 1 has a value-only overflow on page 2."""
    long_val = LONG_VAL[:600]
    items = [
        bkeydata(KEYS[0]),
        bkeydata(VALS[0]),
        bkeydata(KEYS[1], claimed_len=400 if corrupt_key_len else None),
        boverflow(2, len(long_val) if value_tlen is None else value_tlen),
        bkeydata(KEYS[2]),
        bkeydata(VALS[2]),
    ]
    if odd:
        items.append(bkeydata(KEYS[3]))
    return build_db(
        btree_meta(last_pgno=3, root=1),
        {
            1: leaf_page(1, c_db.P_LBTREE, items),
            2: overflow_page(2, long_val[:OVERFLOW_CAPACITY], next_pgno=3),
            3: overflow_page(3, long_val[OVERFLOW_CAPACITY:]),
        },
    )


def db(data: bytes | BinaryIO, recover: bool = True) -> DB:
    if isinstance(data, (bytes, bytearray)):
        data = io.BytesIO(data)
    return DB(data, recover=recover)


def test_hash_chain_across_pages() -> None:
    """A bucket chain spanning pages parses all records, including key-only and value-only overflow."""
    records = list(db(build_hash_db()).records())
    assert records == [(KEYS[0], VALS[0]), (LONG_KEY, VALS[1]), (KEYS[2], LONG_VAL)]

    candidates = list(db(build_hash_db()).iter_records())
    assert all(r.complete for r in candidates)
    assert [(r.pgno, r.slot) for r in candidates] == [(1, 0), (1, 2), (2, 0)]


def test_hash_odd_entry_count() -> None:
    """An odd trailing item is reported with its page and slot, pairing of other records is untouched."""
    records = list(db(build_hash_db(odd=True)).records())
    assert records == [(KEYS[0], VALS[0]), (LONG_KEY, VALS[1]), (KEYS[2], LONG_VAL)]

    candidates = list(db(build_hash_db(odd=True)).iter_records())
    assert len(candidates) == 4
    dangling = candidates[3]
    assert not dangling.complete
    assert dangling.pgno == 2
    assert dangling.slot == 2
    assert dangling.key == KEYS[3]
    assert dangling.data is None
    assert any("unpaired" in error for error in dangling.errors)


def test_hash_truncated_file() -> None:
    """A truncated overflow chain reports the record with its own partial data only."""
    data = build_hash_db()[: 5 * PAGE_SIZE]  # drop the last overflow page
    records = list(db(data).records())
    assert records == [(KEYS[0], VALS[0]), (LONG_KEY, VALS[1])]

    (broken,) = (r for r in db(data).iter_records() if not r.complete)
    assert broken.pgno == 2
    assert broken.slot == 0
    assert broken.key == KEYS[2]
    # Partial data consists of the record's own overflow chain bytes, nothing borrowed
    assert broken.data == LONG_VAL[:OVERFLOW_CAPACITY]
    assert VALS[0] not in broken.data and VALS[1] not in broken.data


@pytest.mark.parametrize(
    ("chain_next", "reason"),
    [
        (1, "expected overflow page"),  # points at a hash page
        (0, "chain ended"),  # PGNO_INVALID before tlen is satisfied
        (4, "cycle detected"),  # points at itself
    ],
)
def test_hash_broken_overflow_chain(chain_next: int, reason: str) -> None:
    """A broken overflow chain is located to the original record and never borrows neighbour bytes."""
    records = list(db(build_hash_db(chain_next=chain_next)).records())
    assert records == [(KEYS[0], VALS[0]), (LONG_KEY, VALS[1])]

    (broken,) = (r for r in db(build_hash_db(chain_next=chain_next)).iter_records() if not r.complete)
    assert broken.pgno == 2
    assert broken.slot == 0
    assert broken.key == KEYS[2]
    assert broken.data == LONG_VAL[:OVERFLOW_CAPACITY]
    assert any(reason in error for error in broken.errors)


def test_btree_leaf_corrupt_key() -> None:
    """A corrupted key item on a btree leaf page only affects its own record."""
    records = list(db(build_btree_db(corrupt_key_len=True)).records())
    assert records == [(KEYS[0], VALS[0]), (KEYS[2], VALS[2])]

    (broken,) = (r for r in db(build_btree_db(corrupt_key_len=True)).iter_records() if not r.complete)
    assert broken.pgno == 1
    assert broken.slot == 2
    assert broken.key is None
    # The record's own value is still reported, but nothing from the neighbours
    assert broken.data == LONG_VAL[:600]


def test_btree_leaf_odd_entry_count() -> None:
    """An odd item on a btree leaf page leaves the pairing of the other records intact."""
    records = list(db(build_btree_db(odd=True)).records())
    assert records == [(KEYS[0], VALS[0]), (KEYS[1], LONG_VAL[:600]), (KEYS[2], VALS[2])]

    candidates = list(db(build_btree_db(odd=True)).iter_records())
    dangling = candidates[3]
    assert not dangling.complete
    assert (dangling.pgno, dangling.slot) == (1, 6)
    assert dangling.key == KEYS[3]
    assert dangling.data is None


def test_btree_leaf_short_overflow_chain() -> None:
    """An overflow chain shorter than the announced length is incomplete, not padded."""
    value_tlen = len(LONG_VAL[:600]) + 100
    records = list(db(build_btree_db(value_tlen=value_tlen)).records())
    assert records == [(KEYS[0], VALS[0]), (KEYS[2], VALS[2])]

    (broken,) = (r for r in db(build_btree_db(value_tlen=value_tlen)).iter_records() if not r.complete)
    assert (broken.pgno, broken.slot) == (1, 2)
    assert broken.key == KEYS[1]
    assert broken.data == LONG_VAL[:600]
    assert len(broken.data) < value_tlen


def test_strict_mode_raises_with_page_and_slot() -> None:
    """Strict mode raises an error that locates the corrupted record by page and slot."""
    with pytest.raises(InvalidEntryError) as excinfo:
        list(db(build_hash_db(odd=True), recover=False).records())
    assert excinfo.value.pgno == 2
    assert excinfo.value.index == 2
    assert "page 2 slot 2" in str(excinfo.value)


def test_source_file_is_only_read() -> None:
    """Parsing never writes to the source file object."""
    written = []

    class Guard(io.BytesIO):
        def write(self, data: bytes) -> int:
            written.append(data)
            raise AssertionError("source file must stay read-only")

    healthy = build_hash_db()
    assert list(db(healthy).records()) == list(db(Guard(healthy)).records())
    assert written == []

    corrupted = build_hash_db(odd=True)
    assert list(db(corrupted).records()) == list(db(Guard(corrupted)).records())
    assert written == []


def test_iter_records_healthy_fixtures(btree_db: BinaryIO, hash_db: BinaryIO) -> None:
    """All records of the healthy fixture databases are complete candidates."""
    for fh in (btree_db, hash_db):
        candidates = list(DB(fh).iter_records())
        assert candidates
        assert all(r.complete for r in candidates)
        assert all(r.pgno is not None and r.slot is not None for r in candidates)
