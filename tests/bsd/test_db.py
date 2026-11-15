from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.db import DB


def _assert_wordlist(db: DB) -> None:
    for i, (key, data) in enumerate(sorted(db.records())):
        assert isinstance(key, bytes)
        assert isinstance(data, bytes)

        assert int(key[:4]) == i + 1
        assert key == data[::-1]


def test_btree(btree_db: BinaryIO) -> None:
    """Test ``DB_BTREE`` database."""
    db = DB(btree_db)
    assert db.is_btree

    _assert_wordlist(db)


def test_hash(hash_db: BinaryIO) -> None:
    """Test ``DB_HASH`` database."""
    db = DB(hash_db)
    assert db.is_hash

    _assert_wordlist(db)


def test_recno(recno_db: BinaryIO) -> None:
    """Test ``DB_RECNO`` database."""
    db = DB(recno_db)
    assert db.is_recno

    records = list(db.records())
    assert len(records) == 2
    assert records[0] == (42, b"thanks for all the fish")
    assert records[1] == (69, b"haha funny number")


RECNO_PAGE_SIZE = 512

# A small synthetic RECNO tree:
#   page 0: metadata, root = 1
#   page 1: internal page (P_IRECNO) pointing at leaf pages 2 and 3
#   page 2: leaf with deleted slots, including the consecutive deleted slots 2-3
#   page 3: leaf whose last live record (slot 10) is followed by trailing deleted slots
# Every slot, live or deleted, consumes a record number; only live slots are records.
RECNO_LEAF_A = [
    (False, b"alpha"),
    (True, b"residual-one"),
    (True, b"residual-two"),
    (False, b"bravo"),
    (True, b"residual-three"),
    (False, b"charlie"),
]
RECNO_LEAF_B = [
    (True, b"residual-four"),
    (False, b"delta"),
    (True, b"residual-five"),
    (False, b"echo"),
    (True, b"residual-six"),
    (True, b"residual-seven"),
]
RECNO_LEAVES = (RECNO_LEAF_A, RECNO_LEAF_B)


def _pack_page(page_type: int, level: int, items: list[bytes]) -> bytes:
    """Pack a page: header, index array, items stored from the end of the page downwards."""
    page = bytearray(RECNO_PAGE_SIZE)
    index = []
    offset = RECNO_PAGE_SIZE
    for item in items:
        offset -= len(item)
        page[offset : offset + len(item)] = item
        index.append(offset)

    header = c_db.PAGE()
    header.entries = len(items)
    header.hf_offset = offset
    header.level = level
    header.type = page_type
    page[: len(c_db.PAGE)] = bytes(header)
    struct.pack_into(f"<{len(index)}H", page, len(c_db.PAGE), *index)
    return bytes(page)


def _recno_leaf_page(slots: list[tuple[bool, bytes]]) -> bytes:
    items = []
    for deleted, data in slots:
        entry = c_db.BKEYDATA()
        entry.len = len(data)
        entry.type = c_db.B_KEYDATA | (c_db.B_DELETE if deleted else 0)
        items.append(bytes(entry) + data)
    return _pack_page(c_db.P_LRECNO, 1, items)


def _recno_internal_page(children: list[tuple[int, int]]) -> bytes:
    items = []
    for pgno, nrecs in children:
        entry = c_db.RINTERNAL()
        entry.pgno = pgno
        entry.nrecs = nrecs
        items.append(bytes(entry))
    return _pack_page(c_db.P_IRECNO, 2, items)


def _recno_meta_page(root: int, record_count: int) -> bytes:
    meta = c_db.BTMETA()
    meta.dbmeta.magic = c_db.DB_BTREEMAGIC
    meta.dbmeta.version = c_db.DB_BTREEVERSION
    meta.dbmeta.pagesize = RECNO_PAGE_SIZE
    meta.dbmeta.type = c_db.P_BTREEMETA
    meta.dbmeta.flags = c_db.BTM_RECNO
    meta.dbmeta.last_pgno = 3
    meta.dbmeta.record_count = record_count
    meta.root = root
    return bytes(meta)


def _recno_tree() -> BinaryIO:
    live_counts = [sum(not deleted for deleted, _ in leaf) for leaf in RECNO_LEAVES]
    return BytesIO(
        b"".join(
            [
                _recno_meta_page(root=1, record_count=sum(live_counts)),
                _recno_internal_page([(2, live_counts[0]), (3, live_counts[1])]),
                _recno_leaf_page(RECNO_LEAF_A),
                _recno_leaf_page(RECNO_LEAF_B),
            ]
        )
    )


def _expected_recno_records() -> list[tuple[int, bytes]]:
    """Expected records derived straight from the constructed page layout."""
    expected = []
    recno = 0
    for leaf in RECNO_LEAVES:
        for deleted, data in leaf:
            recno += 1
            if not deleted:
                expected.append((recno, data))
    return expected


def test_recno_stable_record_numbers() -> None:
    """Live records keep their on-disk slot number across deleted slots and leaf pages."""
    db = DB(_recno_tree())
    assert db.is_recno

    records = list(db.records())
    assert records == _expected_recno_records()

    # The last live record sits at slot 10; the trailing deleted slots 11-12
    # must neither yield records nor shift its number.
    slots = [slot for leaf in RECNO_LEAVES for slot in leaf]
    assert len(slots) == 12
    assert records[-1] == (10, b"echo")


def test_recno_deleted_slots_keep_provenance() -> None:
    """Deleted slots stay visible in the raw traversal so numbering gaps remain
    explainable, but their residual bytes are never promoted to live records.

    The two stages double as a diagnostic: a failure in stage 1 means the tree
    traversal is broken, a failure in stage 2 (with stage 1 passing) means the
    record-number recovery is broken.
    """
    db = DB(_recno_tree())
    slots = [slot for leaf in RECNO_LEAVES for slot in leaf]

    # Stage 1: traversal visits every slot in layout order, delete flags intact.
    entries = list(db._iter_db())
    assert len(entries) == len(slots)
    for (dbt, data), (deleted, slot_data) in zip(entries, slots):
        assert bool(dbt.type & c_db.B_DELETE) == deleted
        assert bytes(data) == slot_data

    # Stage 2: numbering maps each live slot to its 1-based slot number.
    records = list(db.records())
    assert [recno for recno, _ in records] == [i for i, (deleted, _) in enumerate(slots, 1) if not deleted]

    residual = {data for deleted, data in slots if deleted}
    assert residual.isdisjoint(data for _, data in records)


def test_recno_renumbering_counterexample() -> None:
    """Filtering first and renumbering afterwards misattributes every record after a gap."""
    db = DB(_recno_tree())
    records = list(db.records())

    renumbered = list(enumerate((data for _, data in records), 1))
    assert renumbered != records

    # The last live record would be reported as 5 instead of its stable number 10,
    # and every investigation reference into slots 2-3, 5, 7, 9 would silently
    # resolve to the wrong record.
    assert renumbered[-1] == (5, b"echo")
    assert records[-1] == (10, b"echo")
