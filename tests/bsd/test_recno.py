from __future__ import annotations

import io
import struct
from typing import NamedTuple

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.db import DB

PAGE_SIZE = 512
PAGE_HEADER_SIZE = 26


class SlotSpec(NamedTuple):
    """A physical slot as it is written to a RECNO leaf page."""

    data: bytes
    deleted: bool = False


class LeafSpec(NamedTuple):
    """A leaf page in the synthetic tree, with the record count its parent declares."""

    pgno: int
    nrecs: int
    slots: tuple[SlotSpec, ...] = ()
    readable: bool = True


def _page(pgno: int, page_type: int, level: int, items: list[bytes]) -> bytes:
    body = bytearray(PAGE_SIZE)
    offsets = []
    offset = PAGE_SIZE
    for item in items:
        offset -= len(item)
        body[offset : offset + len(item)] = item
        offsets.append(offset)

    struct.pack_into("<QIIIHHBB", body, 0, 0, pgno, 0, 0, len(items), offset, level, page_type)
    for index, item_offset in enumerate(offsets):
        struct.pack_into("<H", body, PAGE_HEADER_SIZE + index * 2, item_offset)

    return bytes(body)


def _bkeydata(slot: SlotSpec) -> bytes:
    slot_type = c_db.B_KEYDATA | (c_db.B_DELETE if slot.deleted else 0)
    return struct.pack("<HB", len(slot.data), slot_type) + slot.data


def _build_recno(leaves: list[LeafSpec]) -> bytes:
    """Build a RECNO database with an internal root page and the given leaves.

    The root page stores each leaf's declared record count in its ``RINTERNAL`` entry. An
    unreadable leaf is still present in the file as a zero-filled page, so the tree layout stays
    intact while the page itself cannot be parsed.
    """
    dbmeta = c_db.DBMETA(
        magic=c_db.DB_BTREEMAGIC,
        version=c_db.DB_BTREEVERSION,
        pagesize=PAGE_SIZE,
        type=c_db.P_BTREEMETA,
        last_pgno=max(leaf.pgno for leaf in leaves),
        flags=c_db.BTM_RECNO,
    )
    meta = c_db.BTMETA(dbmeta=dbmeta, root=1).dumps().ljust(PAGE_SIZE, b"\x00")
    root = _page(1, c_db.P_IRECNO, 2, [struct.pack("<II", leaf.pgno, leaf.nrecs) for leaf in leaves])

    pages = [meta, root]
    for leaf in leaves:
        if leaf.readable:
            pages.append(_page(leaf.pgno, c_db.P_LRECNO, 1, [_bkeydata(slot) for slot in leaf.slots]))
        else:
            pages.append(bytes(PAGE_SIZE))

    return b"".join(pages)


# Layout of the forensic test tree: four record numbers for leaf 2, three for leaf 3, none for
# leaf 4, four declared but unreadable for leaf 5, and two for leaf 6.
#
# Leaf 2: [1 live][2 deleted with residual bytes][3 deleted empty][4 live]
# Leaf 3: [5 deleted][6 deleted][7 live]
# Leaf 4: empty page, declares zero records
# Leaf 5: unreadable page, declares records 8-11
# Leaf 6: [12 live][13 live, last surviving record]
LAYOUT = [
    LeafSpec(
        2,
        4,
        (
            SlotSpec(b"alpha"),
            SlotSpec(b"ghost", True),
            SlotSpec(b"", True),
            SlotSpec(b"beta"),
        ),
    ),
    LeafSpec(3, 3, (SlotSpec(b"", True), SlotSpec(b"", True), SlotSpec(b"gamma"))),
    LeafSpec(4, 0),
    LeafSpec(5, 4, readable=False),
    LeafSpec(6, 2, (SlotSpec(b"delta"), SlotSpec(b"omega"))),
]

# Expectations written out from the layout above, not from the parser implementation.
EXPECTED_RECORDS = [
    (1, b"alpha"),
    (4, b"beta"),
    (7, b"gamma"),
    (12, b"delta"),
    (13, b"omega"),
]
EXPECTED_GAPS = [
    (2, 3, 2, "deleted"),
    (5, 6, 3, "deleted"),
    (8, 11, 5, "unreadable_page"),
]
EXPECTED_PAYLOADS = [data for _, data in EXPECTED_RECORDS]
EXPECTED_RECNOS = [recno for recno, _ in EXPECTED_RECORDS]


def _layout_db() -> DB:
    db = DB(io.BytesIO(_build_recno(LAYOUT)))
    assert db.is_recno
    return db


def test_recno_records_use_layout_record_numbers() -> None:
    """Live records keep the record numbers dictated by the constructed page layout."""
    assert list(_layout_db().records()) == EXPECTED_RECORDS


def test_recno_entries_preserve_deleted_slots() -> None:
    """Every physical slot is reported, and deleted slots retain their number without data."""
    entries = list(_layout_db().recno_entries())

    assert [entry.recno for entry in entries] == list(range(1, 12)) + [12, 13]
    assert [entry.live for entry in entries] == [
        True,
        False,
        False,
        True,
        False,
        False,
        True,
        False,
        False,
        False,
        False,
        True,
        True,
    ]

    deleted = {entry.recno: entry for entry in entries if entry.deleted}
    assert set(deleted) == {2, 3, 5, 6}
    assert deleted[2].data is None
    assert deleted[2].residual == b"ghost"
    assert deleted[2].raw_type == c_db.B_KEYDATA | c_db.B_DELETE
    assert deleted[3].residual == b""
    assert all(not entry.live for entry in deleted.values())


def test_recno_gaps_explain_numbering_holes() -> None:
    """Gaps report deleted slots and unavailable pages with their page and reason."""
    gaps = [(gap.start, gap.end, gap.pgno, gap.reason) for gap in _layout_db().recno_gaps()]

    assert gaps == EXPECTED_GAPS


def test_recno_unreadable_leaf_keeps_following_numbers() -> None:
    """An unreadable subtree consumes its declared record numbers, so later records do not shift."""
    db = _layout_db()

    leaves = list(db.recno_leaves())
    assert [(leaf.pgno, leaf.base, leaf.nrecs, leaf.error is not None) for leaf in leaves] == [
        (2, 1, 4, False),
        (3, 5, 3, False),
        (4, 8, 0, False),
        (5, 8, 4, True),
        (6, 12, 2, False),
    ]

    unavailable = [entry for entry in db.recno_entries() if entry.page_error]
    assert [(entry.recno, entry.pgno) for entry in unavailable] == [(8, 5), (9, 5), (10, 5), (11, 5)]

    anomalies = list(db.recno_anomalies())
    assert [(a.kind, a.pgno, a.base, a.declared) for a in anomalies] == [("unexpected_page_type", 5, 8, 4)]


def test_recno_short_leaf_does_not_renumber_following_leaf() -> None:
    """A leaf with fewer slots than its parent declares leaves missing holes, not shifted records."""
    layout = [
        LeafSpec(2, 5, (SlotSpec(b"one"), SlotSpec(b"two"), SlotSpec(b"", True))),
        LeafSpec(3, 1, (SlotSpec(b"three"),)),
    ]
    db = DB(io.BytesIO(_build_recno(layout)))

    assert list(db.records()) == [(1, b"one"), (2, b"two"), (6, b"three")]
    assert [(gap.start, gap.end, gap.reason) for gap in db.recno_gaps()] == [
        (3, 3, "deleted"),
        (4, 5, "missing"),
    ]
    assert [(a.kind, a.pgno, a.declared, a.actual) for a in db.recno_anomalies()] == [("short_leaf", 2, 5, 3)]


def test_recno_filtered_renumbering_is_a_counterexample() -> None:
    """Filtering to live records and renumbering silently assigns the wrong record numbers."""
    records = list(_layout_db().records())

    naive_renumbered = [(i, data) for i, (_, data) in enumerate(records, 1)]
    assert naive_renumbered == [
        (1, b"alpha"),
        (2, b"beta"),
        (3, b"gamma"),
        (4, b"delta"),
        (5, b"omega"),
    ]

    # The last surviving record is record 13 in the database; renumbering moves it to 5.
    assert dict(naive_renumbered)[5] == b"omega"
    assert dict(records)[13] == b"omega"
    assert naive_renumbered != records


def test_recno_traversal_and_numbering_diagnosis() -> None:
    """Traversal and numbering restoration are checked independently.

    If the payload order differs from the layout, the tree walk lost or reordered pages. If the
    payload order matches but the record numbers differ, the walk is fine and only numbering
    restoration is wrong. This distinction is the basis for blaming the right stage on failure.
    """
    db = _layout_db()

    visited = [leaf.pgno for leaf in db.recno_leaves()]
    traversal_ok = visited == [2, 3, 4, 5, 6]

    live = [entry for entry in db.recno_entries() if entry.live]
    payloads_ok = [entry.data for entry in live] == EXPECTED_PAYLOADS
    numbering_ok = [entry.recno for entry in live] == EXPECTED_RECNOS

    assert traversal_ok, f"traversal missed or reordered pages: {visited}"
    assert payloads_ok, f"traversal produced unexpected payloads: {[entry.data for entry in live]}"
    assert numbering_ok, f"numbering restoration produced {[entry.recno for entry in live]}"


def _build_recno_two_level() -> bytes:
    """Build a RECNO tree with a root internal page, two internal pages and four leaves."""
    dbmeta = c_db.DBMETA(
        magic=c_db.DB_BTREEMAGIC,
        version=c_db.DB_BTREEVERSION,
        pagesize=PAGE_SIZE,
        type=c_db.P_BTREEMETA,
        last_pgno=7,
        flags=c_db.BTM_RECNO,
    )
    meta = c_db.BTMETA(dbmeta=dbmeta, root=1).dumps().ljust(PAGE_SIZE, b"\x00")

    root = _page(1, c_db.P_IRECNO, 3, [struct.pack("<II", 2, 5), struct.pack("<II", 3, 4)])
    internal_left = _page(2, c_db.P_IRECNO, 2, [struct.pack("<II", 4, 3), struct.pack("<II", 5, 2)])
    internal_right = _page(3, c_db.P_IRECNO, 2, [struct.pack("<II", 6, 2), struct.pack("<II", 7, 2)])

    leaf_4 = _page(
        4,
        c_db.P_LRECNO,
        1,
        [_bkeydata(SlotSpec(b"one")), _bkeydata(SlotSpec(b"", True)), _bkeydata(SlotSpec(b"two"))],
    )
    leaf_5 = _page(5, c_db.P_LRECNO, 1, [_bkeydata(SlotSpec(b"", True)), _bkeydata(SlotSpec(b"three"))])
    leaf_6 = _page(6, c_db.P_LRECNO, 1, [_bkeydata(SlotSpec(b"", True)), _bkeydata(SlotSpec(b"", True))])
    leaf_7 = _page(7, c_db.P_LRECNO, 1, [_bkeydata(SlotSpec(b"four")), _bkeydata(SlotSpec(b"five"))])

    return b"".join([meta, root, internal_left, internal_right, leaf_4, leaf_5, leaf_6, leaf_7])


def test_recno_two_level_internal_pages_keep_bases() -> None:
    """Record numbering accumulates subtree counts through every internal level."""
    db = DB(io.BytesIO(_build_recno_two_level()))

    # Leaf bases: 1, 4, 6 and 8. Leaf 4 contributes records 1-3, leaf 5 records 4-5,
    # leaf 6 records 6-7 and leaf 7 records 8-9.
    assert [(leaf.pgno, leaf.base, leaf.nrecs) for leaf in db.recno_leaves()] == [
        (4, 1, 3),
        (5, 4, 2),
        (6, 6, 2),
        (7, 8, 2),
    ]
    assert list(db.records()) == [(1, b"one"), (3, b"two"), (5, b"three"), (8, b"four"), (9, b"five")]
    assert [(gap.start, gap.end, gap.pgno) for gap in db.recno_gaps()] == [
        (2, 2, 4),
        (4, 4, 5),
        (6, 7, 6),
    ]
    assert list(db.recno_anomalies()) == []


def test_recno_truncated_leaf_keeps_following_numbers() -> None:
    """A leaf truncated mid-page turns into one gap; later leaves keep their record numbers."""
    blob = bytearray(_build_recno(LAYOUT))
    # Cut leaf 3 off inside its slot offset table, leaving its header readable.
    offset = 3 * PAGE_SIZE + PAGE_HEADER_SIZE
    truncated = bytes(blob[:offset])

    db = DB(io.BytesIO(truncated))
    assert list(db.records()) == [(1, b"alpha"), (4, b"beta")]

    # Leaf 3 still has a readable header, so its slots are reported as unreadable slots. Leaves 4-6
    # are entirely past the end of the file, yet each still consumes its declared record numbers.
    anomalies = list(db.recno_anomalies())
    assert [(a.kind, a.pgno, a.base) for a in anomalies] == [
        ("unreadable_page", 4, 8),
        ("unreadable_page", 5, 8),
        ("unreadable_page", 6, 12),
    ]

    assert [(gap.start, gap.end, gap.pgno, gap.reason) for gap in db.recno_gaps()] == [
        (2, 3, 2, "deleted"),
        (5, 7, 3, "unreadable_slot"),
        (8, 11, 5, "unreadable_page"),
        (12, 13, 6, "unreadable_page"),
    ]


def test_recno_empty_database() -> None:
    """A RECNO database with a single empty leaf yields no records and no gaps."""
    layout = [LeafSpec(2, 0)]
    db = DB(io.BytesIO(_build_recno(layout)))

    assert list(db.records()) == []
    assert list(db.recno_entries()) == []
    assert list(db.recno_gaps()) == []
    assert list(db.recno_anomalies()) == []
