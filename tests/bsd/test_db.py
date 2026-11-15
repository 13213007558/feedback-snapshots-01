from __future__ import annotations

from typing import BinaryIO

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

    # The database has 69 physical slots, of which only records 42 and 69 are live.
    entries = list(db.recno_entries())
    assert len(entries) == 69
    assert [entry.recno for entry in entries if entry.live] == [42, 69]
    assert all(entry.deleted for entry in entries if not entry.live)

    gaps = list(db.recno_gaps())
    assert [(gap.start, gap.end) for gap in gaps] == [(1, 41), (43, 68)]
