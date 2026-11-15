from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import sqlite3 as dissect_sqlite3
from dissect.database.sqlite3.c_sqlite3 import c_sqlite3

if TYPE_CHECKING:
    from pathlib import Path

# Marker values with distinct, easily recognizable types so that any column
# misalignment immediately shows up as a type/value mismatch.
ROWID_MARKERS = [
    ("NOTE-ALPHA", 0.5, b"\x01\x02\x03"),
    ("NOTE-BRAVO", -2.25, b"\xde\xad\xbe\xef"),
    ("NOTE-CHARLIE", 4096.125, b""),
]

OVERFLOW_PAYLOAD = "OVERFLOW-" + "Z" * 4000

# Declared column order: "payload data", "key two", "flag", "key one", "ratio".
# On-disk record order (WITHOUT ROWID): "key one", "key two", "payload data", "flag", "ratio".
WR_MARKERS = [
    ("PAYLOAD-ALPHA", 111, 7, "ALPHA", 1.5),
    ("PAYLOAD-BRAVO", 222, -8, "BRAVO", -2.75),
    (OVERFLOW_PAYLOAD, 333, 9, "CHARLIE-WIDE", 0.125),
]

WR_DECLARED_COLUMNS = ["payload data", "key two", "flag", "key one", "ratio"]
WR_RECORD_COLUMNS = ["key one", "key two", "payload data", "flag", "ratio"]


@pytest.fixture
def comparison_db(tmp_path: Path) -> Path:
    """Create a database with both storage modes, generated with sqlite3 itself.

    A small page size is used so that the ``OVERFLOW_PAYLOAD`` row is forced to
    spill over into overflow pages.
    """
    path = tmp_path / "comparison.db"
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=512")
    con.execute(
        """
        CREATE TABLE rowid_marks (
            id INTEGER PRIMARY KEY,
            "note text" TEXT,
            score REAL,
            blob_mark BLOB
        )
        """
    )
    con.execute(
        """
        CREATE TABLE wr_marks (
            "payload data" TEXT,
            "key two" INTEGER NOT NULL,
            flag INTEGER,
            "key one" TEXT NOT NULL,
            ratio REAL,
            PRIMARY KEY ("key one", "key two")
        ) WITHOUT ROWID
        """
    )
    con.executemany("INSERT INTO rowid_marks VALUES (NULL, ?, ?, ?)", ROWID_MARKERS)
    con.executemany("INSERT INTO wr_marks VALUES (?, ?, ?, ?, ?)", WR_MARKERS)
    con.commit()
    con.close()
    return path


def test_without_rowid_table_metadata(comparison_db: Path) -> None:
    db = dissect_sqlite3.SQLite3(comparison_db)

    rowid_table = db.table("rowid_marks")
    assert rowid_table.without_rowid is False
    assert rowid_table.primary_key == "id"
    assert rowid_table.primary_key_columns == ["id"]
    assert [column.name for column in rowid_table.record_columns] == ["id", "note text", "score", "blob_mark"]

    wr_table = db.table("wr_marks")
    assert wr_table.without_rowid is True
    # Compound primary key, so no single rowid-aliasable primary key.
    assert wr_table.primary_key is None
    assert wr_table.primary_key_columns == ["key one", "key two"]
    # Columns stay in declaration order, record columns in on-disk (primary key first) order.
    assert [column.name for column in wr_table.columns] == WR_DECLARED_COLUMNS
    assert [column.name for column in wr_table.record_columns] == WR_RECORD_COLUMNS


def test_rows_match_sqlite_column_by_column(comparison_db: Path) -> None:
    """Compare every column of every row of both tables against sqlite3 itself."""
    db = dissect_sqlite3.SQLite3(comparison_db)
    con = sqlite3.connect(comparison_db)

    queries = {
        "rowid_marks": "SELECT * FROM rowid_marks ORDER BY rowid",
        "wr_marks": 'SELECT * FROM wr_marks ORDER BY "key one", "key two"',
    }
    for table_name, query in queries.items():
        table = db.table(table_name)
        column_names = [column.name for column in table.columns]
        expected_rows = con.execute(query).fetchall()

        rows = list(table.rows())
        assert len(rows) == len(expected_rows)

        for row, expected_row in zip(rows, expected_rows):
            # Output column order follows the table declaration.
            assert [name for name, _ in row] == column_names
            for column_name, expected_value in zip(column_names, expected_row):
                assert row[column_name] == expected_value, f"{table_name}.{column_name}"

    con.close()


def test_rowid_table_integer_primary_key_alias(comparison_db: Path) -> None:
    """A regular INTEGER PRIMARY KEY column is still resolved through the rowid alias."""
    db = dissect_sqlite3.SQLite3(comparison_db)
    con = sqlite3.connect(comparison_db)

    expected = con.execute("SELECT rowid, id FROM rowid_marks ORDER BY rowid").fetchall()
    rows = list(db.table("rowid_marks").rows())

    for row, (expected_rowid, expected_id) in zip(rows, expected):
        assert row.id == expected_id == expected_rowid
        # The value comes from the cell key (rowid), not from the record.
        assert row._cell.key == expected_rowid

    con.close()


def test_without_rowid_record_identity(comparison_db: Path) -> None:
    """WITHOUT ROWID records are keyed by their primary key, stored inside the record itself."""
    db = dissect_sqlite3.SQLite3(comparison_db)
    table = db.table("wr_marks")

    cells = list(dissect_sqlite3.walk_tree(db, db.page(table.page)))
    assert len(cells) == len(WR_MARKERS)

    for cell in cells:
        # Index b-tree leaf cells carry no rowid key.
        assert cell.page.header.flags == c_sqlite3.PAGE_TYPE_LEAF_INDEX
        assert cell.key is None
        # The record itself starts with the primary key columns, in primary key order.
        assert isinstance(cell.values[0], str)  # "key one"
        assert isinstance(cell.values[1], int)  # "key two"

    identities = {(row["key one"], row["key two"]) for row in table.rows()}
    assert identities == {(marker[3], marker[1]) for marker in WR_MARKERS}


def test_without_rowid_overflow_record(comparison_db: Path) -> None:
    """Show the primary key and field origins of a record that spans overflow pages."""
    db = dissect_sqlite3.SQLite3(comparison_db)
    table = db.table("wr_marks")

    cells = list(dissect_sqlite3.walk_tree(db, db.page(table.page)))
    overflow_cells = [cell for cell in cells if cell.size is not None and cell.size > cell.max_payload_size]
    assert len(overflow_cells) == 1
    cell = overflow_cells[0]

    # The payload does not fit on the b-tree leaf page: it is continued on overflow pages.
    assert OVERFLOW_PAYLOAD.encode() not in cell.page.data

    # The primary key of the cross-page record comes from the start of the record (the index key).
    assert cell.values[0] == "CHARLIE-WIDE"  # "key one"
    assert cell.values[1] == 333  # "key two"
    # The remaining fields follow in declaration order, reassembled from the overflow chain.
    assert cell.values[2] == OVERFLOW_PAYLOAD  # "payload data"
    assert cell.values[3] == 9  # "flag"
    assert cell.values[4] == 0.125  # "ratio"

    row = next(row for row in table.rows() if row["key one"] == "CHARLIE-WIDE")
    assert row["key two"] == 333
    assert row["payload data"] == OVERFLOW_PAYLOAD
    assert row["flag"] == 9
    assert row["ratio"] == 0.125
    # Output is in declaration order, not in on-disk record order.
    assert [name for name, _ in row] == WR_DECLARED_COLUMNS
