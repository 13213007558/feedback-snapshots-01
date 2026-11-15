from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3.sqlite3 import SQLite3, walk_tree

if TYPE_CHECKING:
    from pathlib import Path


def _create_database(path: Path) -> None:
    """Create a database with a rowid table and several WITHOUT ROWID layouts."""
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE warnings (
            id INTEGER PRIMARY KEY,
            marker TEXT NOT NULL,
            score INT,
            payload BLOB
        );

        CREATE TABLE findings (
            note TEXT,
            "quoted key" INTEGER,
            severity TEXT,
            "case id" INTEGER,
            PRIMARY KEY ("case id", "quoted key")
        ) WITHOUT ROWID;

        CREATE TABLE events (
            label TEXT,
            seen INTEGER,
            uid TEXT,
            PRIMARY KEY (uid, seen DESC)
        ) WITHOUT ROWID;

        CREATE TABLE oversized (
            description TEXT,
            event_id INTEGER,
            body TEXT,
            trailer TEXT,
            PRIMARY KEY (event_id)
        ) WITHOUT ROWID;

        CREATE TABLE huge (
            body TEXT,
            event_id INTEGER,
            PRIMARY KEY (event_id)
        ) WITHOUT ROWID;
        """
    )

    # Deliberately choose values with distinct types so a shifted column is immediately visible.
    connection.execute("INSERT INTO warnings VALUES (?, ?, ?, ?)", (7, "rowid", -7, b"\x00\x01\x02"))
    connection.execute(
        "INSERT INTO findings VALUES (?, ?, ?, ?)",
        ("first finding", 22, "high", 11),
    )
    connection.execute(
        "INSERT INTO findings VALUES (?, ?, ?, ?)",
        ("second finding", 44, "low", 33),
    )
    connection.execute("INSERT INTO events VALUES (?, ?, ?)", ("sign-in", 100, "event-alpha"))
    connection.execute("INSERT INTO events VALUES (?, ?, ?)", ("sign-out", 200, "event-beta"))
    connection.execute(
        "INSERT INTO oversized VALUES (?, ?, ?, ?)",
        ("overflow", 42, "B" * 5000, "after-overflow"),
    )
    connection.execute(
        "INSERT INTO huge VALUES (?, ?)",
        ("C" * 20000, 7),
    )
    connection.commit()
    connection.close()


@pytest.fixture()
def comparison_db(tmp_path: Path) -> Path:
    path = tmp_path / "comparison.sqlite"
    _create_database(path)
    return path


def test_rowid_alias_still_works(comparison_db: Path) -> None:
    with SQLite3(comparison_db) as db:
        table = db.table("warnings")

        assert table.without_rowid is False
        assert table.primary_keys == ["id"]
        assert table.rowid_alias == "id"
        assert [column.name for column in table.columns] == ["id", "marker", "score", "payload"]

        rows = list(table.rows())
        assert len(rows) == 1
        assert list(rows[0]) == [
            ("id", 7),
            ("marker", "rowid"),
            ("score", -7),
            ("payload", b"\x00\x01\x02"),
        ]


def test_without_rowid_composite_key(comparison_db: Path) -> None:
    with SQLite3(comparison_db) as db:
        table = db.table("findings")

        assert table.without_rowid is True
        assert table.primary_keys == ["case id", "quoted key"]
        assert table.rowid_alias is None
        assert [column.name for column in table.columns] == ["note", "quoted key", "severity", "case id"]

        rows = {row["case id"]: row for row in table.rows()}
        assert list(rows[11]) == [
            ("note", "first finding"),
            ("quoted key", 22),
            ("severity", "high"),
            ("case id", 11),
        ]
        assert list(rows[33]) == [
            ("note", "second finding"),
            ("quoted key", 44),
            ("severity", "low"),
            ("case id", 33),
        ]

        # Records are identified by the actual primary key, not by a rowid.
        assert rows[11]["quoted key"] == 22
        assert rows[33]["quoted key"] == 44


def test_without_rowid_key_order_differs_from_declaration(comparison_db: Path) -> None:
    with SQLite3(comparison_db) as db:
        table = db.table("events")

        assert table.without_rowid is True
        assert table.primary_keys == ["uid", "seen"]
        assert [column.name for column in table.columns] == ["label", "seen", "uid"]

        rows = list(table.rows())
        assert [list(row) for row in rows] == [
            [("label", "sign-in"), ("seen", 100), ("uid", "event-alpha")],
            [("label", "sign-out"), ("seen", 200), ("uid", "event-beta")],
        ]


def test_without_rowid_overflow_record(comparison_db: Path) -> None:
    with SQLite3(comparison_db) as db:
        table = db.table("oversized")
        page = db.page(table.page)

        cells = list(walk_tree(db, page))
        assert len(cells) == 1
        cell = cells[0]

        assert cell.key is None
        assert cell.size > db.usable_page_size
        assert len(cell.data) == cell.size

        row = next(table.rows())
        assert list(row) == [
            ("description", "overflow"),
            ("event_id", 42),
            ("body", "B" * 5000),
            ("trailer", "after-overflow"),
        ]


def test_without_rowid_matches_sqlite3(comparison_db: Path) -> None:
    """Compare every column of every row against the sqlite3 module for both storage modes."""
    connection = sqlite3.connect(comparison_db)

    with SQLite3(comparison_db) as db:
        for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
            table = db.table(name)
            assert table is not None

            expected_cursor = connection.execute(f'SELECT * FROM "{name}"')
            expected_columns = [description[0] for description in expected_cursor.description]
            expected_rows = [dict(zip(expected_columns, values, strict=True)) for values in expected_cursor.fetchall()]

            assert table.columns
            assert [column.name for column in table.columns] == expected_columns
            assert [dict(list(row)) for row in table.rows()] == expected_rows

            assert len(list(table.rows())) == len(expected_rows)

    connection.close()


def test_without_rowid_multiple_overflow_pages(comparison_db: Path) -> None:
    with SQLite3(comparison_db) as db:
        table = db.table("huge")
        cell = next(walk_tree(db, db.page(table.page)))

        assert cell.size > db.usable_page_size * 2
        assert len(cell.data) == cell.size

        row = next(table.rows())
        assert list(row) == [
            ("body", "C" * 20000),
            ("event_id", 7),
        ]
