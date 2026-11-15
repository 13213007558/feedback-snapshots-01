from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import sqlite3 as dissect_sqlite3

if TYPE_CHECKING:
    from pathlib import Path


def read_segments(path: Path, segments: tuple) -> bytes:
    """Read the raw bytes located by the given segments straight from the database image."""
    raw = []
    with path.open("rb") as fh:
        for segment in segments:
            fh.seek(segment.offset)
            raw.append(fh.read(segment.size))
    return b"".join(raw)


@pytest.fixture
def mixed_types_db(tmp_path: Path) -> Path:
    """Database with one column storing different actual storage types per row."""
    path = tmp_path / "mixed.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val BLOB)")
    con.executemany(
        "INSERT INTO t (id, val) VALUES (?, ?)",
        [
            (1, 0),
            (2, 1),
            (3, 257),
            (4, 2**40),
            (5, -11644473429),
            (6, 1.0),
            (7, "1"),
            (8, b"1"),
            (9, None),
        ],
    )
    con.commit()
    con.close()
    return path


def test_record_mixed_storage_types(mixed_types_db: Path) -> None:
    db = dissect_sqlite3.SQLite3(mixed_types_db)
    table = db.table("t")
    rows = list(table.rows())
    assert len(rows) == 9

    # The declared column type is BLOB for every row ...
    for row in rows:
        assert row.field("val").declared_type == "BLOB"

    # ... but the actual storage encoding differs per record.
    fields = [row.field("val") for row in rows]
    assert [field.serial_type for field in fields] == [8, 9, 2, 5, 5, 7, 15, 14, 0]
    assert [field.storage_class for field in fields] == [
        "integer",
        "integer",
        "integer",
        "integer",
        "integer",
        "float",
        "text",
        "blob",
        "null",
    ]
    assert [field.value for field in fields] == [0, 1, 257, 2**40, -11644473429, 1.0, "1", b"1", None]

    # The integer 1, text "1", float 1.0 and blob b"1" are distinguishable,
    # even though the integer 1 and float 1.0 compare equal as Python values.
    by_value = {row.id: row.field("val") for row in rows}
    assert by_value[2].value == 1 and by_value[2].storage_class == "integer"
    assert by_value[7].value == "1" and by_value[7].storage_class == "text"
    assert by_value[6].value == 1.0 and by_value[6].storage_class == "float"
    assert by_value[8].value == b"1" and by_value[8].storage_class == "blob"

    # The constants 0 and 1 use the special serial types 8 and 9 and occupy no bytes.
    assert by_value[1].serial_type == 8
    assert by_value[1].raw == b""
    assert by_value[1].segments == ()
    assert by_value[2].serial_type == 9
    assert by_value[2].raw == b""
    assert by_value[2].segments == ()

    # NULL occupies no bytes either.
    assert by_value[9].raw == b""
    assert by_value[9].segments == ()

    # Every stored field can be traced back to its raw bytes in the database image.
    for field in fields:
        assert read_segments(mixed_types_db, field.segments) == field.raw

    # The primary key is stored as the rowid (NULL in the record), but the row
    # interface still resolves it.
    id_field = rows[1].field("id")
    assert id_field.declared_type == "INTEGER"
    assert id_field.serial_type == 0
    assert id_field.value == 2
    assert rows[1]["id"] == 2


def test_record_row_interface_still_works(mixed_types_db: Path) -> None:
    db = dissect_sqlite3.SQLite3(mixed_types_db)
    row = db.table("t").row(6)

    assert row["val"] == "1"
    assert row.val == "1"
    assert row.get("val") == "1"
    assert list(row) == [("id", 7), ("val", "1")]
    assert dict(row.fields)["val"].value == "1"


@pytest.mark.parametrize(
    ("pragma", "encoding"),
    [
        ("UTF-16le", "utf-16-le"),
        ("UTF-16be", "utf-16-be"),
    ],
)
def test_record_utf16_text(tmp_path: Path, pragma: str, encoding: str) -> None:
    path = tmp_path / "utf16.db"
    con = sqlite3.connect(path)
    con.execute(f"PRAGMA encoding='{pragma}'")
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
    con.execute("INSERT INTO t (id, val) VALUES (?, ?)", (1, "héllo 证据"))
    con.commit()
    con.close()

    db = dissect_sqlite3.SQLite3(path)
    row = db.table("t").row(0)
    field = row.field("val")

    assert row.val == "héllo 证据"
    assert field.declared_type == "TEXT"
    assert field.storage_class == "text"
    assert field.encoding == encoding
    assert field.error is None
    assert field.raw == "héllo 证据".encode(encoding)
    assert read_segments(path, field.segments) == field.raw


@pytest.fixture
def overflow_bad_text_db(tmp_path: Path) -> Path:
    """Database with an undecodable text field that spans overflow pages."""
    path = tmp_path / "overflow_bad.db"
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=512")
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, note TEXT, name TEXT)")
    bad_text = b"start-" + b"A" * 1000 + b"\xff\xfe\x80 not valid utf-8 " + b"B" * 900
    con.execute("INSERT INTO t (id, note, name) VALUES (?, CAST(? AS TEXT), ?)", (1, bad_text, "still here"))
    con.commit()
    con.close()
    return path


def test_record_overflow_bad_text(overflow_bad_text_db: Path) -> None:
    db = dissect_sqlite3.SQLite3(overflow_bad_text_db)
    assert db.page_size == 512

    row = db.table("t").row(0)

    # The undecodable text field keeps its raw bytes and the decoding error ...
    note = row.field("note")
    assert note.declared_type == "TEXT"
    assert note.storage_class == "text"
    assert isinstance(note.error, UnicodeDecodeError)
    assert isinstance(note.value, bytes)
    assert note.value == note.raw
    assert len(note.raw) > 1900

    # ... while the other fields of the same record remain available.
    assert row.id == 1
    assert row.name == "still here"
    assert row.field("name").error is None
    assert row.field("name").value == "still here"

    # The field crosses page boundaries, so its raw bytes are located on
    # multiple (overflow) pages and can be traced back to the database image.
    pages = {segment.page for segment in note.segments}
    assert len(pages) > 1
    assert sum(segment.size for segment in note.segments) == len(note.raw)
    assert read_segments(overflow_bad_text_db, note.segments) == note.raw


def test_record_cell_record(overflow_bad_text_db: Path) -> None:
    db = dissect_sqlite3.SQLite3(overflow_bad_text_db)
    table = db.table("t")
    cell = next(iter(db.page(table.page).cells()))

    record = cell.record
    assert record.header_size > 0
    assert record.types == cell.types
    assert record.values == cell.values
    assert [field.serial_type for field in record] == record.types
    assert record.fields[1].raw in cell.data
