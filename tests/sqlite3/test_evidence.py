from __future__ import annotations

import sqlite3 as stdlib_sqlite3
import subprocess
import sys
from io import BytesIO
from typing import TYPE_CHECKING, Any

import pytest

from dissect.database.sqlite3 import sqlite3
from dissect.database.sqlite3.sqlite3 import StorageClass, get_declared_type, read_record, read_record_fields

if TYPE_CHECKING:
    from pathlib import Path


VALUES = [
    # (stored value, serial type, storage class, raw bytes)
    (1, 9, StorageClass.INTEGER, b""),
    ("1", 15, StorageClass.TEXT, b"1"),
    (1.0, 7, StorageClass.REAL, b"\x3f\xf0\x00\x00\x00\x00\x00\x00"),
    (b"1", 14, StorageClass.BLOB, b"1"),
    (0, 8, StorageClass.INTEGER, b""),
    (2, 1, StorageClass.INTEGER, b"\x02"),
    (-1, 1, StorageClass.INTEGER, b"\xff"),
    (128, 2, StorageClass.INTEGER, b"\x00\x80"),
    (32768, 3, StorageClass.INTEGER, b"\x00\x80\x00"),
    (2**23, 4, StorageClass.INTEGER, b"\x00\x80\x00\x00"),
    (2**31, 5, StorageClass.INTEGER, b"\x00\x00\x80\x00\x00\x00"),
    (2**47, 6, StorageClass.INTEGER, b"\x00\x00\x80\x00\x00\x00\x00\x00"),
    (-(2**63), 6, StorageClass.INTEGER, b"\x80\x00\x00\x00\x00\x00\x00\x00"),
]


@pytest.fixture
def typed_db(tmp_path: Path) -> Path:
    """A database with one column that stores many different actual types."""
    path = tmp_path / "typed.db"
    con = stdlib_sqlite3.connect(path)
    con.execute("PRAGMA page_size=512")
    con.execute("CREATE TABLE samples (id INTEGER PRIMARY KEY, value BLOB, note TEXT)")

    for value, *_ in VALUES:
        con.execute("INSERT INTO samples (value) VALUES (?)", (value,))

    # A text value that cannot be decoded as UTF-8, large enough to overflow onto
    # other pages, sharing a record with ordinary fields before and after it.
    broken = b"A" * 9000 + b"\xff\xfe"
    con.execute(
        "INSERT INTO samples (value, note) VALUES (?, CAST(? AS TEXT))",
        ("broken", broken),
    )
    con.execute("INSERT INTO samples (value, note) VALUES (?, ?)", ("after", "ok"))
    con.commit()
    con.close()

    return path


def _normalise(value: Any) -> Any:
    if isinstance(value, float):
        # SQLite stores 1.0 as a real, which is equal to the integer 1.
        return ("real", value)
    return (type(value).__name__, value)


def test_round_trip_storage_types(typed_db: Path) -> None:
    db = sqlite3.SQLite3(typed_db)
    table = db.table("samples")
    records = list(table.records())

    assert len(records) == len(VALUES) + 2

    for record, (expected_value, serial_type, storage_class, expected_raw) in zip(records[: len(VALUES)], VALUES):
        field = record.get("value")

        assert field.serial_type == serial_type
        assert field.storage_class is storage_class
        assert field.raw == expected_raw
        # The declared type is the same for every row, while the storage class
        # above is what this particular record actually uses.
        assert field.declared_type == "BLOB"
        assert field.error is None
        assert _normalise(field.value) == _normalise(expected_value)

        # The raw bytes at the reported payload offset are exactly the stored bytes.
        assert record.cell.data[field.offset : field.offset + len(field.raw)] == field.raw
        assert field.raw_range == (field.offset, field.offset + len(field.raw))

        # The column mapping is interpretation, not the type used by the record.
        assert field.column is table.columns[1]
        assert field.name == "value"

    # The convenience interface uses the same stored values.
    rows = list(table.rows())
    assert [row.value for row in rows[: len(VALUES)]] == [value for value, *_ in VALUES]


def test_field_offsets_and_file_ranges(typed_db: Path) -> None:
    db = sqlite3.SQLite3(typed_db)
    table = db.table("samples")

    record = next(record for record in table.records() if record.key == 2)
    offsets = [field.offset for field in record.fields]
    assert offsets == sorted(offsets)
    assert record.fields[-1].offset > record.fields[0].offset

    value_field = record.get("value")
    assert value_field.offset >= record.fields[0].offset

    # Fields in a single-page cell map back to the main database file.
    note_field = record.get("note")
    assert note_field.storage_class is StorageClass.NULL
    assert note_field.raw == b""
    assert value_field.ranges == (value_field.ranges[0],)

    run = value_field.ranges[0]
    assert run.page == record.cell.page.num
    assert run.source == "database"
    assert run.file_range is not None
    start, end = run.file_range
    assert end - start == len(value_field.raw)

    with typed_db.open("rb") as fh:
        fh.seek(start)
        assert fh.read(end - start) == value_field.raw
    db.close()


def test_wal_fields_have_no_main_file_range(sqlite_db: Path, sqlite_wal: Path) -> None:
    db = sqlite3.SQLite3(sqlite_db, sqlite_wal)
    record = next(db.table("test").records())

    # The latest checkpoint in the WAL overrides the page in the main file.
    for field in record.fields:
        for run in field.ranges:
            assert run.source == "wal"
            assert run.file_range is None
            assert run.page_range == (run.page_offset, run.page_offset + run.length)

    assert record.get("name").raw == b"testing"


def test_broken_text_across_overflow(typed_db: Path) -> None:
    db = sqlite3.SQLite3(typed_db)
    table = db.table("samples")

    broken_record = next(record for record in table.records() if record.value("value") == "broken")
    payload = broken_record.get("note")

    assert payload.declared_type == "TEXT"
    assert payload.storage_class is StorageClass.TEXT
    assert payload.length == 9002
    assert payload.value == payload.raw
    assert isinstance(payload.error, UnicodeDecodeError)
    assert payload.raw.endswith(b"\xff\xfe")
    assert not payload.decoded

    # The affected field is spread over multiple pages, and its runs join to
    # exactly the raw bytes of this one field.
    assert len(payload.ranges) > 1
    assert sum(run.length for run in payload.ranges) == payload.length

    joined = [db.raw_page(run.page)[run.page_offset : run.page_offset + run.length] for run in payload.ranges]
    assert b"".join(joined) == payload.raw

    # Other fields of the same record are still present and unaffected.
    for name, field in broken_record:
        if name == "note":
            continue
        assert field is not None
        assert field.declared_type == {"id": "INTEGER", "value": "BLOB"}[name]
        assert field.error is None

    assert broken_record.value("value") == "broken"
    assert broken_record.rowid == len(VALUES) + 1

    # The INTEGER PRIMARY KEY column is stored as NULL because it is an alias
    # for the rowid. The stored field keeps that fact, while the convenience
    # accessor resolves the rowid.
    assert broken_record.field("id").storage_class is StorageClass.NULL
    assert broken_record.value("id") == broken_record.rowid
    assert broken_record.as_row().id == broken_record.rowid

    # A following record is not swallowed by the decode error.
    following = next(record for record in table.records() if record.value("value") == "after")
    assert following.value("note") == "ok"


def test_record_as_dict_separates_declared_and_storage(typed_db: Path) -> None:
    db = sqlite3.SQLite3(typed_db)
    table = db.table("samples")

    record = next(record for record in table.records() if record.key == 2)
    report = record.as_dict()["value"]

    assert report["declared_type"] == "BLOB"
    assert report["storage_class"] == "text"
    assert report["serial_type"] == 15
    assert report["value"] == "1"
    assert report["raw_range"] == (record.get("value").offset, record.get("value").offset + 1)

    note_report = record.as_dict()["note"]
    assert note_report["declared_type"] == "TEXT"
    assert note_report["storage_class"] == "null"

    # All four values are stored in the same declared BLOB column, but with
    # four different actual storage classes.
    by_key = {record.key: record.as_dict()["value"] for record in table.records()}
    assert [by_key[key]["declared_type"] for key in (1, 2, 3, 4)] == ["BLOB"] * 4
    assert [by_key[key]["storage_class"] for key in (1, 2, 3, 4)] == ["integer", "text", "real", "blob"]


def test_read_record_fields_preserves_header_and_values() -> None:
    # Record: header size 4, serial types 0, 27 and 2, then "testing" and 1337
    data = b"\x04\x00\x1b\x02testing\x059"
    types, fields = read_record_fields(data, "utf-8")

    assert types == [0, 27, 2]
    assert [field.offset for field in fields] == [4, 4, 11]
    assert [len(field.raw) for field in fields] == [0, 7, 2]
    assert [field.storage_class for field in fields] == [
        StorageClass.NULL,
        StorageClass.TEXT,
        StorageClass.INTEGER,
    ]
    assert [field.value for field in fields] == [None, "testing", 1337]

    # The convenience interface is unchanged.
    assert read_record(BytesIO(data), "utf-8") == (types, [None, "testing", 1337])


def test_read_record_fields_without_header() -> None:
    assert read_record_fields(b"", "utf-8") == ([], [])

    # A record header that is shorter than its header varint is not fatal.
    types, fields = read_record_fields(b"\x09\x01", "utf-8")
    assert types == [1]
    assert len(fields) == 1
    assert fields[0].raw == b""


def test_read_record_fields_keeps_bad_text_bytes() -> None:
    # Record with a single field that is text (serial type 17, 2 bytes) with invalid UTF-8
    data = b"\x02\x11\xff\xfe"
    types, fields = read_record_fields(data, "utf-8")

    assert types == [17]
    (field,) = fields
    assert field.storage_class is StorageClass.TEXT
    assert field.value == b"\xff\xfe"
    assert field.raw == b"\xff\xfe"
    assert isinstance(field.error, UnicodeDecodeError)
    assert field.raw_range == (2, 4)


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_utf16_text(tmp_path: Path, encoding: str) -> None:
    path = tmp_path / f"{encoding}.db"
    pragma = {"utf-16-le": "'UTF-16le'", "utf-16-be": "'UTF-16be'"}[encoding]

    con = stdlib_sqlite3.connect(path)
    con.execute(f"PRAGMA encoding={pragma}")
    con.execute("CREATE TABLE texts (id INTEGER PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO texts (value) VALUES (?)", ("héllo 🦊",))
    con.commit()
    con.close()

    db = sqlite3.SQLite3(path)
    assert db.encoding == encoding

    record = next(db.table("texts").records())
    field = record.get("value")
    assert field.storage_class is StorageClass.TEXT
    assert field.value == "héllo 🦊"
    assert field.raw.decode(encoding) == "héllo 🦊"
    assert field.raw_range == (field.offset, field.offset + len(field.raw))


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("INTEGER PRIMARY KEY", "INTEGER"),
        ("TEXT NOT NULL UNIQUE", "TEXT"),
        ('VARCHAR(1337) DEFAULT ("test") NOT NULL', "VARCHAR(1337)"),
        ("DOUBLE PRECISION NOT NULL", "DOUBLE PRECISION"),
        ("DECIMAL(10, 5) DEFAULT 0", "DECIMAL(10, 5)"),
        ("INTEGER REFERENCES moz_origins(id)", "INTEGER"),
        ("", None),
        ("DEFAULT 1", None),
        ("PRIMARY KEY", None),
    ],
)
def test_get_declared_type(description: str, expected: str | None) -> None:
    assert get_declared_type(description) == expected


def test_row_keeps_convenience_and_exposes_evidence(typed_db: Path) -> None:
    db = sqlite3.SQLite3(typed_db)
    row = db.table("samples").row(1)

    # The old convenience interface is unchanged.
    assert row.value == "1"
    assert row["value"] == "1"

    field = row.record.field("value")
    assert field.storage_class is StorageClass.TEXT
    assert field.raw == b"1"
    assert field.declared_type == "BLOB"

    # The row keeps the same cell, but the evidence view can also be requested
    # directly from the table.
    assert row.record.cell is row._cell
    assert row.record.value("value") == "1"
    assert row.record.as_row().value == "1"


def test_evidence_record_does_not_execute_sql(typed_db: Path) -> None:
    """Reading evidence must not load or execute the SQLite SQL engine."""
    script = """
import sys
from pathlib import Path
from dissect.database.sqlite3 import SQLite3

db = SQLite3(Path(sys.argv[1]))
records = list(db.table("samples").records())
assert len(records) == 15
assert records[1].get("value").value == "1"
assert "sqlite3" not in sys.modules
"""
    subprocess.run([sys.executable, "-c", script, str(typed_db)], check=True)


def test_record_without_columns(tmp_path: Path) -> None:
    path = tmp_path / "extra.db"
    con = stdlib_sqlite3.connect(path)
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
    con.execute("INSERT INTO t DEFAULT VALUES")
    con.commit()
    con.close()

    db = sqlite3.SQLite3(path)
    record = next(db.table("t").records())

    # The rowid-alias column is stored as NULL and the record has no extra
    # fields. There is nothing to attach beyond the column that is present.
    assert len(record) == 1
    assert record.value("id") == 1
    assert record.unknowns == []


def test_record_unknown_columns(tmp_path: Path) -> None:
    path = tmp_path / "extra.db"
    con = stdlib_sqlite3.connect(path)
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO t (value) VALUES ('x')")
    con.commit()
    con.close()

    db = sqlite3.SQLite3(path)
    table = db.table("t")
    cell = next(table.rows())._cell

    # Interpret the same cell with a table that declares fewer columns. The
    # extra stored values must stay available as unknowns rather than vanish.
    table.columns = table.columns[:1]
    record = table.record(cell)

    assert record.value("value") is None
    assert len(record.unknowns) == 1
    assert record.unknowns[0].value == "x"
    assert record.unknowns[0].raw == b"x"
