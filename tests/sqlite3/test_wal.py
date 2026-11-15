from __future__ import annotations

import shutil
import sqlite3 as pysqlite3
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import sqlite3
from dissect.database.sqlite3.wal import (
    WAL,
    WAL_HEADER_MAGIC_BE,
    WAL_HEADER_MAGIC_LE,
    checksum,
)
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("db_as_path"),
    [pytest.param(True, id="db_as_path"), pytest.param(False, id="db_as_fh")],
)
@pytest.mark.parametrize(
    ("wal_as_path"),
    [pytest.param(True, id="wal_as_path"), pytest.param(False, id="wal_as_fh")],
)
def test_sqlite_wal(sqlite_db: Path, sqlite_wal: Path, db_as_path: bool, wal_as_path: bool) -> None:
    db = sqlite3.SQLite3(
        sqlite_db if db_as_path else sqlite_db.open("rb"),
        sqlite_wal if wal_as_path else sqlite_wal.open("rb"),
        checkpoint=1,
    )
    _assert_checkpoint_1(db)

    db.close()

    db = sqlite3.SQLite3(
        sqlite_db if db_as_path else sqlite_db.open("rb"),
        sqlite_wal if wal_as_path else sqlite_wal.open("rb"),
        checkpoint=2,
    )
    _assert_checkpoint_2(db)

    db.close()

    db = sqlite3.SQLite3(
        sqlite_db if db_as_path else sqlite_db.open("rb"),
        sqlite_wal if wal_as_path else sqlite_wal.open("rb"),
        checkpoint=3,
    )
    _assert_checkpoint_3(db)

    db.close()


def _assert_checkpoint_1(s: sqlite3.SQLite3) -> None:
    # After the first checkpoint the "after checkpoint" entries are present
    table = next(iter(s.tables()))

    rows = list(table.rows())
    assert len(rows) == 9

    assert rows[0].id == 1
    assert rows[0].name == "testing"
    assert rows[0].value == 1337
    assert rows[1].id == 2
    assert rows[1].name == "omg"
    assert rows[1].value == 7331
    assert rows[2].id == 3
    assert rows[2].name == "A" * 4100
    assert rows[2].value == 4100
    assert rows[3].id == 4
    assert rows[3].name == "B" * 4100
    assert rows[3].value == 4100
    assert rows[4].id == 5
    assert rows[4].name == "negative"
    assert rows[4].value == -11644473429
    assert rows[5].id == 6
    assert rows[5].name == "after checkpoint"
    assert rows[5].value == 42
    assert rows[6].id == 7
    assert rows[6].name == "after checkpoint"
    assert rows[6].value == 43
    assert rows[7].id == 8
    assert rows[7].name == "after checkpoint"
    assert rows[7].value == 44
    assert rows[8].id == 9
    assert rows[8].name == "after checkpoint"
    assert rows[8].value == 45


def _assert_checkpoint_2(s: sqlite3.SQLite3) -> None:
    # After the second checkpoint two more entries are present ("second checkpoint")
    table = next(iter(s.tables()))

    rows = list(table.rows())
    assert len(rows) == 11

    assert rows[0].id == 1
    assert rows[0].name == "testing"
    assert rows[0].value == 1337
    assert rows[1].id == 2
    assert rows[1].name == "omg"
    assert rows[1].value == 7331
    assert rows[2].id == 3
    assert rows[2].name == "A" * 4100
    assert rows[2].value == 4100
    assert rows[3].id == 4
    assert rows[3].name == "B" * 4100
    assert rows[3].value == 4100
    assert rows[4].id == 5
    assert rows[4].name == "negative"
    assert rows[4].value == -11644473429
    assert rows[5].id == 6
    assert rows[5].name == "after checkpoint"
    assert rows[5].value == 42
    assert rows[6].id == 7
    assert rows[6].name == "after checkpoint"
    assert rows[6].value == 43
    assert rows[7].id == 8
    assert rows[7].name == "after checkpoint"
    assert rows[7].value == 44
    assert rows[8].id == 9
    assert rows[8].name == "after checkpoint"
    assert rows[8].value == 45
    assert rows[9].id == 10
    assert rows[9].name == "second checkpoint"
    assert rows[9].value == 100
    assert rows[10].id == 11
    assert rows[10].name == "second checkpoint"
    assert rows[10].value == 101


def _assert_checkpoint_3(s: sqlite3.SQLite3) -> None:
    # After the third checkpoint the deletion and update of one "after checkpoint" are reflected
    table = next(iter(s.tables()))
    rows = list(table.rows())

    assert len(rows) == 10

    assert rows[0].id == 1
    assert rows[0].name == "testing"
    assert rows[0].value == 1337
    assert rows[1].id == 2
    assert rows[1].name == "omg"
    assert rows[1].value == 7331
    assert rows[2].id == 3
    assert rows[2].name == "A" * 4100
    assert rows[2].value == 4100
    assert rows[3].id == 4
    assert rows[3].name == "B" * 4100
    assert rows[3].value == 4100
    assert rows[4].id == 5
    assert rows[4].name == "negative"
    assert rows[4].value == -11644473429
    assert rows[5].id == 6
    assert rows[5].name == "after checkpoint"
    assert rows[5].value == 42
    assert rows[6].id == 8
    assert rows[6].name == "after checkpoint"
    assert rows[6].value == 44
    assert rows[7].id == 9
    assert rows[7].name == "wow"
    assert rows[7].value == 1234
    assert rows[8].id == 10
    assert rows[8].name == "second checkpoint"
    assert rows[8].value == 100
    assert rows[9].id == 11
    assert rows[9].name == "second checkpoint"
    assert rows[9].value == 101


def test_wal_page_count() -> None:
    """Test if we count the page numbers in the SQLite3 and WAL correctly.

    Test data generated using:

        $ sqlite3 tests/_data/sqlite3/page_count.db
        SQLite version 3.45.1 2024-01-30 16:01:20
        Enter ".help" for usage hints.
        sqlite> PRAGMA journal_mode = WAL;
        wal
        sqlite> CREATE TABLE t1 (a, b);
        sqlite> .quit  # commits wal

        $ python
        >>> import sqlite3
        >>> con = sqlite3.connect("tests/_data/sqlite3/page_count.db")
        ... cur = con.cursor()
        >>> cur.execute("INSERT INTO t1 VALUES (1, ?)", ("A" * 8192,))
        >>> con.commit()
        # Copy page_count.db* files before closing
    """
    db = sqlite3.SQLite3(absolute_path("_data/sqlite3/page_count.db"))
    table = db.table("t1")
    assert table.sql == "CREATE TABLE t1 (a, b)"

    row = next(table.rows())
    assert row.a == 1
    assert row.b == "A" * 8192

    assert db.wal
    assert db.wal.highest_page_num == 4
    assert db.header.page_count == 2
    assert db.page_count == 4


WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


@pytest.fixture
def generated_wal_db(tmp_path: Path) -> tuple[Path, Path, list[tuple[int, str]]]:
    """Generate a small valid WAL-mode database using the stdlib sqlite3 module.

    The main database file contains the first commit (rows 1-3) because of an
    explicit checkpoint. The WAL contains two more commits: rows 4-9 and rows 10-15.

    Returns the database path, the WAL path and the rows as reported by SQLite itself.
    """
    src_db = tmp_path / "src.db"
    con = pysqlite3.connect(src_db)
    con.execute("PRAGMA page_size=512")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(i, f"row{i}") for i in range(1, 4)])
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(i, "x" * 400) for i in range(4, 10)])
    con.commit()
    con.executemany("INSERT INTO t VALUES (?, ?)", [(i, "y" * 400) for i in range(10, 16)])
    con.commit()
    expected = con.execute("SELECT id, v FROM t ORDER BY id").fetchall()

    # Copy the database and WAL while the connection is open so the WAL persists
    db_path = tmp_path / "generated.db"
    wal_path = tmp_path / "generated.db-wal"
    shutil.copy(src_db, db_path)
    shutil.copy(f"{src_db}-wal", wal_path)
    con.close()

    return db_path, wal_path, expected


def _frame_layout(wal_path: Path) -> tuple[int, int]:
    """Return the frame size and number of (whole) frames in the WAL."""
    data = wal_path.read_bytes()
    (page_size,) = struct.unpack(">I", data[8:12])
    frame_size = WAL_FRAME_HEADER_SIZE + page_size
    return frame_size, (len(data) - WAL_HEADER_SIZE) // frame_size


def _flip_byte(path: Path, offset: int) -> None:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    path.write_bytes(bytes(data))


def _convert_wal_endianness(wal_path: Path, magic: int) -> None:
    """Rewrite a WAL file with the given magic, recomputing the header checksum and
    the cumulative frame checksum chain in the corresponding endianness.

    The result is a WAL file that SQLite itself accepts.
    """
    endian = "<" if magic == WAL_HEADER_MAGIC_LE else ">"
    data = bytearray(wal_path.read_bytes())
    (page_size,) = struct.unpack(">I", data[8:12])
    frame_size = WAL_FRAME_HEADER_SIZE + page_size

    struct.pack_into(">I", data, 0, magic)
    s0, s1 = checksum(bytes(data[:24]), endian)
    struct.pack_into(">2I", data, 24, s0, s1)

    num_frames = (len(data) - WAL_HEADER_SIZE) // frame_size
    for i in range(num_frames):
        offset = WAL_HEADER_SIZE + i * frame_size
        # The frame checksum chains over the first 8 bytes of the frame header
        # followed by the page data
        buf = bytes(data[offset : offset + 8]) + bytes(
            data[offset + WAL_FRAME_HEADER_SIZE : offset + WAL_FRAME_HEADER_SIZE + page_size]
        )
        s0, s1 = checksum(buf, endian, s0, s1)
        struct.pack_into(">2I", data, offset + 16, s0, s1)

    wal_path.write_bytes(bytes(data))


def _read_rows(db_path: Path) -> list[tuple[int, str]]:
    with sqlite3.SQLite3(db_path) as db:
        return [(row.id, row.v) for row in db.table("t").rows()]


def test_generated_wal_matches_sqlite(generated_wal_db: tuple[Path, Path, list]) -> None:
    """A pristine generated WAL fully validates and reads identical to SQLite."""
    db_path, wal_path, expected = generated_wal_db

    _, num_frames = _frame_layout(wal_path)
    wal = WAL(wal_path)
    assert wal.header_checksum_valid
    assert wal.valid_frame_count == num_frames
    assert len(wal.commits) == 2
    assert all(frame.valid for frame in wal.frames())
    wal.close()

    assert _read_rows(db_path) == expected


@pytest.mark.parametrize(
    ("magic"),
    [pytest.param(WAL_HEADER_MAGIC_LE, id="little_endian"), pytest.param(WAL_HEADER_MAGIC_BE, id="big_endian")],
)
def test_wal_checksum_endianness(generated_wal_db: tuple[Path, Path, list], magic: int, tmp_path: Path) -> None:
    """The checksum chain must validate for both checksum endiannesses."""
    db_path, wal_path, expected = generated_wal_db
    _convert_wal_endianness(wal_path, magic)

    # Sanity check: SQLite itself accepts the rewritten WAL
    check_db = tmp_path / f"check_{magic}.db"
    shutil.copy(db_path, check_db)
    shutil.copy(wal_path, f"{check_db}-wal")
    con = pysqlite3.connect(check_db)
    assert con.execute("SELECT id, v FROM t ORDER BY id").fetchall() == expected
    con.close()

    wal = WAL(wal_path)
    assert wal.header_checksum_valid
    assert wal.valid_frame_count == len(list(wal.frames()))
    assert len(wal.commits) == 2
    wal.close()

    assert _read_rows(db_path) == expected


@pytest.mark.parametrize(
    ("magic"),
    [pytest.param(WAL_HEADER_MAGIC_LE, id="little_endian"), pytest.param(WAL_HEADER_MAGIC_BE, id="big_endian")],
)
def test_wal_corrupt_frame_page_data(generated_wal_db: tuple[Path, Path, list], magic: int) -> None:
    """Corrupting page data of a frame in the first commit invalidates that frame
    and everything after it, including the later valid-looking commit records.

    All frame salts still match the WAL header, so salt matching alone would
    incorrectly accept the corrupted content as committed data.
    """
    db_path, wal_path, expected = generated_wal_db
    _convert_wal_endianness(wal_path, magic)

    frame_size, num_frames = _frame_layout(wal_path)
    wal = WAL(wal_path)
    # Corrupt a frame in the middle of the first commit
    corrupt_idx = wal.commits[0].frames[len(wal.commits[0].frames) // 2].index
    wal.close()

    # Flip a single byte in the page data of the corrupted frame
    _flip_byte(wal_path, WAL_HEADER_SIZE + corrupt_idx * frame_size + WAL_FRAME_HEADER_SIZE + 100)

    wal = WAL(wal_path)
    assert wal.header_checksum_valid
    # The rejection position must point at the exact corrupted frame
    assert wal.valid_frame_count == corrupt_idx
    # The commit records after the corruption do not wash away the corruption
    assert wal.commits == []
    assert wal.checkpoints == []
    assert wal.highest_page_num == 0

    # All frames remain enumerable as raw evidence, but only the frames
    # before the corrupted one are valid
    frames = list(wal.frames())
    assert len(frames) == num_frames
    assert frames[corrupt_idx - 1].valid is True
    assert frames[corrupt_idx].valid is False
    assert not any(frame.valid for frame in frames[corrupt_idx:])
    wal.close()

    # The normal database view falls back to the main database file only
    assert _read_rows(db_path) == expected[:3]


def test_wal_corrupt_frame_header(generated_wal_db: tuple[Path, Path, list]) -> None:
    """Corrupting a frame header in the second commit keeps the first commit
    valid but rejects the corrupted frame and the rest of the chain."""
    db_path, wal_path, expected = generated_wal_db

    frame_size, num_frames = _frame_layout(wal_path)
    wal = WAL(wal_path)
    corrupt_idx = wal.commits[1].frames[0].index
    wal.close()

    # Flip a single byte in the page_number field of the frame header
    _flip_byte(wal_path, WAL_HEADER_SIZE + corrupt_idx * frame_size)

    wal = WAL(wal_path)
    assert wal.valid_frame_count == corrupt_idx
    assert len(wal.commits) == 1

    frames = list(wal.frames())
    assert len(frames) == num_frames
    assert frames[corrupt_idx - 1].valid is True
    assert frames[corrupt_idx].valid is False
    wal.close()

    # Only the first WAL commit is applied on top of the main database
    assert _read_rows(db_path) == expected[:9]


def test_wal_truncated_mid_transaction(generated_wal_db: tuple[Path, Path, list]) -> None:
    """A WAL that ends in the middle of a transaction only applies the last
    complete commit; the leftover frames are not committed data."""
    db_path, wal_path, expected = generated_wal_db

    frame_size, _ = _frame_layout(wal_path)
    wal = WAL(wal_path)
    first_frame_idx = wal.commits[1].frames[0].index
    wal.close()

    # Keep the first commit and a single (non-commit) frame of the second
    # transaction, plus some trailing partial frame data
    data = wal_path.read_bytes()
    keep = WAL_HEADER_SIZE + (first_frame_idx + 1) * frame_size
    wal_path.write_bytes(data[: keep + 10])

    wal = WAL(wal_path)
    assert wal.valid_frame_count == first_frame_idx + 1
    assert len(wal.commits) == 1
    # The partial trailing frame is not enumerated
    assert len(list(wal.frames())) == first_frame_idx + 1
    wal.close()

    assert _read_rows(db_path) == expected[:9]


def test_wal_invalid_header_checksum(generated_wal_db: tuple[Path, Path, list]) -> None:
    """A WAL with a corrupted header checksum cannot be absolutely verified, so
    its frames must not participate in the normal database view. The frames are
    still relatively chain-validated and enumerable as raw evidence."""
    db_path, wal_path, expected = generated_wal_db

    _, num_frames = _frame_layout(wal_path)

    # Flip a single byte in the WAL header checksum
    _flip_byte(wal_path, 24)

    wal = WAL(wal_path)
    assert not wal.header_checksum_valid
    # The frames themselves are intact, so the relative chain still validates
    assert len(wal.commits) == 2
    frames = list(wal.frames())
    assert len(frames) == num_frames
    assert all(frame.valid for frame in frames)
    wal.close()

    # The normal database view must not use the unverifiable WAL
    with sqlite3.SQLite3(db_path) as db:
        assert db.page_count == db.header.page_count
    assert _read_rows(db_path) == expected[:3]
