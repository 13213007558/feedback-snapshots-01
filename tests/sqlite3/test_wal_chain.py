from __future__ import annotations

import shutil
import sqlite3
import struct
from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import sqlite3 as dissect_sqlite3
from dissect.database.sqlite3.wal import WAL, checksum

if TYPE_CHECKING:
    from pathlib import Path

WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def _rewrite_checksums(data: bytearray, endian: str) -> bytearray:
    """Rewrite a WAL file with all checksums recomputed in the given byte order."""
    magic = 0x377F0682 if endian == "<" else 0x377F0683
    struct.pack_into(">I", data, 0, magic)
    page_size = struct.unpack_from(">I", data, 8)[0]

    s0, s1 = checksum(bytes(data[:24]), endian)
    struct.pack_into(">II", data, 24, s0, s1)

    frame_size = WAL_FRAME_HEADER_SIZE + page_size
    offset = WAL_HEADER_SIZE
    while offset + frame_size <= len(data):
        buf = bytes(data[offset : offset + 8]) + bytes(data[offset + WAL_FRAME_HEADER_SIZE : offset + frame_size])
        s0, s1 = checksum(buf, endian, s0, s1)
        struct.pack_into(">II", data, offset + 16, s0, s1)
        offset += frame_size
    return data


@pytest.fixture
def sample_db(tmp_path: Path) -> tuple[Path, Path, list[tuple]]:
    """Generate a small, valid database and WAL file using the stdlib sqlite3 module.

    The main database file contains a checkpointed baseline (rows 1 and 2). The WAL
    file contains two more committed transactions in a single generation:

    - transaction 1: row 3
    - transaction 2: row 4 (with a large value, spanning multiple frames)
    """
    src_db = tmp_path / "src.db"
    con = sqlite3.connect(src_db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
    con.executemany("INSERT INTO t VALUES (?, ?)", [(1, "baseline-a"), (2, "baseline-b")])
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.execute("INSERT INTO t VALUES (3, 'tx1')")
    con.commit()
    con.execute("INSERT INTO t VALUES (4, ?)", ("tx2-" + "x" * 10000,))
    con.commit()

    # Read the expected view through SQLite's own WAL recovery
    expected = con.execute("SELECT id, val FROM t ORDER BY id").fetchall()

    db_path = tmp_path / "sample.db"
    wal_path = tmp_path / "sample.db-wal"
    shutil.copyfile(src_db, db_path)
    shutil.copyfile(f"{src_db}-wal", wal_path)
    con.close()

    return db_path, wal_path, expected


def _rows(db_path: Path, wal_path: Path | None = None) -> list[tuple]:
    db = dissect_sqlite3.SQLite3(db_path, wal_path)
    rows = [(row.id, row.val) for row in db.table("t").rows()]
    db.close()
    return rows


def _corrupt(path: Path, offset: int) -> None:
    """Flip a single byte at the given offset."""
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    path.write_bytes(bytes(data))


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little-endian", "big-endian"])
def test_wal_valid_checksum_chain(sample_db: tuple[Path, Path, list[tuple]], endian: str) -> None:
    """A valid WAL file passes the checksum chain in both byte orders and reads back
    the same view as SQLite itself."""
    db_path, wal_path, expected = sample_db

    if endian == "<":
        # Recomputing the checksums of a SQLite-generated WAL must be idempotent
        assert bytes(_rewrite_checksums(bytearray(wal_path.read_bytes()), "<")) == wal_path.read_bytes()
    else:
        wal_path.write_bytes(bytes(_rewrite_checksums(bytearray(wal_path.read_bytes()), ">")))

    wal = WAL(wal_path)
    assert wal.header_checksum_valid

    frames = list(wal.frames())
    assert len(frames) > 2
    assert wal.valid_frame_count == len(frames)
    assert all(frame.valid for frame in frames)
    assert len(wal.commits) == 2
    assert wal.highest_page_num > 0

    assert _rows(db_path, wal_path) == expected


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little-endian", "big-endian"])
def test_wal_corrupted_frame_header(sample_db: tuple[Path, Path, list[tuple]], endian: str) -> None:
    """A single-byte corruption in the first frame header invalidates that frame and,
    through the chain, all frames after it. The commit marker of the second
    transaction still looks legitimate (matching salts, self-consistent stored
    checksums) but must not wash out the earlier corruption."""
    db_path, wal_path, expected = sample_db
    if endian == ">":
        wal_path.write_bytes(bytes(_rewrite_checksums(bytearray(wal_path.read_bytes()), ">")))

    wal = WAL(wal_path)
    num_frames = len(list(wal.frames()))
    first_frame_offset = wal.commits[0].frames[0].offset

    # Corrupt one byte of the page_number field of the first frame
    _corrupt(wal_path, first_frame_offset + 3)

    wal = WAL(wal_path)
    assert wal.header_checksum_valid

    # All frames remain enumerable as raw evidence
    frames = list(wal.frames())
    assert len(frames) == num_frames

    # The rejection lands on the first frame and taints the rest of the chain
    assert not frames[0].valid
    assert wal.valid_frame_count == 0
    assert all(not frame.valid for frame in frames)

    # The good-looking commit markers do not count as commits
    assert any(frame.page_count > 0 and frame.salt_valid for frame in frames)
    assert wal.commits == []
    assert wal.checkpoints == []
    assert wal.highest_page_num == 0

    # The database view falls back to the checkpointed baseline
    assert _rows(db_path, wal_path) == expected[:2]


@pytest.mark.parametrize("endian", ["<", ">"], ids=["little-endian", "big-endian"])
def test_wal_corrupted_page_data(sample_db: tuple[Path, Path, list[tuple]], endian: str) -> None:
    """A single-byte corruption in the page data of the second transaction rejects
    exactly that transaction; the first transaction remains validly committed."""
    db_path, wal_path, expected = sample_db
    if endian == ">":
        wal_path.write_bytes(bytes(_rewrite_checksums(bytearray(wal_path.read_bytes()), ">")))

    wal = WAL(wal_path)
    commit1_size = len(wal.commits[0].frames)
    num_frames = len(list(wal.frames()))
    tx2_frame_offset = wal.commits[1].frames[0].offset

    # Corrupt one byte of the page data of the first frame of the second transaction
    _corrupt(wal_path, tx2_frame_offset + WAL_FRAME_HEADER_SIZE + 100)

    wal = WAL(wal_path)
    frames = list(wal.frames())
    assert len(frames) == num_frames

    # The first transaction is untouched, everything of the second transaction is rejected
    assert [frame.valid for frame in frames] == [True] * commit1_size + [False] * (num_frames - commit1_size)
    assert wal.valid_frame_count == commit1_size
    assert len(wal.commits) == 1

    # The commit marker of the corrupted transaction is rejected
    assert frames[-1].page_count > 0
    assert frames[-1].salt_valid
    assert not frames[-1].valid

    assert _rows(db_path, wal_path) == expected[:3]

    # SQLite itself agrees with this view of the corrupted WAL
    stdlib_db = db_path.with_name("stdlib.db")
    shutil.copyfile(db_path, stdlib_db)
    shutil.copyfile(wal_path, stdlib_db.with_name("stdlib.db-wal"))
    con = sqlite3.connect(stdlib_db)
    assert con.execute("SELECT id, val FROM t ORDER BY id").fetchall() == expected[:3]
    con.close()


def test_wal_truncated_mid_transaction(sample_db: tuple[Path, Path, list[tuple]]) -> None:
    """A WAL truncated in the middle of a transaction has no valid commit for that
    transaction. The leftover frames are still enumerable but not committed."""
    db_path, wal_path, expected = sample_db

    wal = WAL(wal_path)
    frames = list(wal.frames())
    commit1_size = len(wal.commits[0].frames)
    num_frames = len(frames)
    assert num_frames > commit1_size + 1  # the second transaction spans multiple frames

    # Cut the file in the middle of the page data of the last frame
    wal_path.write_bytes(wal_path.read_bytes()[: frames[-1].offset + WAL_FRAME_HEADER_SIZE + 100])

    wal = WAL(wal_path)
    frames = list(wal.frames())

    # The truncated frame is still enumerated as raw evidence but rejected
    assert len(frames) == num_frames
    assert [frame.valid for frame in frames] == [True] * (num_frames - 1) + [False]
    assert wal.valid_frame_count == num_frames - 1

    # Only the first transaction was committed
    assert len(wal.commits) == 1
    assert _rows(db_path, wal_path) == expected[:3]


def test_wal_missing_commit_marker(sample_db: tuple[Path, Path, list[tuple]]) -> None:
    """A WAL that breaks off right before the commit frame of a transaction contains
    valid but uncommitted frames, which must not show up in the database view."""
    db_path, wal_path, expected = sample_db

    wal = WAL(wal_path)
    frames = list(wal.frames())
    commit1_size = len(wal.commits[0].frames)
    assert frames[-1].page_count > 0  # last frame is the commit frame of transaction 2

    # Drop the commit frame entirely
    wal_path.write_bytes(wal_path.read_bytes()[: frames[-1].offset])

    wal = WAL(wal_path)
    frames = list(wal.frames())

    # The remaining frames of transaction 2 are valid but uncommitted
    assert [frame.valid for frame in frames] == [True] * (len(frames))
    assert wal.valid_frame_count == len(frames)
    assert len(frames) > commit1_size

    assert len(wal.commits) == 1
    assert _rows(db_path, wal_path) == expected[:3]


def test_wal_corrupted_header_checksum(sample_db: tuple[Path, Path, list[tuple]]) -> None:
    """A WAL with a corrupted header checksum has no valid frames at all, yielding a
    clear empty result instead of committed data."""
    db_path, wal_path, expected = sample_db

    num_frames = len(list(WAL(wal_path).frames()))

    # Corrupt one byte of the header checksum
    _corrupt(wal_path, 24)

    wal = WAL(wal_path)
    assert not wal.header_checksum_valid
    assert wal.valid_frame_count == 0
    assert wal.commits == []
    assert wal.checkpoints == []
    assert wal.highest_page_num == 0

    # Frames are still enumerable as raw evidence
    assert len(list(wal.frames())) == num_frames

    assert _rows(db_path, wal_path) == expected[:2]
