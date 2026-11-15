from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import sqlite3
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


def test_wal_checkpoint_view_isolation(tmp_path: Path) -> None:
    """A checkpoint view must not leak pages from later commits.

    When a specific WAL checkpoint is requested, pages not contained in that
    checkpoint must be resolved from earlier commits or the main database file,
    never from commits that came after the checkpoint. Otherwise future schema
    versions (e.g. columns added by a later ALTER TABLE) would be mixed into a
    historical view.
    """
    import shutil
    import sqlite3 as pysqlite3

    from dissect.database.sqlite3.wal import WAL

    db_path = tmp_path / "evidence.db"
    con = pysqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA wal_autocheckpoint=0;")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, b TEXT);")
    con.execute("INSERT INTO t VALUES (1, 'old');")
    con.commit()
    con.execute("ALTER TABLE t ADD COLUMN c TEXT DEFAULT 'dflt';")
    con.commit()
    con.execute("INSERT INTO t VALUES (2, 'new', 'real');")
    con.commit()

    # Freeze the database and WAL before closing checkpoints the WAL away.
    frozen_db = tmp_path / "frozen.db"
    shutil.copy(db_path, frozen_db)
    shutil.copy(db_path.with_name(f"{db_path.name}-wal"), frozen_db.with_name(f"{frozen_db.name}-wal"))
    con.close()

    wal = WAL(frozen_db.with_name(f"{frozen_db.name}-wal"))
    commits = wal.commits
    # Commits: 1) CREATE TABLE, 2) first INSERT, 3) ALTER TABLE, 4) second INSERT
    assert len(commits) == 4

    # View at commit #2 (before the ALTER TABLE): the future column "c" must not appear.
    db = sqlite3.SQLite3(frozen_db, wal=wal, checkpoint=commits[1])
    table = db.table("t")
    assert [column.name for column in table.columns] == ["id", "b"]
    rows = list(table.rows())
    assert len(rows) == 1
    assert rows[0].id == 1
    assert rows[0].b == "old"
    assert {key: value for key, value in rows[0]} == {"id": 1, "b": "old"}

    # View at commit #3 (right after the ALTER TABLE): one row, "c" filled from the
    # schema default because the old record physically stores only two values.
    db = sqlite3.SQLite3(frozen_db, wal=wal, checkpoint=commits[2])
    table = db.table("t")
    assert [column.name for column in table.columns] == ["id", "b", "c"]
    rows = list(table.rows())
    assert len(rows) == 1
    assert rows[0].c == "dflt"
    assert len(rows[0]._cell.values) == 2  # the default is not in the record bytes

    # Latest view: both rows, default only for the old record.
    db = sqlite3.SQLite3(frozen_db, wal=wal)
    rows = list(db.table("t").rows())
    assert [(row.id, row.b, row.c) for row in rows] == [(1, "old", "dflt"), (2, "new", "real")]
