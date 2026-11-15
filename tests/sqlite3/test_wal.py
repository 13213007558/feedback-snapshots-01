from __future__ import annotations

import hashlib
import shutil
import sqlite3 as stdlib_sqlite3
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


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _create_commit_history_db(directory: Path) -> tuple[Path, Path]:
    """Create a database with three consecutive WAL commits.

    The second commit adds a column with a default value, the third commit
    deletes a range of rows and shrinks the database. Test data is generated
    using the standard library only, so the fixture is fully reproducible.
    """
    db_path = directory / "commit_history.db"
    conn = stdlib_sqlite3.connect(db_path, isolation_level=None)

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("PRAGMA auto_vacuum=FULL")
    conn.execute("VACUUM")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, payload TEXT, marker TEXT)")

    conn.execute("BEGIN")
    for id_ in range(1, 81):
        conn.execute("INSERT INTO t VALUES (?, ?, ?)", (id_, "x" * 180, "initial"))
    conn.execute("COMMIT")

    # Move the initial contents into the main database file, so the WAL only
    # contains the three commits we want to inspect.
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # Commit 1: modify page 1 (schema) and add a row that allocates a new tail page.
    conn.execute("BEGIN")
    conn.execute("UPDATE t SET payload = ?, marker = 'c1' WHERE id = 1", ("a" * 300,))
    conn.execute("INSERT INTO t VALUES (1001, ?, 'c1')", ("n" * 400,))
    conn.execute("COMMIT")

    # Commit 2: change the schema and modify a data page.
    conn.execute("BEGIN")
    conn.execute("ALTER TABLE t ADD COLUMN note TEXT DEFAULT 'note'")
    conn.execute("UPDATE t SET payload = ?, marker = 'c2' WHERE id = 40", ("b" * 300,))
    conn.execute("COMMIT")

    # Commit 3: delete a range of rows, which shrinks the database.
    conn.execute("BEGIN")
    conn.execute("DELETE FROM t WHERE id BETWEEN 20 AND 60")
    conn.execute("COMMIT")

    # Copy the files while the connection is still open, because closing the
    # connection performs a checkpoint and removes the WAL.
    wal_path = directory / "commit_history.db-wal"
    shutil.copyfile(db_path, directory / "copy.db")
    shutil.copyfile(wal_path, directory / "copy.db-wal")

    conn.close()

    return directory / "copy.db", directory / "copy.db-wal"


@pytest.fixture
def commit_history_db(tmp_path: Path) -> tuple[Path, Path]:
    return _create_commit_history_db(tmp_path)


def test_wal_commit_views(commit_history_db: tuple[Path, Path]) -> None:
    """Open commit views out of order and verify the historical contents.

    Test data generated using:

        sqlite3.connect("commit_history.db", isolation_level=None)
        PRAGMA journal_mode=WAL
        PRAGMA wal_autocheckpoint=0
        PRAGMA auto_vacuum=FULL
        VACUUM
        CREATE TABLE t (id INTEGER PRIMARY KEY, payload TEXT, marker TEXT)
        -- insert 80 rows, COMMIT
        PRAGMA wal_checkpoint(TRUNCATE)
        -- commit 1: UPDATE id=1, INSERT id=1001
        -- commit 2: ALTER TABLE ADD COLUMN note TEXT DEFAULT 'note', UPDATE id=40
        -- commit 3: DELETE FROM t WHERE id BETWEEN 20 AND 60
        -- copy db and wal before closing the connection

    The second commit changes the schema and the third commit shrinks the
    database, so each view has to resolve untouched pages through the correct
    historical version and apply the page count of its own commit.
    """
    db_path, wal_path = commit_history_db
    digest_db = _digest(db_path)
    digest_wal = _digest(wal_path)

    db = sqlite3.SQLite3(db_path)
    assert db.wal
    assert len(db.wal.commits) == 3

    # Open the views in an arbitrary order to make sure they do not share state.
    views = [db.commit_view(i) for i in (2, 0, 1)]

    view_3, view_1, view_2 = views

    assert view_1.page_count == 8
    assert [column.name for column in view_1.table("t").columns] == ["id", "payload", "marker"]
    rows = list(view_1.table("t").rows())
    assert len(rows) == 81
    assert sorted({row.marker for row in rows}) == ["c1", "initial"]
    assert view_1.table("t").row(0).marker == "c1"

    assert view_2.page_count == 8
    assert [column.name for column in view_2.table("t").columns] == ["id", "payload", "marker", "note"]
    rows = list(view_2.table("t").rows())
    assert len(rows) == 81
    assert sorted({row.marker for row in rows}) == ["c1", "c2", "initial"]
    assert view_2.table("t").row(0).note == "note"

    assert view_3.page_count == 7
    assert [column.name for column in view_3.table("t").columns] == ["id", "payload", "marker", "note"]
    rows = list(view_3.table("t").rows())
    assert len(rows) == 40
    assert sorted({row.marker for row in rows}) == ["c1", "initial"]
    assert [row.id for row in rows if 20 <= row.id <= 60] == []
    assert view_3.table("t").row(0).marker == "c1"

    # The database and WAL are only read, never modified.
    assert _digest(db_path) == digest_db
    assert _digest(wal_path) == digest_wal


def test_wal_commit_view_page_sources(commit_history_db: tuple[Path, Path]) -> None:
    """Verify that every page in a commit view reports the correct source."""
    db_path, _ = commit_history_db
    db = sqlite3.SQLite3(db_path)
    commits = db.wal.commits
    assert len(commits) == 3

    view_1 = db.commit_view(0)
    view_2 = db.commit_view(1)
    view_3 = db.commit_view(2)

    # The first commit rewrote page 1, so it comes from its own commit.
    assert view_1.page_source(1).from_wal
    assert view_1.page_source(1).commit is commits[0]

    # Page 5 is untouched by the first commit and must come from the database file.
    assert view_1.page_source(5).from_database
    assert view_1.page_source(5).frame is None
    assert view_1.page_source(5).frame_index is None

    # The second commit rewrites the schema page and one data page. Page 2 is
    # untouched by the second commit and remains visible from commit 1.
    assert view_2.page_source(1).commit is commits[1]
    assert view_2.page_source(5).commit is commits[1]
    assert view_2.page_source(2).commit is commits[0]

    # The third commit shrinks the database. Old tail pages are no longer part
    # of this view, even though they are still present in the WAL.
    assert view_3.page_count == 7
    assert db.wal.commit_history(2).keys() == set(range(1, 8))
    with pytest.raises(sqlite3.InvalidPageNumber):
        view_3.page_source(8)
    assert all(view_3.page_source(num).commit is commits[2] for num in range(1, 8))

    # Every page in all views must be explained by either the database or a frame.
    for view in (view_1, view_2, view_3):
        for num in range(1, view.page_count + 1):
            source = view.page_source(num)
            assert (source.frame is None) == source.from_database
            assert (source.frame is not None) == source.from_wal

    # Rows and pages from different views are independent objects.
    assert view_1.table("t") is not view_2.table("t")
    assert view_1.page(1) is not view_2.page(1)
    assert view_1.page(1).data != view_3.page(1).data

    # Page caches are per view and never share Page instances.
    assert view_1.page(4) is not view_2.page(4)
    assert view_1.page(4) is view_1.page(4)

    # Schemas and row objects are bound to their own view.
    table_1 = view_1.table("t")
    table_2 = view_2.table("t")
    assert [column.name for column in table_1.columns] != [column.name for column in table_2.columns]
    row_1 = table_1.row(0)
    row_2 = table_2.row(0)
    assert row_1.get("note") is None
    assert row_2.get("note") == "note"
    assert row_1._table is table_1
    assert row_2._table is table_2
