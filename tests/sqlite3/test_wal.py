from __future__ import annotations

import hashlib
import shutil
import sqlite3 as sqlite3_stdlib
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
        >>> con = sqlite3_stdlib.connect("tests/_data/sqlite3/page_count.db")
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


def _build_commit_history(path: Path) -> list[tuple[str, str, int]]:
    """Create a WAL database with three commits that touch different pages and shrink on every commit.

    Returns the expected table value and page count after every commit.
    """
    con = sqlite3_stdlib.connect(path, isolation_level=None)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA auto_vacuum=FULL")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=-1")

    for name in ("alpha", "beta", "gamma"):
        con.execute(f"CREATE TABLE {name}(id INTEGER PRIMARY KEY, value TEXT)")
    con.execute("CREATE TABLE bulk(id INTEGER PRIMARY KEY, tag TEXT, payload BLOB)")

    con.execute("BEGIN")
    for i in range(1, 91):
        con.execute("INSERT INTO bulk VALUES (?, ?, ?)", (i, f"bulk-{i:03}", bytes([i % 251]) * 1000))
    for name in ("alpha", "beta", "gamma"):
        con.execute(f"INSERT INTO {name} VALUES (1, ?)", (f"{name}-base",))
    con.execute("COMMIT")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    expected = []
    snapshots = []
    commits = [
        ("alpha", "UPDATE alpha SET value = 'alpha-commit-0' WHERE id = 1", 1, 30),
        ("beta", "UPDATE beta SET value = 'beta-commit-1' WHERE id = 1", 31, 60),
        ("gamma", "UPDATE gamma SET value = 'gamma-commit-2' WHERE id = 1", 61, 90),
    ]

    for index, (table, statement, low, high) in enumerate(commits):
        con.execute("BEGIN")
        con.execute(statement)
        if index == 1:
            # A schema change in the middle commit must only be visible from that commit onwards.
            con.execute("CREATE TABLE delta(id INTEGER PRIMARY KEY, value TEXT)")
            con.execute("INSERT INTO delta VALUES (1, 'delta-commit-1')")
        con.execute("DELETE FROM bulk WHERE id BETWEEN ? AND ?", (low, high))
        con.execute("COMMIT")

        expected.append((table, f"{table}-commit-{index}", con.execute("PRAGMA page_count").fetchone()[0]))

        # Capture an independent oracle of the logical content at this commit.
        snapshot = path.with_name(f"snapshot-{index}.sqlite")
        con.execute("VACUUM INTO ?", (str(snapshot),))
        snapshots.append(
            {
                name: con.execute(f"SELECT * FROM {name} ORDER BY id").fetchall()
                for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            }
        )

    # Copy the files before closing because SQLite removes the WAL when the last connection closes.
    copy = path.with_name("captured.sqlite")
    shutil.copyfile(path, copy)
    shutil.copyfile(path.with_name(f"{path.name}-wal"), copy.with_name(f"{copy.name}-wal"))
    con.close()

    return copy, expected, snapshots


@pytest.fixture()
def commit_history(tmp_path: Path) -> tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]]:
    return _build_commit_history(tmp_path / "history.sqlite")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_wal_commit_views(
    commit_history: tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]],
) -> None:
    """Test that commit views expose exactly the logical content of each historical commit, out of order."""
    path, expected, snapshots = commit_history
    digests = _digest(path), _digest(path.with_name(f"{path.name}-wal"))

    db = sqlite3.SQLite3(path)
    assert len(db.wal.commits) == 3

    for indices in ((2, 0, 1), (1, 2, 0)):
        for index in indices:
            view = db.commit_view(index)
            _, value, page_count = expected[index]
            assert view.commit.index == index
            assert view.page_count == page_count

            # Every table must match the independent snapshot of this commit byte for byte.
            snapshot = snapshots[index]
            view_tables = {table.name for table in view.tables()}
            assert view_tables == set(snapshot)
            for name, rows in snapshot.items():
                table = view.table(name)
                columns = [column.name for column in table.columns]
                assert [tuple(row[column] for column in columns) for row in table.rows()] == rows

            # Targeted checks so a failure is readable.
            assert view.table(expected[index][0]).row(0).value == value
            assert len(list(view.table("bulk").rows())) == 30 * (2 - index)

            # Every page in the view has a source, and that source is visible at this commit.
            for page in range(1, view.page_count + 1):
                source = view.page_source(page)
                assert source.page_number == page
                assert source.kind in (sqlite3.PageSource.WAL, sqlite3.PageSource.DATABASE)
                if source.kind == sqlite3.PageSource.WAL:
                    assert source.commit_index is not None
                    assert source.commit_index <= index
                    assert source.frame.page_number == page
                    assert source.frame_index == db.wal.frame_index(source.frame)
                else:
                    assert source.frame_index is None
                    assert source.commit_index is None

            assert [source.page_number for source in view.page_sources()] == list(range(1, page_count + 1))

            # Old tail pages that were removed by a shrinking commit no longer belong to this view.
            with pytest.raises(sqlite3.InvalidPageNumber):
                view.page(page_count + 1)
            with pytest.raises(sqlite3.InvalidPageNumber):
                view.page_source(page_count + 1)

    assert (_digest(path), _digest(path.with_name(f"{path.name}-wal"))) == digests


def test_wal_commit_view_page_sources(
    commit_history: tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]],
) -> None:
    """Each page of a commit view must resolve to the newest version visible at that commit, never a later one."""
    path, _, _ = commit_history
    db = sqlite3.SQLite3(path)

    sources = [{page: db.commit_view(index).page_source(page) for page in range(1, 8)} for index in range(3)]

    # alpha is written in commit 0 and stays at that version in all later views.
    assert sources[0][3].kind == sqlite3.PageSource.WAL
    assert sources[0][3].commit_index == 0
    assert sources[1][3] == sources[0][3]
    assert sources[2][3] == sources[0][3]

    # beta is only written in commit 1; earlier views must read the database file, not the future frame.
    assert sources[0][4].kind == sqlite3.PageSource.DATABASE
    assert sources[1][4].kind == sqlite3.PageSource.WAL
    assert sources[1][4].commit_index == 1
    assert sources[2][4] == sources[1][4]

    # gamma is only written in commit 2; the first two views must not see it.
    assert sources[0][5].kind == sqlite3.PageSource.DATABASE
    assert sources[1][5].kind == sqlite3.PageSource.DATABASE
    assert sources[2][5].kind == sqlite3.PageSource.WAL
    assert sources[2][5].commit_index == 2

    # Every commit updates the change counter on page 1, so each view sees the version from its own commit.
    for index in range(3):
        assert sources[index][1].kind == sqlite3.PageSource.WAL
        assert sources[index][1].commit_index == index

    # Every WAL source in a view points at or before that view's commit.
    for index, page_sources in enumerate(sources):
        for source in page_sources.values():
            if source.kind == sqlite3.PageSource.WAL:
                assert source.commit_index is not None
                assert source.commit_index <= index


def test_wal_commit_views_are_isolated(
    commit_history: tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]],
) -> None:
    """Views must not share page caches, schema objects or row objects with each other or the latest database."""
    path, expected, _ = commit_history
    db = sqlite3.SQLite3(path)

    first = db.commit_view(0)
    last = db.commit_view(2)

    assert first.page is not last.page
    assert first.page(3) is not last.page(3)

    first_tables = {table.name: table for table in first.tables()}
    last_tables = {table.name: table for table in last.tables()}
    assert "delta" not in first_tables
    assert "delta" in last_tables
    assert first_tables["alpha"] is not last_tables["alpha"]

    first_row = first_tables["alpha"].row(0)
    last_row = last_tables["alpha"].row(0)
    assert first_row is not last_row
    assert first_row.value == "alpha-commit-0"
    assert last_row.value == "alpha-commit-0"
    assert first_tables["beta"].row(0).value == "beta-base"
    assert last_tables["beta"].row(0).value == "beta-commit-1"


def test_wal_commit_views_do_not_modify_inputs(
    commit_history: tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]],
) -> None:
    path, _, _ = commit_history
    wal = path.with_name(f"{path.name}-wal")
    digests = _digest(path), _digest(wal)

    for _ in range(3):
        db = sqlite3.SQLite3(path)
        views = list(db.commit_views())
        assert len(views) == 3
        for view in views:
            for table in view.tables():
                list(table.rows())
        db.close()

    assert (_digest(path), _digest(wal)) == digests


def test_wal_commit_view_requires_wal(sqlite_db: Path) -> None:
    db = sqlite3.SQLite3(sqlite_db, wal=None)
    db.wal = None

    with pytest.raises(sqlite3.NoWriteAheadLog):
        db.commit_view(0)

    assert list(db.commit_views()) == []


def test_wal_commit_view_by_object(
    commit_history: tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]],
) -> None:
    """A view can be created from a Commit object as well as from an index."""
    path, _, _ = commit_history
    db = sqlite3.SQLite3(path)

    commit = db.wal.commits[1]
    view = db.commit_view(commit)
    assert view.commit is commit
    assert view.page_count == commit.page_count

    # Commits from another WAL are rejected.
    other = sqlite3.SQLite3(absolute_path("_data/sqlite3/test.sqlite"))
    with pytest.raises(ValueError, match="does not belong"):
        db.commit_view(other.wal.commits[0])

    # Out-of-range indices are rejected.
    with pytest.raises(IndexError, match="out of range"):
        db.commit_view(3)


def test_wal_commit_view_independent_caches(
    commit_history: tuple[Path, list[tuple[str, str, int]], list[dict[str, list[tuple]]]],
) -> None:
    """Each view must have its own page cache, so reading one view cannot change another."""
    path, _, _ = commit_history
    db = sqlite3.SQLite3(path)

    view = db.commit_view(0)
    first_page = view.page(3)
    assert view.page(3) is first_page
    assert list(view.page_sources())[2].commit_index == 0

    other = db.commit_view(0)
    assert other.page is not view.page
    assert other.page(3) is not first_page
    assert other.page(3).data == first_page.data

    # The latest database view has its own cache and still sees the newest page contents.
    assert db.page(3) is not first_page
    assert db.page(3).data != first_page.data or db.page_source(3) == view.page_source(3)


def test_wal_commit_views_skip_superseded_generations(tmp_path: Path) -> None:
    """Frames left over from before a WAL reset must not be offered as historical commit views."""
    path = tmp_path / "reset.sqlite"
    con = sqlite3_stdlib.connect(path, isolation_level=None)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=-1")
    con.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT)")

    con.execute("BEGIN")
    for i in range(1, 501):
        con.execute("INSERT INTO items VALUES (?, ?)", (i, "X" * 200))
    con.execute("COMMIT")

    # Advance the WAL past its first generation and checkpoint, after which a reset reuses the file start.
    for i in range(1, 4):
        con.execute("UPDATE items SET value = ? WHERE id = 1", (f"old-{i}",))
        con.execute("PRAGMA wal_checkpoint(PASSIVE)")
    for i in range(1, 3):
        con.execute("UPDATE items SET value = ? WHERE id = 1", (f"new-{i}",))

    copy = tmp_path / "captured.sqlite"
    shutil.copyfile(path, copy)
    shutil.copyfile(path.with_name(f"{path.name}-wal"), copy.with_name(f"{copy.name}-wal"))
    con.close()

    db = sqlite3.SQLite3(copy)
    assert db.wal
    assert len(db.wal.commits) > len(db.wal.valid_commits)
    assert [commit.index for commit in db.wal.commits] == list(range(len(db.wal.valid_commits))) + [-1] * (
        len(db.wal.commits) - len(db.wal.valid_commits)
    )

    # Only usable commits are addressable and every one of them is internally consistent.
    views = list(db.commit_views())
    assert len(views) == len(db.wal.valid_commits)
    for view in views:
        assert view.commit.index >= 0
        list(view.tables())

    with pytest.raises(IndexError, match="out of range"):
        db.commit_view(len(views))

    # A stale commit object is rejected instead of being silently resolved against the current main file.
    stale = db.wal.commits[-1]
    with pytest.raises(sqlite3.InvalidCommit):
        db.commit_view(stale)
