from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from dissect.database.sqlite3.sqlite3 import Provenance, SQLite3


def _build_wal_evidence(tmp_path: Path) -> Path:
    live_path = tmp_path / "evidence.db"
    conn = sqlite3.connect(live_path)
    conn.execute("PRAGMA journal_mode=WAL")
    cur = conn.cursor()
    cur.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, label TEXT)")
    cur.executemany("INSERT INTO evidence(label) VALUES (?)", [("alpha",), ("beta",)])
    conn.commit()

    cur.execute("ALTER TABLE evidence ADD COLUMN note TEXT DEFAULT 'legacy-note'")
    conn.commit()

    cur.execute("UPDATE evidence SET note = ? WHERE id = 1", ("alpha-rewritten",))
    conn.commit()

    cur.execute("INSERT INTO evidence(id, label, note) VALUES (3, 'gamma', NULL)")
    conn.commit()

    # A clean close checkpoints the WAL and removes the sidecar, so capture the
    # main file and WAL while the connection is still open.
    captured = tmp_path / "captured.db"
    shutil.copyfile(live_path, captured)
    shutil.copyfile(live_path.with_name("evidence.db-wal"), tmp_path / "captured.db-wal")
    conn.close()
    return captured


def test_wal_commit_views_are_isolated(tmp_path: Path) -> None:
    db_path = _build_wal_evidence(tmp_path)
    wal_path = tmp_path / "captured.db-wal"

    db = SQLite3(db_path)
    assert db.wal is not None
    commits = db.wal.commits
    # commit#0 is the empty journal-mode switch; the data transactions are #1-#4.
    assert len(commits) == 5

    # Commit 1: original two-column schema, only the two pre-alter rows.
    view0 = SQLite3(db_path, wal_path, commits[1])
    table0 = view0.table("evidence")
    assert [column.name for column in table0.columns] == ["id", "label"]
    assert [row._cell.key for row in table0.rows()] == [1, 2]

    # Commit 2: the ADD COLUMN is visible; old rows gain a synthesized default
    # but the later-update / later-insert rows must not leak into this view.
    view1 = SQLite3(db_path, wal_path, commits[2])
    table1 = view1.table("evidence")
    assert [column.name for column in table1.columns] == ["id", "label", "note"]
    rows1 = list(table1.rows())
    assert [row._cell.key for row in rows1] == [1, 2]
    assert all(row.provenance("note") == Provenance.DEFAULT for row in rows1)

    # Commit 3: the UPDATE is materialized into physical bytes on row 1.
    view2 = SQLite3(db_path, wal_path, commits[3])
    rows2 = {row._cell.key: row for row in view2.table("evidence").rows()}
    assert rows2[1].provenance("note") == Provenance.STORED
    assert rows2[1].get("note") == "alpha-rewritten"
    assert rows2[2].provenance("note") == Provenance.DEFAULT

    # Commit 4 (head): the new explicit-NULL row is present and its stored NULL
    # is distinguished from a reader-synthesized default.
    view3 = SQLite3(db_path, wal_path, commits[4])
    rows3 = {row._cell.key: row for row in view3.table("evidence").rows()}
    assert sorted(rows3) == [1, 2, 3]
    assert rows3[3].provenance("note") == Provenance.STORED
    assert rows3[3].get("note") is None
    db.close()


def test_default_value_not_reported_as_stored_bytes(tmp_path: Path) -> None:
    db_path = _build_wal_evidence(tmp_path)

    db = SQLite3(db_path)
    table = db.table("evidence")
    row_beta = next(row for row in table.rows() if row._cell.key == 2)

    # The pre-alter row physically holds only two record fields (id alias + label);
    # the note column exists solely because of the current schema DEFAULT.
    assert len(row_beta._cell.values) == 2
    assert row_beta.get("note") == "legacy-note"
    assert row_beta.provenance("note") == Provenance.DEFAULT
    assert row_beta.provenance("id") == Provenance.ROWID
    assert row_beta.provenance("label") == Provenance.STORED
    db.close()
