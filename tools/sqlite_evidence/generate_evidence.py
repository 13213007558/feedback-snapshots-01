"""Generate offline SQLite evidence demonstrating ALTER TABLE / schema evolution.

The generated databases are never opened by a *live* SQLite engine again in the
diagnostic pipeline; only dissect.database parses the captured bytes. Every
snapshot is a self-contained forensic artifact (main file + WAL sidecar).

Stages captured (``evidence`` table):

  S0  create table, insert old rows; force WAL mode and commit
  S1  ALTER TABLE ADD COLUMN note TEXT DEFAULT 'legacy-note'   (constant default)
      ALTER TABLE ADD COLUMN flag INTEGER DEFAULT 7             (constant default)
  S2  UPDATE a pre-alter row so a defaulted column is physically written
  S3  insert a fully-populated row and a row that stores an explicit NULL
      in a column that also has a DEFAULT (these must not be conflated)
  S4  ALTER TABLE ADD COLUMN extra TEXT DEFAULT ('XX')          (parenthesized literal)

SQLite rejects ``ALTER TABLE ... DEFAULT <non-constant expression>`` outright
("Cannot add a column with non-constant default"), so an expression default can
only appear on a table at CREATE time. A separate table (``exprdefault``)
covers that case; SQLite materializes such values into every existing row.

A second table (``blobdefault``) demonstrates a BLOB literal default
(``DEFAULT x'2a2b'``) and a third (``nodefault``) an ADD COLUMN with no
DEFAULT at all.
"""
from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"


def _snapshot(conn: sqlite3.Connection, path: Path, tag: str) -> None:
    # Copy while the connection is open so the WAL sidecar is preserved exactly.
    shutil.copyfile(path, EVIDENCE_DIR / f"{tag}.db")
    shutil.copyfile(path.with_name(path.name + "-wal"), EVIDENCE_DIR / f"{tag}.db-wal")


def build(path: Path) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    for old in EVIDENCE_DIR.glob("*.db*"):
        old.unlink()

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    cur = conn.cursor()

    # ---- S0: original schema, two rows written before any ALTER ----
    cur.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, label TEXT NOT NULL)")
    cur.executemany("INSERT INTO evidence(label) VALUES (?)", [("alpha",), ("beta",)])
    conn.commit()
    _snapshot(conn, path, "s0_pre_alter")

    # ---- S1: add columns with *constant* defaults; old rows are not rewritten ----
    cur.execute("ALTER TABLE evidence ADD COLUMN note TEXT DEFAULT 'legacy-note'")
    cur.execute("ALTER TABLE evidence ADD COLUMN flag INTEGER DEFAULT 7")
    conn.commit()
    _snapshot(conn, path, "s1_add_const_defaults")

    # ---- S2: materialize a default into physical bytes on one old row ----
    cur.execute("UPDATE evidence SET note = ? WHERE id = 1", ("alpha-rewritten",))
    conn.commit()
    _snapshot(conn, path, "s2_update_materializes_default")

    # ---- S3: new row fully populated; another row stores an explicit NULL ----
    cur.execute("INSERT INTO evidence(id, label, note, flag) VALUES (3, 'gamma', 'gamma-note', 9)")
    cur.execute("INSERT INTO evidence(id, label, note) VALUES (4, 'delta', NULL)")
    conn.commit()
    _snapshot(conn, path, "s3_insert_explicit_null")

    # ---- S4: add a column whose default is a parenthesized constant literal ----
    cur.execute("ALTER TABLE evidence ADD COLUMN extra TEXT DEFAULT ('XX')")
    conn.commit()
    _snapshot(conn, path, "s4_add_expression_default")

    # Expression default can only be set at CREATE time; existing rows are
    # physically rewritten to hold the evaluated expression.
    cur.execute("CREATE TABLE exprdefault (id INTEGER PRIMARY KEY, tag TEXT DEFAULT (upper('z')))")
    cur.execute("INSERT INTO exprdefault(id) VALUES (1)")
    conn.commit()

    # BLOB literal constant default (parser corner case: x'...' literal).
    cur.execute("CREATE TABLE blobdefault (id INTEGER PRIMARY KEY, payload BLOB DEFAULT x'2a2b')")
    cur.execute("INSERT INTO blobdefault(id) VALUES (1)")
    conn.commit()

    # Third table: added column without any default -> physical missing = SQL NULL.
    cur.execute("CREATE TABLE nodefault (id INTEGER PRIMARY KEY, label TEXT)")
    cur.execute("INSERT INTO nodefault(label) VALUES ('before')")
    cur.execute("ALTER TABLE nodefault ADD COLUMN added TEXT")
    cur.execute("INSERT INTO nodefault(label) VALUES ('after')")
    conn.commit()
    _snapshot(conn, path, "s5_extra_tables")

    conn.close()


if __name__ == "__main__":
    db_path = EVIDENCE_DIR / "evidence.db"
    build(db_path)
    print("Generated evidence in", EVIDENCE_DIR)
    for artifact in sorted(EVIDENCE_DIR.glob("*.db*")):
        print(" ", artifact.name, artifact.stat().st_size, "bytes")
