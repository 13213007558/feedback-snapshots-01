"""Offline diagnostic: how ALTER TABLE schema changes affect forensic
interpretation of SQLite records with dissect.database.

Scenario (all in WAL mode, no checkpoint -> everything lives in the WAL):
  tx1: CREATE TABLE t(id INTEGER PRIMARY KEY, b TEXT); INSERT id=1,2   (old schema)
  tx2: ALTER TABLE t ADD COLUMN c TEXT DEFAULT 'dflt'                  (schema change)
  tx3: INSERT id=3 with explicit NULL in c
  tx4: INSERT id=4 with real value in c
  tx5: ALTER TABLE t ADD COLUMN d INTEGER DEFAULT 99                   (2nd schema change)
  tx6: INSERT id=5 with real values in c and d

Views compared:
  A. main file only (WAL removed)         -> what was checkpointed into the db
  B. main file + WAL (latest)             -> what SQLite itself would show today
  C. main file + WAL at each WAL commit   -> historical states (forensic timeline)

For every row we report, per field, the PROVENANCE:
  PHYSICAL        value decoded from the record bytes (serial type in record header)
  ROWID-ALIAS     INTEGER PRIMARY KEY: record stores NULL, real value is the b-tree key
  PARSER-DEFAULT  column missing from record bytes; filled from CURRENT schema DEFAULT
  ABSENT          column missing from record bytes; schema has no DEFAULT (NULL)
  n/a             column not present in the schema used for this view
"""
from __future__ import annotations

import shutil
import sqlite3 as pysqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dissect.database.sqlite3.sqlite3 import Row, SQLite3, walk_tree
from dissect.database.sqlite3.wal import WAL

STEPS = [
    ("tx1", "CREATE TABLE t(id INTEGER PRIMARY KEY, b TEXT);"
            "INSERT INTO t VALUES (1, 'old-1');"
            "INSERT INTO t VALUES (2, 'old-2');"),
    ("tx2", "ALTER TABLE t ADD COLUMN c TEXT DEFAULT 'dflt';"),
    ("tx3", "INSERT INTO t(id, b, c) VALUES (3, 'new-3', NULL);"),
    ("tx4", "INSERT INTO t(id, b, c) VALUES (4, 'new-4', 'real-4');"),
    ("tx5", "ALTER TABLE t ADD COLUMN d INTEGER DEFAULT 99;"),
    ("tx6", "INSERT INTO t VALUES (5, 'new-5', 'real-5', 555);"),
]


def build(workdir: Path) -> tuple[Path, Path]:
    db_path = workdir / "evidence.db"
    con = pysqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA wal_autocheckpoint=0;")  # keep everything in the WAL
    for _, sql in STEPS:
        for stmt in sql.split(";"):
            stmt = stmt.strip()
            if stmt:
                con.execute(stmt)
        con.commit()
    # Freeze a forensic copy while the connection is still open (closing the
    # last connection would checkpoint and delete the WAL).
    frozen_db = workdir / "frozen.db"
    shutil.copy(db_path, frozen_db)
    shutil.copy(Path(str(db_path) + "-wal"), Path(str(frozen_db) + "-wal"))
    con.close()
    # The main file as it was BEFORE any checkpoint: the frozen db without its WAL.
    main_only = workdir / "main_only.db"
    shutil.copy(frozen_db, main_only)
    return frozen_db, main_only


def provenance(table, cell, row) -> list[str]:
    cols = [c.name for c in table.columns]
    physical = cell.values
    lines = []
    for idx, name in enumerate(cols):
        value = row._values.get(name)
        if idx < len(physical):
            if name == table.primary_key and physical[idx] is None and cell.key is not None:
                lines.append(f"    {name:>4} = {value!r:12} ROWID-ALIAS   (record stores NULL, key={cell.key})")
            else:
                lines.append(f"    {name:>4} = {value!r:12} PHYSICAL      (serial type {cell.types[idx]})")
        else:
            col = table.columns[idx]
            tag = "PARSER-DEFAULT" if col.default_value is not None else "ABSENT->NULL   "
            lines.append(f"    {name:>4} = {value!r:12} {tag} (not in record bytes)")
    for value in row._unknowns:
        lines.append(f"    ???? = {value!r:12} UNKNOWN       (in record bytes, no column in this schema)")
    return lines


def dump_view(title: str, db: SQLite3) -> None:
    print(f"\n=== {title} ===")
    tables = list(db.tables())
    if not tables:
        print("  (no user tables visible in this view)")
        return
    for table in tables:
        ncols = len(table.columns)
        print(f"  schema[{table.name}] ({ncols} cols): {table.sql.strip()}")
        for cell in walk_tree(db, db.page(table.page)):
            row = Row(table, cell)
            print(f"  rowid={cell.key} page={cell.page.num} record serial types={cell.types} "
                  f"({len(cell.values)} physical value(s) vs {ncols} schema column(s))")
            for line in provenance(table, cell, row):
                print(line)


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="sqlite-schema-evol-"))
    db_path, main_only = build(workdir)
    print(f"evidence built at: {db_path} (WAL size={Path(str(db_path) + '-wal').stat().st_size} bytes)")

    # View A: main file only, no WAL.
    dump_view("VIEW A: main file only (no WAL)", SQLite3(main_only))

    # View B: main + WAL, latest state.
    dump_view("VIEW B: main file + WAL (latest committed state)", SQLite3(db_path))

    # View C: historical state at each WAL commit.
    wal = WAL(Path(str(db_path) + "-wal"))
    print(f"\nWAL commits: {len(wal.commits)} commit(s), "
          f"checkpoint epochs (salt1 dedup): {len(wal.checkpoints)}")
    for idx, commit in enumerate(wal.commits):
        pages = sorted({f.page_number for f in commit.frames})
        dump_view(f"VIEW C{idx + 1}: state at WAL commit #{idx + 1} "
                  f"(frames touch pages {pages})",
                  SQLite3(db_path, wal=wal, checkpoint=commit))


if __name__ == "__main__":
    main()
