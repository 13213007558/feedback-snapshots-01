# SQLite `ALTER TABLE` schema-evolution forensic diagnostic

This package reproduces, entirely offline, how an `ALTER TABLE ... ADD COLUMN`
changes the interpretation of historical SQLite records, and proves which
values are physically stored in a record versus reconstructed by the reader.

It is built on `dissect.database` and adds an **independent, stdlib-only**
byte reader so the conclusions do not rely on a single parser.

## The core forensic fact

A SQLite record stores one serial-type/value pair **per column that had a value
at write time**. Adding a column with a *constant* default does **not** rewrite
existing rows:

- old records keep their original, shorter serial-type list;
- the default exists only in the current `CREATE TABLE` text in `sqlite_master`;
- a reader attaches the default when the record has fewer fields than the
  schema has columns.

Therefore a default shown for a pre-`ALTER` row is **not evidence that the
bytes were ever written**. Only after the row is rewritten (e.g. an `UPDATE`),
or the value is explicitly inserted, does the column appear in the record.

Two cases must not be conflated:

- an **explicit `NULL`** is a real field with serial type `0` (stored bytes);
- a **missing field** on an old row has no bytes at all; the value is either a
  synthesized `DEFAULT` or, with no default, an indeterminate SQL `NULL`.

SQLite also rejects `ALTER TABLE ... DEFAULT <non-constant expression>`
("Cannot add a column with non-constant default"). Non-constant expression
defaults can only be set at `CREATE TABLE` time, and SQLite then **materializes
the evaluated value into every existing row**, so the bytes are physically
present.

## Layout

- `generate_evidence.py` — builds the staged database and snapshots every
  transaction (main file + WAL sidecar) under `evidence/`.
- `raw_verifier.py` — independent stdlib-only b-tree/WAL/record reader used as
  ground truth; never imports `dissect`.
- `diagnose.py` — cross-validates `dissect.database` against the raw reader and
  emits a per-row, per-column provenance report (`REPORT.txt`, `REPORT.json`).
- `evidence/` — captured `*.db` / `*.db-wal` artifacts at each stage.
- `REPORT.txt` / `REPORT.json` — the generated line-by-line results.

## Run

```bash
python tools/sqlite_evidence/generate_evidence.py
python tools/sqlite_evidence/diagnose.py            # human-readable
python tools/sqlite_evidence/diagnose.py --json     # machine-readable
python tools/sqlite_evidence/diagnose.py --table nodefault
```

## Provenance labels

| Label     | Meaning                                                                 |
|-----------|-------------------------------------------------------------------------|
| `stored`  | A field exists in the record bytes (includes an explicit NULL, type 0). |
| `rowid`   | `INTEGER PRIMARY KEY` value taken from the b-tree rowid/cell key.       |
| `default` | No field in the record; value synthesized from the schema `DEFAULT`.    |
| `null`    | No field and no usable default; indeterminate, cannot be proven on disk.|
| `unknown` | Physical field with no matching column in the schema used to read it.   |

## Read-path defects found and fixed

1. **WAL point-in-time leakage** — pinning a view to an early `Commit` still
   scanned *all* later commits in `raw_page`, so rows/columns from future
   transactions leaked into historical views. A pinned commit now reconstructs
   exactly the cumulative frame state up to and including that commit
   (`dissect/database/sqlite3/sqlite3.py`, `wal.py`).
2. **No stored-vs-synthesized distinction** — `Row` silently filled missing
   fields from defaults with the same shape as stored data. It now tracks
   per-column `Provenance` (`Row.provenance`, `Row.explain`) and keeps extra
   physical fields in `Row._unknowns` instead of relabeling them.
3. **DEFAULT parsing gaps** — BLOB literals (`x'2a2b'`) were not decoded and
   the regex tokenizer produced garbage for parenthesized expressions. DEFAULT
   extraction is now depth/quote aware; BLOB literals decode to `bytes` and
   non-constant expressions are flagged (`Column.default_is_expression`) rather
   than misreported.
