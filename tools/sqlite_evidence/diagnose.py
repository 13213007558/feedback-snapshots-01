"""Offline forensic diagnostic for SQLite schema evolution / ALTER TABLE.

For every captured snapshot this tool reports, per row and per column:

  * the fields that are *physically present* in the record bytes (serial types
    and decoded values), read by an independent stdlib-only verifier;
  * the schema (CREATE TABLE text + parsed columns/defaults) used to interpret
    those bytes, taken from the page-1 sqlite_master of the exact view;
  * how dissect.database obtained each rendered value (stored / synthesized
    DEFAULT / rowid alias / indeterminate NULL / unknown physical field);
  * an explicit agreement check between the independent reader and dissect.

It runs fully offline against the captured ``*.db`` / ``*.db-wal`` artifacts and
never opens them with a live SQLite engine.

Usage:
    python tools/sqlite_evidence/diagnose.py [--table evidence] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dissect.database.sqlite3.sqlite3 import Provenance, SQLite3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from raw_verifier import parse_table_rootpage, read_wal_commits  # noqa: E402

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence"

# Snapshots in acquisition order.
SNAPSHOTS = [
    "s0_pre_alter",
    "s1_add_const_defaults",
    "s2_update_materializes_default",
    "s3_insert_explicit_null",
    "s4_add_expression_default",
    "s5_extra_tables",
]


def _value_repr(value: object) -> str:
    if isinstance(value, bytes):
        return "x'" + value.hex() + "'"
    return repr(value)


def _build_page_provider(db: SQLite3):
    """Return a get_page callable bound to a dissect point-in-time view."""

    def get_page(page_num: int):
        return db.raw_page(page_num)

    return get_page


def diagnose_snapshot(tag: str, table_name: str) -> dict:
    db_path = EVIDENCE_DIR / f"{tag}.db"
    report = {"snapshot": tag, "views": []}

    db = SQLite3(db_path)
    if not db.wal:
        db.close()
        return report

    wal_info, raw_commits = read_wal_commits(db_path.with_name(db_path.name + "-wal"), db.page_size)
    report["wal_salt"] = list(wal_info["salt"])
    report["wal_commit_count"] = len(db.wal.commits)

    # One view per physical WAL commit: this is the true point-in-time
    # reconstruction, plus the latest (head) view for comparison.
    views = [(f"commit#{c.index}", c) for c in db.wal.commits]
    for view_name, commit in views:
        view = SQLite3(db_path, db_path.with_name(db_path.name + "-wal"), commit)
        table = view.table(table_name)
        if table is None:
            view.close()
            continue

        schema_sql = " ".join(table.sql.split())
        columns = [
            {
                "name": col.name,
                "default_value": col.default_value,
                "default_is_expression": col.default_is_expression,
            }
            for col in table.columns
        ]

        # Independent ground truth from raw bytes, using the same page view.
        raw_records = parse_table_rootpage(
            table.page, _build_page_provider(view), f"wal-{view_name}"
        )
        raw_by_rowid = {rec.rowid: rec for rec in raw_records}

        rows_out = []
        for row in table.rows():
            rowid = row._cell.key
            raw = raw_by_rowid.get(rowid)
            physical = (
                {
                    "field_count": raw.physical_field_count,
                    "serial_types": list(raw.serial_types),
                    "values": [_safe(v) for v in raw.values],
                    "page": raw.page,
                    "cell_offset": raw.cell_offset,
                }
                if raw
                else None
            )
            explained = row.explain()
            rendered = {
                name: {
                    "value": _safe(info["value"]),
                    "provenance": info["provenance"].value,
                }
                for name, info in explained.items()
            }
            # Cross-check: number of physical fields equals number of STORED/ROWID
            # placeholder columns (ROWID columns consume the leading serial-type-0).
            stored_columns = [
                name
                for name, info in explained.items()
                if info["provenance"] in (Provenance.STORED, Provenance.ROWID)
            ]
            agree = raw is not None and raw.physical_field_count == len(
                row._cell.values
            )
            rows_out.append(
                {
                    "rowid": rowid,
                    "physical_record": physical,
                    "rendered": rendered,
                    "unknown_physical_fields": list(row._unknowns),
                    "cross_check_field_count_agrees": agree,
                    "physical_field_columns": stored_columns,
                }
            )

        report["views"].append(
            {
                "view": view_name,
                "pages_in_commit": sorted(f.page_number for f in commit.frames),
                "schema_sql": schema_sql,
                "columns": columns,
                "rows": rows_out,
            }
        )
        view.close()

    db.close()
    return report


def _safe(value: object):
    if isinstance(value, bytes):
        return "x'" + value.hex() + "'"
    return value


def render_text(report: dict) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append(
        f"SNAPSHOT {report['snapshot']}  "
        f"(WAL commits={report['wal_commit_count']}, salt={report['wal_salt']})"
    )
    seen_signatures: set[tuple] = set()
    for view in report["views"]:
        signature = (
            view["schema_sql"],
            tuple(view["pages_in_commit"]),
            tuple(
                (r["rowid"], tuple(r["physical_record"]["serial_types"])) for r in view["rows"]
            ),
        )
        duplicate = signature in seen_signatures
        seen_signatures.add(signature)
        if duplicate:
            lines.append("-" * 78)
            lines.append(
                f"VIEW {view['view']}  pages_in_commit={view['pages_in_commit']}  "
                "(identical state, skipped)"
            )
            continue
        lines.append("-" * 78)
        lines.append(f"VIEW {view['view']}  pages_in_commit={view['pages_in_commit']}")
        lines.append(f"  SCHEMA (interprets this view): {view['schema_sql']}")
        lines.append("  COLUMN DEFAULTS (from current schema text):")
        for col in view["columns"]:
            if col["default_is_expression"]:
                kind = "EXPRESSION(indeterminate)"
            elif col["default_value"] is None:
                kind = "no default"
            else:
                kind = "constant"
            lines.append(
                f"    - {col['name']:<8} default={_value_repr(col['default_value']):<18} ({kind})"
            )
        for row in view["rows"]:
            phys = row["physical_record"]
            lines.append(
                f"  ROW rowid={row['rowid']}  PHYSICAL fields={phys['field_count']} "
                f"serial_types={phys['serial_types']} values={phys['values']} "
                f"@page{phys['page']}:0x{phys['cell_offset']:x}"
            )
            for name, info in row["rendered"].items():
                marker = {
                    "stored": "PHYSICAL ",
                    "rowid": "ROWID    ",
                    "default": "SYNTH    ",
                    "null": "NULL?    ",
                    "unknown": "UNKNOWN  ",
                }[info["provenance"]]
                lines.append(
                    f"      {marker} {name:<8} = {_value_repr(info['value']):<16} [{info['provenance']}]"
                )
            if row["unknown_physical_fields"]:
                lines.append(
                    "      !! UNKNOWN physical fields without schema column: "
                    f"{row['unknown_physical_fields']}"
                )
            lines.append(
                f"      cross-check field count agrees: {row['cross_check_field_count_agrees']}"
            )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default="evidence")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    full = []
    for tag in SNAPSHOTS:
        report = diagnose_snapshot(tag, args.table)
        full.append(report)
        if not args.as_json:
            print(render_text(report))

    if args.as_json:
        print(json.dumps(full, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
