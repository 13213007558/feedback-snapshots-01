"""Render the boundary matrix as a retained, reviewable size matrix.

Two renderers are provided: a fixed-width text table for quick review and a
CSV writer for archival. Each row records the plaintext/package/container
sizes, the FAT/DIFAT allocation, every independent check outcome and the
precise defect codes, so the matrix doubles as evidence for derived
encryption artifacts.
"""

from __future__ import annotations

import csv
import io

from .runner import RowResult, run_matrix

COLUMNS = [
    ("label", "label", 24),
    ("plaintext", "plaintext_size", 9),
    ("package", "package_size", 9),
    ("container", "file_size", 9),
    ("region", "region", 8),
    ("mini", "goes_mini", 5),
    ("FAT", "num_fat", 4),
    ("DIFAT", "num_difat", 5),
    ("segs", "segments", 5),
    ("struct", "structural_ok", 6),
    ("leak", "leak_ok", 6),
    ("bytes", "bytes_restored", 6),
    ("hmac", "integrity_ok", 6),
    ("passwd", "password_ok", 6),
    ("defects", "defect_codes", 30),
]


def _fmt(value):
    if isinstance(value, bool):
        # Generic booleans read as ok/FAIL; callers that want yes/no use _yn.
        return "ok" if value else "FAIL"
    if isinstance(value, list):
        return ",".join(value) if value else "-"
    return str(value)


def _yn(value):
    return "yes" if value else "no"


def render_text(rows: list[RowResult]) -> str:
    header = "  ".join(name.rjust(width) for name, _, width in COLUMNS)
    lines = [header, "-" * len(header)]
    for row in rows:
        cells = []
        for _, attr, width in COLUMNS:
            if attr == "goes_mini":
                text = _yn(getattr(row, attr))
            else:
                text = _fmt(getattr(row, attr))
            cells.append(text.rjust(width) if attr not in ("label", "defects", "region") else text.ljust(width))
        lines.append("  ".join(cells).rstrip())
    passed = sum(1 for r in rows if r.fully_ok)
    lines.append("")
    lines.append(f"summary: {passed}/{len(rows)} rows fully verified "
                 f"(independent OLE structure + leak scan + byte-exact decrypt + HMAC)")
    return "\n".join(lines)


def render_csv(rows: list[RowResult]) -> str:
    # lineterminator="\n" keeps the artifact byte-stable across platforms.
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([name for name, _, _ in COLUMNS])
    for row in rows:
        writer.writerow([
            _yn(getattr(row, attr)) if attr == "goes_mini" else _fmt(getattr(row, attr))
            for _, attr, _ in COLUMNS
        ])
    return buf.getvalue()


def build_text_report() -> str:
    return render_text(run_matrix())


if __name__ == "__main__":
    import sys
    if "--csv" in sys.argv:
        sys.stdout.write(render_csv(run_matrix()))
    else:
        sys.stdout.write(build_text_report() + "\n")
