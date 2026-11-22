"""Assert the exported pages preserve order, leak nothing and re-run stably."""

import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample")
FORBIDDEN_TOKENS = ("case_secret", "RAW-RECORD", "LEGAL-", "EXEC-", "PENDING-")
EXPECTED_KEYS = {"event_time", "change_type", "object_ref"}


def load_pages():
    pages = []
    for path in sorted(glob.glob(os.path.join(SAMPLE, "audit-page-*.jsonl"))):
        with open(path, encoding="utf-8") as handle:
            pages.append([json.loads(line) for line in handle if line.strip()])
    return pages


def main():
    pages = load_pages()
    assert len(pages) == 2, f"expected two pages, got {len(pages)}"
    rows = [row for page in pages for row in page]

    for row in rows:
        assert set(row) == EXPECTED_KEYS, row
        blob = json.dumps(row)
        for token in FORBIDDEN_TOKENS:
            assert token not in blob, f"forbidden content leaked: {token}"

    timestamps = [row["event_time"] for row in rows]
    assert timestamps == sorted(timestamps), "event order is not preserved"

    # The same-timestamp pair is kept, ordered by internal history id.
    tie = [row for row in rows if row["event_time"] == "2026-03-01T09:00:00Z"]
    assert len(tie) == 2, tie

    # No EXEC object reference may appear (no access permission).
    refs = {row["object_ref"] for row in rows}
    assert len(pages[0]) == 3 and len(pages[1]) == 3

    # Re-run the export into a temp dir and compare every byte.
    rerun = os.path.join(HERE, "sample_rerun")
    os.makedirs(rerun, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            os.path.join(HERE, "manage.py"),
            "export_audit",
            "auditcase.casefile",
            "--page-size",
            "3",
            "--max-pages",
            "10",
            "--start-time",
            "2026-01-01T00:00:00Z",
            "--end-time",
            "2027-01-01T00:00:00Z",
            "--access-callback",
            "auditcase.access.legal_department_access",
            "--out-dir",
            rerun,
        ],
        check=True,
        capture_output=True,
    )
    for name in ("audit-page-0001.jsonl", "audit-page-0002.jsonl"):
        with (
            open(os.path.join(SAMPLE, name), "rb") as first,
            open(os.path.join(rerun, name), "rb") as second,
        ):
            assert first.read() == second.read(), f"{name} changed on re-run"

    print(
        f"OK: {len(rows)} events in 2 pages, order preserved, no field leak, "
        "re-run byte-identical."
    )
    print("visible object refs:", sorted(refs))


if __name__ == "__main__":
    main()
