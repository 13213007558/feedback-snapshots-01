"""Reproducible end-to-end driver: build, mutate, audit, cross-check.

Run from the repository root with ``.venv/bin/python ewf-table-audit/run_all.py``.
Outputs land in ``ewf-table-audit/images`` and ``ewf-table-audit/reports``.
The dissect.evidence source tree and any pre-existing evidence are never
modified; every scenario image is regenerated from scratch.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
REPORTS = ROOT / "reports"
IMAGES = ROOT / "images"


def run(module: str) -> None:
    print(f"\n=== {module} ===")
    subprocess.run([sys.executable, str(SRC / module)], check=True)


def main() -> None:
    IMAGES.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    run("generate_scenarios.py")
    for image in sorted(IMAGES.glob("*.E01")):
        report = REPORTS / f"{image.stem}.json"
        subprocess.run(
            [sys.executable, str(SRC / "ewf_table_audit.py"), str(image), "--json", str(report)],
            check=True,
        )
    run("cross_check_dissect.py")

    divergent = IMAGES / "04_tables_divergent_both_valid.E01"
    for table_name in ("table", "table2"):
        subprocess.run(
            [
                sys.executable,
                str(SRC / "forced_table_reader.py"),
                str(divergent),
                "--table",
                table_name,
                "--json",
                REPORTS / f"04_forced_{table_name}.json",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    image_stems = {image.stem for image in IMAGES.glob("*.E01")}
    summary = {}
    for report in sorted(REPORTS.glob("*.json")):
        if report.stem not in image_stems:
            continue
        payload = json.loads(report.read_text())
        summary[report.stem] = {
            "verdict": payload["verdict"],
            "reason": payload["verdict_reason"],
            "table_valid": payload["tables"]["table"]["structurally_valid"],
            "table2_valid": payload["tables"]["table2"]["structurally_valid"],
            "table_candidate": payload["tables"]["table"]["candidate_sha256"],
            "table2_candidate": payload["tables"]["table2"]["candidate_sha256"],
        }
    (REPORTS / "verdict_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    print("\n=== verdict summary ===")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
