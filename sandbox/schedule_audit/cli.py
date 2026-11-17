"""
Command line entry point for the offline Schedule audit.

Usage::

    python -m sandbox.schedule_audit.cli SNAPSHOT.json [--schedule schedule,1]

The snapshot's ``evaluation-instant`` must be a timezone-aware ISO 8601
string representing device-local wall clock time.  This tool never reads the
analysis machine's own clock or timezone.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .analyzer import AuditConfigurationError, analyze_point
from .snapshot import SnapshotError, load_snapshot_file


def _format_report(report) -> str:
    lines: List[str] = []
    lines.append(
        f"evaluation instant (caller-supplied): " f"{report.evaluation_instant}"
    )
    lines.append(f"device-local datetime: " f"{report.device_local_datetime}")
    lines.append(f"schedule: {report.schedule_identifier}")
    lines.append(f"  schedule verdict: {report.schedule_verdict.value}")
    lines.append(f"  declared value:   {report.declared_value!r}")
    lines.append(f"point: {report.point_identifier}")
    lines.append(f"  point verdict:    {report.point_verdict.value}")
    lines.append(f"  effective value:  {report.effective_value!r}")
    lines.append(f"  schedule writes at priority: " f"{report.schedule_write_priority}")
    lines.append(f"  active command priority:    " f"{report.active_command_priority}")
    lines.append(f"CONCLUSION: {report.conclusion.value}")

    lines.append("")
    lines.append("evidence (each conclusion cites its configuration basis):")
    for item in report.evidence:
        lines.append(f"  [{item.declared_vs_executed:8s}] {item.source}")
        lines.append(f"             {item.detail}")
        lines.append(f"             basis: {item.basis}")

    if report.pending:
        lines.append("")
        lines.append("pending (offline analysis cannot resolve):")
        for item in report.pending:
            lines.append(f"  - {item['reason']}: {item['detail']}")

    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline BACnet Schedule control-path audit"
    )
    parser.add_argument("snapshot", help="path to the snapshot JSON document")
    parser.add_argument(
        "--schedule",
        help="object identifier of the schedule to audit "
        "(required when the snapshot has several)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the report as JSON instead of human-readable text",
    )
    args = parser.parse_args(argv)

    try:
        audit_input = load_snapshot_file(args.snapshot)
        report = analyze_point(audit_input, schedule_id=args.schedule)
    except (SnapshotError, AuditConfigurationError) as err:
        print(f"audit failed: {err}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(_format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
