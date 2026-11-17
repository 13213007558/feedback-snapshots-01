#!/usr/bin/env python3
"""Offline RPZ rehearsal driver.

Loads the trusted policy-zone configuration and a probe list, then prints
which rule actually fires for every probe, which candidates were overridden,
and which zone content could not be interpreted and stays pending.

Nothing here opens a socket or starts a name server; the only inputs are the
local zone files and JSON documents.

Usage (from the repository root)::

    python examples/rpz_rehearsal/rehearse.py \
        --config examples/rpz_rehearsal/config.json \
        --probes examples/rpz_rehearsal/probes.json \
        [--json]
"""

import argparse
import json
from pathlib import Path

import dns.rpz


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("examples/rpz_rehearsal/config.json"),
        help="trusted policy-zone configuration (zone order fixes priority)",
    )
    parser.add_argument(
        "--probes",
        type=Path,
        default=Path("examples/rpz_rehearsal/probes.json"),
        help="JSON list of offline probes",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit the machine-readable report instead of text",
    )
    return parser.parse_args()


def render_text(report: dict) -> str:
    lines: list[str] = []
    lines.append("RPZ offline rehearsal")
    lines.append(f"zone priority (highest first): {', '.join(report['zone_priority'])}")
    lines.append(
        "supported: triggers="
        + ", ".join(report["supported_triggers"])
        + " actions="
        + ", ".join(report["supported_actions"])
    )
    lines.append("")

    if report["pending_rules"]:
        lines.append("Uninterpreted zone rules (kept pending, never enforced):")
        for item in report["pending_rules"]:
            lines.append(
                f"  [{item['zone']}] {item['owner']} "
                f"trigger={item['trigger']} reason={item['reason']}"
            )
            lines.append(f"      {item['source_rr']}")
        lines.append("")

    for number, evaluation in enumerate(report["evaluations"], start=1):
        target = evaluation["qname"] or ", ".join(evaluation["addresses"])
        lines.append(f"{number}. probe: {target}")
        applied = evaluation["applied"]
        if applied is None:
            lines.append("   result: no enforceable rule matched")
        else:
            lines.append(
                f"   result: action={applied['action']} "
                f"zone={applied['zone']} owner={applied['owner']}"
            )
            lines.append(
                f"      synthetic={applied['synthetic']} "
                f"authoritative={applied['authoritative']} rcode={applied['rcode']}"
            )
            lines.append(f"      source RR: {applied['source_rr']}")
        for item in evaluation["overridden"]:
            lines.append(
                f"   overridden: [{item['zone']}] {item['owner']} "
                f"action={item['action']} ({item['overridden_by']})"
            )
        for item in evaluation["pending_matched"]:
            lines.append(
                f"   pending match: [{item['zone']}] {item['owner']} "
                f"reason={item['reason']} - {item['detail']}"
            )
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    config = json.loads(args.config.read_text())
    probes = json.loads(args.probes.read_text())
    # Resolve relative zone paths in the config against the config file's
    # directory so the example runs from any working directory.
    base_dir = args.config.parent
    for zone in config["zones"]:
        zone_path = Path(zone["file"])
        if zone_path.is_absolute() or zone_path.exists():
            continue
        zone["file"] = str(base_dir / zone_path)
    engine = dns.rpz.PolicyEngine.from_config(config)
    report = engine.run(probes)
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))


if __name__ == "__main__":
    main()
