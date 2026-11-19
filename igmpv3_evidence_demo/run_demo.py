"""Runnable end-to-end demonstration of the IGMPv3 evidence model.

Run from the repository root:

    python3 -m igmpv3_evidence_demo.run_demo

The script regenerates the byte transcript, decodes every frame with Scapy,
replays it against a fixed clock and prints a verdict for every provisioned
(port, group, source) triple at each checkpoint, including one triple for a
source that a receiver reports but provisioning never permits.
"""

import os

from .analyze import build_engine, default_transcript_path, load_transcript
from .config import demo_config
from .evidence_model import RTYPE_NAME
from .transcript_build import (
    G1,
    G2,
    S1,
    S2,
    S21,
    S22,
    S99,
    build_transcript,
    write_artifacts,
)

CHECKPOINTS = [45, 65, 95, 105, 150, 190, 215, 230, 305, 480, 580]

# The last triple is deliberately absent from trusted provisioning.
EVALUATED_TRIPLES = [
    ("p1", G1, S1),
    ("p1", G1, S2),
    ("p2", G2, S21),
    ("p2", G2, S22),
    ("p2", G2, S99),
]


def _print_header(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _print_transcript(entries: list[dict]) -> None:
    _print_header("1. Raw byte transcript (each line is one stored frame)")
    for entry in entries:
        if entry["kind"] == "GAP":
            print(
                f"{entry['frame_id']:<7} t={entry['timestamp']:<4} "
                f"{entry['kind']:<6} port={entry['port_id']} "
                f"lost={entry['lost_seconds']}s | {entry['note']}"
            )
            continue
        length = len(entry["hex_bytes"]) // 2
        print(
            f"{entry['frame_id']:<7} t={entry['timestamp']:<4} "
            f"{entry['kind']:<6} port={entry['port_id'] or '-':<3} "
            f"{length:>3}B | {entry['note']}"
        )


def _print_decoded_records(entries: list[dict]) -> None:
    _print_header("2. IGMPv3 layer decoded from the stored bytes (Scapy)")
    from .analyze import parse_query_bytes, parse_report_bytes

    for entry in entries:
        if entry["kind"] == "REPORT":
            for record in parse_report_bytes(
                entry["frame_id"],
                entry["timestamp"],
                entry["port_id"],
                entry["hex_bytes"],
            ):
                sources = ",".join(sorted(record.sources)) or "-"
                print(
                    f"{entry['frame_id']:<7} {RTYPE_NAME[record.rtype]:<24} "
                    f"group={record.group} sources={{{sources}}}"
                )
        elif entry["kind"] == "QUERY":
            query = parse_query_bytes(
                entry["frame_id"], entry["timestamp"], entry["hex_bytes"]
            )
            print(
                f"{entry['frame_id']:<7} GENERAL_QUERY            "
                f"gaddr={query.group}"
            )
        else:
            print(f"{entry['frame_id']:<7} CAPTURE_GAP on {entry['port_id']} "
                  f"({entry['lost_seconds']}s unrecorded)")


def _print_policy(config) -> None:
    _print_header("3. Trusted provisioning (authorization source of truth)")
    print(config.to_json())
    print(f"fixed Group Membership Interval: {config.group_membership_interval} s")


def _print_checkpoint_tables(config, entries: list[dict]) -> None:
    _print_header("4. Fixed-clock verdicts (default-deny; reports are not grants)")
    for checkpoint in CHECKPOINTS:
        engine = build_engine(
            entries, config.group_membership_interval, until=checkpoint
        )
        engine.advance(checkpoint)
        print(f"\n--- checkpoint t={checkpoint}s ---")
        print(
            f"{'port':<4} {'group':<11} {'source':<15} "
            f"{'decision':<12} reason"
        )
        for port_id, group, source in EVALUATED_TRIPLES:
            policy_reason = config.policy_lookup(port_id, group, source)
            verdict = engine.evaluate(port_id, group, source, policy_reason)
            print(
                f"{port_id:<4} {group:<11} {source:<15} "
                f"{verdict.decision:<12} {verdict.reason}"
            )


def _print_evidence_chains(config, entries: list[dict]) -> None:
    _print_header("5. Evidence and preconditions behind selected verdicts")
    selected = [
        (45, "p1", G1, S1),
        (65, "p1", G1, S2),
        (150, "p1", G1, S1),
        (230, "p1", G1, S1),
        (480, "p1", G1, S1),
        (230, "p2", G2, S99),
    ]
    for checkpoint, port_id, group, source in selected:
        engine = build_engine(
            entries, config.group_membership_interval, until=checkpoint
        )
        engine.advance(checkpoint)
        policy_reason = config.policy_lookup(port_id, group, source)
        verdict = engine.evaluate(port_id, group, source, policy_reason)
        print(
            f"\nt={checkpoint} {port_id}/{group}/{source} -> "
            f"{verdict.decision} ({verdict.reason})"
        )
        refs = ", ".join(verdict.evidence_refs) if verdict.evidence_refs else "-"
        print(f"  referenced raw records: {refs}")
        for item in verdict.preconditions:
            print(f"  precondition: {item}")


def _print_boundaries() -> None:
    _print_header("6. Provable vs unknown boundaries (model scope)")
    for line in [
        "PROVABLE: a provisioned triple whose current CSR-anchored state, with no",
        "open capture gap and a live membership timer, includes (INCLUDE) or does",
        "not exclude (EXCLUDE) the source.",
        "UNKNOWN / NOT_PROVABLE: no CSR anchor, an open capture gap, or an expired",
        "timer. These fail closed; they are never silently treated as allowed.",
        "EXPLICIT DENY: policy mismatch (port/group/source not provisioned) or a",
        "current state that excludes the source. A reported address cannot override.",
        "NOT MODELED: other receivers, querier behavior, the Layer 2 forwarding",
        "table and the data plane. Passive reports alone cannot reconstruct them.",
    ]:
        print(line)


def main() -> None:
    config = demo_config()
    here = os.path.dirname(os.path.abspath(__file__))
    artifact_dir = os.path.join(here, "artifacts")
    write_artifacts(build_transcript(), artifact_dir)
    entries = load_transcript(default_transcript_path())
    _print_transcript(entries)
    _print_decoded_records(entries)
    _print_policy(config)
    _print_checkpoint_tables(config, entries)
    _print_evidence_chains(config, entries)
    _print_boundaries()
    print("\nartifacts:")
    for name in sorted(os.listdir(artifact_dir)):
        print(f"  {os.path.join(artifact_dir, name)}")


if __name__ == "__main__":
    main()
