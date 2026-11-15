"""Runnable offline diagnosis: same provider GUID, different manifest versions.

Run with::

    python -m diagnostics.manifest_conflict.run_diagnosis
    python -m diagnostics.manifest_conflict.run_diagnosis --output-dir /tmp/etl-diagnosis

The script generates two synthetic ETL files (one per "collector"), writes the conflicting
manifests to per-collector repositories, exercises cold-cache load ordering and cache stickiness,
and emits both a machine-readable JSON report and a human-readable text report.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from uuid import UUID

from dissect.etl import manifest

from .diagnose import build_router, clear_cache, diagnose_event
from .manifests import VARIANTS, write_repos
from .synthetic_etl import build_etl

PROVIDER_GUID = UUID("f1c2a3b4-1111-2222-3333-444455556666")
OPCODE = 11
EVENT_VERSION = 0
# Counter(4) + "AB" as UTF-16LE(4) + NUL(2) + two trailing bytes.
PAYLOAD = (7).to_bytes(4, "little") + "AB".encode("utf-16-le") + b"\x00\x00" + b"\xcc\xdd"

COLLECTORS = ("collector-a", "collector-b", "collector-c")


def _scenario_order(router, etl_blob: bytes, order: tuple[str, ...]) -> list[dict]:
    """Cold cache: load each collector in ``order`` and parse the same event bytes."""
    results = []
    for collector in order:
        clear_cache()
        results.append(asdict(diagnose_event(etl_blob, PROVIDER_GUID, router, collector)))
    return results


def _scenario_sticky(router, etl_blob: bytes, first: str, second: str) -> list[dict]:
    """Warm the cache with ``first``, then switch the active source to ``second``."""
    clear_cache()
    first_result = diagnose_event(etl_blob, PROVIDER_GUID, router, first)
    second_result = diagnose_event(etl_blob, PROVIDER_GUID, router, second)
    return [asdict(first_result), asdict(second_result)]


def run(output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    repo_root = output_dir / "repos"
    locations = write_repos(repo_root, PROVIDER_GUID)

    etl_blob_a = build_etl(PROVIDER_GUID, OPCODE, EVENT_VERSION, PAYLOAD)
    etl_blob_b = build_etl(PROVIDER_GUID, OPCODE, EVENT_VERSION, PAYLOAD)
    (output_dir / "collector-a-events.etl").write_bytes(etl_blob_a)
    (output_dir / "collector-b-events.etl").write_bytes(etl_blob_b)

    router = build_router(PROVIDER_GUID)
    identical = etl_blob_a == etl_blob_b

    report = {
        "provider_guid": str(PROVIDER_GUID),
        "event_descriptor": {"opcode": OPCODE, "version": EVENT_VERSION, "payload_hex": PAYLOAD.hex()},
        "etl_files_byte_identical": identical,
        "repositories": {name: str(path) for name, path in locations.items()},
        "scenarios": {
            "cold_cache_order_a_then_b": _scenario_order(router, etl_blob_a, ("collector-a", "collector-b")),
            "cold_cache_order_b_then_a": _scenario_order(router, etl_blob_b, ("collector-b", "collector-a")),
            "sticky_cache_a_then_b": _scenario_sticky(router, etl_blob_a, "collector-a", "collector-b"),
            "sticky_cache_b_then_a": _scenario_sticky(router, etl_blob_b, "collector-b", "collector-a"),
            "missing_event_entry_collector_c": _scenario_order(router, etl_blob_a, ("collector-c",)),
        },
        "cache_key_type": f"dict key in {manifest.__name__}.CACHE is the UUID only (no version/source)",
        "variants": list(VARIANTS),
    }

    (output_dir / "report.json").write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False))
    (output_dir / "report.txt").write_text(render_text(report))
    return report


def render_text(report: dict) -> str:
    lines = [
        "dissect.etl same-GUID / different-manifest conflict diagnosis",
        "=" * 64,
        f"provider GUID        : {report['provider_guid']}",
        f"event descriptor     : opcode={OPCODE} version={EVENT_VERSION}",
        f"payload ({len(PAYLOAD)} bytes)   : {PAYLOAD.hex()}",
        f"ETL files identical  : {report['etl_files_byte_identical']}",
        "",
    ]
    for scenario, results in report["scenarios"].items():
        lines.append(f"[{scenario}]")
        for result in results:
            origin = result["manifest_origin"]
            lines.append(f"  - active source   : {result['collector']}")
            lines.append(f"    cache hit       : {origin['cache_hit']}  compiled: {origin['compiled_sources']}")
            lines.append(f"    provider name   : {origin['provider_name']}  symbol: {origin.get('event_symbol')}")
            lines.append(f"    parsed values   : {result['parsed_values']}")
            lines.append(
                f"    payload/consumed/unconsumed: "
                f"{result['payload_size']}/{result['consumed_bytes']}/{result['unconsumed_bytes']}"
                f"  unconsumed_hex={result['unconsumed_hex']}"
            )
            lines.append(f"    exception       : {result['exception']}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    default_output = Path(__file__).resolve().parent.parent / "output"
    parser.add_argument("--output-dir", type=Path, default=default_output)
    args = parser.parse_args()
    report = run(args.output_dir)
    print(render_text(report))
    print(f"JSON report : {args.output_dir / 'report.json'}")
    print(f"text report : {args.output_dir / 'report.txt'}")


if __name__ == "__main__":
    main()
