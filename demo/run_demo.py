#!/usr/bin/env python3
"""Reproduce the whole analysis from a clean state.

    python demo/run_demo.py --out out/

Writes deterministic fixtures, then one report per policy, plus a comparison
file.  Inputs and outputs are byte-stable; `pytest demo/tests` asserts that.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

import report  # noqa: E402
import resolver  # noqa: E402
import scenario  # noqa: E402


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="demo/out", type=Path)
    parser.add_argument(
        "--policies",
        nargs="*",
        default=list(resolver.POLICY_DESCRIPTIONS),
    )
    args = parser.parse_args()

    fixtures_dir = args.out / "fixtures"
    paths = scenario.build(fixtures_dir)
    candidates = [str(paths["candidate_v1"]), str(paths["candidate_v2"])]
    # Reports record paths relative to --out so their bytes are location
    # independent; the sha256 fields carry the real identity of each file.
    display = {str(path): str(path.relative_to(args.out)) for path in paths.values()}
    display_host = display[str(paths["host"])]

    manifest = {
        "fixtures": {
            name: {
                "path": str(path.relative_to(args.out)),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for name, path in paths.items()
        }
    }
    (args.out / "fixtures.sha256.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    summary = []
    for policy in args.policies:
        built = report.build_report(
            str(paths["host"]),
            candidates,
            policy,
            display_paths=display,
            display_host=display_host,
        )
        json_path, text_path = report.write_report(built, args.out / policy)
        summary.append(
            {
                "policy": policy,
                "json": str(json_path.relative_to(args.out)),
                "text": str(text_path.relative_to(args.out)),
                "selected": {
                    str(ref["assembly_ref_rid"]): (
                        ref["selected"]["path"] if ref["selected"] else None
                    )
                    for ref in built["resolution"]["assembly_refs"]
                },
                "method_identity": {
                    member["token"]: (
                        {
                            "type": member["target"]["type"],
                            "signature_hex": member["target"]["signature_hex"],
                            "matches": member["target"]["signature_matches_ref"],
                        }
                        if member["target"] and member["target"].get("found")
                        else None
                    )
                    for member in built["resolution"]["member_refs"]
                },
            }
        )

    (args.out / "comparison.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(args.policies)} reports and fixtures under {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
