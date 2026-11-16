"""Inspect one or more files with the detection contract.

Examples::

    python experiments/detection_contract/inspect_volume.py volume.img
    python experiments/detection_contract/inspect_volume.py --passphrase hunter2 volume.img
    python experiments/detection_contract/inspect_volume.py --json volume.img

Exit codes: 0 when no error, 1 when the file could not be read, 2 for a key verification rejection.
"""

from __future__ import annotations

import argparse
import gzip
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from dissect.fve.detect import Conclusion, detect  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, nargs="+", help="file to inspect")
    parser.add_argument("--offset", type=int, default=0, help="volume start offset inside the file")
    parser.add_argument("--size", type=int, default=None, help="volume size in bytes")
    parser.add_argument("--passphrase", help="attempt key verification with this passphrase")
    parser.add_argument("--recovery-password", help="BitLocker recovery password")
    parser.add_argument("--bek", type=Path, help="BitLocker BEK file")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args(argv)

    material: dict[str, object] = {}
    if args.passphrase:
        material["passphrase"] = args.passphrase
    if args.recovery_password:
        material["recovery_password"] = args.recovery_password
    if args.bek:
        material["bek"] = args.bek.open("rb")

    exit_code = 0
    for path in args.input:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rb") as fh:
                result = detect(fh, offset=args.offset, size=args.size, key_material=material or None)
        except OSError as exc:
            print(f"{path}: cannot read: {exc}", file=sys.stderr)
            exit_code = max(exit_code, 1)
            continue

        if args.json:
            print(result.to_json())
        else:
            print(f"{path}: {result.conclusion.value}")
            print(f"  format          : {result.format.value if result.format else '-'}")
            print(f"  confirmed format: {result.confirmed_format.value if result.confirmed_format else '-'}")
            print(f"  ambiguous       : {result.ambiguous}")
            for candidate in result.candidates:
                if not candidate.evidence:
                    continue
                print(f"  [{candidate.format.value if candidate.format else 'generic'}] {candidate.conclusion.value}")
                for evidence in candidate.evidence:
                    print(f"    - {evidence.kind.value}: {evidence.detail}")
            for verification in result.verifications:
                print(
                    f"  verify {verification.format.value}: {verification.status.value}"
                    f" ({verification.method}) {verification.error or ''}".rstrip()
                )
            for warning in result.warnings:
                print(f"  warning: {warning}")
            for fmt, error in result.probe_errors.items():
                print(f"  probe error {fmt}: {error}")

        if result.conclusion is Conclusion.NOT_ENCRYPTED:
            exit_code = max(exit_code, 0)
        if any(v.status.value == "rejected" for v in result.verifications):
            exit_code = max(exit_code, 2)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
