"""Print EWF acquisition metadata with explicit provenance.

Examples:
    ewf-meta image.E01
    ewf-meta --format details image.E01

``brief`` prints only verbatim selected values, ``summary`` adds the header integrity state and
``details`` also includes every conflicting candidate with its segment, section and byte range.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dissect.evidence.ewf import EWF


def main() -> int:
    parser = argparse.ArgumentParser(description="Show acquisition metadata declared by an EWF image")
    parser.add_argument("file", metavar="EWF", help="EWF segment file to inspect")
    parser.add_argument(
        "--format",
        choices=("brief", "summary", "details"),
        default="brief",
        help="amount of provenance to include (default: brief)",
    )
    args = parser.parse_args()

    with Path(args.file).open("rb") as fh:
        try:
            ewf = EWF(fh)
        except ValueError as e:
            print(f"Unable to open EWF: {e}", file=sys.stderr)
            return 1

        metadata = ewf.metadata
        if args.format == "brief":
            result = metadata.brief()
        elif args.format == "summary":
            result = metadata.summary()
        else:
            result = metadata.details()

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
