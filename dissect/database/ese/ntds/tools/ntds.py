from __future__ import annotations

import argparse
import json
from pathlib import Path

from dissect.database.ese.ntds import NTDS


def main() -> None:
    parser = argparse.ArgumentParser(description="dissect.database.ese.ntds NTDS parser")
    parser.add_argument("input", help="NTDS database to read")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--objectClass", help="show only objects of this class")
    group.add_argument("-m", "--membership", help="trace offline group relationships for this principal")
    parser.add_argument("-j", "--json", action="store_true", default=False, help="output in JSON format")
    parser.add_argument(
        "--no-primary-group",
        action="store_false",
        dest="include_primary_group",
        help="only follow explicit member links (default includes primaryGroupID relationships)",
    )
    parser.add_argument("--max-depth", type=int, default=16, help="maximum number of edges in a path")
    parser.add_argument("--max-paths", type=int, default=10000, help="maximum number of paths to collect")
    args = parser.parse_args()

    with Path(args.input).open("rb") as fh:
        ntds = NTDS(fh)

        if args.membership is not None:
            trace = ntds.trace_memberships(
                args.membership,
                max_depth=args.max_depth,
                max_paths=args.max_paths,
                include_primary_group=args.include_primary_group,
            )
            if args.json:
                print(json.dumps(trace.as_dict(), default=str))
            else:
                print(trace.explain())
            return

        for record in ntds.search(objectClass=args.objectClass):
            if args.json:
                print(json.dumps(record.as_dict(), default=str))
            else:
                print(record)


if __name__ == "__main__":
    main()
