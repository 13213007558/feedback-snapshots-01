# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""bounded entry-point review for a managed plugin.

reads metadata and CIL only. the assembly is never loaded or executed.
exit codes: 0 no reachable finding, 1 manual review, 2 reject.
"""

from __future__ import annotations

import sys
import json
import argparse
from typing import TYPE_CHECKING, Any, List, Optional

if TYPE_CHECKING:
    from dnfile import dnPE

try:
    import dnfile
except ImportError:  # pragma: no cover - dependency is optional for the core package
    dnfile = None

from dncil.analysis.review import Decision, ReviewLimits, review_entry_points
from dncil.analysis.metadata import MetadataError
from dncil.analysis.dnfile_adapter import DnfileMetadataView

EXIT_CODES = {
    Decision.NO_REACHABLE_FINDING: 0,
    Decision.MANUAL_REVIEW: 1,
    Decision.REJECT: 2,
}


def _parse_token(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value, 10)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="Review managed plugin entry points without executing the plugin",
    )
    parser.add_argument("path", help="path to a .NET assembly")
    parser.add_argument(
        "--entry",
        action="append",
        default=None,
        metavar="TOKEN",
        help="entry MethodDef token (hex or decimal); may be repeated",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--max-methods", type=int, default=ReviewLimits.max_methods)
    parser.add_argument("--max-depth", type=int, default=ReviewLimits.max_depth)
    parser.add_argument("--max-instructions", type=int, default=ReviewLimits.max_instructions)
    args = parser.parse_args(argv)

    if dnfile is None:
        print("error: dnfile is required: pip install dnfile", file=sys.stderr)
        return 3

    limits = ReviewLimits(
        max_methods=args.max_methods,
        max_depth=args.max_depth,
        max_instructions=args.max_instructions,
    )

    pe: "dnPE" = dnfile.dnPE(args.path)
    try:
        view = DnfileMetadataView(pe)
        entries = [_parse_token(value) for value in args.entry] if args.entry else None
        report = review_entry_points(view, entries, limits)
    except MetadataError as error:
        print(f"error: {error}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.format_text())
    return EXIT_CODES[report.decision]


if __name__ == "__main__":
    raise SystemExit(main())
