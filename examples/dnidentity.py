#!/usr/bin/env python3
"""Read-only metadata identity comparison for two .NET modules.

Examples:

    python examples/dnidentity.py original.exe reordered.exe
    python examples/dnidentity.py original.exe modified.exe --json

Exit status is 0 when every type and method was matched with a unique
identity, and 1 when there are changes, ambiguous candidates, or unmatched
rows.  Inputs are parsed only; nothing is loaded or executed.
"""

import sys
import json
import argparse

import dnfile.identity


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare .NET metadata by structural identity, not row token."
    )
    parser.add_argument("left", help="baseline .NET module")
    parser.add_argument("right", help="module to compare")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        comparison = dnfile.identity.compare(args.left, args.right)
    except dnfile.identity.IdentityError as e:
        parser.error(str(e))

    if args.json:
        json.dump(comparison.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(comparison.render())
    return 0 if comparison.is_clean else 1


if __name__ == "__main__":
    sys.exit(main())
