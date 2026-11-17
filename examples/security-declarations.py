#!/usr/bin/env python
"""
List DeclSecurity ownership, actions and interpreted permission payloads.

The report intentionally separates storage facts (action, blob, coded index
target) from interpreted content and from runtime effects, which are not
inferred.
"""
import sys

import dnfile


def main(path):
    pe = dnfile.dnPE(path)
    analysis = pe.analyze_security_declarations()
    if analysis is None:
        print("no CLR metadata in this file")
        return 1

    print(analysis.format_report())
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: {} FILE".format(sys.argv[0]), file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
