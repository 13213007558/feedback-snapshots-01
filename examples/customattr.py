#!/usr/bin/env python
"""
Statically interpret .NET CustomAttribute payloads.

No assembly is loaded and no attribute class is instantiated: values are
reconstructed only from metadata tables and raw #Blob bytes.
"""
import sys
import logging

import dnfile
from dnfile import customattr

logger = logging.getLogger(__name__)


def main(path):
    pe = dnfile.dnPE(path)
    if not pe.net or not pe.net.mdtables:
        print("no .NET metadata found")
        return 1

    for i, result in enumerate(customattr.decode_custom_attributes(pe)):
        print(customattr.format_interpretation(result, i))
        print()

    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARN)
    sys.exit(main(sys.argv[1]))
