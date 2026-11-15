#!/usr/bin/env python

"""
Write a filtered copy of a pcap-ng capture plus a manifest mapping every
output block back to the source block it came from.

The predicate receives each packet block in source order.  Identical packets
remain separate occurrences here because selection is per source block.
"""

import argparse
import sys

import pcapng


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="input pcap-ng file")
    parser.add_argument("destination", help="output pcap-ng file")
    parser.add_argument(
        "--needle",
        default="",
        help="keep packets whose bytes contain this ASCII string",
    )
    parser.add_argument(
        "--manifest",
        help="write the manifest JSON here (default: standard output)",
    )
    args = parser.parse_args(argv)

    needle = args.needle.encode()

    def keep(block):
        return needle in block.packet_data

    manifest = pcapng.derive_capture(args.source, args.destination, keep)

    if args.manifest:
        with open(args.manifest, "w") as fp:
            fp.write(manifest.to_json(indent=2))
    else:
        sys.stdout.write(manifest.to_json(indent=2) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
