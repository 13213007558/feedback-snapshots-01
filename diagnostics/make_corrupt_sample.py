#!/usr/bin/env python3
"""Build a synthetic *partially damaged* BLF from the intact repository fixture.

The intact DRIVERS*.TM.blf has both general blocks (current type 2 at 0x800,
shadow type 3 at 0x8200) populated.  We introduce two independent,
deterministic defects while leaving the primary control block and the current
general block byte-identical:

  A. Scribble the shadow general block's log-block header (offset 0x8200) so
     its TotalSectors/ValidSectors no longer match a decodable block.  This
     simulates one-sided corruption of the shadow metadata view.

  B. Truncate the file right after the shadow general block (cut at 0x8400),
     so both scratch (truncate) blocks referenced by the descriptor table sit
     at/beyond EOF.  This simulates a torn tail / truncated record.

The current general block, the stream and both container contexts inside it
remain fully parseable, which lets the report demonstrate that the minimum
readable-container evidence still holds from one view while every cross-copy
and truncate conclusion is correctly marked undecidable.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

SHADOW_GENERAL_OFFSET = 0x8200
CUT_AT = 0x8400  # keep one 512-byte sector of the shadow general block, then cut


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path, help="intact .blf fixture to copy and damage")
    ap.add_argument("dest", type=Path, help="output path for the damaged copy")
    args = ap.parse_args()

    data = bytearray(args.source.read_bytes())
    original_len = len(data)

    # Defect A: corrupt the shadow general block header fields.
    # Bytes 4-5 are TotalSectors, 6-7 ValidSectors in CLFS_LOG_BLOCK_HEADER.
    data[SHADOW_GENERAL_OFFSET + 4] = 0xFF
    data[SHADOW_GENERAL_OFFSET + 5] = 0x00
    data[SHADOW_GENERAL_OFFSET + 6] = 0xFF
    data[SHADOW_GENERAL_OFFSET + 7] = 0x00

    # Defect B: truncate the tail (removes scratch blocks at 0xfc00/0xfe00).
    if CUT_AT > len(data):
        raise SystemExit("cut point beyond source length")
    data = data[:CUT_AT]

    args.dest.parent.mkdir(parents=True, exist_ok=True)
    args.dest.write_bytes(bytes(data))
    print(f"source         : {args.source} ({original_len} bytes)")
    print(f"defect A       : shadow general block header scribbled at "
          f"0x{SHADOW_GENERAL_OFFSET:x} (TotalSectors/ValidSectors -> 0x00ff)")
    print(f"defect B       : truncated at 0x{CUT_AT:x} "
          f"(scratch blocks 0xfc00/0xfe00 now beyond EOF)")
    print(f"damaged output : {args.dest} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
