#!/usr/bin/env python
"""
Runnable evidence for opaque (UnknownBlock) preservation.

It builds two sections with different byte orders, each containing the same
kind of unknown block, and demonstrates the full operation matrix:

  1. keeping an unknown block in its home section  -> payload bytes preserved
  2. moving it to another section, same byte order -> payload bytes preserved
  3. moving it to a section with another byte order -> refused, reason given
  4. writing a little-endian-captured payload into a big-endian section
     -> refused at write time, reason given
  5. moving a local-use (MSB-set) extension between sections, even with the
     same byte order -> refused, reason given

The point of the refusals: an opaque payload has no schema, so the library
cannot know which bytes are numeric fields and must not pretend to have
byte-swapped them; and the format's local-use extensions are defined as
private and must not be copied by a generic "keep unknown blocks" path.
"""

import io
import struct

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import OpaqueBlockError

STANDARD_UNKNOWN_TYPE = 0x00000009  # MSB clear
LOCAL_USE_TYPE = 0x80000001  # MSB set: private extension
PAYLOAD = b"\xDE\xAD\xBE\xEF opaque-payload"  # 22 bytes -> padded to 24


def section_header(endianness):
    return (
        struct.pack(endianness + "II", 0x0A0D0D0A, 28)
        + struct.pack(endianness + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        + struct.pack(endianness + "I", 28)
    )


def interface_description(endianness):
    return (
        struct.pack(endianness + "IIHHI", 1, 20, 0, 0, 0)
        + struct.pack(endianness + "I", 20)
    )


def unknown_block(endianness, block_type, payload):
    padding = b"\x00" * ((-len(payload)) % 4)
    length = 12 + len(payload) + len(padding)
    return (
        struct.pack(endianness + "II", block_type, length)
        + payload
        + padding
        + struct.pack(endianness + "I", length)
    )


def heading(text):
    print("\n" + "=" * 72 + "\n" + text + "\n" + "-" * 72)


def scan(data):
    return list(FileScanner(io.BytesIO(data)))


def main():
    little_endian_file = (
        section_header("<")
        + interface_description("<")
        + unknown_block("<", STANDARD_UNKNOWN_TYPE, PAYLOAD)
        + unknown_block("<", LOCAL_USE_TYPE, b"private local-use payload!!")
    )
    big_endian_file = section_header(">") + interface_description(">")

    le_shb, _le_idb, le_unknown, le_local = scan(little_endian_file)
    be_shb = scan(big_endian_file)[0]

    print("scanned little-endian unknown block: {0!r}".format(le_unknown))
    print("payload bytes captured: {0!r}".format(le_unknown.data))
    print(
        "home section endianness: {0!r}, target big-endian section: {1!r}".format(
            le_unknown.source_endianness, be_shb.endianness
        )
    )

    # 1. Preserve in the home section ----------------------------------------
    heading("1. Keep unknown block in its original (little-endian) section")
    out = io.BytesIO()
    writer = FileWriter(out, le_shb)
    writer.write_block(le_unknown)
    writer.write_block(le_local)
    home_only = out.getvalue()
    print("output is byte-identical to the input file: {0}".format(
        home_only == little_endian_file
    ))
    reread = [b for b in scan(home_only) if isinstance(b, blocks.UnknownBlock)]
    print("payload bytes after round-trip: {0!r}".format(reread[0].data))
    print("payload unchanged: {0}".format(reread[0].data == le_unknown.data))

    # 2. Relocate to another section with the same byte order ----------------
    heading("2. Move unknown block to ANOTHER little-endian section")
    other_le_shb = blocks.SectionHeader(endianness="<")
    le_unknown.move_to_section(other_le_shb)
    print("relocation accepted; block.section is the new section: {0}".format(
        le_unknown.section is other_le_shb
    ))
    out = io.BytesIO()
    writer = FileWriter(out, other_le_shb)
    writer.write_block(le_unknown)
    moved = [b for b in scan(out.getvalue()) if isinstance(b, blocks.UnknownBlock)][0]
    print("payload bytes after relocation: {0!r}".format(moved.data))
    print("payload unchanged: {0}".format(moved.data == le_unknown.data))
    le_unknown.move_to_section(le_shb)  # restore home for later steps

    # 3. Refuse relocation across byte orders --------------------------------
    heading("3. Move unknown block into the BIG-endian section (refused)")
    try:
        le_unknown.move_to_section(be_shb)
    except OpaqueBlockError as exc:
        print("refused with OpaqueBlockError:\n  {0}".format(exc))

    # 4. Refuse a cross-endian write even if attachment was forced -----------
    heading("4. Write little-endian payload through a big-endian writer")
    forged = blocks.UnknownBlock(
        be_shb, STANDARD_UNKNOWN_TYPE, le_unknown.data, endianness="<"
    )
    out = io.BytesIO()
    writer = FileWriter(out, be_shb)
    try:
        writer.write_block(forged)
    except OpaqueBlockError as exc:
        print("refused with OpaqueBlockError:\n  {0}".format(exc))
    print(
        "no partial block emitted (stream holds the SHB only): {0}".format(
            out.getvalue() == big_endian_file
        )
    )

    # 5. Refuse copying a local-use extension between sections ---------------
    heading("5. Move a local-use (MSB-set) block between same-endian sections")
    target_shb = blocks.SectionHeader(endianness="<")
    print("block type 0x{0:08X} is local-use: {1}".format(
        le_local.block_type, le_local.is_local_use
    ))
    try:
        le_local.move_to_section(target_shb)
    except OpaqueBlockError as exc:
        print("refused with OpaqueBlockError:\n  {0}".format(exc))
    print(
        "it remains writable in its home section: {0}".format(
            le_local.section is le_shb
        )
    )


if __name__ == "__main__":
    main()
