"""Read an EWF logical image while forcing a specific block map.

The stock :class:`dissect.evidence.ewf.ewf.EWF` reader only follows primary
``table`` sections (``Segment.tables`` explicitly filters out ``table2``).
For an audit we must be able to reconstruct the *candidate* implied by each
map independently. This reader reuses the exact block location formula from
``EWF.read_chunk`` but takes the table name as an argument:

    absolute = base_offset + (entry & 0x7FFFFFFF)
    compressed = (entry >> 31) == 1

It is intentionally separate from the library so the installed package stays
untouched. Every emitted chunk is annotated with its source table and offset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

DESCRIPTOR_SIZE = 76
TABLE_HEADER_SIZE = 24
COMPRESSED_FLAG = 0x80000000
OFFSET_MASK = 0x7FFFFFFF


def find_sections(data: bytes) -> list[dict]:
    sections = []
    offset = 13
    while True:
        name = data[offset : offset + 16].rstrip(b"\x00").decode("latin-1")
        next_offset, size = struct.unpack("<QQ", data[offset + 16 : offset + 32])
        sections.append({"type": name, "offset": offset, "next": next_offset, "size": size})
        if name == "done" or next_offset == offset:
            break
        offset = next_offset
    return sections


def parse_table(data: bytes, section: dict) -> dict:
    header_start = section["offset"] + DESCRIPTOR_SIZE
    number_of_entries, _reserved, base_offset = struct.unpack(
        "<IIQ", data[header_start : header_start + 16]
    )
    entries_start = header_start + TABLE_HEADER_SIZE
    entries = list(
        struct.unpack(
            f"<{number_of_entries}I",
            data[entries_start : entries_start + number_of_entries * 4],
        )
    )
    return {"base_offset": base_offset, "entries": entries}


def read_with_table(path: Path, table_name: str) -> dict:
    data = path.read_bytes()
    sections = find_sections(data)
    table_section = next(section for section in sections if section["type"] == table_name)
    table = parse_table(data, table_section)

    data_sections = [section for section in sections if section["type"] in ("sectors", "data")]
    bound_section = next(
        section
        for section in data_sections
        if section["offset"] + DESCRIPTOR_SIZE == table["base_offset"]
    )
    data_end = bound_section["offset"] + bound_section["size"]

    pieces = []
    provenance = []
    entries = table["entries"]
    for index, word in enumerate(entries):
        absolute = table["base_offset"] + (word & OFFSET_MASK)
        compressed = bool(word & COMPRESSED_FLAG)
        if index + 1 < len(entries):
            end = table["base_offset"] + (entries[index + 1] & OFFSET_MASK)
        else:
            end = min(data_end, table_section["offset"]) if absolute < table_section["offset"] else data_end
        stored = data[absolute:end]
        if compressed:
            logical = zlib.decompress(stored)
            checksum_ok = None
        else:
            logical, trailer = stored[:-4], struct.unpack("<I", stored[-4:])[0]
            checksum_ok = (zlib.adler32(logical) & 0xFFFFFFFF) == trailer
        pieces.append(logical)
        provenance.append(
            {
                "chunk": index,
                "table": table_name,
                "table_section_offset": hex(table_section["offset"]),
                "descriptor_word": f"0x{word:08x}",
                "absolute_offset": hex(absolute),
                "end_offset": hex(end),
                "compressed": compressed,
                "chunk_checksum_ok": checksum_ok,
                "logical_sha256": hashlib.sha256(logical).hexdigest(),
            }
        )
    stitched = b"".join(pieces)
    return {
        "file": path.name,
        "forced_table": table_name,
        "logical_size": len(stitched),
        "logical_sha256": hashlib.sha256(stitched).hexdigest(),
        "chunk_provenance": provenance,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--table", choices=("table", "table2"), required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = read_with_table(args.image, args.table)
    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
