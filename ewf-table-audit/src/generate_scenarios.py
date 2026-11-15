"""Generate the reproducible EWF table/table2 divergence scenario set.

A pristine image is built first and copied per scenario; the pristine file and
the dissect.evidence source tree are never modified. Every mutation records the
exact bytes changed so downstream diagnostics are fully traceable.

Scenario classes:
* 00/01 clean baselines (uncompressed / compressed), both tables identical;
* 02/03  entry tampering: all checksums stay valid because EWF table checksums
  do not cover the entry array - failure only appears on the read path;
* 04     two structurally legal tables mapping two distinct chunk sets;
* 05/06  stale checksums: descriptor / table-header Adler-32 invalidated;
* 07     valid checksums but a wrong base offset;
* 08     valid checksums but the last chunk crosses its section boundary.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ewf_builder as eb  # noqa: E402

DESCRIPTOR_SIZE = eb.DESCRIPTOR_SIZE
TABLE_HEADER_SIZE = eb.TABLE_HEADER_SIZE
IMAGES = Path(__file__).resolve().parent.parent / "images"
REPORTS = Path(__file__).resolve().parent.parent / "reports"


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def logical_chunks() -> list[bytes]:
    chunks = [bytes([0x41 + index] * 512) for index in range(5)]
    chunks.append(b"FINAL-PARTIAL-CHUNK-" + b"z" * 100)
    return chunks


def alternate_chunks() -> list[bytes]:
    chunks = [bytes([0x61 + index] * 512) for index in range(5)]
    chunks.append(b"ALTERNATE-PARTIAL-" + b"q" * 100)
    return chunks


def patch_descriptor(buf: bytearray, section_offset: int) -> None:
    struct.pack_into("<I", buf, section_offset + 72, adler32(bytes(buf[section_offset : section_offset + 72])))


def patch_table_header(buf: bytearray, table_offset: int) -> None:
    header_start = table_offset + DESCRIPTOR_SIZE
    struct.pack_into("<I", buf, header_start + 20, adler32(bytes(buf[header_start : header_start + 16])))
    patch_descriptor(buf, table_offset)


def invalidate_table_checksums(buf: bytearray, table_offset: int) -> None:
    header_start = table_offset + DESCRIPTOR_SIZE
    stored = struct.unpack("<I", bytes(buf[header_start + 20 : header_start + 24]))[0]
    struct.pack_into("<I", buf, header_start + 20, stored ^ 0xDEADBEEF)
    desc_stored = struct.unpack("<I", bytes(buf[table_offset + 72 : table_offset + 76]))[0]
    struct.pack_into("<I", buf, table_offset + 72, desc_stored ^ 0xDEADBEEF)


def set_entry(buf: bytearray, table_offset: int, index: int, word: int) -> None:
    entry_start = table_offset + DESCRIPTOR_SIZE + TABLE_HEADER_SIZE + index * 4
    struct.pack_into("<I", buf, entry_start, word)


def entry_word(buf: bytearray, table_offset: int, index: int) -> int:
    entry_start = table_offset + DESCRIPTOR_SIZE + TABLE_HEADER_SIZE + index * 4
    return struct.unpack("<I", bytes(buf[entry_start : entry_start + 4]))[0]


def table_header(buf: bytearray, table_offset: int) -> tuple[int, int]:
    header_start = table_offset + DESCRIPTOR_SIZE
    number_of_entries, _reserved, base_offset = struct.unpack(
        "<IIQ", bytes(buf[header_start : header_start + 16])
    )
    return number_of_entries, base_offset


def section_offsets(image: bytes) -> dict[str, int]:
    result: dict[str, int] = {}
    offset = 13
    while True:
        name = image[offset : offset + 16].rstrip(b"\x00").decode("latin-1")
        next_offset, _size = struct.unpack("<QQ", image[offset + 16 : offset + 32])
        result.setdefault(name, offset)
        if name == "done" or next_offset == offset:
            break
        offset = next_offset
    return result


def save(buf: bytes, name: str, manifest: dict) -> Path:
    path = IMAGES / name
    path.write_bytes(buf)
    manifest["images"][name] = {"size": len(buf), "sha256": hashlib.sha256(buf).hexdigest()}
    return path


def main() -> None:
    IMAGES.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"scenarios": {}, "images": {}}

    chunks = logical_chunks()
    pristine = eb.build_image(chunks)
    pristine_bytes = pristine.image
    save(pristine_bytes, "00_baseline_uncompressed.E01", manifest)
    (REPORTS / "expected_logical.sha256").write_text(
        hashlib.sha256(b"".join(chunks)).hexdigest() + "  logical-image-baseline\n"
    )
    save(eb.build_image(chunks, compress=True).image, "01_baseline_compressed.E01", manifest)

    offsets = section_offsets(pristine_bytes)
    table_off = offsets["table"]
    table2_off = offsets["table2"]
    entry_count, base_offset = table_header(bytearray(pristine_bytes), table_off)

    # 02: primary entry tampered, all checksums remain valid (entry array is not
    # checksummed). Damage surfaces only when following the block map.
    buf = bytearray(pristine_bytes)
    word = entry_word(buf, table_off, 2)
    set_entry(buf, table_off, 2, word + 0x40)
    save(bytes(buf), "02_primary_entry_tampered_checksums_valid.E01", manifest)
    manifest["scenarios"]["02"] = {
        "name": "primary entry tampered, checksums valid",
        "mutation": f"table entry[2] 0x{word:08x} -> 0x{word + 0x40:08x}; no checksum covers entries",
        "table_offset": hex(table_off),
        "table2_offset": hex(table2_off),
    }

    # 03: backup compression flag flipped; reads following table2 fail while
    # every Adler-32 in the image still verifies.
    buf = bytearray(pristine_bytes)
    word = entry_word(buf, table2_off, 3)
    set_entry(buf, table2_off, 3, word ^ 0x80000000)
    save(bytes(buf), "03_backup_flag_flipped_checksums_valid.E01", manifest)
    manifest["scenarios"]["03"] = {
        "name": "backup compression flag flipped, checksums valid",
        "mutation": f"table2 entry[3] 0x{word:08x} -> 0x{word ^ 0x80000000:08x}",
        "table_offset": hex(table_off),
        "table2_offset": hex(table2_off),
    }

    # 04: two fully legal tables, two complete and different chunk sets.
    alt = alternate_chunks()
    divergent_bytes, divergent_info = eb.build_divergent_image(chunks, alt)
    save(divergent_bytes, "04_tables_divergent_both_valid.E01", manifest)
    manifest["scenarios"]["04"] = {
        "name": "both tables structurally valid, different block maps",
        "mutation": "table maps chunk set A via first sectors section; table2 maps set B via a second sectors section",
        "table_a_offset": hex(divergent_info["table_a_offset"]),
        "table_b_offset": hex(divergent_info["table_b_offset"]),
        "base_a": hex(divergent_info["base_a"]),
        "base_b": hex(divergent_info["base_b"]),
        "baseline_logical_sha256": hashlib.sha256(b"".join(chunks)).hexdigest(),
        "alternate_logical_sha256": hashlib.sha256(b"".join(alt)).hexdigest(),
    }

    # 05: primary table header + descriptor checksums invalidated.
    buf = bytearray(pristine_bytes)
    invalidate_table_checksums(buf, table_off)
    save(bytes(buf), "05_primary_stale_checksums.E01", manifest)
    manifest["scenarios"]["05"] = {
        "name": "primary table stale Adler-32 values",
        "mutation": "table header and section descriptor Adler-32 each XOR 0xDEADBEEF; bytes otherwise unchanged",
        "table_offset": hex(table_off),
        "table2_offset": hex(table2_off),
    }

    # 06: both tables carry invalid Adler-32 values.
    buf = bytearray(pristine_bytes)
    invalidate_table_checksums(buf, table_off)
    invalidate_table_checksums(buf, table2_off)
    save(bytes(buf), "06_both_tables_stale_checksums.E01", manifest)
    manifest["scenarios"]["06"] = {
        "name": "both tables stale Adler-32 values",
        "mutation": "table and table2 header/descriptor checksums invalidated",
        "table_offset": hex(table_off),
        "table2_offset": hex(table2_off),
    }

    # 07: primary base offset rewritten and checksums recomputed, so the table
    # is internally consistent but binds to the wrong address.
    buf = bytearray(pristine_bytes)
    header_start = table_off + DESCRIPTOR_SIZE
    wrong_base = base_offset + 0x80
    struct.pack_into("<Q", buf, header_start + 8, wrong_base)
    patch_table_header(buf, table_off)
    save(bytes(buf), "07_primary_wrong_base_offset.E01", manifest)
    manifest["scenarios"]["07"] = {
        "name": "primary table wrong base offset, checksums recomputed",
        "mutation": f"table base_offset {base_offset:#x} -> {wrong_base:#x}",
        "table_offset": hex(table_off),
        "table2_offset": hex(table2_off),
    }

    # 08: primary last-chunk entry moved onto the table boundary; checksums are
    # recomputed, so structure is legal but the last chunk span is invalid.
    buf = bytearray(pristine_bytes)
    bad_last = table_off - base_offset
    set_entry(buf, table_off, entry_count - 1, bad_last)
    patch_table_header(buf, table_off)
    save(bytes(buf), "08_primary_last_chunk_overflow.E01", manifest)
    manifest["scenarios"]["08"] = {
        "name": "primary last chunk crosses section boundary",
        "mutation": f"table entry[{entry_count - 1}] -> {bad_last:#x}; absolute target equals table offset",
        "table_offset": hex(table_off),
        "table2_offset": hex(table2_off),
    }

    (REPORTS / "scenario_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
