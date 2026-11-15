"""Build minimal, byte-controlled EWF (E01) images with table/table2 divergence.

All artefacts are written to ewf_table_diagnostic/images. The pristine baseline
image is never modified: every scenario is written to its own file.

Layout reference (offsets are recorded in the generated manifest):
  SegmentHeader (EVF) -> header2 -> volume -> data section(s) -> table/table2
  sections -> done.

Checksums follow the libewf convention also implied by dissect's structures:
Adler-32, big-endian, computed over the section bytes excluding the checksum
field itself. dissect.evidence never verifies these checksums; this builder and
the companion diagnostic do, so that corruption is detectable independently of
whether the data still "reads".
"""
from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

SEGMENT_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
DESCRIPTOR_SIZE = 76          # c_ewf.SectionDescriptor
TABLE_HEADER_SIZE = 24        # c_ewf.TableSection
CHUNK_SIZE = 4096             # 8 sectors * 512 bytes
N_CHUNKS = 4
HIGH_BIT = 0x80000000


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def descriptor(section_type: bytes, next_offset: int, payload: bytes) -> tuple[bytes, int]:
    """Return a full section (descriptor + payload) and the section's raw size.

    Section descriptor checksums are Adler-32 stored little-endian (verified
    against libewf-produced images), unlike table checksums which are big-endian.
    """
    raw_size = DESCRIPTOR_SIZE + len(payload)
    head = struct.pack("<16sQQ40s", section_type, next_offset, raw_size, b"\x00" * 40)
    checksum = adler32(head)
    return head + struct.pack("<I", checksum) + payload, raw_size


def table_section(number_of_entries: int, base_offset: int, entries: list[int]) -> bytes:
    # All EWF Adler-32 checksums are stored little-endian (verified empirically
    # against libewf-produced images), including the uncompressed chunk trailer.
    header_body = struct.pack("<IIQI", number_of_entries, 0, base_offset, 0)
    header_checksum = adler32(header_body)
    entry_bytes = b"".join(struct.pack("<I", entry) for entry in entries)
    entries_checksum = adler32(entry_bytes)
    payload = (
        header_body
        + struct.pack("<I", header_checksum)
        + entry_bytes
        + struct.pack("<I", entries_checksum)
    )
    return payload


def volume_section() -> bytes:
    # Mirrors c_ewf.VolumeSection (1052 bytes); checksum over all but last 4.
    body = b"".join(
        [
            struct.pack("<B", 1),                    # media_type = Fixed
            b"\x00" * 3,                             # reserved_1
            struct.pack("<III", N_CHUNKS, 8, 512),   # chunks, sectors/chunk, sector size
            struct.pack("<Q", N_CHUNKS * 8),         # number_of_sectors
            struct.pack("<III", 0, 0, 0),            # chs
            struct.pack("<B", 1),                    # media_flags = Image
            b"\x00" * 3,
            struct.pack("<III", 0, 0, 0),            # palm / unknown / smart logs
            struct.pack("<B", 0),                    # compression_level = None
            b"\x00" * 3,
            struct.pack("<II", 0, 0),                # error granularity / unknown
            b"\x00" * 16,                            # set_identifier
            b"\x00" * 964,                           # pad (sized to total 1048 incl. signature)
            b"EVFS",                                 # signature (not parsed by dissect)
        ]
    )
    assert len(body) == 1048
    return body + struct.pack("<I", adler32(body))


def make_payload(set_name: bytes, chunk_index: int) -> bytes:
    marker = b"SET-%s|chunk-%02d|" % (set_name, chunk_index)
    return marker + bytes([0x41 + chunk_index]) * (CHUNK_SIZE - len(marker))


def encode_chunk(payload: bytes, compressed: bool) -> bytes:
    if compressed:
        return zlib.compress(payload)
    return payload + struct.pack("<I", adler32(payload))


@dataclass
class ChunkRecord:
    index: int
    compressed: bool
    relative_offset: int
    stored_length: int
    payload_sha256: str


def build_data_section(set_name: bytes, compression_map: tuple[bool, ...]) -> tuple[bytes, list[ChunkRecord]]:
    records: list[ChunkRecord] = []
    blob = bytearray()
    for index, compressed in enumerate(compression_map):
        payload = make_payload(set_name, index)
        encoded = encode_chunk(payload, compressed)
        records.append(
            ChunkRecord(
                index=index,
                compressed=compressed,
                relative_offset=len(blob),
                stored_length=len(encoded),
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
        blob += encoded
    return bytes(blob), records


def entries_for(records: list[ChunkRecord], data_descriptor_start: int) -> list[int]:
    # base_offset is 0 in these images, so entries must hold absolute offsets:
    # dissect computes offset_of_chunk = table.base_offset + (entry & 0x7fffffff).
    # record.relative_offset is relative to the data payload (after descriptor).
    result = []
    for record in records:
        entry = data_descriptor_start + DESCRIPTOR_SIZE + record.relative_offset
        if record.compressed:
            entry |= HIGH_BIT
        result.append(entry)
    return result


def assemble(sections: list[bytes]) -> bytearray:
    image = bytearray(SEGMENT_SIGNATURE + struct.pack("<BHH", 1, 1, 0))
    image += b"".join(sections)
    return image


def header2_section() -> bytes:
    text = "ewf_table_diagnostic reproducible fixture".encode("utf-8")
    return zlib.compress(text)


def build_layout(b_data_between_tables: bool, table2_points_b: bool) -> dict:
    """Build an image and return its manifest.

    b_data_between_tables: place the SET-B data section between table and table2
      (required so that a table2 referencing B has a legal last-chunk boundary).
    table2_points_b: table2 entries point at SET-B instead of SET-A.
    """
    compression_map = (False, True, False, True)
    data_a, records_a = build_data_section(b"A", compression_map)
    data_b, records_b = build_data_section(b"B", compression_map)

    sections: list[tuple[str, bytes]] = []
    sections.append(("header2", header2_section()))
    sections.append(("volume", volume_section()))
    sections.append(("data", data_a))
    sections.append(("__table_anchor__", b""))  # placeholder, resolved below
    if b_data_between_tables:
        sections.append(("data", data_b))
    sections.append(("__table2_anchor__", b""))
    if not b_data_between_tables:
        sections.append(("data", data_b))

    # Resolve absolute offsets using a dry run with empty table payloads.
    def render(table_payload_a: bytes, table_payload_b: bytes) -> list[tuple[str, bytes]]:
        rendered: list[tuple[str, bytes]] = []
        for name, payload in sections:
            if name == "__table_anchor__":
                rendered.append(("table", table_payload_a))
            elif name == "__table2_anchor__":
                rendered.append(("table2", table_payload_b))
            else:
                rendered.append((name, payload))
        return rendered

    def layout_offsets(rendered: list[tuple[str, bytes]]) -> dict[str, int]:
        offset = len(SEGMENT_SIGNATURE) + 5
        offsets: dict[str, int] = {}
        for name, payload in rendered:
            offsets.setdefault(name + "_first", offset)
            offsets[name + "_last"] = offset
            offset += DESCRIPTOR_SIZE + len(payload)
        offsets["__end__"] = offset
        return offsets

    # First pass: discover where each data section begins (base_offset = 0).
    dummy = table_section(N_CHUNKS, 0, [0] * N_CHUNKS)
    first_render = render(dummy, dummy)
    offsets = layout_offsets(first_render)
    data_section_starts = [
        offset
        for name, offset in offsets.items()
        if name == "data_first" or name == "data_last"
    ]
    # Every section is visited exactly once in order; keep distinct starts only.
    seen: set[int] = set()
    ordered_starts = [x for x in data_section_starts if not (x in seen or seen.add(x))]
    data_a_start = ordered_starts[0]
    data_b_start_abs = ordered_starts[1]

    entries_a = entries_for(records_a, data_a_start)
    entries_b = entries_for(records_b, data_b_start_abs)
    table_payload = table_section(N_CHUNKS, 0, entries_a)
    table2_payload = table_section(N_CHUNKS, 0, entries_b if table2_points_b else entries_a)

    final_render = render(table_payload, table2_payload)
    final_offsets = layout_offsets(final_render)

    # Patch section descriptors with correct "next" offsets and checksums.
    image = bytearray(SEGMENT_SIGNATURE + struct.pack("<BHH", 1, 1, 0))
    section_manifest = []
    total = len(image)
    flat = final_render + [("done", b"")]
    for idx, (name, payload) in enumerate(flat):
        section_start = total
        if name == "done":
            next_offset = section_start
        else:
            next_offset = section_start + DESCRIPTOR_SIZE + len(payload)
        blob, raw_size = descriptor(name.encode(), next_offset, payload)
        image += blob
        section_manifest.append(
            {
                "name": name,
                "descriptor_offset": section_start,
                "raw_size": raw_size,
                "next_offset": next_offset,
            }
        )
        total += len(blob)

    manifest = {
        "chunk_size": CHUNK_SIZE,
        "number_of_chunks": N_CHUNKS,
        "compression_map": list(compression_map),
        "base_offset": 0,
        "sections": section_manifest,
        "data_a_start": data_a_start,
        "data_b_start": data_b_start_abs,
        "entries_primary": entries_a,
        "entries_backup": entries_b if table2_points_b else entries_a,
        "chunks_a": [record.__dict__ for record in records_a],
        "chunks_b": [record.__dict__ for record in records_b],
        "image_size": len(image),
        "layout": "B-between-tables" if b_data_between_tables else "B-after-table2",
    }
    return {"image": bytes(image), "manifest": manifest}


def corrupt_table(image: bytearray, manifest: dict, section_name: str) -> None:
    """Invalidate one table section in-place: header checksum + first entry.

    The first entry is repointed past end of file, which the diagnostic flags
    as an out-of-bounds block location independently of the checksum failure.
    """
    section = next(s for s in manifest["sections"] if s["name"] == section_name)
    descriptor_offset = section["descriptor_offset"]
    payload_start = descriptor_offset + DESCRIPTOR_SIZE
    # Flip the table header checksum (last 4 bytes of the 24-byte header).
    checksum_at = payload_start + TABLE_HEADER_SIZE - 4
    image[checksum_at : checksum_at + 4] = b"\xde\xad\xbe\xef"
    # Repoint entry 0 beyond the file while keeping its compression flag intact.
    entry0_at = payload_start + TABLE_HEADER_SIZE
    (old,) = struct.unpack("<I", image[entry0_at : entry0_at + 4])
    struct.pack_into("<I", image, entry0_at, (old & HIGH_BIT) | 0x007FFFFF)


def main() -> None:
    out_dir = Path(__file__).resolve().parents[1] / "images"
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = {
        # name: (B between tables, table2 points at B)
        "baseline.E01": (False, False),
        "case1_primary_corrupt.E01": (False, False),
        "case2_backup_corrupt.E01": (False, False),
        "case3_divergent_legal.E01": (True, True),
        "case4_both_tables_corrupt.E01": (False, False),
    }

    index: dict[str, dict] = {}
    built: dict[str, dict] = {}
    for name, args in scenarios.items():
        built[name] = build_layout(*args)

    baseline_bytes = built["baseline.E01"]["image"]
    baseline_hash = hashlib.sha256(baseline_bytes).hexdigest()

    for name, artifact in built.items():
        image = bytearray(artifact["image"])
        manifest = artifact["manifest"]
        if name == "case1_primary_corrupt.E01":
            corrupt_table(image, manifest, "table")
            manifest["applied_corruption"] = "primary table: bad header checksum, entry0 repointed OOB"
        elif name == "case2_backup_corrupt.E01":
            corrupt_table(image, manifest, "table2")
            manifest["applied_corruption"] = "backup table2: bad header checksum, entry0 repointed OOB"
        elif name == "case4_both_tables_corrupt.E01":
            corrupt_table(image, manifest, "table")
            corrupt_table(image, manifest, "table2")
            manifest["applied_corruption"] = "both tables: bad header checksum; entries otherwise unchanged"
        else:
            manifest["applied_corruption"] = "none"

        path = out_dir / name
        path.write_bytes(bytes(image))
        manifest["file"] = str(path)
        manifest["sha256"] = hashlib.sha256(bytes(image)).hexdigest()
        index[name] = manifest

    # Guard: the pristine baseline on disk must equal the unmodified build.
    assert hashlib.sha256((out_dir / "baseline.E01").read_bytes()).hexdigest() == baseline_hash
    index["__baseline_untouched_sha256__"] = baseline_hash

    (out_dir / "manifest.json").write_text(json.dumps(index, indent=2, sort_keys=True))
    print(f"Wrote {len(scenarios)} images and manifest to {out_dir}")
    for name in scenarios:
        print(f"  {name}: {index[name]['sha256'][:16]}... ({index[name]['image_size']} bytes)")


if __name__ == "__main__":
    main()
