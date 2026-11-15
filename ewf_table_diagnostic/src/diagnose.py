"""Repeatable diagnostic for EWF table vs table2 block-location divergence.

The diagnostic deliberately does NOT stop at "the image decompresses". For every
table it independently verifies structural integrity and block-level evidence,
mirroring the location path used by dissect.evidence (dissect/evidence/ewf/ewf.py,
EWF.read_chunk) but without its implicit trust:

  * section descriptor Adler-32 checksum
  * table header and table entry-array Adler-32 checksums
  * base offset, compression flag (entry bit 31) and block bounds
  * last-chunk boundary against the owning section (ewf.py lines 202-216)
  * uncompressed trailing Adler-32 chunk checksum and zlib decompression
  * cross-table agreement of every decoded chunk

Each per-chunk result records the table, raw entry value, absolute offset and
span used, so any recovered byte can be traced to its source table and offset.

Verdicts:
  RECOVERABLE  - exactly one table is structurally valid and its blocks verify;
                 the other is demonstrably corrupt or inconsistent.
  CONFLICT     - both tables are structurally valid and readable, but locate or
                 decode different content; no tool may silently pick one.
  INSUFFICIENT - neither table provides verified, self-consistent evidence
                 (e.g. both fail checksum or bounds checks). A successful
                 decompression alone never upgrades this to RECOVERABLE.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

from dissect.evidence.ewf import c_ewf

DESCRIPTOR_SIZE = len(c_ewf.SectionDescriptor)
TABLE_HEADER_SIZE = len(c_ewf.TableSection)
HIGH_BIT = 0x80000000
LOW_MASK = 0x7FFFFFFF
RECOVERABLE = "RECOVERABLE"
CONFLICT = "CONFLICT"
INSUFFICIENT = "INSUFFICIENT"


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


@dataclass
class TableLocation:
    section_type: str
    descriptor_offset: int
    payload_offset: int
    raw_section_size: int
    number_of_entries: int
    base_offset: int
    stored_header_checksum: int
    computed_header_checksum: int
    stored_entries_checksum: int
    computed_entries_checksum: int
    descriptor_checksum_ok: bool
    header_checksum_ok: bool
    entries_checksum_ok: bool
    entries: list[int]
    structurally_valid: bool
    invalid_reasons: list[str] = field(default_factory=list)


@dataclass
class BlockResult:
    table: str
    chunk: int
    raw_entry: str
    absolute_offset: int
    compressed: bool
    span_start: int
    span_end: int
    span_length: int
    in_bounds: bool
    decode_ok: bool
    chunk_checksum_ok: bool | None
    payload_sha256: str | None
    payload_preview: str | None
    errors: list[str] = field(default_factory=list)


def parse_sections(buf: bytes) -> list[dict]:
    """Walk section descriptors using the same next-offset chain as Segment."""
    sections = []
    offset = len(c_ewf.SegmentHeader)
    while True:
        descriptor = c_ewf.SectionDescriptor(buf[offset : offset + DESCRIPTOR_SIZE])
        section_type = descriptor.type.rstrip(b"\x00").decode()
        # Adler-32 over the 72 bytes preceding the checksum; stored little-endian.
        computed = adler32(buf[offset : offset + DESCRIPTOR_SIZE - 4])
        sections.append(
            {
                "type": section_type,
                "offset": offset,
                "next": descriptor.next,
                "size": descriptor.size,
                "stored_checksum": descriptor.checksum,
                "computed_checksum": computed,
                "checksum_ok": descriptor.checksum == computed,
            }
        )
        if descriptor.next == offset or section_type == "done":
            break
        offset = descriptor.next
    return sections


def parse_table(buf: bytes, section: dict) -> TableLocation:
    payload_offset = section["offset"] + DESCRIPTOR_SIZE
    header = c_ewf.TableSection(buf[payload_offset : payload_offset + TABLE_HEADER_SIZE])
    number_of_entries = header.number_of_entries
    base_offset = header.base_offset

    header_bytes = buf[payload_offset : payload_offset + 20]
    computed_header = adler32(header_bytes)
    entries_start = payload_offset + TABLE_HEADER_SIZE
    entry_bytes = buf[entries_start : entries_start + number_of_entries * 4]
    entries = list(struct.unpack(f"<{number_of_entries}I", entry_bytes))
    # Table checksums are little-endian Adler-32 (same convention as descriptors).
    stored_entries_checksum = struct.unpack(
        "<I", buf[entries_start + len(entry_bytes) : entries_start + len(entry_bytes) + 4]
    )[0]
    computed_entries = adler32(entry_bytes)

    invalid_reasons = []
    descriptor_ok = section["checksum_ok"]
    header_ok = header.checksum == computed_header
    entries_ok = stored_entries_checksum == computed_entries
    if not descriptor_ok:
        invalid_reasons.append("section descriptor checksum mismatch")
    if not header_ok:
        invalid_reasons.append("table header checksum mismatch")
    if not entries_ok:
        invalid_reasons.append("table entries checksum mismatch")
    if base_offset != 0:
        invalid_reasons.append(f"non-zero base offset {base_offset:#x} (fixtures use 0)")

    return TableLocation(
        section_type=section["type"],
        descriptor_offset=section["offset"],
        payload_offset=payload_offset,
        raw_section_size=section["size"],
        number_of_entries=number_of_entries,
        base_offset=base_offset,
        stored_header_checksum=header.checksum,
        computed_header_checksum=computed_header,
        stored_entries_checksum=stored_entries_checksum,
        computed_entries_checksum=computed_entries,
        descriptor_checksum_ok=descriptor_ok,
        header_checksum_ok=header_ok,
        entries_checksum_ok=entries_ok,
        entries=entries,
        structurally_valid=not invalid_reasons,
        invalid_reasons=invalid_reasons,
    )


def block_span(table: TableLocation, index: int) -> tuple[int, int]:
    """Replicate ewf.py read_chunk boundary logic, including last-chunk rule."""
    start = table.base_offset + (table.entries[index] & LOW_MASK)
    if index == table.number_of_entries - 1:
        if start < table.descriptor_offset:
            end = table.descriptor_offset
        elif start < table.descriptor_offset + table.raw_section_size:
            end = table.descriptor_offset + table.raw_section_size
        else:
            raise ValueError("Unknown size of last chunk")
    else:
        end = table.base_offset + (table.entries[index + 1] & LOW_MASK)
    return start, end


def read_block(buf: bytes, file_size: int, table: TableLocation, index: int) -> BlockResult:
    raw_entry = table.entries[index]
    compressed = bool(raw_entry >> 31)
    errors: list[str] = []
    try:
        start, end = block_span(table, index)
    except ValueError as exc:
        return BlockResult(
            table=table.section_type,
            chunk=index,
            raw_entry=hex(raw_entry),
            absolute_offset=raw_entry & LOW_MASK,
            compressed=compressed,
            span_start=-1,
            span_end=-1,
            span_length=-1,
            in_bounds=False,
            decode_ok=False,
            chunk_checksum_ok=None,
            payload_sha256=None,
            payload_preview=None,
            errors=[str(exc)],
        )

    in_bounds = 0 <= start < end <= file_size
    payload = None
    chunk_checksum_ok = None
    if in_bounds:
        raw = buf[start:end]
        if compressed:
            try:
                payload = zlib.decompress(raw)
            except zlib.error as exc:
                errors.append(f"zlib decompress failed: {exc}")
        else:
            if len(raw) < 4:
                errors.append("uncompressed block shorter than 4-byte checksum")
            else:
                stored = struct.unpack("<I", raw[-4:])[0]
                chunk_checksum_ok = adler32(raw[:-4]) == stored
                if not chunk_checksum_ok:
                    errors.append("uncompressed chunk Adler-32 checksum mismatch")
                payload = raw[:-4]
    else:
        errors.append(f"block span [{start:#x},{end:#x}) outside file of {file_size:#x}")

    decode_ok = payload is not None and not errors
    return BlockResult(
        table=table.section_type,
        chunk=index,
        raw_entry=hex(raw_entry),
        absolute_offset=start,
        compressed=compressed,
        span_start=start,
        span_end=end,
        span_length=end - start,
        in_bounds=in_bounds,
        decode_ok=decode_ok,
        chunk_checksum_ok=chunk_checksum_ok,
        payload_sha256=hashlib.sha256(payload).hexdigest() if payload is not None else None,
        payload_preview=payload[:18].decode("latin-1") if payload is not None else None,
        errors=errors,
    )


def evaluate_table(buf: bytes, file_size: int, table: TableLocation) -> list[BlockResult]:
    return [read_block(buf, file_size, table, index) for index in range(table.number_of_entries)]


def cross_compare(primary_blocks: list[BlockResult], backup_blocks: list[BlockResult]) -> dict:
    per_chunk = []
    all_agree = True
    for primary, backup in zip(primary_blocks, backup_blocks):
        agree = (
            primary.decode_ok
            and backup.decode_ok
            and primary.payload_sha256 == backup.payload_sha256
        )
        all_agree &= agree
        per_chunk.append(
            {
                "chunk": primary.chunk,
                "agree": agree,
                "primary_offset": primary.absolute_offset,
                "backup_offset": backup.absolute_offset,
                "primary_sha256": primary.payload_sha256,
                "backup_sha256": backup.payload_sha256,
            }
        )
    return {"all_chunks_agree": all_agree, "chunks": per_chunk}


def decide(
    primary: TableLocation,
    backup: TableLocation,
    primary_blocks: list[BlockResult],
    backup_blocks: list[BlockResult],
    comparison: dict,
) -> tuple[str, str]:
    primary_ok = primary.structurally_valid and all(block.decode_ok for block in primary_blocks)
    backup_ok = backup.structurally_valid and all(block.decode_ok for block in backup_blocks)

    if primary_ok and backup_ok:
        if comparison["all_chunks_agree"]:
            return RECOVERABLE, "both tables valid and content identical; primary/backup corroborate each other"
        return CONFLICT, "both tables structurally valid but point to different blocks/content"
    if primary_ok ^ backup_ok:
        surviving = "primary table" if primary_ok else "backup table2"
        broken = "backup table2" if primary_ok else "primary table"
        return RECOVERABLE, f"only {surviving} verifies; {broken} is structurally invalid or unreadable"
    return INSUFFICIENT, "neither table yields fully verified, self-consistent blocks"


def diagnose_image(path: Path) -> dict:
    buf = path.read_bytes()
    file_size = len(buf)
    sections = parse_sections(buf)
    table_sections = [section for section in sections if section["type"] == "table"]
    table2_sections = [section for section in sections if section["type"] == "table2"]
    if len(table_sections) != 1 or len(table2_sections) != 1:
        raise ValueError(f"expected one table and one table2, got {len(table_sections)}/{len(table2_sections)}")

    primary = parse_table(buf, table_sections[0])
    backup = parse_table(buf, table2_sections[0])
    primary_blocks = evaluate_table(buf, file_size, primary)
    backup_blocks = evaluate_table(buf, file_size, backup)
    comparison = cross_compare(primary_blocks, backup_blocks)
    verdict, rationale = decide(primary, backup, primary_blocks, backup_blocks, comparison)

    return {
        "image": str(path),
        "file_size": file_size,
        "sha256": hashlib.sha256(buf).hexdigest(),
        "sections": sections,
        "tables": {"primary": asdict(primary), "backup": asdict(backup)},
        "blocks": {
            "primary": [asdict(block) for block in primary_blocks],
            "backup": [asdict(block) for block in backup_blocks],
        },
        "cross_table_comparison": comparison,
        "verdict": verdict,
        "rationale": rationale,
        "dissect_note": "Segment.tables uses type(section) is TableSection, so dissect.evidence never reads table2",
    }


def render_text(report: dict) -> str:
    lines = []
    lines.append(f"image: {report['image']}")
    lines.append(f"sha256: {report['sha256']}")
    lines.append(f"size: {report['file_size']} bytes")
    lines.append("sections:")
    for section in report["sections"]:
        check = "ok" if section["checksum_ok"] else "BAD"
        lines.append(
            f"  {section['type']:<8} desc_off={section['offset']:#08x} "
            f"raw={section['size']:#x} next={section['next']:#x} checksum={check}"
        )
    for label, table in report["tables"].items():
        lines.append(
            f"{label} ({table['section_type']}) at {table['descriptor_offset']:#x}: "
            f"base_offset={table['base_offset']:#x} entries={table['number_of_entries']} "
            f"structurally_valid={table['structurally_valid']}"
        )
        lines.append(
            f"  checksums descriptor={table['descriptor_checksum_ok']} "
            f"header={table['header_checksum_ok']} entries={table['entries_checksum_ok']}"
        )
        if table["invalid_reasons"]:
            lines.append(f"  invalid_reasons={table['invalid_reasons']}")
    lines.append("block traceability (table / chunk / entry -> offset,span / compressed / verify):")
    for label in ("primary", "backup"):
        for block in report["blocks"][label]:
            verify = "ok" if block["decode_ok"] else "FAIL"
            checksum = block["chunk_checksum_ok"]
            lines.append(
                f"  [{label}] chunk={block['chunk']} entry={block['raw_entry']} "
                f"offset={block['absolute_offset']:#x} span=[{block['span_start']:#x},{block['span_end']:#x}) "
                f"compressed={block['compressed']} adler={checksum} verify={verify} "
                f"sha256={str(block['payload_sha256'])[:16]} preview={block['payload_preview']!r}"
            )
            for error in block["errors"]:
                lines.append(f"      error: {error}")
    lines.append(f"cross-table agreement: {report['cross_table_comparison']['all_chunks_agree']}")
    lines.append(f"VERDICT: {report['verdict']} - {report['rationale']}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("images", nargs="+", type=Path, help="EWF .E01 images to diagnose")
    parser.add_argument("--json-dir", type=Path, help="directory to write per-image JSON reports")
    args = parser.parse_args()

    if args.json_dir:
        args.json_dir.mkdir(parents=True, exist_ok=True)

    reports = []
    for image in args.images:
        report = diagnose_image(image)
        reports.append(report)
        print(render_text(report))
        print("\n" + "=" * 88 + "\n")
        if args.json_dir:
            out = args.json_dir / f"{image.stem}.diagnostic.json"
            out.write_text(json.dumps(report, indent=2, sort_keys=True))

    print("summary:")
    for report in reports:
        print(f"  {Path(report['image']).name:<32} {report['verdict']:<12} {report['rationale']}")


if __name__ == "__main__":
    main()
