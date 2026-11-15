"""Forensic, repeatable audit of EWF ``table`` / ``table2`` block maps.

The audit never modifies the evidence file and never silently picks a table.
Every section is parsed directly from the on-disk bytes so that a corrupted
table does not prevent the backup table (or vice versa) from being examined.

Traceability rule applied throughout: every candidate chunk read records the
table name, table section offset, entry index, the raw 32 bit descriptor word,
the resulting absolute file offset and the compression flag. A successful
decompression is explicitly *not* treated as proof of content authenticity.

Reference implementation followed for block location (paraphrased, not
imported at read time): ``dissect/evidence/ewf/ewf.py`` ``EWF.read_chunk``:
``absolute = table.base_offset + (entry & 0x7FFFFFFF)`` and
``compressed = (entry >> 31) == 1``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

DESCRIPTOR_SIZE = 76
SEGMENT_HEADER_SIZE = 13
TABLE_HEADER_SIZE = 24
COMPRESSED_FLAG = 0x80000000
OFFSET_MASK = 0x7FFFFFFF
SECTION_TYPES = ("header", "header2", "volume", "disk", "data", "sectors", "table", "table2", "hash", "done")


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


@dataclass
class SectionInfo:
    type: str
    offset: int
    next_offset: int
    raw_size: int
    descriptor_checksum: int
    descriptor_checksum_ok: bool
    parse_error: str | None = None


@dataclass
class ChunkRead:
    chunk_index: int
    table: str
    table_offset: int
    entry_index: int
    descriptor_word: str
    absolute_offset: int | None
    relative_offset: int | None
    compressed: bool
    end_offset: int | None
    stored_size: int | None
    status: str
    detail: str
    logical_size: int | None = None
    logical_sha256: str | None = None
    checksum_ok: bool | None = None


@dataclass
class TableAudit:
    name: str
    section_offset: int
    descriptor_ok: bool
    header_checksum_ok: bool | None
    number_of_entries: int | None
    base_offset: int | None
    base_offset_matches_data: bool | None
    entry_words: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    reads: list[ChunkRead] = field(default_factory=list)
    candidate_sha256: str | None = None
    candidate_logical_size: int | None = None
    candidate_complete: bool = False

    @property
    def failed_reads(self) -> list[ChunkRead]:
        return [read for read in self.reads if read.status != "ok"]

    @property
    def structurally_valid(self) -> bool:
        return (
            self.descriptor_ok
            and self.header_checksum_ok is True
            and self.number_of_entries is not None
            and self.base_offset is not None
            and not self.issues
        )


class EWFTableAudit:
    """Parse one EWF segment and independently audit both block maps."""

    def __init__(self, path: str | Path, expected_chunks: int | None = None):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.expected_chunks = expected_chunks
        self.sections: list[SectionInfo] = list(self._walk_sections())
        self.data_sections = [
            section for section in self.sections if section.type in ("sectors", "data")
        ]
        self.data_section = self.data_sections[0] if self.data_sections else None
        self.volume = self._parse_volume()
        self.chunk_size = 512
        self.number_of_chunks = expected_chunks or (self.volume or {}).get("number_of_chunks")
        if self.volume:
            self.chunk_size = self.volume["sectors_per_chunk"] * self.volume["sector_size"]
            if self.number_of_chunks is None:
                self.number_of_chunks = self.volume["number_of_chunks"]
        self.tables: dict[str, TableAudit] = {}
        for section in self.sections:
            if section.type in ("table", "table2"):
                self.tables[section.type] = self._audit_table(section)
        self._attempt_reads()
        self.verdict, self.verdict_reason = self._decide()

    # ------------------------------------------------------------------ parse
    def _walk_sections(self) -> list[SectionInfo]:
        sections: list[SectionInfo] = []
        offset = SEGMENT_HEADER_SIZE
        file_size = len(self.data)
        for _ in range(64):
            if offset + DESCRIPTOR_SIZE > file_size:
                sections.append(
                    SectionInfo("<truncated>", offset, 0, 0, 0, False, "section descriptor exceeds file")
                )
                break
            raw = self.data[offset : offset + DESCRIPTOR_SIZE]
            name_raw, next_offset, raw_size = struct.unpack("<16sQQ", raw[:32])
            stored_checksum = struct.unpack("<I", raw[72:76])[0]
            checksum_ok = adler32(raw[:72]) == stored_checksum
            name = name_raw.rstrip(b"\x00").decode("latin-1", errors="replace")
            parse_error = None
            if name not in SECTION_TYPES:
                parse_error = f"unknown section type {name!r}"
            if raw_size and offset + raw_size > file_size:
                parse_error = (parse_error or "") + " section size exceeds file"
            sections.append(
                SectionInfo(name, offset, next_offset, raw_size, stored_checksum, checksum_ok, parse_error)
            )
            if name == "done" or next_offset == offset or next_offset > file_size:
                break
            offset = next_offset
        return sections

    def _parse_volume(self) -> dict | None:
        section = next((item for item in self.sections if item.type in ("volume", "disk")), None)
        if section is None or section.raw_size < DESCRIPTOR_SIZE + 24:
            return None
        body = self.data[section.offset + DESCRIPTOR_SIZE : section.offset + section.raw_size]
        try:
            (
                media_type,
                number_of_chunks,
                sectors_per_chunk,
                bytes_per_sector,
                number_of_sectors,
            ) = struct.unpack("<B3xIIII", body[:20])
        except struct.error:
            return None
        checksum = struct.unpack("<I", body[-4:])[0]
        return {
            "media_type": media_type,
            "number_of_chunks": number_of_chunks,
            "sectors_per_chunk": sectors_per_chunk,
            "sector_size": bytes_per_sector,
            "number_of_sectors": number_of_sectors,
            "checksum": checksum,
            "checksum_ok": adler32(body[:-4]) == checksum,
            "section_offset": section.offset,
        }

    # ---------------------------------------------------------------- tables
    def _audit_table(self, section: SectionInfo) -> TableAudit:
        audit = TableAudit(
            name=section.type,
            section_offset=section.offset,
            descriptor_ok=section.descriptor_checksum_ok,
            header_checksum_ok=None,
            number_of_entries=None,
            base_offset=None,
            base_offset_matches_data=None,
        )
        if section.parse_error:
            audit.issues.append(section.parse_error.strip())
        header_start = section.offset + DESCRIPTOR_SIZE
        if header_start + TABLE_HEADER_SIZE > len(self.data):
            audit.issues.append("table header exceeds file")
            return audit
        number_of_entries, _reserved, base_offset, _pad, stored_header_checksum = struct.unpack(
            "<IIQ4sI", self.data[header_start : header_start + TABLE_HEADER_SIZE]
        )
        # Inner checksum covers the first 16 bytes: number_of_entries, reserved
        # and base_offset (verified against reference EWF fixtures).
        header_head = self.data[header_start : header_start + 16]
        audit.header_checksum_ok = adler32(header_head) == stored_header_checksum
        audit.number_of_entries = number_of_entries
        audit.base_offset = base_offset
        if self.data_sections:
            matching = [
                section.offset + DESCRIPTOR_SIZE == base_offset for section in self.data_sections
            ]
            audit.base_offset_matches_data = any(matching)
            if not audit.base_offset_matches_data:
                expected = [
                    f"{section.offset + DESCRIPTOR_SIZE:#x}" for section in self.data_sections
                ]
                audit.issues.append(
                    f"base_offset {base_offset:#x} matches no chunk-data section body (starts: {', '.join(expected)})"
                )
        if not audit.descriptor_ok:
            audit.issues.append("section descriptor Adler-32 mismatch")
        if not audit.header_checksum_ok:
            audit.issues.append("table header Adler-32 mismatch (first 16 header bytes)")

        entries_start = header_start + TABLE_HEADER_SIZE
        if entries_start + number_of_entries * 4 > len(self.data):
            audit.issues.append("entry array exceeds file")
            return audit
        words = list(
            struct.unpack(
                f"<{number_of_entries}I",
                self.data[entries_start : entries_start + number_of_entries * 4],
            )
        )
        audit.entry_words = [f"0x{word:08x}" for word in words]

        if self.number_of_chunks is not None and number_of_entries != self.number_of_chunks:
            audit.issues.append(
                f"entry count {number_of_entries} != volume number_of_chunks {self.number_of_chunks}"
            )
        if base_offset > len(self.data):
            audit.issues.append("base_offset beyond end of file")
        for index, word in enumerate(words):
            relative = word & OFFSET_MASK
            absolute = base_offset + relative
            if absolute >= len(self.data):
                audit.issues.append(f"entry {index}: absolute offset {absolute:#x} beyond file")
            if index and relative <= (words[index - 1] & OFFSET_MASK):
                audit.issues.append(f"entry {index}: offsets not strictly increasing")
                break
        return audit

    # ----------------------------------------------------------------- reads
    def _attempt_reads(self) -> None:
        for name, audit in self.tables.items():
            if audit.number_of_entries is None or audit.base_offset is None:
                continue
            self._read_table(audit)

    def _read_table(self, audit: TableAudit) -> None:
        words = [int(word, 16) for word in audit.entry_words]
        table_end = audit.section_offset + next(
            section.raw_size for section in self.sections if section.offset == audit.section_offset
        )
        pieces: list[bytes] = []
        all_ok = True
        for index, word in enumerate(words):
            relative = word & OFFSET_MASK
            compressed = bool(word & COMPRESSED_FLAG)
            absolute = audit.base_offset + relative
            if index + 1 < len(words):
                end = audit.base_offset + (words[index + 1] & OFFSET_MASK)
            else:
                # Last-chunk boundary, generalized from EWF.read_chunk:
                # 1. when the chunk sits in a chunk-data section whose body
                #    starts at this table's base offset, it ends at that
                #    section's raw end (each table may bind its own section);
                # 2. a chunk embedded inside this table ends at its raw end;
                # 3. otherwise the first later table section is used, then the
                #    table descriptor offset itself.
                bound_section = next(
                    (
                        section
                        for section in self.data_sections
                        if section.offset + DESCRIPTOR_SIZE == audit.base_offset
                    ),
                    None,
                )
                if bound_section is not None and absolute < bound_section.offset + bound_section.raw_size:
                    end = bound_section.offset + bound_section.raw_size
                elif absolute >= audit.section_offset:
                    end = table_end
                else:
                    later_tables = [
                        section.offset
                        for section in self.sections
                        if section.type in ("table", "table2") and section.offset >= absolute
                    ]
                    end = later_tables[0] if later_tables else audit.section_offset
            read = ChunkRead(
                chunk_index=index,
                table=audit.name,
                table_offset=audit.section_offset,
                entry_index=index,
                descriptor_word=f"0x{word:08x}",
                absolute_offset=absolute,
                relative_offset=relative,
                compressed=compressed,
                end_offset=end,
                stored_size=None,
                status="ok",
                detail="",
            )
            if end <= absolute or end > len(self.data):
                read.status = "error"
                read.detail = f"invalid span [{absolute:#x},{end:#x})"
                all_ok = False
                audit.reads.append(read)
                continue
            stored = self.data[absolute:end]
            read.stored_size = len(stored)
            try:
                if compressed:
                    logical = zlib.decompress(stored)
                    read.checksum_ok = None
                else:
                    if len(stored) < 4:
                        raise ValueError("uncompressed chunk missing 4 byte Adler-32 trailer")
                    payload, trailer = stored[:-4], struct.unpack("<I", stored[-4:])[0]
                    read.checksum_ok = adler32(payload) == trailer
                    if not read.checksum_ok:
                        raise ValueError("chunk trailer Adler-32 mismatch")
                    logical = payload
            except (zlib.error, ValueError) as exc:
                read.status = "error"
                read.detail = str(exc)
                all_ok = False
                audit.reads.append(read)
                continue
            read.logical_size = len(logical)
            read.logical_sha256 = hashlib.sha256(logical).hexdigest()
            if index == len(words) - 1 and len(logical) > self.chunk_size:
                read.status = "error"
                read.detail = f"last chunk {len(logical)} bytes exceeds chunk size {self.chunk_size}"
                all_ok = False
            elif index != len(words) - 1 and len(logical) != self.chunk_size:
                read.status = "error"
                read.detail = f"full chunk decompressed to {len(logical)} bytes, expected {self.chunk_size}"
                all_ok = False
            pieces.append(logical)
            audit.reads.append(read)
        if all_ok and pieces:
            stitched = b"".join(pieces)
            audit.candidate_complete = True
            audit.candidate_logical_size = len(stitched)
            audit.candidate_sha256 = hashlib.sha256(stitched).hexdigest()

    # --------------------------------------------------------------- verdict
    def _decide(self) -> tuple[str, str]:
        primary = self.tables.get("table")
        backup = self.tables.get("table2")
        if primary is None or backup is None:
            return "INSUFFICIENT_EVIDENCE", "one of table/table2 is absent"

        primary_map = [int(word, 16) for word in primary.entry_words]
        backup_map = [int(word, 16) for word in backup.entry_words]
        maps_equal = primary_map == backup_map and primary.base_offset == backup.base_offset

        both_structurally_valid = primary.structurally_valid and backup.structurally_valid
        any_read_complete = primary.candidate_complete or backup.candidate_complete

        if not both_structurally_valid:
            if not any_read_complete:
                return (
                    "INSUFFICIENT_EVIDENCE",
                    "at least one block map is structurally invalid and no complete candidate read exists",
                )
            if not primary.structurally_valid and not backup.structurally_valid:
                return (
                    "INSUFFICIENT_EVIDENCE",
                    "both tables fail structural checksums; readable bytes cannot be attributed to a trusted map",
                )
            survivor = primary if primary.structurally_valid else backup
            if maps_equal:
                return (
                    "RECOVERABLE_SINGLE_TABLE",
                    f"maps agree and only {survivor.name} passes structural validation and reads completely",
                )
            return (
                "INSUFFICIENT_EVIDENCE",
                f"only {survivor.name} passes validation but the maps disagree; "
                "the survivor cannot be authenticated",
            )

        if not any_read_complete:
            return (
                "INSUFFICIENT_EVIDENCE",
                "both tables parse structurally but neither yields a complete candidate read",
            )

        if maps_equal:
            if (
                primary.candidate_complete
                and backup.candidate_complete
                and primary.candidate_sha256 == backup.candidate_sha256
            ):
                return (
                    "RECOVERABLE_CONSISTENT",
                    "both tables valid, identical maps and identical candidate output",
                )
            return "CONFLICT", "maps match but candidate reads disagree or fail"

        if primary.candidate_complete and backup.candidate_complete:
            return (
                "CONFLICT",
                "both tables are structurally valid and fully readable but point at different blocks",
            )
        return (
            "INSUFFICIENT_EVIDENCE",
            "valid tables diverge and at least one candidate read is incomplete",
        )

    # ------------------------------------------------------------- reporting
    def to_dict(self) -> dict:
        return {
            "file": str(self.path),
            "file_size": len(self.data),
            "file_sha256": hashlib.sha256(self.data).hexdigest(),
            "chunk_size": self.chunk_size,
            "number_of_chunks": self.number_of_chunks,
            "volume": self.volume,
            "sections": [asdict(section) for section in self.sections],
            "tables": {
                name: {
                    **{key: value for key, value in asdict(audit).items() if key != "reads"},
                    "structurally_valid": audit.structurally_valid,
                    "failed_read_count": len(audit.failed_reads),
                    "reads": [asdict(read) for read in audit.reads],
                }
                for name, audit in self.tables.items()
            },
            "verdict": self.verdict,
            "verdict_reason": self.verdict_reason,
        }

    def render_text(self) -> str:
        report = self.to_dict()
        lines = [
            f"EWF table audit: {self.path}",
            f"file sha256: {report['file_sha256']}",
            f"chunk size: {self.chunk_size}  declared chunks: {self.number_of_chunks}",
            "",
            "sections:",
        ]
        for section in self.sections:
            marker = "ok " if section.descriptor_checksum_ok else "BAD"
            lines.append(
                f"  [{marker}] {section.type:8s} off={section.offset:#08x} next={section.next_offset:#08x} "
                f"size={section.raw_size:#08x} cksum={section.descriptor_checksum:#010x}"
                + (f"  ERROR: {section.parse_error}" if section.parse_error else "")
            )
        if self.volume:
            lines += [
                "",
                f"volume: chunks={self.volume['number_of_chunks']} chunk_size="
                f"{self.volume['sectors_per_chunk'] * self.volume['sector_size']} "
                f"checksum_ok={self.volume['checksum_ok']}",
            ]
        for name, audit in self.tables.items():
            lines += [
                "",
                f"== {name} @ {audit.section_offset:#x} ==",
                f"descriptor_ok={audit.descriptor_ok} header_checksum_ok={audit.header_checksum_ok} "
                f"entries={audit.number_of_entries} base_offset={audit.base_offset and hex(audit.base_offset)} "
                f"base_matches_data={audit.base_offset_matches_data}",
                f"structurally_valid={audit.structurally_valid} complete_candidate={audit.candidate_complete} "
                f"candidate_sha256={audit.candidate_sha256}",
            ]
            for issue in audit.issues:
                lines.append(f"  ISSUE: {issue}")
            for read in audit.reads:
                lines.append(
                    f"  chunk {read.chunk_index:02d} word={read.descriptor_word} "
                    f"abs={read.absolute_offset and hex(read.absolute_offset)} "
                    f"end={read.end_offset and hex(read.end_offset)} compressed={read.compressed} "
                    f"status={read.status} sha={read.logical_sha256 and read.logical_sha256[:12]}"
                    + (f"  {read.detail}" if read.detail else "")
                )
        lines += ["", f"VERDICT: {self.verdict} - {self.verdict_reason}"]
        return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--json", type=Path, help="write machine readable report")
    parser.add_argument("--expected-chunks", type=int, default=None)
    args = parser.parse_args()
    audit = EWFTableAudit(args.image, args.expected_chunks)
    print(audit.render_text())
    if args.json:
        args.json.write_text(json.dumps(audit.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
