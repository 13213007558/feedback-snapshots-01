"""Read-only consistency diagnostics for captured CIM store files.

A CIM store is three moving parts: ``INDEX.BTR``, ``OBJECTS.DATA`` and one or
more ``MAPPING*.MAP`` files.  Each mapping file carries two tables - an object
table and an index table - that translate logical page numbers used by the
index B-tree into physical page numbers in the two data files.

Copying the three parts at different moments produces material that can look
readable while silently mixing generations.  This module answers:

* Which candidate mapping does :class:`dissect.cim.cim.CIM` actually select, and
  is that selection justified by the bytes?
* Do the object table and the index table in a mapping belong together?
* Does the index B-tree, read through a candidate's index table, actually
  resolve every data reference through the same candidate's object table?
* What is proven by the bytes, and what can only be called insufficient?

Nothing is written, repaired or normalised: every access is an explicit read at
a recorded offset, so the diagnosis describes what the parser will really do.
"""

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from dissect.cim.c_cim import (
    INDEX_PAGE_INVALID,
    INDEX_PAGE_INVALID2,
    INDEX_PAGE_SIZE,
    MAPPING_PAGE_ID_MASK,
    UNMAPPED_PAGE_VALUE,
    c_cim,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

MAPPING_SIGNATURE = 0xABCD
FOOTER_SIGNATURE = 0xDCBA
INDEX_PAGE_SIGNATURE = 0xACCC
CLEAN_FLAG = 0x1

Status = Literal["proven", "insufficient", "ok"]

#: Resolution outcomes that mean an index key cannot be served by an object table.
DANGLING = frozenset({"page_oob", "unmapped", "phys_oob", "record_missing", "size_short"})


@dataclass(frozen=True)
class MappingEntryInfo:
    """One logical-to-physical page entry of a mapping table."""

    page_number: int
    page_crc: int | None
    free_space: int | None
    used_space: int | None
    first_id: int | None
    second_id: int | None

    @property
    def is_mapped(self) -> bool:
        return self.page_number != UNMAPPED_PAGE_VALUE


@dataclass(frozen=True)
class MappingTable:
    """A single mapping table, stored as one contiguous segment of a mapping file."""

    source: str
    ordinal: int
    offset: int
    version: int
    first_id: int | None
    second_id: int | None
    physical_page_count: int
    mapping_entry_count: int
    entries: tuple[MappingEntryInfo, ...]
    footer_signature: int | None
    entry_offsets: tuple[int, ...] = ()

    @property
    def location(self) -> str:
        return f"{self.source}#table{self.ordinal}@0x{self.offset:x}"

    @property
    def mapped(self) -> list[MappingEntryInfo]:
        return [e for e in self.entries if e.is_mapped]

    @property
    def unmapped_count(self) -> int:
        return sum(1 for e in self.entries if not e.is_mapped)

    @property
    def highest_physical_page(self) -> int | None:
        mapped = self.mapped
        return max(e.page_number for e in mapped) if mapped else None

    @property
    def entry_generations(self) -> frozenset[int]:
        return frozenset(e.first_id for e in self.mapped if e.first_id is not None)

    @property
    def duplicate_physical_pages(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for entry in self.mapped:
            counts[entry.page_number] = counts.get(entry.page_number, 0) + 1
        return {page: count for page, count in counts.items() if count > 1}

    def page_table(self) -> tuple[tuple[int, int | None], ...]:
        """The comparable part of the table, ignoring generation stamps."""
        return tuple((e.page_number, e.page_crc) for e in self.entries)

    def entry_offset(self, logical: int) -> int | None:
        return self.entry_offsets[logical] if logical < len(self.entry_offsets) else None


@dataclass(frozen=True)
class MappingCandidate:
    """A parsed ``MAPPINGn.MAP``: an object table and an index table."""

    source: str
    tables: tuple[MappingTable, ...]
    trailing_flags: int | None = None

    @property
    def object_table(self) -> MappingTable | None:
        return self.tables[0] if self.tables else None

    @property
    def index_table(self) -> MappingTable | None:
        return self.tables[1] if len(self.tables) > 1 else None

    @property
    def complete(self) -> bool:
        obj, idx = self.object_table, self.index_table
        return bool(
            obj
            and idx
            and obj.footer_signature == FOOTER_SIGNATURE
            and idx.footer_signature == FOOTER_SIGNATURE
        )

    @property
    def version(self) -> int | None:
        return self.tables[0].version if self.tables else None

    @property
    def first_id(self) -> int | None:
        return self.tables[0].first_id if self.tables else None

    @property
    def clean(self) -> bool | None:
        return None if self.trailing_flags is None else bool(self.trailing_flags & CLEAN_FLAG)

    def table_for(self, role: Literal["objects", "index"]) -> MappingTable | None:
        return self.object_table if role == "objects" else self.index_table


@dataclass(frozen=True)
class IndexPageInfo:
    logical: int
    physical: int
    signature: int
    logical_id: int
    record_count: int
    keys: tuple[str, ...]
    children: tuple[int, ...]


@dataclass(frozen=True)
class CrossResult:
    """Resolution of one candidate's index keys through one candidate's object table."""

    index_source: str
    object_source: str
    keys: int
    resolved: int
    dangling: int
    breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.dangling == 0


@dataclass(frozen=True)
class Finding:
    code: str
    status: Status
    location: str
    detail: str


@dataclass(frozen=True)
class Selection:
    """How :func:`dissect.cim.utils.find_current_mapping` behaves on this material."""

    library_pick: str | None
    newest_by_stamp: str | None
    version_tie: tuple[str, ...]
    order_dependent: bool


@dataclass
class Report:
    object_pages: int
    index_pages: int
    candidates: list[MappingCandidate]
    selection: Selection
    findings: list[Finding]
    cross: list[CrossResult]
    verdict: str
    recommended_source: str | None
    reasons: list[str]

    @property
    def proven(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "proven"]

    @property
    def insufficient(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "insufficient"]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "recommended_source": self.recommended_source,
            "reasons": self.reasons,
            "object_pages": self.object_pages,
            "index_pages": self.index_pages,
            "selection": {
                "library_pick": self.selection.library_pick,
                "newest_by_stamp": self.selection.newest_by_stamp,
                "version_tie": list(self.selection.version_tie),
                "order_dependent": self.selection.order_dependent,
            },
            "candidates": [
                {
                    "source": c.source,
                    "complete": c.complete,
                    "version": c.version,
                    "first_id": c.first_id,
                    "clean": c.clean,
                    "tables": [
                        {
                            "ordinal": t.ordinal,
                            "offset": t.offset,
                            "version": t.version,
                            "first_id": t.first_id,
                            "second_id": t.second_id,
                            "physical_page_count": t.physical_page_count,
                            "mapping_entry_count": t.mapping_entry_count,
                            "mapped": len(t.mapped),
                            "unmapped": t.unmapped_count,
                            "footer_signature": t.footer_signature,
                            "entry_generations": sorted(t.entry_generations),
                        }
                        for t in c.tables
                    ],
                }
                for c in self.candidates
            ],
            "findings": [
                {"code": f.code, "status": f.status, "location": f.location, "detail": f.detail}
                for f in self.findings
            ],
            "cross": [
                {
                    "index_source": c.index_source,
                    "object_source": c.object_source,
                    "keys": c.keys,
                    "resolved": c.resolved,
                    "dangling": c.dangling,
                    "breakdown": c.breakdown,
                }
                for c in self.cross
            ],
        }

    def to_text(self) -> str:
        lines = [f"verdict: {self.verdict}"]
        if self.recommended_source:
            lines.append(f"recommended view: {self.recommended_source}")
        for reason in self.reasons:
            lines.append(f"  - {reason}")

        lines.append("")
        lines.append("candidates:")
        for candidate in self.candidates:
            if candidate.version is None:
                lines.append(f"  {candidate.source}: unparsable")
                continue
            lines.append(
                f"  {candidate.source}: complete={candidate.complete} version=0x{candidate.version:04x} "
                f"first_id={_hex(candidate.first_id)} clean={candidate.clean}"
            )
            for table in candidate.tables:
                lines.append(
                    f"    table{table.ordinal} @0x{table.offset:x} version=0x{table.version:04x} "
                    f"first_id={_hex(table.first_id)} second_id={_hex(table.second_id)} "
                    f"declared_pages={table.physical_page_count} entries={table.mapping_entry_count} "
                    f"mapped={len(table.mapped)} unmapped={table.unmapped_count} "
                    f"entry_generations={[hex(g) for g in sorted(table.entry_generations)]}"
                )

        lines.append("")
        lines.append(f"proven: {len(self.proven)}")
        for finding in self.proven:
            lines.append(f"  [{finding.code}] {finding.location}: {finding.detail}")

        lines.append("")
        lines.append(f"insufficient: {len(self.insufficient)}")
        for finding in self.insufficient:
            lines.append(f"  [{finding.code}] {finding.location}: {finding.detail}")

        if self.cross:
            lines.append("")
            lines.append("cross-combination (index table x object table):")
            for result in self.cross:
                marker = "ok" if result.ok else "DANGLING"
                lines.append(
                    f"  {result.index_source} x {result.object_source}: keys={result.keys} "
                    f"resolved={result.resolved} dangling={result.dangling} [{marker}]"
                )

        return "\n".join(lines)


def _hex(value: int | None) -> str:
    return "none" if value is None else f"0x{value:x}"


def _looks_xp(first_id: int, second_id: int, physical_page_count: int, mapping_entry_count: int) -> bool:
    """Mirror :func:`dissect.cim.utils.is_xp_mapping` using the non-XP header read."""
    if mapping_entry_count < physical_page_count // 10:
        return True
    return first_id - 1 != second_id


def _parse_mapping(data: bytes, source: str) -> tuple[list[MappingTable], int | None]:
    tables: list[MappingTable] = []
    offset = 0

    while offset + 16 <= len(data) and struct.unpack_from("<I", data, offset)[0] == MAPPING_SIGNATURE:
        _, version, first_id, second_id, physical_page_count, mapping_entry_count = struct.unpack_from(
            "<6I", data, offset
        )
        xp = _looks_xp(first_id, second_id, physical_page_count, mapping_entry_count)
        if xp:
            _, version, physical_page_count, mapping_entry_count = struct.unpack_from("<4I", data, offset)
            first_id = second_id = None
            header_size, entry_size = 16, 4
        else:
            header_size, entry_size = 24, 24

        entries_start = offset + header_size
        entries_end = entries_start + entry_size * mapping_entry_count
        if entries_end + 4 > len(data):
            break

        entries: list[MappingEntryInfo] = []
        entry_offsets: list[int] = []
        for i in range(mapping_entry_count):
            entry_offset = entries_start + entry_size * i
            entry_offsets.append(entry_offset)
            if xp:
                page_number = struct.unpack_from("<I", data, entry_offset)[0] & MAPPING_PAGE_ID_MASK
                entries.append(MappingEntryInfo(page_number, None, None, None, None, None))
            else:
                page_number, page_crc, free_space, used_space, entry_first, entry_second = struct.unpack_from(
                    "<6I", data, entry_offset
                )
                entries.append(
                    MappingEntryInfo(
                        page_number=page_number & MAPPING_PAGE_ID_MASK,
                        page_crc=page_crc,
                        free_space=free_space,
                        used_space=used_space,
                        first_id=entry_first,
                        second_id=entry_second,
                    )
                )

        free_dword_count = struct.unpack_from("<I", data, entries_end)[0]
        footer_offset = entries_end + 4 + free_dword_count * 4
        if footer_offset + 4 > len(data):
            break

        tables.append(
            MappingTable(
                source=source,
                ordinal=len(tables),
                offset=offset,
                version=version,
                first_id=first_id,
                second_id=second_id,
                physical_page_count=physical_page_count,
                mapping_entry_count=mapping_entry_count,
                entries=tuple(entries),
                footer_signature=struct.unpack_from("<I", data, footer_offset)[0],
                entry_offsets=tuple(entry_offsets),
            )
        )
        offset = footer_offset + 4

    trailing = struct.unpack_from("<I", data, offset)[0] if offset + 4 <= len(data) else None
    return tables, trailing


def parse_mapping(data: bytes, source: str) -> MappingCandidate:
    """Parse one in-memory mapping file."""
    tables, trailing = _parse_mapping(data, source)
    return MappingCandidate(source=source, tables=tuple(tables), trailing_flags=trailing)


def _parse_index_page(buf: bytes, logical: int, physical: int) -> IndexPageInfo | None:
    if len(buf) < INDEX_PAGE_SIZE:
        return None

    fh = BytesIO(buf)
    start = fh.tell()
    try:
        page = c_cim.index_page(fh)
    except Exception:
        return None
    payload = fh.read(INDEX_PAGE_SIZE - (fh.tell() - start))

    def string_part(idx: int) -> str:
        offset = page.string_table[idx]
        end = payload.find(b"\x00", offset)
        if offset >= len(payload) or end < 0:
            raise ValueError("string offset outside page payload")
        return payload[offset:end].decode("utf8")

    def key(idx: int) -> str:
        str_idx = page.keys[idx]
        count = page.string_definition_table[str_idx]
        parts = [string_part(page.string_definition_table[str_idx + 1 + i]) for i in range(count)]
        return "/".join(parts)

    try:
        keys = tuple(key(i) for i in range(page.record_count))
        children = tuple(page.children)
    except Exception:
        return None

    return IndexPageInfo(
        logical=logical,
        physical=physical,
        signature=page.signature,
        logical_id=page.logical_id,
        record_count=page.record_count,
        keys=keys,
        children=children,
    )


def _object_records(buf: bytes) -> dict[int, int] | None:
    """Return ``record_id -> size`` for one object page, or ``None`` if unparsable.

    A record may span into following pages, so ``offset + size`` may exceed the
    page; only an offset outside the page makes the TOC unreadable.
    """
    if len(buf) < INDEX_PAGE_SIZE:
        return None

    fh = BytesIO(buf)
    records: dict[int, int] = {}
    while fh.tell() + 16 <= len(buf):
        entry = c_cim.toc_entry(fh)
        if entry.record_id == 0 and entry.offset == 0 and entry.size == 0 and entry.crc == 0:
            break
        if entry.offset >= len(buf):
            return None
        records.setdefault(entry.record_id, entry.size)
    return records


def _index_pages(candidate: MappingCandidate, index: bytes) -> dict[int, IndexPageInfo]:
    table = candidate.index_table
    if table is None:
        return {}

    pages: dict[int, IndexPageInfo] = {}
    for logical, entry in enumerate(table.entries):
        if not entry.is_mapped:
            continue
        physical = entry.page_number
        if (physical + 1) * INDEX_PAGE_SIZE > len(index):
            continue
        buf = index[physical * INDEX_PAGE_SIZE : (physical + 1) * INDEX_PAGE_SIZE]
        page = _parse_index_page(buf, logical, physical)
        if page is not None:
            pages[logical] = page
    return pages


def _walk_index(pages: dict[int, IndexPageInfo], root: int) -> dict[int, IndexPageInfo]:
    reachable: dict[int, IndexPageInfo] = {}
    stack = [root]
    while stack:
        logical = stack.pop()
        if logical in reachable:
            continue
        page = pages.get(logical)
        if page is None:
            continue
        reachable[logical] = page
        for child in page.children[: page.record_count + 1]:
            if child in (INDEX_PAGE_INVALID, INDEX_PAGE_INVALID2):
                continue
            stack.append(child)
    return reachable


def _resolve(reference: str, objects: bytes, table: MappingTable) -> str:
    """Resolve one data-reference key through an object mapping table."""
    last = reference.rsplit("/", 1)[-1]
    if last.count(".") < 3:
        return "notref"

    try:
        _, logical, record_id, length = last.rsplit(".", 3)
        logical, record_id, length = int(logical), int(record_id), int(length)
    except ValueError:
        return "notref"

    if logical < 0 or logical >= len(table.entries):
        return "page_oob"
    entry = table.entries[logical]
    if not entry.is_mapped:
        return "unmapped"

    physical = entry.page_number
    if (physical + 1) * INDEX_PAGE_SIZE > len(objects):
        return "phys_oob"

    records = _object_records(objects[physical * INDEX_PAGE_SIZE : (physical + 1) * INDEX_PAGE_SIZE])
    if records is None or record_id not in records:
        return "record_missing"
    if records[record_id] < length:
        return "size_short"
    return "ok"


def _data_references(pages: dict[int, IndexPageInfo]) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for page in pages.values():
        for key in page.keys:
            if key in seen:
                continue
            seen.add(key)
            if key.rsplit("/", 1)[-1].count(".") >= 3:
                refs.append(key)
    return refs


def _resolve_all(refs: Sequence[str], objects: bytes, table: MappingTable) -> tuple[int, dict[str, int]]:
    breakdown: dict[str, int] = {}
    for reference in refs:
        outcome = _resolve(reference, objects, table)
        breakdown[outcome] = breakdown.get(outcome, 0) + 1
    dangling = sum(count for outcome, count in breakdown.items() if outcome in DANGLING)
    return dangling, breakdown


def _library_pick(candidates: Sequence[MappingCandidate]) -> MappingCandidate | None:
    """Replicate ``find_current_mapping``: strict ``>`` on version, first file wins ties."""
    current: MappingCandidate | None = None
    max_version = 0
    for candidate in candidates:
        if candidate.version is None:
            continue
        if candidate.version > max_version:
            current = candidate
            max_version = candidate.version
    return current


def diagnose(index: bytes, objects: bytes, mappings: Sequence[tuple[str, bytes]]) -> Report:
    """Diagnose a captured CIM file set without modifying it.

    Args:
        index: Contents of ``INDEX.BTR``.
        objects: Contents of ``OBJECTS.DATA``.
        mappings: ``(name, contents)`` pairs for every available ``MAPPING*.MAP``.

    Returns:
        A :class:`Report` separating proven contradictions from insufficient material.
    """
    candidates = [parse_mapping(data, name) for name, data in mappings]
    findings: list[Finding] = []

    object_pages = len(objects) // INDEX_PAGE_SIZE
    index_pages = len(index) // INDEX_PAGE_SIZE

    # ---- Layout: does each file carry both tables, and are they the same version?
    for candidate in candidates:
        if len(candidate.tables) < 2:
            findings.append(
                Finding(
                    "layout.tables",
                    "proven",
                    candidate.source,
                    f"only {len(candidate.tables)} mapping table(s); the parser reads an object table followed by an "
                    "index table from the same file, so this file cannot serve both roles",
                )
            )
        elif candidate.object_table.version != candidate.index_table.version:
            findings.append(
                Finding(
                    "layout.version",
                    "proven",
                    candidate.source,
                    "object and index tables declare different versions "
                    f"(0x{candidate.object_table.version:04x} != 0x{candidate.index_table.version:04x})",
                )
            )

    # ---- Layout: declared page capacity versus the actual size of each file.
    for role, actual, filename in (("objects", object_pages, "OBJECTS.DATA"), ("index", index_pages, "INDEX.BTR")):
        for candidate in candidates:
            table = candidate.table_for(role)
            if table is None:
                continue
            if table.physical_page_count == actual:
                continue
            highest = table.highest_physical_page
            truncated = highest is not None and highest >= actual
            if truncated:
                findings.append(
                    Finding(
                        f"layout.capacity.{role}",
                        "proven",
                        f"{table.location} -> {filename}",
                        f"declares {table.physical_page_count} physical pages but {filename} holds {actual}; "
                        f"mapped pages reach {highest}, so references are cut off",
                    )
                )
            else:
                findings.append(
                    Finding(
                        f"layout.capacity.{role}",
                        "insufficient",
                        f"{table.location} -> {filename}",
                        f"declares {table.physical_page_count} physical pages but {filename} holds {actual}; "
                        f"highest mapped page is {highest}, so no mapped reference is cut off and the missing "
                        "pages cannot be shown to matter",
                    )
                )

    # ---- Generation stamps inside the tables.
    for role in ("objects", "index"):
        for candidate in candidates:
            table = candidate.table_for(role)
            if table is None or table.first_id is None:
                continue
            foreign = sorted(g for g in table.entry_generations if g != table.first_id)
            if foreign:
                findings.append(
                    Finding(
                        "generation.entries",
                        "proven",
                        table.location,
                        f"header first_id={_hex(table.first_id)} but entries declare {[hex(g) for g in foreign]}; "
                        "the page table was assembled from more than one generation",
                    )
                )

    # ---- Trailing clean flag: MAPPING_FILE_CLEAN is defined but never read by the library.
    for candidate in candidates:
        if candidate.clean is False:
            findings.append(
                Finding(
                    "mapping.clean",
                    "insufficient",
                    f"{candidate.source} trailing dword 0x0",
                    "the clean flag after the last footer is cleared (MAPPING_FILE_CLEAN=0x1 is defined but unused by "
                    "dissect.cim); the mapping was not marked settled, which is consistent with an interrupted or "
                    "stale capture but does not by itself prove a mixed one",
                )
            )

    # ---- Page identity, role by role.
    for candidate in candidates:
        table = candidate.index_table
        if table is None:
            continue
        checked = 0
        bad: list[str] = []
        first_bad_offset: int | None = None
        for logical, entry in enumerate(table.entries):
            if not entry.is_mapped:
                continue
            physical = entry.page_number
            if (physical + 1) * INDEX_PAGE_SIZE > len(index):
                continue
            checked += 1
            page = _parse_index_page(
                index[physical * INDEX_PAGE_SIZE : (physical + 1) * INDEX_PAGE_SIZE], logical, physical
            )
            if page is None or page.signature != INDEX_PAGE_SIGNATURE or page.logical_id != logical:
                bad.append(f"logical {logical} at INDEX.BTR@0x{physical * INDEX_PAGE_SIZE:x}")
                if first_bad_offset is None:
                    first_bad_offset = entry.entry_offset(logical)
        if bad:
            findings.append(
                Finding(
                    "page.identity.index",
                    "proven",
                    f"{table.location} + {table.source}@0x{first_bad_offset or 0:x}",
                    f"{len(bad)}/{checked} mapped index pages do not carry the logical_id their mapping entry "
                    f"assigns; examples: {'; '.join(bad[:4])}",
                )
            )
        elif checked:
            findings.append(
                Finding(
                    "page.identity.index",
                    "ok",
                    table.location,
                    f"{checked}/{checked} mapped index pages carry the expected logical_id",
                )
            )

    for candidate in candidates:
        table = candidate.object_table
        if table is None:
            continue
        checked = 0
        bad = 0
        example = ""
        for logical, entry in enumerate(table.entries):
            if not entry.is_mapped or not entry.free_space:
                continue
            physical = entry.page_number
            if (physical + 1) * INDEX_PAGE_SIZE > len(objects):
                continue
            records = _object_records(objects[physical * INDEX_PAGE_SIZE : (physical + 1) * INDEX_PAGE_SIZE])
            if records is None:
                continue
            computed = INDEX_PAGE_SIZE - sum(records.values()) - 16 * (len(records) + 1)
            checked += 1
            if computed != entry.free_space:
                bad += 1
                if not example:
                    example = (
                        f"logical {logical} at OBJECTS.DATA@0x{physical * INDEX_PAGE_SIZE:x}: "
                        f"declared free {entry.free_space}, TOC implies {computed}"
                    )
        if bad:
            findings.append(
                Finding(
                    "page.identity.objects",
                    "proven",
                    table.location,
                    f"{bad}/{checked} pages whose entry declares free_space disagree with the object page TOC; "
                    f"example: {example}",
                )
            )
        elif checked:
            findings.append(
                Finding(
                    "page.identity.objects",
                    "ok",
                    table.location,
                    f"{checked}/{checked} pages with a declared free_space match the object page TOC",
                )
            )

    # ---- Mapping table sanity: duplicates and out-of-range physical pages.
    for role, filename, limit in (("objects", "OBJECTS.DATA", object_pages), ("index", "INDEX.BTR", index_pages)):
        for candidate in candidates:
            table = candidate.table_for(role)
            if table is None:
                continue
            duplicates = table.duplicate_physical_pages
            if duplicates:
                findings.append(
                    Finding(
                        "page.mapping.duplicate",
                        "proven",
                        table.location,
                        f"one physical page is mapped by several logical pages: {dict(list(duplicates.items())[:5])}",
                    )
                )
            outside = sorted({e.page_number for e in table.mapped if e.page_number >= limit})
            if outside:
                findings.append(
                    Finding(
                        "page.mapping.range",
                        "proven",
                        f"{table.location} -> {filename}",
                        f"{len(outside)} physical page numbers point past the end of {filename}: {outside[:5]}",
                    )
                )

    # ---- Page CRC: state the limit of the evidence, never call it corruption.
    findings.append(
        Finding(
            "page.crc",
            "insufficient",
            "all mapping tables -> INDEX.BTR, OBJECTS.DATA",
            "page_crc is stored but dissect.cim never validates it; CRC-32 and CRC-32C over the page do not "
            "reproduce the stored value, so per-page integrity cannot be confirmed from this material",
        )
    )

    # ---- Selection: what the library does, and whether it is justified.
    library_pick = _library_pick(candidates)
    versions = [c.version for c in candidates if c.version is not None]
    max_version = max(versions) if versions else None
    tie = tuple(c.source for c in candidates if max_version is not None and c.version == max_version)
    stamped = [c for c in candidates if c.first_id is not None]
    newest = max(stamped, key=lambda c: c.first_id) if stamped else None
    selection = Selection(
        library_pick=library_pick.source if library_pick else None,
        newest_by_stamp=newest.source if newest else None,
        version_tie=tie,
        order_dependent=len(tie) > 1,
    )

    if len(tie) > 1:
        findings.append(
            Finding(
                "selection.version_tie",
                "proven",
                ", ".join(tie),
                f"{len(tie)} candidates share version 0x{max_version:04x} yet declare different generations "
                f"({', '.join(_hex(c.first_id) for c in candidates if c.source in tie)}); "
                "find_current_mapping uses a strict '>' so input order decides",
            )
        )
    if newest and library_pick and newest.source != library_pick.source:
        findings.append(
            Finding(
                "selection.newest",
                "proven",
                f"{newest.source} vs {library_pick.source}",
                f"the parser selects {library_pick.source} (version 0x{library_pick.version:04x}) while the highest "
                f"declared generation is {newest.source} (first_id {_hex(newest.first_id)}) at "
                f"{newest.object_table.location if newest.object_table else newest.source}; "
                "selection by version does not establish recency",
            )
        )

    # ---- Compare page tables, role by role.
    for role in ("objects", "index"):
        comparable = [(c.source, c.table_for(role)) for c in candidates if c.table_for(role) is not None]
        for i in range(len(comparable)):
            for j in range(i + 1, len(comparable)):
                left_name, left = comparable[i]
                right_name, right = comparable[j]
                if left.page_table() == right.page_table():
                    if (
                        left.first_id is not None
                        and right.first_id is not None
                        and left.first_id != right.first_id
                    ):
                        findings.append(
                            Finding(
                                f"mapping.{role}.same_table",
                                "insufficient",
                                f"{left.location} vs {right.location}",
                                "identical page tables but different generation stamps "
                                f"(first_id {_hex(left.first_id)} vs {_hex(right.first_id)}); that is consistent with "
                                "a newer generation that changed no page mapping, and also with a re-stamped copy. "
                                "The stamps alone cannot decide which, so this is not counted as a contradiction",
                            )
                        )
                    continue

                diffs = [n for n, (a, b) in enumerate(zip(left.page_table(), right.page_table())) if a != b]
                first = diffs[0]
                findings.append(
                    Finding(
                        f"mapping.{role}.divergence",
                        "proven",
                        f"{left.location} vs {right.location}",
                        f"{len(diffs)} logical entries map to different physical pages "
                        f"({diffs[:8]}); e.g. logical {first} maps to {left.entries[first].page_number} in "
                        f"{left_name} but {right.entries[first].page_number} in {right_name}, so the two files "
                        "describe different generations",
                    )
                )

                # Two physical copies exist for the same logical page and only the table decides which is live.
                left_pages = {e.page_number for e in left.mapped}
                right_pages = {e.page_number for e in right.mapped}
                only_left = sorted(left_pages - right_pages)
                only_right = sorted(right_pages - left_pages)
                if only_left or only_right:
                    findings.append(
                        Finding(
                            f"mapping.{role}.orphan_copies",
                            "proven",
                            f"{left.location} vs {right.location}",
                            "the data file holds two physical copies of the diverging logical pages: "
                            f"{len(only_left)} referenced only by {left_name} ({only_left[:6]}) and "
                            f"{len(only_right)} only by {right_name} ({only_right[:6]}); whichever table is used, the "
                            "other copy is silently bypassed, so mixing tables changes what is read",
                        )
                    )

    # ---- Read the index through each index table, resolve through each object table.
    index_tables = {c.source: _index_pages(c, index) for c in candidates}
    walkable: dict[str, dict[int, IndexPageInfo]] = {}
    for candidate in candidates:
        table = candidate.index_table
        if table is None or not table.entries:
            continue
        root = table.entries[0].used_space or 0
        pages = index_tables.get(candidate.source, {})
        if root not in pages:
            findings.append(
                Finding(
                    "reference.root",
                    "proven",
                    table.location,
                    f"root logical page {root} (from entry 0 used_space) is unmapped or unparsable in this table; "
                    "no index traversal is possible",
                )
            )
            continue
        walkable[candidate.source] = _walk_index(pages, root)

    cross: list[CrossResult] = []
    for index_source, pages in walkable.items():
        refs = _data_references(pages)
        for candidate in candidates:
            object_table = candidate.object_table
            if object_table is None:
                continue
            dangling, breakdown = _resolve_all(refs, objects, object_table)
            cross.append(
                CrossResult(
                    index_source=index_source,
                    object_source=candidate.source,
                    keys=len(refs),
                    resolved=len(refs) - dangling,
                    dangling=dangling,
                    breakdown=breakdown,
                )
            )

    for result in cross:
        if not result.ok:
            findings.append(
                Finding(
                    "reference.cross",
                    "proven",
                    f"{result.index_source} index table x {result.object_source} object table",
                    f"{result.dangling}/{result.keys} data references dangle ({result.breakdown}); the index keys "
                    "and the object pages do not belong to the same capture state, so this combination is unreadable",
                )
            )

    self_dangling: dict[str, int] = {}
    for candidate in candidates:
        if candidate.source not in walkable or candidate.object_table is None:
            continue
        refs = _data_references(walkable[candidate.source])
        dangling, breakdown = _resolve_all(refs, objects, candidate.object_table)
        self_dangling[candidate.source] = dangling
        findings.append(
            Finding(
                "reference.self",
                "proven" if dangling else "ok",
                f"{candidate.source} (index table + object table)",
                f"{dangling}/{len(refs)} data references dangle against this file's own object table"
                + (f" ({breakdown})" if dangling else ""),
            )
        )

    # ---- If several candidates read cleanly, the material supports several conflicting views.
    readable = [c for c in candidates if self_dangling.get(c.source) == 0]
    divergent_views = False
    for i in range(len(readable)):
        for j in range(i + 1, len(readable)):
            left, right = readable[i], readable[j]
            if left.object_table is None or right.object_table is None:
                continue
            if left.object_table.page_table() != right.object_table.page_table():
                divergent_views = True
    if len(readable) > 1:
        findings.append(
            Finding(
                "coverage.multiple_views",
                "proven",
                ", ".join(c.source for c in readable),
                f"{len(readable)} candidate mappings are each internally readable but disagree on physical pages"
                if divergent_views
                else f"{len(readable)} candidate mappings are each internally readable and agree on physical pages",
            )
        )

    # ---- Coverage: what the material cannot establish, independent of what it contains.
    findings.append(
        Finding(
            "coverage.window",
            "insufficient",
            "INDEX.BTR, OBJECTS.DATA, MAPPING*.MAP",
            "none of the three files carries an independent capture timestamp that would prove they were read "
            "inside one consistent window; agreeing page tables are strong but circumstantial evidence",
        )
    )
    if len(candidates) < 3:
        findings.append(
            Finding(
                "coverage.candidates",
                "insufficient",
                ", ".join(c.source for c in candidates) or "no MAPPING file",
                f"{len(candidates)} of the usual 3 MAPPING files are present; a missing file may have carried a "
                "newer or older generation, so its absence neither proves nor disproves a mixed capture",
            )
        )
    if len(walkable) <= 1:
        findings.append(
            Finding(
                "coverage.comparison",
                "insufficient",
                ", ".join(walkable) or "no traversable mapping",
                "fewer than two independently traversable index tables are available, so generation divergence "
                "between mapping files cannot be cross-checked",
            )
        )

    # ---- Verdict.
    complete = [c for c in candidates if c.complete]
    usable = [c for c in complete if self_dangling.get(c.source, 1) == 0]

    reasons: list[str] = []
    if not candidates:
        verdict = "insufficient"
        reasons.append(
            "no MAPPING file was supplied; a missing mapping is missing material, not evidence of tampering"
        )
    elif not complete:
        verdict = "insufficient"
        reasons.append("no MAPPING file contains both an object and an index table with a valid footer")
    elif not usable:
        verdict = "untrusted"
        reasons.append("every complete MAPPING file has dangling references against its own object table")
    else:
        verdict = "trusted_with_caveats"
        reasons.append(
            f"{len(usable)} complete mapping file(s) resolve all of their own index references: "
            + ", ".join(c.source for c in usable)
        )

    recommended_source: str | None = None
    if usable:
        recommended = max(usable, key=lambda c: (c.clean is True, c.first_id or 0))
        recommended_source = recommended.source
        if newest and recommended.source != newest.source:
            reasons.append(
                f"recommended {recommended.source} but the highest declared generation is {newest.source}; "
                "their page tables differ, so the earlier one may be stale"
            )
        if len(usable) > 1:
            reasons.append(
                "several generations are individually readable; merging their page tables is exactly the case the "
                "cross-combination check proves inconsistent"
            )
        if recommended.clean is False:
            reasons.append(f"{recommended.source} has a cleared clean flag (0x0)")

        # State the read view explicitly: one file's own two tables, never a mixture.
        others = [c for c in usable if c.source != recommended.source]
        if others:
            same = [
                c.source
                for c in others
                if c.object_table
                and recommended.object_table
                and c.object_table.page_table() == recommended.object_table.page_table()
            ]
            different = [c.source for c in others if c.source not in same]
            parts = []
            if same:
                parts.append(f"{' and '.join(same)} agree page-for-page but still must not be spliced in")
            if different:
                parts.append(f"{' and '.join(different)} map different physical pages and must not be mixed in")
            reasons.append(
                f"trustworthy view = INDEX.BTR + OBJECTS.DATA read through {recommended.source}'s own object and "
                f"index tables only; {'; '.join(parts)}"
            )
    if verdict == "trusted_with_caveats":
        reasons.append("page-level integrity rests on structural checks only; page_crc cannot be re-derived")

    return Report(
        object_pages=object_pages,
        index_pages=index_pages,
        candidates=candidates,
        selection=selection,
        findings=findings,
        cross=cross,
        verdict=verdict,
        recommended_source=recommended_source,
        reasons=reasons,
    )


def diagnose_directory(path: Path | str) -> Report:
    """Diagnose ``path`` read-only, accepting any subset of ``MAPPING*.MAP`` files."""
    path = Path(path)
    index = path.joinpath("INDEX.BTR").read_bytes()
    objects = path.joinpath("OBJECTS.DATA").read_bytes()
    mappings = [(p.name, p.read_bytes()) for p in sorted(path.glob("MAPPING*.MAP"))]
    return diagnose(index, objects, mappings)


def main(argv: Sequence[str] | None = None) -> int:
    """Print a read-only report for a capture directory."""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m dissect.cim.consistency", description=__doc__)
    parser.add_argument("path", type=Path, help="directory containing INDEX.BTR, OBJECTS.DATA and MAPPING*.MAP")
    parser.add_argument("--json", action="store_true", help="emit machine readable output")
    args = parser.parse_args(argv)

    try:
        report = diagnose_directory(args.path)
    except FileNotFoundError as exc:
        print(f"missing required file: {exc.filename}", file=sys.stderr)
        return 2

    print(json.dumps(report.to_dict(), indent=2) if args.json else report.to_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
