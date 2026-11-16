"""Offline consistency diagnostics for CIM repository files.

This module is intentionally read-only: it opens the supplied ``INDEX.BTR``, ``OBJECTS.DATA`` and ``MAPPING*.MAP``
files in binary mode and never writes to them.  It is meant to answer a narrower question than :class:`CIM` does:
given a set of copied files, which mapping generation can actually be combined with the index and object files into a
coherent read view, and where do the materials contradict each other?

The CIM mapping file layout is described in :mod:`dissect.cim.c_cim`.  A single ``MAPPINGn.MAP`` file can contain two
consecutive mappings: the object mapping first, followed by a ``0xDCBA`` footer, the index mapping, another ``0xDCBA``
footer and, for the last mapping in the file, an optional trailing flag.  :class:`CIM` reuses the same file handle for
both mappings, which is why the sections have to be checked separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from dissect.cim.c_cim import (
    DATA_PAGE_SIZE,
    INDEX_PAGE_SIZE,
    MAPPING_FILE_CLEAN,
    MAPPING_PAGE_ID_MASK,
    UNMAPPED_PAGE_VALUE,
    c_cim,
)
from dissect.cim.exceptions import Error

MAPPING_SIGNATURE = 0xABCD
MAPPING_FOOTER_SIGNATURE = 0xDCBA
INDEX_SIGNATURE = 0xACCC
MAX_TOC_ENTRIES = DATA_PAGE_SIZE // 16
MAX_INDEX_RECORDS = 1024
DATA_REFERENCE_RE = re.compile(r"^.*\.(\d+)\.(\d+)\.(\d+)$")

ROLE_OBJECT = "object"
ROLE_INDEX = "index"


@dataclass
class Section:
    """One mapping structure inside a ``MAPPINGn.MAP`` file."""

    role: str
    offset: int
    layout: str
    version: int
    first_id: int
    second_id: int | None
    physical_page_count: int
    entry_count: int
    entries_offset: int
    footer_signature: int | None
    end_offset: int
    truncated: bool = False
    problems: list[str] = field(default_factory=list)


@dataclass
class MappingFile:
    """Parsed mapping file with all mapping sections found in it."""

    name: str
    size: int
    sections: list[Section] = field(default_factory=list)
    clean_flag: int | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def object_section(self) -> Section | None:
        return next((section for section in self.sections if section.role == ROLE_OBJECT), None)

    @property
    def index_section(self) -> Section | None:
        return next((section for section in self.sections if section.role == ROLE_INDEX), None)


@dataclass
class EntrySummary:
    mapped: int = 0
    unmapped: int = 0
    out_of_range: int = 0
    duplicate_targets: int = 0
    max_target: int | None = None
    samples: list[str] = field(default_factory=list)


@dataclass
class ObjectMappingCheck(EntrySummary):
    parseable_pages: int = 0
    free_space_matches: int = 0
    spanning_pages: int = 0
    generation_mismatches: int = 0
    non_toc_pages: int = 0


@dataclass
class IndexMappingCheck(EntrySummary):
    identity_matches: int = 0
    identity_mismatches: int = 0
    signature_mismatches: int = 0
    reachable_pages: int = 0
    reachable_keys: int = 0
    data_references: int = 0
    file_pages: int = 0
    header_page_count: int = 0
    unreferenced_pages: int = 0


@dataclass
class LayoutDifference:
    other: str
    object_entries: int
    index_entries: int
    object_samples: list[str] = field(default_factory=list)
    index_samples: list[str] = field(default_factory=list)


@dataclass
class Candidate:
    name: str
    object_section: Section | None
    index_section: Section | None
    object_check: ObjectMappingCheck | None
    index_check: IndexMappingCheck | None
    resolution: dict[str, int] = field(default_factory=dict)
    fingerprint: str = ""
    generation_key: tuple[int, int, int] = (0, 0, 0)
    self_consistent: bool = False
    differences: list[LayoutDifference] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class CrossResult:
    index_candidate: str
    object_candidate: str
    counts: dict[str, int]


@dataclass
class Diagnosis:
    index_path: str
    objects_path: str
    index_size: int
    objects_size: int
    index_pages: int
    objects_pages: int
    mappings: list[MappingFile]
    candidates: list[Candidate]
    cross: list[CrossResult]
    verdict: str
    primary: str | None
    trusted: list[str]
    stale: list[str]
    contradictions: list[str]
    insufficiencies: list[str]
    observations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _Entry:
    logical: int
    page_number: int
    page_crc: int
    free_space: int
    used_space: int
    first_id: int
    second_id: int
    offset: int

    @property
    def target(self) -> int:
        return self.page_number & MAPPING_PAGE_ID_MASK

    @property
    def is_mapped(self) -> bool:
        return self.target != UNMAPPED_PAGE_VALUE


@dataclass
class _SectionData:
    section: Section
    entries: list[_Entry]


def _read_exact(fh: BinaryIO, size: int, offset: int) -> bytes:
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise EOFError(f"short read at 0x{offset:x}: wanted {size}, got {len(data)}")
    return data


def parse_mapping_file(path: Path | str, name: str | None = None) -> tuple[MappingFile, list[_SectionData]]:
    """Parse all mapping sections in a mapping file without modifying it."""
    path = Path(path)
    name = name or path.name
    size = path.stat().st_size
    mapping = MappingFile(name=name, size=size)
    parsed: list[_SectionData] = []

    with path.open("rb") as fh:
        offset = 0
        role = ROLE_OBJECT
        while offset < size:
            try:
                section_data = _parse_section(fh, size, offset, role)
            except (EOFError, Error, struct.error, ValueError) as exc:
                mapping.problems.append(f"{role} mapping at 0x{offset:x}: {exc}")
                break

            mapping.sections.append(section_data.section)
            parsed.append(section_data)
            offset = section_data.section.end_offset

            if section_data.section.truncated:
                break

            # A trailing dword after the final footer is the per-file clean flag.  The constant exists in
            # c_cim.py, but dissect.cim itself never interprets it.
            remaining = size - offset
            if remaining == 4:
                mapping.clean_flag = struct.unpack("<I", _read_exact(fh, 4, offset))[0]
                offset += 4
            elif remaining > 4 and struct.unpack("<I", _read_exact(fh, 4, offset))[0] == MAPPING_SIGNATURE:
                role = ROLE_INDEX if role == ROLE_OBJECT else f"extra{len(mapping.sections)}"
                continue
            elif remaining:
                mapping.problems.append(f"{remaining} trailing byte(s) after final mapping footer at 0x{offset:x}")
                if remaining >= 4:
                    mapping.clean_flag = struct.unpack("<I", _read_exact(fh, 4, offset))[0]
                break
            else:
                break

    if not mapping.sections:
        mapping.problems.append("no mapping section found")
    if mapping.object_section is None:
        mapping.problems.append("object mapping section is missing")
    if mapping.index_section is None:
        mapping.problems.append("index mapping section is missing")

    return mapping, parsed


def _parse_section(fh: BinaryIO, size: int, offset: int, role: str) -> _SectionData:
    signature = struct.unpack("<I", _read_exact(fh, 4, offset))[0]
    if signature != MAPPING_SIGNATURE:
        raise Error(f"invalid mapping signature 0x{signature:08x}")

    # Detect the XP layout with the same rule that dissect.cim.utils.is_xp_mapping uses.
    header = _read_exact(fh, 24, offset)
    _, _, _, _, page_count, entry_count = struct.unpack("<6I", header)
    layout = "xp" if entry_count < page_count // 10 else "normal"

    if layout == "xp":
        first_id = second_id = None
        version, page_count, entry_count = struct.unpack_from("<III", header, 4)
        entries_offset = offset + 16
        entries_size = 4 * entry_count
        free_offset = entries_offset + entries_size
        if free_offset + 4 > size:
            section = Section(
                role=role,
                offset=offset,
                layout=layout,
                version=version,
                first_id=0,
                second_id=None,
                physical_page_count=page_count,
                entry_count=entry_count,
                entries_offset=entries_offset,
                footer_signature=None,
                end_offset=size,
                truncated=True,
                problems=["truncated XP mapping"],
            )
            return _SectionData(section, [])
        entries = []
        for logical in range(entry_count):
            raw = struct.unpack("<I", _read_exact(fh, 4, entries_offset + 4 * logical))[0]
            entries.append(
                _Entry(
                    logical=logical,
                    page_number=raw,
                    page_crc=0,
                    free_space=0,
                    used_space=0,
                    first_id=0,
                    second_id=0,
                    offset=entries_offset + 4 * logical,
                )
            )
        free_count = struct.unpack("<I", _read_exact(fh, 4, free_offset))[0]
        footer_offset = free_offset + 4 + 4 * free_count
        if footer_offset + 4 > size:
            section = Section(
                role=role,
                offset=offset,
                layout=layout,
                version=version,
                first_id=0,
                second_id=None,
                physical_page_count=page_count,
                entry_count=entry_count,
                entries_offset=entries_offset,
                footer_signature=None,
                end_offset=size,
                truncated=True,
                problems=["truncated XP mapping free list"],
            )
            return _SectionData(section, [])
        footer_signature = struct.unpack("<I", _read_exact(fh, 4, footer_offset))[0]
        end_offset = footer_offset + 4
    else:
        version, first_id, second_id, page_count, entry_count = struct.unpack_from("<5I", header, 4)
        entries_offset = offset + 24
        entries_size = 24 * entry_count
        free_offset = entries_offset + entries_size
        if free_offset + 4 > size:
            section = Section(
                role=role,
                offset=offset,
                layout=layout,
                version=version,
                first_id=first_id,
                second_id=second_id,
                physical_page_count=page_count,
                entry_count=entry_count,
                entries_offset=entries_offset,
                footer_signature=None,
                end_offset=size,
                truncated=True,
                problems=[f"truncated mapping: entries end at 0x{free_offset:x}, file size 0x{size:x}"],
            )
            return _SectionData(section, [])
        raw = _read_exact(fh, entries_size, entries_offset)
        entries = []
        for logical in range(entry_count):
            values = struct.unpack_from("<6I", raw, 24 * logical)
            entries.append(
                _Entry(
                    logical=logical,
                    page_number=values[0],
                    page_crc=values[1],
                    free_space=values[2],
                    used_space=values[3],
                    first_id=values[4],
                    second_id=values[5],
                    offset=entries_offset + 24 * logical,
                )
            )
        free_count = struct.unpack("<I", _read_exact(fh, 4, free_offset))[0]
        footer_offset = free_offset + 4 + 4 * free_count
        if footer_offset + 4 > size:
            section = Section(
                role=role,
                offset=offset,
                layout=layout,
                version=version,
                first_id=first_id,
                second_id=second_id,
                physical_page_count=page_count,
                entry_count=entry_count,
                entries_offset=entries_offset,
                footer_signature=None,
                end_offset=size,
                truncated=True,
                problems=[f"truncated free list: footer would be at 0x{footer_offset:x}, file size 0x{size:x}"],
            )
            return _SectionData(section, [])
        footer_signature = struct.unpack("<I", _read_exact(fh, 4, footer_offset))[0]
        end_offset = footer_offset + 4

    problems = []
    if footer_signature != MAPPING_FOOTER_SIGNATURE:
        problems.append(f"footer signature 0x{footer_signature:08x} at 0x{end_offset - 4:x}")

    section = Section(
        role=role,
        offset=offset,
        layout=layout,
        version=version,
        first_id=first_id or 0,
        second_id=second_id,
        physical_page_count=page_count,
        entry_count=entry_count,
        entries_offset=entries_offset,
        footer_signature=footer_signature,
        end_offset=end_offset,
        problems=problems,
    )
    return _SectionData(section, entries)


def _physical_targets(section: _SectionData) -> list[int]:
    return [entry.target if entry.is_mapped else UNMAPPED_PAGE_VALUE for entry in section.entries]


def _summarize_entries(entries: list[_Entry], page_count: int) -> EntrySummary:
    summary = EntrySummary()
    seen: set[int] = set()
    for entry in entries:
        if not entry.is_mapped:
            summary.unmapped += 1
            continue
        summary.mapped += 1
        summary.max_target = entry.target if summary.max_target is None else max(summary.max_target, entry.target)
        if entry.target >= page_count:
            summary.out_of_range += 1
            if len(summary.samples) < 5:
                summary.samples.append(f"logical {entry.logical}: target {entry.target} >= {page_count}")
        if entry.target in seen:
            summary.duplicate_targets += 1
            if len(summary.samples) < 5:
                summary.samples.append(f"logical {entry.logical}: duplicate target {entry.target}")
        seen.add(entry.target)
    return summary


def _read_toc(page: bytes) -> list[tuple[int, int, int, int]] | None:
    entries: list[tuple[int, int, int, int]] = []
    for index in range(MAX_TOC_ENTRIES):
        values = struct.unpack_from("<4I", page, index * 16)
        if values == (0, 0, 0, 0):
            break
        entries.append(values)

    if not entries:
        return None

    # dissect.cim read ``Objects.Store`` records across page boundaries: a record may start in this page and
    # continue in the following logical pages.  Only the TOC itself has to fit in the page.
    toc_size = len(entries) * 16
    for record_id, record_offset, record_size, _ in entries:
        if record_id == 0 or record_size == 0:
            return None
        if record_offset < toc_size or record_offset >= DATA_PAGE_SIZE:
            return None

    return entries


def _check_object_section(section: _SectionData, objects: bytes, objects_pages: int) -> ObjectMappingCheck:
    check = ObjectMappingCheck(**_summarize_entries(section.entries, objects_pages).__dict__)
    page_cache: dict[int, list[tuple[int, int, int, int]] | None] = {}

    for entry in section.entries:
        if not entry.is_mapped:
            continue
        if entry.first_id != section.section.first_id:
            check.generation_mismatches += 1
            if len(check.samples) < 5:
                check.samples.append(
                    f"logical {entry.logical}: entry first_id {entry.first_id} != section {section.section.first_id}"
                )
        if entry.target >= objects_pages:
            continue

        if entry.target not in page_cache:
            start = entry.target * DATA_PAGE_SIZE
            page_cache[entry.target] = _read_toc(objects[start : start + DATA_PAGE_SIZE])
        toc = page_cache[entry.target]
        if toc is None:
            check.non_toc_pages += 1
            continue

        check.parseable_pages += 1
        tail = DATA_PAGE_SIZE - max(offset + size for _, offset, size, _ in toc)
        if tail < 0:
            check.spanning_pages += 1
            continue
        if tail == entry.free_space:
            check.free_space_matches += 1
        elif len(check.samples) < 5:
            check.samples.append(
                f"logical {entry.logical}: free_space {entry.free_space} != TOC tail {tail} (page {entry.target})"
            )

    return check


def _parse_index_page(raw: bytes) -> tuple[Any, bytes, int] | None:
    if len(raw) != INDEX_PAGE_SIZE:
        return None
    signature = struct.unpack_from("<I", raw)[0]
    if signature != INDEX_SIGNATURE:
        return None
    logical_id, _pad, _root, record_count = struct.unpack_from("<4I", raw, 4)
    if record_count > MAX_INDEX_RECORDS:
        return None

    from io import BytesIO

    fh = BytesIO(raw)
    try:
        page = c_cim.index_page(fh)
        data = fh.read()
    except (EOFError, Error, struct.error, ValueError):
        return None
    return page, data, logical_id


def _index_page_keys(page: Any, data: bytes) -> list[str]:
    keys = []
    for index in range(page.record_count):
        string_index = page.keys[index]
        if string_index >= len(page.string_definition_table):
            raise ValueError(f"string definition index {string_index} out of range")
        part_count = page.string_definition_table[string_index]
        parts = []
        for part in range(part_count):
            definition_index = string_index + 1 + part
            if definition_index >= len(page.string_definition_table):
                raise ValueError("string definition table overflow")
            string_index_part = page.string_definition_table[definition_index]
            if string_index_part >= len(page.string_table):
                raise ValueError("string table overflow")
            offset = page.string_table[string_index_part]
            end = data.find(b"\x00", offset)
            if end < 0:
                end = len(data)
            parts.append(data[offset:end].decode("utf8", errors="replace"))
        keys.append("/".join(parts))
    return keys


def _collect_index_references(
    section: _SectionData, index: bytes, index_pages: int
) -> tuple[int, int, int, list[tuple[int, int, int]]]:
    if not section.entries:
        return 0, 0, 0, []

    root_logical = section.entries[0].used_space
    reachable: set[int] = set()
    keys: list[str] = []
    references: list[tuple[int, int, int]] = []
    errors = 0
    stack = [root_logical]

    while stack:
        logical = stack.pop()
        if logical in reachable:
            continue
        if logical >= len(section.entries):
            errors += 1
            continue
        reachable.add(logical)
        entry = section.entries[logical]
        if not entry.is_mapped or entry.target >= index_pages:
            errors += 1
            continue

        raw = index[entry.target * INDEX_PAGE_SIZE : (entry.target + 1) * INDEX_PAGE_SIZE]
        parsed = _parse_index_page(raw)
        if parsed is None:
            errors += 1
            continue
        page, data, _ = parsed
        try:
            page_keys = _index_page_keys(page, data)
        except (IndexError, ValueError):
            errors += 1
            continue
        keys.extend(page_keys)

        for key in page_keys:
            match = DATA_REFERENCE_RE.match(key)
            if match:
                references.append((int(match.group(1)), int(match.group(2)), int(match.group(3))))

        for child in page.children:
            if child not in (0, 0xFFFFFFFF) and child not in reachable:
                stack.append(child)

    return len(reachable), len(keys), len(references), references


def _check_index_section(
    section: _SectionData, index: bytes, index_pages: int
) -> tuple[IndexMappingCheck, list[tuple[int, int, int]]]:
    check = IndexMappingCheck(**_summarize_entries(section.entries, index_pages).__dict__)
    check.file_pages = index_pages
    check.header_page_count = section.section.physical_page_count

    for entry in section.entries:
        if not entry.is_mapped or entry.target >= index_pages:
            continue
        raw = index[entry.target * INDEX_PAGE_SIZE : (entry.target + 1) * INDEX_PAGE_SIZE]
        parsed = _parse_index_page(raw)
        if parsed is None:
            check.signature_mismatches += 1
            if len(check.samples) < 5:
                check.samples.append(f"logical {entry.logical}: page {entry.target} is not a valid index page")
            continue
        _, _, logical_id = parsed
        if logical_id == entry.logical:
            check.identity_matches += 1
        else:
            check.identity_mismatches += 1
            if len(check.samples) < 5:
                check.samples.append(
                    f"logical {entry.logical}: page {entry.target} header says logical_id {logical_id}"
                )

    check.reachable_pages, check.reachable_keys, check.data_references, references = _collect_index_references(
        section, index, index_pages
    )
    in_range_targets = {
        entry.target
        for entry in section.entries
        if entry.is_mapped and entry.target < index_pages
    }
    check.unreferenced_pages = max(index_pages - len(in_range_targets), 0)
    return check, references


def _resolve_references(
    references: list[tuple[int, int, int]], object_section: _SectionData, objects: bytes, objects_pages: int
) -> dict[str, int]:
    counts = {
        "ok": 0,
        "page_unmapped": 0,
        "page_out_of_range": 0,
        "page_unparseable": 0,
        "record_missing": 0,
        "record_short": 0,
    }
    page_cache: dict[int, dict[int, tuple[int, int]] | None] = {}

    for logical_page, record_id, length in references:
        if logical_page >= len(object_section.entries):
            counts["page_out_of_range"] += 1
            continue
        entry = object_section.entries[logical_page]
        if not entry.is_mapped:
            counts["page_unmapped"] += 1
            continue
        if entry.target >= objects_pages:
            counts["page_out_of_range"] += 1
            continue

        if entry.target not in page_cache:
            start = entry.target * DATA_PAGE_SIZE
            toc = _read_toc(objects[start : start + DATA_PAGE_SIZE])
            page_cache[entry.target] = None if toc is None else {rid: (offset, size) for rid, offset, size, _ in toc}

        records = page_cache[entry.target]
        if records is None:
            counts["page_unparseable"] += 1
            continue
        record = records.get(record_id)
        if record is None:
            counts["record_missing"] += 1
            continue
        if record[1] < length:
            counts["record_short"] += 1
            continue
        counts["ok"] += 1

    return counts


def _fingerprint(object_section: _SectionData | None, index_section: _SectionData | None) -> str:
    digest = hashlib.sha256()
    for section_data in (object_section, index_section):
        if section_data is None:
            digest.update(b"missing")
            continue
        for target in _physical_targets(section_data):
            digest.update(struct.pack("<I", target))
        digest.update(b"|")
    return digest.hexdigest()


def _generation_key(object_section: _SectionData | None, index_section: _SectionData | None) -> tuple[int, int, int]:
    section = object_section.section if object_section else (index_section.section if index_section else None)
    if section is None:
        return (0, 0, 0)
    return (section.version, section.first_id, section.second_id or 0)


def _layout_difference(
    other: Candidate, primary_sections: tuple[_SectionData | None, _SectionData | None], other_sections
) -> LayoutDifference:
    difference = LayoutDifference(other=other.name, object_entries=0, index_entries=0)
    primary_object, primary_index = primary_sections
    other_object, other_index = other_sections

    if primary_object is not None and other_object is not None:
        for left, right in zip(primary_object.entries, other_object.entries):
            if left.target != right.target:
                difference.object_entries += 1
                if len(difference.object_samples) < 5:
                    difference.object_samples.append(
                        f"logical {left.logical}: {left.target} -> {right.target} @0x{right.offset:x}"
                    )
    if primary_index is not None and other_index is not None:
        for left, right in zip(primary_index.entries, other_index.entries):
            if left.target != right.target:
                difference.index_entries += 1
                if len(difference.index_samples) < 5:
                    difference.index_samples.append(
                        f"logical {left.logical}: {left.target} -> {right.target} @0x{right.offset:x}"
                    )
    return difference


def diagnose(
    index_path: Path | str,
    objects_path: Path | str,
    mapping_paths: list[Path | str],
) -> Diagnosis:
    """Diagnose whether the supplied files can form a coherent read view.

    Args:
        index_path: Path to ``INDEX.BTR``.
        objects_path: Path to ``OBJECTS.DATA``.
        mapping_paths: Paths to candidate ``MAPPING*.MAP`` files.

    Returns:
        A structured :class:`Diagnosis`.
    """
    index_path = Path(index_path)
    objects_path = Path(objects_path)
    index = index_path.read_bytes()
    objects = objects_path.read_bytes()
    index_pages = len(index) // INDEX_PAGE_SIZE
    objects_pages = len(objects) // DATA_PAGE_SIZE

    mappings: list[MappingFile] = []
    parsed: dict[str, tuple[_SectionData | None, _SectionData | None]] = {}
    for path in mapping_paths:
        mapping, sections = parse_mapping_file(path)
        mappings.append(mapping)
        object_section = next((item for item in sections if item.section.role == ROLE_OBJECT), None)
        index_section = next((item for item in sections if item.section.role == ROLE_INDEX), None)
        parsed[mapping.name] = (object_section, index_section)

    candidates: list[Candidate] = []
    references_by_candidate: dict[str, list[tuple[int, int, int]]] = {}
    index_checks: dict[str, IndexMappingCheck] = {}

    for mapping in mappings:
        object_section, index_section = parsed[mapping.name]
        candidate = Candidate(
            name=mapping.name,
            object_section=object_section.section if object_section else None,
            index_section=index_section.section if index_section else None,
            object_check=None,
            index_check=None,
        )
        candidate.problems.extend(mapping.problems)
        if object_section is not None:
            candidate.problems.extend(object_section.section.problems)
        if index_section is not None:
            candidate.problems.extend(index_section.section.problems)

        if object_section is not None and candidate.object_section is not None:
            candidate.object_check = _check_object_section(object_section, objects, objects_pages)
        if index_section is not None and candidate.index_section is not None:
            candidate.index_check, references = _check_index_section(index_section, index, index_pages)
            references_by_candidate[mapping.name] = references
            index_checks[mapping.name] = candidate.index_check

        if object_section is not None:
            candidate.resolution = _resolve_references(
                references_by_candidate.get(mapping.name, []), object_section, objects, objects_pages
            )

        candidate.fingerprint = _fingerprint(object_section, index_section)
        candidate.generation_key = _generation_key(object_section, index_section)

        object_ok = True
        if candidate.object_check is not None:
            object_ok = (
                candidate.object_check.out_of_range == 0
                and candidate.object_check.duplicate_targets == 0
                and candidate.object_check.generation_mismatches == 0
            )
            comparable = candidate.object_check.parseable_pages - candidate.object_check.spanning_pages
            if comparable:
                object_ok = object_ok and candidate.object_check.free_space_matches == comparable

        index_ok = True
        if candidate.index_check is not None:
            index_ok = (
                candidate.index_check.out_of_range == 0
                and candidate.index_check.duplicate_targets == 0
                and candidate.index_check.identity_mismatches == 0
                and candidate.index_check.signature_mismatches == 0
                and candidate.index_check.reachable_pages > 0
                and candidate.index_check.reachable_keys > 0
            )

        resolution_ok = True
        if candidate.resolution:
            resolution_ok = all(
                candidate.resolution.get(name, 0) == 0
                for name in ("page_unmapped", "page_out_of_range", "page_unparseable", "record_missing", "record_short")
            )

        candidate.self_consistent = bool(
            object_section is not None and index_section is not None and object_ok and index_ok and resolution_ok
        )
        candidates.append(candidate)

    cross: list[CrossResult] = []
    for index_candidate in candidates:
        references = references_by_candidate.get(index_candidate.name, [])
        for object_candidate in candidates:
            object_section = parsed[object_candidate.name][0]
            if object_section is None:
                continue
            counts = _resolve_references(references, object_section, objects, objects_pages)
            cross.append(
                CrossResult(
                    index_candidate=index_candidate.name,
                    object_candidate=object_candidate.name,
                    counts=counts,
                )
            )

    contradictions: list[str] = []
    insufficiencies: list[str] = []
    observations: list[str] = []

    if not mappings:
        insufficiencies.append("no MAPPING material supplied; no read view can be selected")
    for mapping in mappings:
        for problem in mapping.problems:
            insufficiencies.append(f"{mapping.name}: {problem}")

    valid = [candidate for candidate in candidates if candidate.self_consistent]
    newest = max(candidates, key=lambda item: item.generation_key) if candidates else None
    newest_valid = max(valid, key=lambda item: item.generation_key) if valid else None
    trusted: list[Candidate] = []
    stale: list[Candidate] = []
    primary: Candidate | None = None

    if not candidates:
        verdict = "insufficient"
    elif not valid:
        verdict = "contradiction"
        contradictions.append("no candidate mapping is self-consistent with the supplied INDEX.BTR and OBJECTS.DATA")
    else:
        # Mirror ``find_current_mapping``: keep the first candidate with the highest version.  This matters when
        # two candidates share a version but not a file name, because dissect.cim would open the first one.
        library_choice = None
        library_version = -1
        for candidate in candidates:
            version = candidate.object_section.version if candidate.object_section else 0
            if version > library_version:
                library_choice = candidate
                library_version = version
        primary = library_choice if library_choice in valid else newest_valid
        trusted = [candidate for candidate in valid if candidate.fingerprint == primary.fingerprint]
        stale = [candidate for candidate in valid if candidate.fingerprint != primary.fingerprint]
        verdict = "consistent" if not stale else "multiple_generations"
        if newest is not None and not newest.self_consistent:
            contradictions.append(
                f"newest candidate by header order is {newest.name} "
                f"(version {newest.generation_key[0]}, first_id {newest.generation_key[1]}), "
                f"but it is not self-consistent; falling back to {primary.name}"
            )
        if stale:
            contradictions.append(
                f"stale generation(s) {', '.join(item.name for item in stale)} form a coherent but different page "
                f"generation; they must not be mixed with {', '.join(item.name for item in trusted)}"
            )

    # Report per-candidate layout differences against the selected view and cross-generation resolutions.
    if primary is not None:
        primary_sections = parsed[primary.name]
        for candidate in candidates:
            if candidate is primary:
                continue
            candidate.differences.append(_layout_difference(candidate, primary_sections, parsed[candidate.name]))
        for result in cross:
            if result.index_candidate == result.object_candidate:
                continue
            if not references_by_candidate.get(result.index_candidate):
                continue
            index_candidate = next(item for item in candidates if item.name == result.index_candidate)
            object_candidate = next(item for item in candidates if item.name == result.object_candidate)
            if index_candidate.fingerprint == object_candidate.fingerprint:
                continue
            failures = sum(
                result.counts.get(name, 0)
                for name in ("page_unmapped", "page_out_of_range", "page_unparseable", "record_missing", "record_short")
            )
            if failures:
                contradictions.append(
                    f"mixing index mapping {result.index_candidate} with object mapping "
                    f"{result.object_candidate} leaves {failures} of {sum(result.counts.values())} "
                    "index data references unresolved"
                )

    for candidate in candidates:
        if candidate.object_check is None:
            insufficiencies.append(
                f"{candidate.name}: object mapping section is missing; object evidence is unreadable"
            )
        elif candidate.object_section is not None and candidate.object_section.physical_page_count != objects_pages:
            insufficiencies.append(
                f"{candidate.name}: object mapping declares {candidate.object_section.physical_page_count} physical "
                f"pages, but OBJECTS.DATA contains {objects_pages}"
            )
        elif candidate.object_check.non_toc_pages:
            observations.append(
                f"{candidate.name}: {candidate.object_check.non_toc_pages} mapped object page(s) have no TOC at "
                "offset 0; they are data continuation pages, not independently verifiable"
            )
        if candidate.index_check is None:
            insufficiencies.append(f"{candidate.name}: index mapping section is missing; index evidence is unreadable")
        elif candidate.index_check.header_page_count != index_pages:
            insufficiencies.append(
                f"{candidate.name}: index mapping declares {candidate.index_check.header_page_count} physical pages, "
                f"but INDEX.BTR contains {index_pages}; no mapped entry points beyond page {index_pages - 1}, "
                "so a lost page cannot be confirmed or excluded from these files alone"
            )
        if candidate.index_check is not None and candidate.index_check.unreferenced_pages:
            observations.append(
                f"{candidate.name}: {candidate.index_check.unreferenced_pages} physical index page(s) are not "
                "referenced by this mapping; they may be free space or older generations"
            )

    if len(candidates) == 1:
        insufficiencies.append(
            f"{candidates[0].name} is the only mapping candidate; a coherent single-generation view can be formed, "
            "but there is no second candidate with which to cross-check currency"
        )
    for candidate in candidates:
        if candidate.object_section is not None and candidate.index_section is not None:
            if candidate.object_section.version != candidate.index_section.version:
                contradictions.append(
                    f"{candidate.name}: object mapping version {candidate.object_section.version} != "
                    f"index mapping version {candidate.index_section.version}"
                )
            if candidate.object_section.first_id != candidate.index_section.first_id:
                contradictions.append(
                    f"{candidate.name}: object mapping first_id {candidate.object_section.first_id} != "
                    f"index mapping first_id {candidate.index_section.first_id}"
                )

    if len(candidates) > 1:
        by_version: dict[int, list[Candidate]] = {}
        for candidate in candidates:
            for section in (candidate.object_section, candidate.index_section):
                if section is not None:
                    by_version.setdefault(section.version, []).append(candidate)
                    break
        for version, tied in by_version.items():
            if len(tied) < 2:
                continue
            names = ", ".join(item.name for item in tied)
            same_view = len({item.fingerprint for item in tied}) == 1
            if same_view:
                observations.append(
                    f"{names} share version {version} and map every logical page to the same physical page; "
                    "dissect.cim.utils.find_current_mapping keeps the first one seen (strict > comparison), "
                    "which changes the selected file but not the read view"
                )
            else:
                contradictions.append(
                    f"{names} share version {version} but map logical pages differently; "
                    "dissect.cim.utils.find_current_mapping would depend on input order"
                )

    clean_flags = {mapping.name: mapping.clean_flag for mapping in mappings if mapping.clean_flag is not None}
    if clean_flags:
        observations.append(
            "trailing clean flags: "
            + ", ".join(f"{name}=0x{flag:x}" for name, flag in clean_flags.items())
            + f"; MAPPING_FILE_CLEAN=0x{MAPPING_FILE_CLEAN:x} is defined but unused by dissect.cim, "
            "so the flag is supporting evidence only"
        )

    observations.append(
        "mapping page_crc values are recorded but not validated: dissect.cim never checks them, so they can only be "
        "used as a hint, not as proof that a page belongs to a mapping generation"
    )

    return Diagnosis(
        index_path=str(index_path),
        objects_path=str(objects_path),
        index_size=len(index),
        objects_size=len(objects),
        index_pages=index_pages,
        objects_pages=objects_pages,
        mappings=mappings,
        candidates=candidates,
        cross=cross,
        verdict=verdict,
        primary=primary.name if primary else None,
        trusted=[item.name for item in trusted],
        stale=[item.name for item in stale],
        contradictions=contradictions,
        insufficiencies=insufficiencies,
        observations=observations,
    )


def format_report(diagnosis: Diagnosis) -> str:
    """Render a human-readable report."""
    lines: list[str] = []
    add = lines.append

    add("CIM offline consistency diagnosis")
    add("=" * 34)
    add(f"INDEX.BTR   : {diagnosis.index_path} ({diagnosis.index_size} bytes, {diagnosis.index_pages} pages)")
    add(f"OBJECTS.DATA: {diagnosis.objects_path} ({diagnosis.objects_size} bytes, {diagnosis.objects_pages} pages)")
    add("")
    add("Candidates")
    add("----------")
    for candidate in diagnosis.candidates:
        object_section = candidate.object_section
        index_section = candidate.index_section
        add(f"{candidate.name}:")
        if object_section:
            add(
                f"  object mapping @0x{object_section.offset:x} [{object_section.layout}]: "
                f"version={object_section.version} "
                f"ids={object_section.first_id}/{object_section.second_id} "
                f"pages={object_section.physical_page_count} entries={object_section.entry_count}"
            )
        else:
            add("  object mapping: MISSING")
        if index_section:
            add(
                f"  index mapping  @0x{index_section.offset:x} [{index_section.layout}]: "
                f"version={index_section.version} "
                f"ids={index_section.first_id}/{index_section.second_id} "
                f"pages={index_section.physical_page_count} entries={index_section.entry_count}"
            )
        else:
            add("  index mapping : MISSING")
        add(f"  self-consistent: {candidate.self_consistent}")
        if candidate.object_check:
            check = candidate.object_check
            comparable = check.parseable_pages - check.spanning_pages
            add(
                f"  objects: mapped={check.mapped} unmapped={check.unmapped} oob={check.out_of_range} "
                f"dup={check.duplicate_targets} toc_pages={check.parseable_pages} "
                f"spanning={check.spanning_pages} free_space_match={check.free_space_matches}/{comparable}"
            )
        if candidate.index_check:
            check = candidate.index_check
            add(
                f"  index:   mapped={check.mapped} unmapped={check.unmapped} oob={check.out_of_range} "
                f"dup={check.duplicate_targets} identity={check.identity_matches}/{check.mapped} "
                f"reachable={check.reachable_pages} keys={check.reachable_keys} refs={check.data_references}"
            )
        if candidate.resolution:
            add(f"  self-resolution: {candidate.resolution}")
        for difference in candidate.differences:
            add(
                f"  differs from {diagnosis.primary}: object_entries={difference.object_entries} "
                f"index_entries={difference.index_entries}"
            )
            for sample in difference.object_samples + difference.index_samples:
                add(f"    {sample}")
        for problem in candidate.problems:
            add(f"  problem: {problem}")
        add("")

    add("Cross-combination (index candidate x object candidate)")
    add("--------------------------------------------------------")
    for result in diagnosis.cross:
        counts = result.counts
        failures = sum(
            counts.get(name, 0)
            for name in ("page_unmapped", "page_out_of_range", "page_unparseable", "record_missing", "record_short")
        )
        add(
            f"  {result.index_candidate} + {result.object_candidate}: "
            f"ok={counts.get('ok', 0)} unresolved={failures}"
        )
    add("")

    add("Verdict")
    add("-------")
    add(f"  status: {diagnosis.verdict}")
    add(f"  primary: {diagnosis.primary or 'none'}")
    add(f"  trusted view: {', '.join(diagnosis.trusted) or 'none'}")
    add(f"  stale/alternate: {', '.join(diagnosis.stale) or 'none'}")
    for item in diagnosis.contradictions:
        add(f"  CONTRADICTION: {item}")
    for item in diagnosis.insufficiencies:
        add(f"  INSUFFICIENT: {item}")
    for item in diagnosis.observations:
        add(f"  OBSERVATION: {item}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description="Read-only consistency diagnostic for dissect.cim artifacts")
    parser.add_argument("index", help="path to INDEX.BTR")
    parser.add_argument("objects", help="path to OBJECTS.DATA")
    parser.add_argument("mappings", nargs="*", help="paths to MAPPING*.MAP files")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    diagnosis = diagnose(args.index, args.objects, args.mappings)
    if args.json:
        print(json.dumps(diagnosis.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_report(diagnosis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
