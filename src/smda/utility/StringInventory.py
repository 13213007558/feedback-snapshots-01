"""Inventory of string bytes found by content scan, separate from recovered references.

A string present in a sample is not evidence that any function references it. This module
scans the mapped image on its own and records where each occurrence lives (code, read-only
data, writable data or unused padding), how it is encoded and terminated, and which of the
occurrences recovered code actually reaches. Reference evidence is only attached where a
recovered instruction names the string's start through an address-shaped operand; an
immediate or a stored word that merely equals the address is not a reference.
"""

import bisect
import re
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.utility.StringExtractor import _read_string_header, derefs, read_string

MIN_STRING_LENGTH = 4

PROVENANCE_CODE = "code"
PROVENANCE_RODATA = "rodata"
PROVENANCE_DATA = "data"
PROVENANCE_PADDING = "padding"
PROVENANCE_UNMAPPED = "unmapped"

_ENCODING_NAMES = {"ascii": "ascii", "utf8": "utf-8", "unicode": "utf-16-le"}
_TERMINATOR_BYTES = {"ascii": 1, "utf8": 1, "unicode": 2}

_NUL_FREE_RUN_RE = re.compile(rb"[^\x00]{4,}")
_UTF16_RUN_RE = re.compile(rb"(?:[\x09-\x0d\x20-\x7e]\x00){2,}\x00\x00")
# Bytes the existing C-string rule accepts; a UTF-8 literal may also carry high bytes.
_PRINTABLE_BYTES = frozenset((*range(0x09, 0x0E), *range(0x20, 0x7F)))

# Only mnemonics whose immediate operand is the address itself. A bare `mov reg, imm` or
# `push imm` carries a value that may merely look like an address, so it is not evidence.
_ADDRESS_MATERIALIZING_MNEMONICS = {
    "intel": frozenset(("lea",)),
    "aarch64": frozenset(("adr", "adrp")),
    "arm": frozenset(("adr", "add", "sub", "mov")),
}
_PC_REGISTERS = frozenset(("rip", "eip", "pc"))
_WRITABLE_SECTION_NAMES = (".data", ".bss", "__data", "__bss")


def _section_kinds(report, binary_info=None) -> List[Tuple[str, int, int, str]]:
    """(name, start, end, kind) for every section the report can describe, sorted by start."""
    sections: List[Tuple[str, int, int, str]] = []
    if binary_info is not None and hasattr(binary_info, "getSectionKinds"):
        try:
            sections = list(binary_info.getSectionKinds())
        except Exception as exc:
            reraise_non_operational_exception(exc)
            sections = []
    if not sections:
        sections = _section_kinds_from_report(report)
    merged: Dict[int, Tuple[str, int, int, str]] = {}
    for name, start, end, kind in sections:
        if end <= start:
            continue
        previous = merged.get(start)
        if previous is None or end > previous[2]:
            merged[start] = (name, start, end, kind)
    return [merged[start] for start in sorted(merged)]


def _section_kinds_from_report(report) -> List[Tuple[str, int, int, str]]:
    """Fallback when the loader metadata is gone (e.g. a report loaded from JSON): the
    serialized section list keeps only the ranges, so the kind is inferred from the name when
    one survived and from the code areas otherwise."""
    sections: List[Tuple[str, int, int, str]] = []
    code_areas = _normalized_ranges(report.code_areas)
    for section in report.code_sections or []:
        try:
            name, start, end = section[0], int(section[1]), int(section[2])
        except (IndexError, TypeError, ValueError):
            continue
        if end <= start:
            continue
        if start == 0:
            kind = PROVENANCE_UNMAPPED
        elif _overlaps(start, end, code_areas):
            kind = PROVENANCE_CODE
        elif name.lower() in _WRITABLE_SECTION_NAMES:
            kind = PROVENANCE_DATA
        else:
            kind = PROVENANCE_RODATA
        sections.append((str(name or ""), start, end, kind))
    return sections


def _normalized_ranges(ranges) -> List[Tuple[int, int]]:
    normalized = []
    for entry in ranges or []:
        try:
            start, end = int(entry[0]), int(entry[1])
        except (IndexError, TypeError, ValueError):
            continue
        if end > start:
            normalized.append((start, end))
    return normalized


def _overlaps(start: int, end: int, ranges: Iterable[Tuple[int, int]]) -> bool:
    return any(range_start < end and start < range_end for range_start, range_end in ranges)


def _instruction_spans(report) -> List[Tuple[int, int]]:
    """The byte span of every recovered instruction, the narrowest code evidence there is."""
    spans = []
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            try:
                size = len(instruction.bytes or "") // 2
            except TypeError:
                size = 0
            if instruction.offset is not None and size > 0:
                spans.append((instruction.offset, instruction.offset + size))
    return spans


def _locate(addr: int, sections: Sequence[Tuple[str, int, int, str]], instruction_spans, code_areas):
    """(provenance, section name) for an address in the mapped image.

    A section's own flags are the primary evidence: a read-only section inside a broadly
    executable PT_LOAD stays read-only data, because the flags describe what the loader maps
    there and the segment only says what the whole range permits. Outside every declared
    section, only recovered instruction bytes are code; the rest of an executable segment is
    the padding a linker leaves between functions, which is exactly what the section table
    would have to name separately to be anything else. Without any section metadata the loader's
    code areas are the only mapping evidence and are used instead.
    """
    for name, start, end, kind in sections:
        if start <= addr < end:
            return kind, name
    if _overlaps(addr, addr + 1, instruction_spans):
        return PROVENANCE_CODE, None
    if not sections:
        # No section table at all (a raw buffer): a loader-supplied code area is the only
        # statement about what the bytes are, so an unowned address inside one is code.
        return (PROVENANCE_CODE if _overlaps(addr, addr + 1, code_areas) else PROVENANCE_PADDING), None
    return PROVENANCE_PADDING, None


def _printable_utf8(decoded: str) -> bool:
    return all(character.isprintable() or character in "\t\n\r\v\f" for character in decoded)


def _scan_candidates(buffer: bytes, base_addr: int, references: Dict[int, List[Dict[str, Any]]]):
    """Yield (start, end, content, type) for NUL-terminated occurrences.

    ASCII and UTF-8 share the NUL-free run scan: both are terminated by a single NUL. A run may
    hold several literals packed back to back; each referenced start begins its own literal,
    because that is how a compiler lays out a C string table. A run nothing references is one
    literal, exactly the run the existing C-string rule would read.
    """
    reference_starts = sorted(references)
    for match in _NUL_FREE_RUN_RE.finditer(buffer):
        run_start, run_end = match.start(), match.end()
        first = bisect.bisect_left(reference_starts, run_start)
        last = bisect.bisect_left(reference_starts, run_end)
        cuts = [run_start]
        for position in reference_starts[first:last]:
            if position > cuts[-1] and position < run_end:
                cuts.append(position)
        cuts.append(run_end)
        for segment_start, segment_end in zip(cuts, cuts[1:], strict=False):
            if segment_end - segment_start < MIN_STRING_LENGTH:
                continue
            run = buffer[segment_start:segment_end]
            if all(byte in _PRINTABLE_BYTES for byte in run):
                content, string_type = run.decode("ascii"), "ascii"
            else:
                try:
                    content, string_type = run.decode("utf-8"), "utf8"
                except UnicodeDecodeError:
                    continue
                if not _printable_utf8(content):
                    continue
            yield base_addr + segment_start, base_addr + segment_end, content, string_type
    for match in _UTF16_RUN_RE.finditer(buffer):
        content_bytes = match.group()[:-2]
        if len(content_bytes) // 2 < MIN_STRING_LENGTH:
            continue
        try:
            content = content_bytes.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if content.isprintable():
            yield base_addr + match.start(), base_addr + match.start() + len(content_bytes), content, "unicode"


def _scan(buffer: bytes, base_addr: int, references: Dict[int, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    candidates = sorted(
        _scan_candidates(buffer, base_addr, references), key=lambda item: (item[0], -(item[1] - item[0]))
    )
    accepted: List[Dict[str, Any]] = []
    for start, end, content, string_type in candidates:
        if accepted and start < accepted[-1]["byte_range"][1]:
            # a UTF-16 literal covers bytes the single-byte scan also splits into runs; the
            # longer encoding at the same start already described them
            continue
        accepted.append(
            {
                "string": content,
                "data_addr": start,
                "byte_range": [start, end],
                "type": string_type,
                "encoding": _ENCODING_NAMES[string_type],
                "terminator_bytes": _TERMINATOR_BYTES[string_type],
            }
        )
    return accepted


def _operand_is_address(detailed, operand, target: int) -> bool:
    """Whether one decoded operand names target as a memory address."""
    memory = getattr(operand, "mem", None)
    if memory is None:
        return False
    base_register = int(getattr(memory, "base", 0) or 0)
    displacement = int(getattr(memory, "disp", 0) or 0)
    try:
        base_name = (detailed.reg_name(base_register) or "").lower()
    except Exception as exc:
        reraise_non_operational_exception(exc)
        base_name = ""
    if base_name in _PC_REGISTERS:
        # PC-relative displacement is resolved against the end of the instruction, the same
        # way the report's own getDataRefs() does, so the same target round-trips here
        displacement += detailed.address + detailed.size
        return displacement == target
    if base_register == 0:
        # absolute memory operand: the displacement is the address it touches
        return displacement == target
    return False


def _is_address_shaped(report, instruction, target: int) -> bool:
    """Whether the instruction names target as an address rather than merely holding the value.

    A memory operand names the bytes at target, and on AArch64/ARM the `adr` mnemonic computes
    one. A bare immediate load such as `mov eax, <addr>` is a constant that happens to equal a
    mapped address and is deliberately not evidence: the value could be a length, a flags word,
    a hash, or an unrelated number.
    """
    architecture = report.architecture or "intel"
    mnemonic = (instruction.mnemonic or "").lower()
    operands_text = instruction.operands or ""
    if "[" in operands_text:
        try:
            detailed = instruction.getDetailed()
        except Exception as exc:
            reraise_non_operational_exception(exc)
            detailed = None
        if detailed is not None:
            for operand in getattr(detailed, "operands", []) or []:
                if _operand_is_address(detailed, operand, target):
                    return True
    if mnemonic in _ADDRESS_MATERIALIZING_MNEMONICS.get(architecture, frozenset()):
        for operand in operands_text.split(","):
            try:
                if int(operand.strip().lstrip("#"), 0) == target:
                    return True
            except ValueError:
                continue
    return False


def _collect_evidence(report, sections, code_areas, instruction_spans) -> Dict[int, List[Dict[str, Any]]]:
    """Map each referenced string start to the instruction evidence that names it.

    Only an address-shaped operand counts. A stored word whose value equals an address, or an
    immediate that is not an address operand, is a numeric resemblance and is not recorded.
    """
    evidence: Dict[int, List[Dict[str, Any]]] = {}
    for function in report.getFunctions():
        for instruction in function.getInstructions():
            try:
                data_refs = list(instruction.getDataRefs())
            except Exception as exc:
                reraise_non_operational_exception(exc)
                continue
            for data_ref in data_refs:
                if not _is_address_shaped(report, instruction, data_ref):
                    continue
                if _locate(data_ref, sections, instruction_spans, code_areas)[0] == PROVENANCE_UNMAPPED:
                    continue
                string_at_ref = _string_start(report, data_ref)
                if string_at_ref:
                    # the operand names the literal's first byte, the strongest reading
                    _add_evidence(evidence, data_ref, _reference(function, instruction, "direct"))
                    continue
                header = None
                try:
                    header = _read_string_header(report, data_ref)
                except Exception as exc:
                    reraise_non_operational_exception(exc)
                if header is not None and header[0]:
                    # a (pointer, length) header names the bytes at the pointer; that is a
                    # direct naming of the literal, though the instruction named the header
                    _add_evidence(evidence, header[2], _reference(function, instruction, "string-header"))
                    continue
                try:
                    chain = list(derefs(report, data_ref))
                except Exception as exc:
                    reraise_non_operational_exception(exc)
                    chain = [data_ref]
                for depth, candidate in enumerate(chain):
                    if _locate(candidate, sections, instruction_spans, code_areas)[0] == PROVENANCE_UNMAPPED:
                        continue
                    _add_evidence(
                        evidence,
                        candidate,
                        _reference(function, instruction, "direct" if depth == 0 else "pointer"),
                    )
    return evidence


def _string_start(report, addr: int) -> bool:
    """True when a NUL-terminated string of at least MIN_STRING_LENGTH bytes starts at addr."""
    try:
        result = read_string(report, addr)
    except Exception as exc:
        reraise_non_operational_exception(exc)
        return False
    return bool(result) and len(result[0].rstrip("\x00")) >= MIN_STRING_LENGTH


def _add_evidence(evidence: Dict[int, List[Dict[str, Any]]], start: int, reference: Dict[str, Any]) -> None:
    references = evidence.setdefault(start, [])
    if any(
        (existing["ins_addr"], existing["via"]) == (reference["ins_addr"], reference["via"]) for existing in references
    ):
        return
    references.append(reference)


def _reference(function, instruction, via: str) -> Dict[str, Any]:
    return {
        "ins_addr": instruction.offset,
        "function": function.offset,
        "mnemonic": instruction.mnemonic or "",
        "operands": instruction.operands or "",
        "via": via,
    }


def build_string_inventory(report, binary_info=None) -> List[Dict[str, Any]]:
    """Scan the report's mapped image and return its string occurrences with evidence.

    The result is a list of JSON-safe dicts sorted by ``byte_range`` start. Each occurrence
    carries the decoded text, its virtual byte range (content only, terminator excluded), the
    encoding assumption and terminator width, the section provenance, and the recovered
    instructions that reference its exact start. An occurrence with an empty ``references``
    list is a scan finding only: it exists in the bytes, but no recovered code was shown to
    use it. Nothing is derived from a stored word or a non-address immediate.
    """
    buffer = report.buffer
    base_addr = report.base_addr
    if buffer is None or base_addr is None:
        return []
    sections = _section_kinds(report, binary_info)
    instruction_spans = _instruction_spans(report)
    code_areas = _normalized_ranges(report.code_areas)
    evidence = _collect_evidence(report, sections, code_areas, instruction_spans)
    entries = _scan(buffer, base_addr, evidence)
    for entry in entries:
        provenance, section_name = _locate(entry["data_addr"], sections, instruction_spans, code_areas)
        entry["provenance"] = provenance
        entry["section"] = section_name
        entry["references"] = evidence.get(entry["data_addr"], [])
    entries.sort(key=lambda entry: (entry["byte_range"][0], entry["byte_range"][1]))
    return entries


def summarize_inventory(entries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    referenced = 0
    for entry in entries:
        counts[entry["provenance"]] = counts.get(entry["provenance"], 0) + 1
        if entry["references"]:
            referenced += 1
    return {"total": len(entries), "referenced": referenced, "by_provenance": dict(sorted(counts.items()))}
