"""Provenance preserving metadata extraction for EWF header and hash sections.

An EWF image may carry several ``header`` (legacy format 1) and ``header2`` (format 3) sections,
possibly across multiple segment files. Each section can state the same field (case number,
examiner, acquisition time, ...) with a different value, use a different encoding, repeat keys or
omit fields entirely.

This module keeps every claim as a separate :class:`ValueCandidate` together with its origin
(segment, section, encoding, line, occurrence) and the exact bytes backing it. Values stored on the
candidates are verbatim evidence text. Canonical field names and parsed timestamps are parser
interpretations and are always nested under explicit ``inferred`` keys. A header that cannot be
decompressed, decoded or parsed is recorded as corrupt with its error and never contributes a
value, so it cannot override a healthy header. Digests from ``hash`` sections are reported as
claimed and never marked verified.
"""

from __future__ import annotations

import codecs
import dataclasses
import datetime
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.ewf.c_ewf import c_ewf
from dissect.evidence.ewf.ewf import EWF, Section, Segment

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

HEADER_SECTION_TYPES = ("header", "header2")

# Single letter identifiers used inside the "main" block of header/header2 sections, mapped to
# human readable field names. The mapping is a parser interpretation: the literal key token in the
# evidence is always preserved on the candidate as ``raw_key``. Identifiers not in this mapping are
# retained under their literal key.
FIELD_NAMES: dict[str, str] = {
    "c": "case_number",
    "n": "evidence_number",
    "a": "description",
    "e": "examiner_name",
    "t": "notes",
    "m": "acquisition_time",
    "u": "system_time",
    "av": "acquisition_version",
    "ov": "operating_system",
}

# Fields whose value is an acquisition timestamp in one of the EWF date notations.
TIME_FIELDS = frozenset(("acquisition_time", "system_time"))

CANONICAL_FIELD_ORDER = (
    "case_number",
    "evidence_number",
    "description",
    "examiner_name",
    "notes",
    "acquisition_time",
    "system_time",
    "acquisition_version",
    "operating_system",
)

_SELECTION_NO_VALUE = "no_value"
_SELECTION_UNANIMOUS = "unanimous"
_SELECTION_MAJORITY = "majority"
_SELECTION_PREFERRED_HEADER = "preferred_header"

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9]{1,3}")


@dataclass(frozen=True)
class HeaderOrigin:
    """Where a header (or a claim made inside a header) came from.

    Args:
        segment_index: Zero based index of the segment file.
        section_index: Zero based index of the section within that segment.
        section_type: The raw section type, either ``header`` or ``header2``.
        descriptor_offset: File offset of the section descriptor.
        encoding: Codec used to decode the (decompressed) payload.
        encoding_fallback: Whether a lossy fallback codec (latin-1) was used.
        format_version: Format version claimed by the first payload line (usually 1 or 3).
        payload_size: Size in bytes of the compressed section payload.
    """

    segment_index: int
    section_index: int
    section_type: str
    descriptor_offset: int
    encoding: str
    encoding_fallback: bool
    format_version: int | None
    payload_size: int

    def as_dict(self) -> dict[str, object]:
        """Return the origin as plain JSON serializable data."""
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class ValueCandidate:
    """A single value claim with full provenance.

    The ``value`` and ``raw_value`` are verbatim evidence content; ``field`` is the parser
    interpretation of ``raw_key`` and may therefore be an inferred name.

    Args:
        field: Canonical field name (mapped) or the literal key when no mapping is known.
        raw_key: The literal key token as it appears in the evidence.
        value: The decoded, verbatim value text.
        raw_value: The exact bytes in the decompressed payload backing ``value``.
        byte_offset: Offset of ``raw_value`` in the decompressed payload.
        block: Name of the payload block (``main``, ``srce``, ``sub``, ...).
        line_number: One based line number of the value in the decoded payload.
        occurrence: Zero based occurrence of the key within the block (for duplicated keys).
        known_field: Whether the key was mapped through :data:`FIELD_NAMES`.
        origin: The header this candidate was read from.
    """

    field: str
    raw_key: str
    value: str
    raw_value: bytes
    byte_offset: int
    block: str
    line_number: int
    occurrence: int
    known_field: bool
    origin: HeaderOrigin


@dataclass(frozen=True)
class ParsedTime:
    """Result of interpreting a timestamp value.

    Only ``raw`` is evidence content. The ``datetime`` and ``timezone_known`` flag are parser
    inference.

    Args:
        raw: The verbatim value text.
        kind: One of ``epoch_seconds``, ``space_separated``, ``iso8601`` or ``unparsed``.
        datetime: The interpreted datetime, or ``None`` when it could not be parsed.
        timezone_known: Whether the interpretation carries a timezone.
    """

    raw: str
    kind: str
    datetime: datetime.datetime | None
    timezone_known: bool

    def as_dict(self) -> dict[str, object]:
        """Return the parsed time as plain JSON serializable data."""
        return {
            "raw": self.raw,
            "kind": self.kind,
            "datetime": self.datetime.isoformat() if self.datetime else None,
            "timezone_known": self.timezone_known,
        }


@dataclass(frozen=True)
class ClaimedHash:
    """A digest stored in a ``hash`` section.

    The parser never recomputes or verifies the digest, so ``verified`` is always ``False``: this
    is a claim made by the evidence, not a fact established by the parser.
    """

    algorithm: str
    digest: str
    origin: HeaderOrigin
    verified: bool = False


@dataclass
class ParsedHeader:
    """The result of parsing a single header section.

    A corrupt header is represented by ``error`` being set and an empty ``candidates`` list. It can
    therefore never contribute values or override a healthy header.
    """

    origin: HeaderOrigin
    raw: bytes
    text: str | None
    candidates: list[ValueCandidate] = field(default_factory=list)
    error: str | None = None

    @property
    def healthy(self) -> bool:
        """Whether the header could be decompressed, decoded and parsed."""
        return self.error is None


@dataclass(frozen=True)
class FieldReport:
    """All candidates for one field plus the deterministic display selection."""

    field: str
    candidates: tuple[ValueCandidate, ...]
    distinct_values: tuple[str, ...]
    selected: ValueCandidate | None
    selection_reason: str
    conflicting: bool

    def parsed_times(self) -> list[ParsedTime]:
        """Return the parser interpretation of every candidate, verbatim value first."""
        return [parse_time(candidate.value) for candidate in self.candidates]


@dataclass
class MetadataReport:
    """Aggregated view of every header and hash section in an EWF image."""

    headers: list[ParsedHeader]
    hashes: list[ClaimedHash]
    fields: dict[str, FieldReport]
    segment_errors: dict[int, str] = field(default_factory=dict)

    @property
    def healthy_headers(self) -> list[ParsedHeader]:
        """All headers that were parsed without an error."""
        return [header for header in self.headers if header.healthy]

    @property
    def corrupt_headers(self) -> list[ParsedHeader]:
        """All headers that could not be parsed, with their error recorded."""
        return [header for header in self.headers if not header.healthy]

    @property
    def has_conflicts(self) -> bool:
        """Whether any field carries more than one distinct non-empty value."""
        return any(report.conflicting for report in self.fields.values())

    def explain(self, field_name: str) -> FieldReport:
        """Expand the full evidence (every candidate and the selection reason) for a field."""
        return self.fields[field_name]

    def brief(self) -> dict[str, dict[str, object]]:
        """Produce a compact, JSON serializable display view.

        Every selected value is marked as verbatim evidence, while parser interpretations (field
        name mapping, interpreted timestamps) are nested under explicit ``inferred`` keys.
        """
        result: dict[str, dict[str, object]] = {}
        for field_name in self._ordered_field_names():
            report = self.fields[field_name]
            selected = report.selected
            entry: dict[str, object] = {
                "field": field_name,
                "value": selected.value if selected else None,
                "value_source": "verbatim" if selected else None,
                "raw_key": selected.raw_key if selected else None,
                "conflict": report.conflicting,
                "distinct_values": list(report.distinct_values),
                "selection_reason": report.selection_reason,
                "source": selected.origin.as_dict() if selected else None,
                "inferred": {
                    "field_name_mapped_from": selected.raw_key if selected and selected.known_field else None,
                },
            }
            if field_name in TIME_FIELDS:
                entry["time_candidates"] = [parsed.as_dict() for parsed in report.parsed_times()]
                if selected:
                    entry["inferred"]["time"] = parse_time(selected.value).as_dict()
            result[field_name] = entry
        return result

    def _ordered_field_names(self) -> list[str]:
        canonical = [name for name in CANONICAL_FIELD_ORDER if name in self.fields]
        extra = sorted(name for name in self.fields if name not in CANONICAL_FIELD_ORDER)
        return canonical + extra


def parse_time(value: str) -> ParsedTime:
    """Interpret an EWF timestamp value without inventing a timezone.

    EWF ``header2`` sections store epoch seconds (timezone is inherently UTC), legacy ``header``
    sections store space separated local wall time without a timezone. Anything else is attempted
    as ISO 8601 and otherwise left unparsed; the verbatim value is always retained.
    """
    stripped = value.strip()

    if stripped.isdigit() and len(stripped) >= 9:
        try:
            parsed = datetime.datetime.fromtimestamp(int(stripped), tz=datetime.timezone.utc)
            return ParsedTime(value, "epoch_seconds", parsed, True)
        except (OverflowError, OSError, ValueError):
            pass

    try:
        parsed = datetime.datetime.strptime(stripped, "%Y %m %d %H %M %S")
        return ParsedTime(value, "space_separated", parsed, False)
    except ValueError:
        pass

    try:
        parsed = datetime.datetime.fromisoformat(stripped)
        return ParsedTime(value, "iso8601", parsed, parsed.tzinfo is not None)
    except ValueError:
        return ParsedTime(value, "unparsed", None, False)


def read_headers(source: EWF | BinaryIO | list[BinaryIO] | list[Path] | Path | str) -> list[ParsedHeader]:
    """Parse every header section in an EWF image, keeping corrupt headers as failed records.

    Args:
        source: An :class:`EWF` instance, a (list of) open segment file handle(s), or a path.

    Returns:
        One :class:`ParsedHeader` per header section, in on-disk order. A section that cannot be
        decompressed, decoded or parsed is returned with its ``error`` set and never raises. A
        segment whose sections cannot even be enumerated (for example an encrypted, still locked
        ADCRYPT container) is skipped; use :func:`read_metadata` to see those segment errors.
    """
    parsed_headers: list[ParsedHeader] = []
    for segment_index, sections, _error in _enumerate_sections(source):
        for section_index, section in enumerate(sections):
            if section.descriptor.type in HEADER_SECTION_TYPES:
                parsed_headers.append(_parse_header_section(segment_index, section_index, section))
    return parsed_headers


def _enumerate_sections(
    source: EWF | BinaryIO | list[BinaryIO] | list[Path] | Path | str,
) -> Iterable[tuple[int, list[Section], str | None]]:
    """Yield ``(segment_index, sections, error)`` tolerating unreadable segments.

    When a segment cannot be enumerated its sections list is empty and the error is populated, so a
    single locked or damaged segment never aborts parsing of the remaining segments.
    """
    for segment_index, segment in _iter_segments(source):
        try:
            yield segment_index, list(segment.sections), None
        except (UnicodeDecodeError, ValueError, EOFError) as exc:
            yield segment_index, [], f"section enumeration failed: {exc}"


def read_metadata(source: EWF | BinaryIO | list[BinaryIO] | list[Path] | Path | str) -> MetadataReport:
    """Read all header claims and claimed hashes and build the display report."""
    headers: list[ParsedHeader] = []
    hashes: list[ClaimedHash] = []
    segment_errors: dict[int, str] = {}

    for segment_index, sections, error in _enumerate_sections(source):
        if error is not None:
            segment_errors[segment_index] = error
            continue
        for section_index, section in enumerate(sections):
            try:
                section_type = section.descriptor.type
            except UnicodeDecodeError as exc:
                segment_errors[segment_index] = f"section type could not be decoded: {exc}"
                continue
            if section_type in HEADER_SECTION_TYPES:
                headers.append(_parse_header_section(segment_index, section_index, section))
            elif section_type == "hash":
                hashes.append(_parse_hash_section(segment_index, section_index, section))

    candidates_by_field: dict[str, list[ValueCandidate]] = {}
    for header in headers:
        if not header.healthy:
            continue
        for candidate in header.candidates:
            # A key present with an empty value is a missing claim, not a value to display.
            if not candidate.value.strip():
                continue
            candidates_by_field.setdefault(candidate.field, []).append(candidate)

    reports = {
        field_name: _build_field_report(field_name, candidates)
        for field_name, candidates in candidates_by_field.items()
    }
    return MetadataReport(headers=headers, hashes=hashes, fields=reports, segment_errors=segment_errors)


def render_report(report: MetadataReport) -> str:
    """Render a human readable report that labels verbatim vs inferred content."""
    lines = ["EWF metadata", "============", ""]

    lines.append("Brief display (values are verbatim evidence text)")
    lines.append("--------------------------------------------------")
    for field_name in report._ordered_field_names():
        field_report = report.fields[field_name]
        selected = field_report.selected
        if selected is None:
            lines.append(f"{field_name}: <no non-empty value in any healthy header>")
            continue

        suffix = ""
        if field_name in TIME_FIELDS:
            parsed = parse_time(selected.value)
            if parsed.datetime:
                tz_label = "UTC" if parsed.timezone_known else "timezone unknown"
                suffix = f"  -> [parser-inferred] {parsed.datetime.isoformat()} ({tz_label}, {parsed.kind})"
        conflict = "CONFLICT" if field_report.conflicting else field_report.selection_reason
        lines.append(f"{field_name}: {selected.value!r} [verbatim] ({conflict}){suffix}")
        lines.append(
            "    from: "
            f"segment {selected.origin.segment_index} {selected.origin.section_type} "
            f"section #{selected.origin.section_index} @{selected.origin.descriptor_offset:#x} "
            f"encoding={selected.origin.encoding}"
        )

    if report.has_conflicts:
        lines.append("")
        lines.append("Conflicting claims (full evidence trail)")
        lines.append("----------------------------------------")
        for field_name in report._ordered_field_names():
            field_report = report.fields[field_name]
            if not field_report.conflicting:
                continue
            lines.append(
                f"{field_name}: {field_report.selection_reason} selected "
                f"{field_report.selected.value!r} out of {len(field_report.distinct_values)} values"
            )
            for candidate in field_report.candidates:
                lines.append(
                    f"  - {candidate.value!r} [verbatim] key={candidate.raw_key!r} "
                    f"segment {candidate.origin.segment_index} {candidate.origin.section_type} "
                    f"#{candidate.origin.section_index} line {candidate.line_number} "
                    f"occurrence {candidate.occurrence}"
                )

    if report.segment_errors:
        lines.append("")
        lines.append("Unreadable segments (skipped, no claims taken from them)")
        lines.append("------------------------------------------------------")
        for segment_index in sorted(report.segment_errors):
            lines.append(f"  - segment {segment_index}: {report.segment_errors[segment_index]}")

    corrupt = report.corrupt_headers
    if corrupt:
        lines.append("")
        lines.append("Corrupt headers (kept separate, never used as a value source)")
        lines.append("-------------------------------------------------------------")
        for header in corrupt:
            lines.append(
                f"  - segment {header.origin.segment_index} {header.origin.section_type} "
                f"#{header.origin.section_index} @{header.origin.descriptor_offset:#x}: {header.error}"
            )

    lines.append("")
    lines.append("Claimed hashes (parser did NOT verify)")
    lines.append("--------------------------------------")
    if not report.hashes:
        lines.append("  - none")
    for claimed in report.hashes:
        lines.append(
            f"  - {claimed.algorithm}: {claimed.digest} [claimed, not verified] "
            f"segment {claimed.origin.segment_index} section #{claimed.origin.section_index}"
        )

    return "\n".join(lines)


def _iter_segments(
    source: EWF | BinaryIO | list[BinaryIO] | list[Path] | Path,
) -> Iterable[tuple[int, Segment]]:
    if isinstance(source, EWF):
        for index in range(len(source.fh)):
            yield index, source.segment(index)
        return

    if isinstance(source, Path | str):
        ewf = EWF(Path(source))
        for index in range(len(ewf.fh)):
            yield index, ewf.segment(index)
        return

    if isinstance(source, list) and source and all(isinstance(item, Path) for item in source):
        ewf = EWF(source)
        for index in range(len(ewf.fh)):
            yield index, ewf.segment(index)
        return

    if not isinstance(source, list):
        source = [source]

    for index, fh in enumerate(source):
        yield index, Segment(fh)


def _parse_header_section(segment_index: int, section_index: int, section: Section) -> ParsedHeader:
    descriptor = section.descriptor
    compressed = descriptor.data

    def origin(encoding: str, fallback: bool, version: int | None) -> HeaderOrigin:
        return HeaderOrigin(
            segment_index=segment_index,
            section_index=section_index,
            section_type=descriptor.type,
            descriptor_offset=descriptor.offset,
            encoding=encoding,
            encoding_fallback=fallback,
            format_version=version,
            payload_size=len(compressed),
        )

    try:
        raw = zlib.decompress(compressed)
    except zlib.error as exc:
        return ParsedHeader(
            origin=origin("unknown", False, None),
            raw=compressed,
            text=None,
            error=f"zlib decompression failed: {exc}",
        )

    try:
        text, encoding, fallback, bom_length = _decode_payload(raw)
        version = _format_version(text)
        candidates = list(_parse_payload(text, raw, encoding, bom_length, origin(encoding, fallback, version)))
    except (UnicodeDecodeError, ValueError) as exc:
        return ParsedHeader(
            origin=origin("unknown", False, None),
            raw=raw,
            text=None,
            error=f"header payload could not be parsed: {exc}",
        )

    if not any(candidate.block == "main" for candidate in candidates):
        return ParsedHeader(
            origin=origin(encoding, fallback, version),
            raw=raw,
            text=text,
            error="no main block with key/value lines found",
        )

    return ParsedHeader(origin=origin(encoding, fallback, version), raw=raw, text=text, candidates=candidates)


def _decode_payload(raw: bytes) -> tuple[str, str, bool, int]:
    if raw.startswith(codecs.BOM_UTF16_LE):
        return raw[len(codecs.BOM_UTF16_LE) :].decode("utf-16-le"), "utf-16-le", False, len(codecs.BOM_UTF16_LE)
    if raw.startswith(codecs.BOM_UTF16_BE):
        return raw[len(codecs.BOM_UTF16_BE) :].decode("utf-16-be"), "utf-16-be", False, len(codecs.BOM_UTF16_BE)
    # The UTF-16-BE BOM is itself valid UTF-8, so only attempt UTF-8 when no UTF-16 BOM is present.
    try:
        return raw.decode("utf-8"), "utf-8", False, 0
    except UnicodeDecodeError:
        # A legacy header is not required to be UTF-8. Latin-1 always round-trips every byte.
        return raw.decode("latin-1"), "latin-1", True, 0


def _format_version(text: str) -> int | None:
    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
    return int(first_line) if first_line.isdigit() else None


def _parse_payload(
    text: str, raw: bytes, encoding: str, bom_length: int, origin: HeaderOrigin
) -> Iterable[ValueCandidate]:
    for block_name, block_lines in _iter_blocks(text):
        key_item = _find_key_line(block_lines)
        if key_item is None:
            continue
        key_index, (_key_lineno, key_line, key_offset) = key_item
        key_tokens = _line_tokens(key_line, key_offset)

        value_item = _find_value_line(block_lines, key_index, len(key_tokens))
        value_lineno, value_line, value_offset = value_item
        value_tokens = _line_tokens(value_line, value_offset)

        occurrences: dict[str, int] = {}
        for position, (key, _key_start, _key_end) in enumerate(key_tokens):
            if position >= len(value_tokens):
                break
            value, value_start, value_end = value_tokens[position]
            occurrence = occurrences.get(key, 0)
            occurrences[key] = occurrence + 1

            known_field = block_name == "main" and key in FIELD_NAMES
            field_name = FIELD_NAMES[key] if known_field else key if block_name == "main" else f"{block_name}.{key}"
            byte_start = bom_length + len(text[:value_start].encode(encoding))
            byte_end = bom_length + len(text[:value_end].encode(encoding))

            yield ValueCandidate(
                field=field_name,
                raw_key=key,
                value=value,
                raw_value=raw[byte_start:byte_end],
                byte_offset=byte_start,
                block=block_name,
                line_number=value_lineno,
                occurrence=occurrence,
                known_field=known_field,
                origin=origin,
            )


def _iter_blocks(text: str) -> Iterable[tuple[str, list[tuple[int, str, int]]]]:
    line_offsets: list[tuple[int, str, int]] = []
    position = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        offset = text.index(line, position)
        line_offsets.append((line_number, line, offset))
        position = offset + len(line)

    current: list[tuple[int, str, int]] = []
    for item in line_offsets:
        if item[1] == "":
            if current:
                yield _block_name(current), _block_body(current)
                current = []
        else:
            current.append(item)
    if current:
        yield _block_name(current), _block_body(current)


def _block_name(block_lines: Sequence[tuple[int, str, int]]) -> str:
    # The first payload block starts with a format version line, its block name is the next line.
    if len(block_lines) > 1 and block_lines[0][1].strip().isdigit():
        return block_lines[1][1]
    return block_lines[0][1]


def _block_body(block_lines: Sequence[tuple[int, str, int]]) -> list[tuple[int, str, int]]:
    # Drop the format version line and the block name line, keeping the key/value content only.
    if len(block_lines) > 1 and block_lines[0][1].strip().isdigit():
        return list(block_lines[2:])
    return list(block_lines[1:])


def _find_key_line(
    block_lines: Sequence[tuple[int, str, int]],
) -> tuple[int, tuple[int, str, int]] | None:
    for index, item in enumerate(block_lines):
        _lineno, line, offset = item
        tokens = _line_tokens(line, offset)
        if not tokens or not all(
            _IDENTIFIER_RE.fullmatch(token) and any(char.isalpha() for char in token) for token, *_ in tokens
        ):
            continue
        # The next content line is the value line. In header2 blocks a numeric metadata line can
        # precede the key line; such a line never follows the key line, so skip those.
        following = block_lines[index + 1]
        following_tokens = _line_tokens(following[1], following[2])
        if following_tokens and not all(token.strip().lstrip("-").isdigit() for token, *_ in following_tokens):
            return index, item
    return None


def _find_value_line(
    block_lines: Sequence[tuple[int, str, int]], key_index: int, expected_tokens: int
) -> tuple[int, str, int]:
    # Prefer a following line with the same number of tab-separated fields; otherwise the very next
    # line is the value line (single-field headers do not contain a tab).
    for item in block_lines[key_index + 1 :]:
        lineno, line, offset = item
        if len(_line_tokens(line, offset)) == expected_tokens:
            return item
    return block_lines[key_index + 1]


def _line_tokens(line: str, line_offset: int) -> list[tuple[str, int, int]]:
    tokens: list[tuple[str, int, int]] = []
    start = 0
    for index, char in enumerate(line):
        if char == "\t":
            tokens.append((line[start:index], line_offset + start, line_offset + index))
            start = index + 1
    tokens.append((line[start:], line_offset + start, line_offset + len(line)))
    return tokens


def _build_field_report(field_name: str, candidates: Sequence[ValueCandidate]) -> FieldReport:
    non_empty = [candidate for candidate in candidates if candidate.value.strip()]

    distinct: list[str] = []
    seen: set[str] = set()
    for candidate in non_empty:
        normalized = candidate.value.strip()
        if normalized not in seen:
            seen.add(normalized)
            distinct.append(candidate.value)

    if not non_empty:
        return FieldReport(
            field=field_name,
            candidates=tuple(candidates),
            distinct_values=(),
            selected=None,
            selection_reason=_SELECTION_NO_VALUE,
            conflicting=False,
        )

    if len(distinct) == 1:
        return FieldReport(
            field=field_name,
            candidates=tuple(candidates),
            distinct_values=tuple(distinct),
            selected=non_empty[0],
            selection_reason=_SELECTION_UNANIMOUS,
            conflicting=False,
        )

    # One vote per healthy header per distinct value, so a duplicated key cannot skew the count.
    votes: dict[str, set[tuple[int, int]]] = {}
    for candidate in non_empty:
        votes.setdefault(candidate.value.strip(), set()).add(
            (candidate.origin.segment_index, candidate.origin.section_index)
        )

    max_votes = max(len(headers) for headers in votes.values())
    leading = [value for value, headers in votes.items() if len(headers) == max_votes]
    tied = len(leading) > 1

    def first_candidate(value: str) -> ValueCandidate:
        return next(candidate for candidate in non_empty if candidate.value.strip() == value)

    selected = min(
        (first_candidate(value) for value in leading),
        key=lambda candidate: (
            0 if candidate.origin.section_type == "header2" else 1,
            candidate.origin.segment_index,
            candidate.origin.descriptor_offset,
        ),
    )

    return FieldReport(
        field=field_name,
        candidates=tuple(candidates),
        distinct_values=tuple(distinct),
        selected=selected,
        selection_reason=_SELECTION_PREFERRED_HEADER if tied else _SELECTION_MAJORITY,
        conflicting=True,
    )


def _parse_hash_section(segment_index: int, section_index: int, section: Section) -> ClaimedHash:
    hash_section = c_ewf.HashSection(section.descriptor.data)
    return ClaimedHash(
        algorithm="md5",
        digest=hash_section.md5.hex(),
        origin=HeaderOrigin(
            segment_index=segment_index,
            section_index=section_index,
            section_type="hash",
            descriptor_offset=section.descriptor.offset,
            encoding="binary",
            encoding_fallback=False,
            format_version=None,
            payload_size=len(section.descriptor.data),
        ),
    )
