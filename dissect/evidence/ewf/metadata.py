"""Acquisition metadata declared by EWF ``header`` and ``header2`` sections.

An EWF image can contain several header sections, in several segments, that disagree about the
case, the examiner or the acquisition time. This module therefore keeps every declaration and
records where it came from: the segment, the section type and offset, the encoding, and the exact
byte range of the value inside the decompressed header payload.

Two kinds of output are available:

* :meth:`EWFMetadata.summary` shows one selected declaration per field for a concise display.
* :meth:`EWFMetadata.details` and :meth:`EWFMetadata.conflicts` keep every candidate and the
  reason it was not selected.

The selection strategy is deterministic and is applied only to structurally sound headers whose
section descriptor checksum is valid:

1. A non-empty declaration beats an empty one.
2. The earliest segment wins, so the primary acquisition declaration in the first segment is
   preferred over repetitions in later segments.
3. Within a segment, ``header2`` wins over ``header``.
4. The earliest section and the earliest column win any remaining tie.

A header that fails the descriptor checksum, zlib decompression or text decoding is marked
unusable, and its declarations are retained as evidence but can never be selected. This means a
damaged header cannot hide or override an intact one.

Values are reported verbatim. Anything the parser derived from them, such as a parsed timestamp
or the image geometry, is nested in a separate structure and marked ``parser_inferred``. Digests
found in the image are declarations, not verifications: :class:`DeclaredDigest` always reports
``verified == False``.
"""

from __future__ import annotations

import codecs
import re
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.evidence.ewf import c_ewf
from dissect.evidence.ewf.ewf import HeaderSection, SectionDescriptor

if TYPE_CHECKING:
    from dissect.evidence.ewf.ewf import EWF, Segment

__all__ = [
    "DeclaredDigest",
    "EWFMetadata",
    "FieldCandidate",
    "FieldResolution",
    "HeaderField",
    "HeaderRecord",
    "HeaderSource",
    "ImageInfo",
    "ParsedTime",
    "parse_time",
]

FIELD_NAMES = {
    "a": "description",
    "c": "case_number",
    "n": "evidence_number",
    "e": "examiner_name",
    "t": "notes",
    "av": "acquisition_software_version",
    "ov": "operating_system",
    "m": "acquisition_time",
    "u": "system_time",
    "p": "password",
    "md": "model",
    "sn": "serial_number",
    "dc": "compression",
}

# Long key names that have been seen in other EWF writers.
FIELD_ALIASES = {
    "acquiry_date": "acquisition_time",
    "acquiry_software_version": "acquisition_software_version",
    "system_date": "system_time",
    "compression_level": "compression",
}

FIELD_ORDER = (
    "case_number",
    "evidence_number",
    "description",
    "examiner_name",
    "notes",
    "acquisition_time",
    "system_time",
    "acquisition_software_version",
    "operating_system",
    "model",
    "serial_number",
    "compression",
    "password",
)

TIME_FIELDS = frozenset({"acquisition_time", "system_time"})

# The selection strategy is deliberately conservative and deterministic:
# - only structurally sound headers with a valid section descriptor checksum may be displayed
# - a non-empty declaration beats an empty one
# - the earliest segment wins, so the primary acquisition declaration is preferred over
#   repetitions in later segments
# - within a segment, header2 (the newer, richer schema) beats header
# - the earliest section and earliest column win any remaining tie
HEADER_KIND_PRIORITY = {"header2": 2, "header": 1}

KNOWN_SECTION_TYPES = frozenset(
    {
        "header",
        "header2",
        "volume",
        "disk",
        "data",
        "sectors",
        "table",
        "table2",
        "hash",
        "done",
        "next",
        "error2",
        "errors",
        "digest",
    }
)

SELECTION_STRATEGY = (
    (
        "Only headers whose section descriptor checksum is valid, whose zlib payload decompresses, "
        "whose text decodes and whose main key/value block is well formed may supply a displayed value."
    ),
    "Within that set, a non-empty declaration beats an empty one.",
    "Within a segment, header2 wins over header.",
    "The earliest segment wins.",
    "The earliest section and the earliest column win any remaining tie.",
    "All declarations, including those in damaged headers, are retained as candidates.",
    "Digests found in the image are declarations only and are never reported as verified.",
)

_PARSER_INFERENCE = True


@dataclass(frozen=True, slots=True)
class HeaderSource:
    """Location and integrity state of a single header section."""

    segment_index: int
    segment_number: int
    segment_path: str | None
    kind: str
    section_offset: int
    section_size: int
    data_offset: int
    data_size: int
    descriptor_checksum_valid: bool
    encoding: str | None
    encoding_inferred: bool
    payload_size: int | None
    status: str
    problems: tuple[str, ...]

    @property
    def usable(self) -> bool:
        """Whether this header may contribute values to the default display."""
        return self.status == "ok"

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation."""
        return {
            "segment_index": self.segment_index,
            "segment_number": self.segment_number,
            "segment_path": self.segment_path,
            "kind": self.kind,
            "section_offset": self.section_offset,
            "section_size": self.section_size,
            "data_offset": self.data_offset,
            "data_size": self.data_size,
            "descriptor_checksum_valid": self.descriptor_checksum_valid,
            "encoding": self.encoding,
            "encoding_inferred": self.encoding_inferred,
            "payload_size": self.payload_size,
            "status": self.status,
            "usable": self.usable,
            "problems": list(self.problems),
        }


@dataclass(frozen=True, slots=True)
class HeaderField:
    """A single tab separated value from a header section."""

    key: str
    name: str | None
    value: str | None
    line_index: int
    field_index: int
    payload_offset: int | None
    payload_size: int | None
    raw_value: bytes | None
    source: HeaderSource
    missing: bool = False

    @property
    def is_empty(self) -> bool:
        """Whether the declared value is absent or whitespace only."""
        return self.value is None or not self.value.strip()

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation preserving the raw bytes."""
        return {
            "name": self.name,
            "key": self.key,
            "value": self.value,
            "verbatim": True,
            "empty": self.is_empty,
            "missing_value_cell": self.missing,
            "line_index": self.line_index,
            "field_index": self.field_index,
            "payload_offset": self.payload_offset,
            "payload_size": self.payload_size,
            "raw_value": self.raw_value.hex() if self.raw_value is not None else None,
            "source": self.source.as_dict(),
        }


@dataclass(slots=True)
class HeaderRecord:
    """A parsed header or header2 section."""

    source: HeaderSource
    version: str | None
    text: str | None
    payload: bytes | None = field(repr=False, default=None)
    fields: list[HeaderField] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        """The section type."""
        return self.source.kind

    @property
    def usable(self) -> bool:
        """Whether this header may contribute values to the default display."""
        return self.source.usable

    def fields_for(self, name: str) -> list[HeaderField]:
        """Return all declarations of a canonical field name in this header."""
        return [item for item in self.fields if item.name == name]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation."""
        return {
            "source": self.source.as_dict(),
            "version": self.version,
            "text": self.text,
            "fields": [item.as_dict() for item in self.fields],
            "issues": list(self.issues),
        }


@dataclass(frozen=True, slots=True)
class ParsedTime:
    """A parser interpretation of a verbatim time declaration."""

    raw: str
    datetime: datetime | None
    timezone_known: bool
    interpretation: str
    inferred: bool = _PARSER_INFERENCE

    @property
    def timezone(self) -> str | None:
        """The timezone of the interpreted value, if it is known."""
        if self.datetime is not None and self.datetime.tzinfo is not None:
            return self.datetime.tzname()
        return None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation."""
        return {
            "raw": self.raw,
            "value": self.datetime.isoformat() if self.datetime is not None else None,
            "timezone": self.timezone,
            "timezone_known": self.timezone_known,
            "interpretation": self.interpretation,
            "parser_inferred": self.inferred,
        }


@dataclass(frozen=True, slots=True)
class FieldCandidate:
    """A single declaration that could be displayed for a field."""

    field: HeaderField
    selected: bool
    rejected_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation."""
        result = self.field.as_dict()
        result["selected"] = self.selected
        result["rejected_reason"] = self.rejected_reason
        return result


@dataclass(slots=True)
class FieldResolution:
    """The selection result for one canonical metadata field."""

    name: str
    selected: FieldCandidate | None
    candidates: list[FieldCandidate]
    status: str
    notes: list[str]
    parsed: ParsedTime | None = None

    @property
    def value(self) -> str | None:
        """The verbatim selected value, exactly as declared in the header."""
        return self.selected.field.value if self.selected else None

    @property
    def source(self) -> HeaderSource | None:
        """The source of the selected value."""
        return self.selected.field.source if self.selected else None

    @property
    def conflict(self) -> bool:
        """Whether more than one distinct usable declaration exists."""
        return self.status == "conflict"

    def as_dict(self, *, include_candidates: bool = True) -> dict[str, Any]:
        """Return a JSON friendly representation.

        The ``value`` key is always the verbatim header text. Any interpretation, such as a
        parsed timestamp, is nested under ``parsed`` and explicitly marked as parser inferred.
        """
        result: dict[str, Any] = {
            "name": self.name,
            "value": self.value,
            "value_origin": "header declaration" if self.selected else None,
            "verbatim": True,
            "status": self.status,
            "candidate_count": len(self.candidates),
            "conflict": self.conflict,
            "selected_from": self.source.as_dict() if self.source else None,
            "parsed": self.parsed.as_dict() if self.parsed else None,
            "notes": list(self.notes),
        }
        if include_candidates:
            result["candidates"] = [candidate.as_dict() for candidate in self.candidates]
        return result


@dataclass(frozen=True, slots=True)
class DeclaredDigest:
    """A digest declared by the image, not a verification of the image contents."""

    algorithm: str
    value: str
    segment_index: int
    segment_number: int
    segment_path: str | None
    section_offset: int
    section_size: int
    payload_offset: int
    payload_size: int
    raw_value: bytes
    section_checksum_valid: bool | None

    @property
    def verification_status(self) -> str:
        """The verification state of this declaration."""
        return "not_verified"

    @property
    def verified(self) -> bool:
        """Always ``False``: a declaration is not a verification of image contents."""
        return False

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation.

        ``verified`` is always ``False``: the digest is what the image says about itself. The
        parser never labels a declaration as a successful verification of the image contents.
        """
        return {
            "algorithm": self.algorithm,
            "value": self.value,
            "verified": self.verified,
            "verification_status": self.verification_status,
            "section_checksum_valid": self.section_checksum_valid,
            "source": {
                "segment_index": self.segment_index,
                "segment_number": self.segment_number,
                "segment_path": self.segment_path,
                "section_offset": self.section_offset,
                "section_size": self.section_size,
                "payload_offset": self.payload_offset,
                "payload_size": self.payload_size,
                "raw_value": self.raw_value.hex(),
                "verbatim": True,
            },
        }


@dataclass(frozen=True, slots=True)
class ImageInfo:
    """Container facts derived by the parser from binary sections."""

    size: int
    chunk_size: int
    segment_count: int
    volume: dict[str, Any] | None
    parser_inferred: bool = _PARSER_INFERENCE

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly representation."""
        return {
            "size": self.size,
            "chunk_size": self.chunk_size,
            "segment_count": self.segment_count,
            "volume": self.volume,
            "parser_inferred": self.parser_inferred,
        }


class EWFMetadata:
    """Collect acquisition metadata from every header in an EWF container.

    The parser keeps every declaration, including duplicates, empty values and declarations in
    damaged headers. :meth:`summary` applies the documented selection strategy for a concise
    display, while :meth:`details` and :meth:`conflicts` retain the full evidence trail.

    Args:
        ewf: The EWF container to read metadata from.
    """

    def __init__(self, ewf: EWF):
        if ewf.is_locked():
            raise ValueError("EWF container is locked by ADCRYPT")

        self.ewf = ewf
        self.errors: list[str] = []
        self.headers = self._read_headers()
        self.digests = self._read_digests()
        self.image = ImageInfo(
            size=ewf.size,
            chunk_size=ewf.chunk_size,
            segment_count=len(ewf.fh),
            volume=self._volume_info(),
        )
        self.fields = {name: self._resolve(name) for name in FIELD_ORDER}

    def __getitem__(self, name: str) -> FieldResolution:
        return self.fields[name]

    def header_statuses(self) -> list[dict[str, Any]]:
        """Return the location and integrity state of every header section."""
        return [header.source.as_dict() for header in self.headers]

    def conflicts(self) -> list[FieldResolution]:
        """Return all fields with more than one distinct usable declaration."""
        return [resolution for resolution in self.fields.values() if resolution.conflict]

    def summary(self) -> dict[str, Any]:
        """Return a concise display of the selected declarations and their status."""
        return {
            "fields": {name: resolution.as_dict(include_candidates=False) for name, resolution in self.fields.items()},
            "headers": self.header_statuses(),
            "hashes": [digest.as_dict() for digest in self.digests],
            "image": self.image.as_dict(),
            "selection_strategy": list(SELECTION_STRATEGY),
            "errors": list(self.errors),
        }

    def details(self) -> dict[str, Any]:
        """Return the full evidence trail, including every candidate declaration."""
        return {
            "fields": {name: resolution.as_dict(include_candidates=True) for name, resolution in self.fields.items()},
            "headers": [header.as_dict() for header in self.headers],
            "hashes": [digest.as_dict() for digest in self.digests],
            "image": self.image.as_dict(),
            "selection_strategy": list(SELECTION_STRATEGY),
            "errors": list(self.errors),
        }

    def brief(self) -> dict[str, str | None]:
        """Return a minimal display mapping for a receiving UI.

        Only verbatim selected values are returned. Use :meth:`details` to show provenance and
        conflicting candidates alongside this display.
        """
        return {
            "case_number": self.fields["case_number"].value,
            "evidence_number": self.fields["evidence_number"].value,
            "description": self.fields["description"].value,
            "examiner_name": self.fields["examiner_name"].value,
            "acquisition_time": self.fields["acquisition_time"].value,
        }

    def _read_headers(self) -> list[HeaderRecord]:
        headers: list[HeaderRecord] = []
        for segment_index in range(len(self.ewf.fh)):
            try:
                segment = self.ewf.segment(segment_index)
            except Exception as e:
                self.errors.append(f"Unable to open segment {segment_index}: {e}")
                continue

            for descriptor in self._iter_sections(segment, segment_index):
                kind = _section_kind(descriptor)
                if kind in ("header", "header2"):
                    headers.append(self._read_header(segment, segment_index, HeaderSection(descriptor)))

        return headers

    def _iter_sections(self, segment: Segment, segment_index: int) -> list[SectionDescriptor]:
        """Walk the section chain without letting one damaged descriptor hide later sections."""
        try:
            segment.fh.seek(0, 2)
            file_size = segment.fh.tell()
        except Exception as e:
            self.errors.append(f"Unable to determine size of segment {segment_index}: {e}")
            return []

        sections: list[SectionDescriptor] = []
        offset = len(c_ewf.SegmentHeader)
        seen: set[int] = set()

        while offset not in seen and 0 <= offset < file_size:
            seen.add(offset)

            try:
                segment.fh.seek(offset)
                descriptor = SectionDescriptor(segment.fh)
            except Exception as e:
                self.errors.append(f"Unable to read section descriptor in segment {segment_index} at {offset:#x}: {e}")
                break

            sections.append(descriptor)

            kind = _section_kind(descriptor)
            next_offset = descriptor.next
            if next_offset == offset or kind == "done":
                break

            if not 0 < next_offset < file_size or next_offset <= offset:
                recovered = self._recover_next(segment, descriptor, file_size)
                if recovered is None:
                    self.errors.append(
                        f"Broken section link in segment {segment_index} at {offset:#x}; "
                        "later sections could not be recovered"
                    )
                    break

                self.errors.append(
                    f"Broken section link in segment {segment_index} at {offset:#x}; "
                    f"recovered section at {recovered:#x}"
                )
                next_offset = recovered

            offset = next_offset

        return sections

    def _recover_next(self, segment: Segment, descriptor: SectionDescriptor, file_size: int) -> int | None:
        """Find the next section after a broken link using the section's own size fields."""
        candidates = {
            descriptor.offset + descriptor.raw_size,
            descriptor.offset + len(c_ewf.SectionDescriptor) + descriptor.size,
        }

        for candidate in sorted(candidate for candidate in candidates if 0 < candidate < file_size):
            try:
                segment.fh.seek(candidate)
                recovered = SectionDescriptor(segment.fh)
            except Exception:
                continue

            if _section_kind(recovered) not in KNOWN_SECTION_TYPES:
                continue

            if self._descriptor_checksum_valid(segment, candidate):
                return candidate

        return None

    def _read_header(self, segment: Segment, segment_index: int, section: HeaderSection) -> HeaderRecord:
        descriptor = section.descriptor
        problems: list[str] = []

        checksum_valid = self._descriptor_checksum_valid(segment, descriptor.offset)
        if not checksum_valid:
            problems.append("section descriptor checksum mismatch")

        try:
            raw_payload, payload_problem = self._section_payload(segment, descriptor)
            if payload_problem:
                problems.append(payload_problem)
        except Exception as e:
            raw_payload = b""
            problems.append(f"unable to read section payload: {e}")

        payload: bytes | None = None
        text: str | None = None
        encoding: str | None = None
        encoding_inferred = False
        version: str | None = None
        fields: list[HeaderField] = []
        issues: list[str] = []

        if raw_payload:
            try:
                payload = zlib.decompress(raw_payload)
            except zlib.error as e:
                problems.append(f"zlib decompression failed: {e}")

        if payload is not None:
            try:
                text, encoding, encoding_inferred = _decode_header(payload)
            except UnicodeDecodeError as e:
                problems.append(f"text decoding failed: {e}")

        if text is not None:
            version, fields, issues = _parse_header_text(text, payload, encoding)
            if not fields:
                problems.append("no main metadata block with key and value rows")

        data_size = len(raw_payload)
        status = "ok" if not problems else "corrupt" if payload is None or text is None else "invalid"

        source = HeaderSource(
            segment_index=segment_index,
            segment_number=segment.number,
            segment_path=_segment_path(self.ewf, segment_index),
            kind=_section_kind(descriptor),
            section_offset=descriptor.offset,
            section_size=descriptor.raw_size,
            data_offset=descriptor.offset + len(c_ewf.SectionDescriptor),
            data_size=data_size,
            descriptor_checksum_valid=checksum_valid,
            encoding=encoding,
            encoding_inferred=encoding_inferred,
            payload_size=len(payload) if payload is not None else None,
            status=status,
            problems=tuple(problems),
        )

        # Rebind fields to the final source object so provenance is complete.
        fields = [
            HeaderField(
                key=item.key,
                name=item.name,
                value=item.value,
                line_index=item.line_index,
                field_index=item.field_index,
                payload_offset=item.payload_offset,
                payload_size=item.payload_size,
                raw_value=item.raw_value,
                source=source,
                missing=item.missing,
            )
            for item in fields
        ]

        return HeaderRecord(
            source=source,
            version=version,
            text=text,
            payload=payload,
            fields=fields,
            issues=issues,
        )

    def _descriptor_checksum_valid(self, segment: Segment, offset: int) -> bool:
        segment.fh.seek(offset)
        raw = segment.fh.read(len(c_ewf.SectionDescriptor))
        if len(raw) != len(c_ewf.SectionDescriptor):
            return False

        stored = int.from_bytes(raw[-4:], "little")
        calculated = zlib.adler32(raw[:-4]) & 0xFFFFFFFF
        return stored == calculated

    def _section_payload(self, segment: Segment, descriptor: SectionDescriptor) -> tuple[bytes, str | None]:
        """Read the section body, bounded by the actual file size.

        A damaged descriptor may declare a size or next offset that runs past the end of the
        segment. Reading only what is physically present keeps one bad header from aborting the
        metadata scan or hiding later, intact headers.

        Returns the bytes that are physically present and a problem description if the declared
        size had to be adjusted or the payload is truncated.
        """
        segment.fh.seek(0, 2)
        file_size = segment.fh.tell()

        data_offset = descriptor.offset + len(c_ewf.SectionDescriptor)
        available = max(0, file_size - data_offset)
        size = descriptor.size
        problem = None
        if size <= 0:
            size = available
        elif size > available:
            size = available
            problem = f"section payload truncated: declared {descriptor.size} bytes, only {available} available"

        segment.fh.seek(data_offset)
        return segment.fh.read(size), problem

    def _resolve(self, name: str) -> FieldResolution:
        candidates: list[FieldCandidate] = []
        usable: list[FieldCandidate] = []

        for header in self.headers:
            for item in header.fields_for(name):
                candidate = FieldCandidate(field=item, selected=False)
                candidates.append(candidate)
                if item.source.usable and not item.is_empty:
                    usable.append(candidate)

        if not candidates:
            return FieldResolution(
                name=name,
                selected=None,
                candidates=[],
                status="missing",
                notes=["field is not present in any header section"],
            )

        usable.sort(key=_candidate_sort_key)
        selected = usable[0] if usable else None
        selected_value = _normalized(selected.field.value) if selected else None

        distinct = {_normalized(candidate.field.value) for candidate in usable if candidate.field.value is not None}
        status = "conflict" if selected is not None and len(distinct) > 1 else "consistent" if selected else "missing"

        notes: list[str] = []
        if selected is not None:
            notes.append(
                "selected by strategy: usable header only, earliest segment, header2 before header, earliest section"
            )
            if status == "conflict":
                notes.append(f"{len(distinct)} distinct declarations retained; see candidates and conflicts()")
        elif all(not candidate.field.source.usable for candidate in candidates):
            notes.append("all declarations are in headers that failed integrity or structure checks")
        else:
            notes.append("all declarations are empty; no value is presented as selected")

        resolved: list[FieldCandidate] = []
        for candidate in candidates:
            if candidate is selected:
                resolved.append(FieldCandidate(field=candidate.field, selected=True))
                continue

            resolved.append(
                FieldCandidate(
                    field=candidate.field,
                    selected=False,
                    rejected_reason=_rejection_reason(candidate.field, selected_value),
                )
            )

        parsed = None
        if selected is not None and name in TIME_FIELDS and selected.field.value is not None:
            parsed = parse_time(selected.field.value)

        return FieldResolution(
            name=name,
            selected=next((item for item in resolved if item.selected), None),
            candidates=resolved,
            status=status,
            notes=notes,
            parsed=parsed,
        )

    def _read_digests(self) -> list[DeclaredDigest]:
        digests: list[DeclaredDigest] = []
        for segment_index in range(len(self.ewf.fh)):
            try:
                segment = self.ewf.segment(segment_index)
            except Exception as e:
                self.errors.append(f"Unable to open segment {segment_index}: {e}")
                continue

            for descriptor in self._iter_sections(segment, segment_index):
                if _section_kind(descriptor) != "hash":
                    continue

                try:
                    payload, problem = self._section_payload(segment, descriptor)
                except ValueError as e:
                    self.errors.append(
                        f"Unable to read hash section at segment {segment_index} offset {descriptor.offset:#x}: {e}"
                    )
                    continue

                md5 = payload[:16]
                if len(md5) != 16:
                    self.errors.append(
                        f"Unable to read hash section at segment {segment_index} "
                        f"offset {descriptor.offset:#x}: hash section is too short"
                    )
                    continue

                if problem:
                    self.errors.append(f"Hash section at segment {segment_index}: {problem}")

                stored = int.from_bytes(payload[32:36], "little") if len(payload) >= 36 else None
                calculated = zlib.adler32(payload[:32]) & 0xFFFFFFFF if len(payload) >= 32 else None
                checksum_valid = stored is not None and calculated is not None and stored == calculated

                digests.append(
                    DeclaredDigest(
                        algorithm="md5",
                        value=md5.hex(),
                        segment_index=segment_index,
                        segment_number=segment.number,
                        segment_path=_segment_path(self.ewf, segment_index),
                        section_offset=descriptor.offset,
                        section_size=descriptor.raw_size,
                        payload_offset=descriptor.offset + len(c_ewf.SectionDescriptor),
                        payload_size=min(16, len(payload)),
                        raw_value=md5,
                        section_checksum_valid=checksum_valid,
                    )
                )

        return digests

    def _volume_info(self) -> dict[str, Any] | None:
        volume = self.ewf.volume
        if volume is None:
            return None

        data = volume.data
        return {
            "number_of_chunks": data.number_of_chunks,
            "sectors_per_chunk": data.sectors_per_chunk,
            "bytes_per_sector": data.bytes_per_sector,
            "number_of_sectors": data.number_of_sectors,
            "parser_inferred": True,
        }


_PLACEHOLDER_SOURCE = HeaderSource(
    segment_index=0,
    segment_number=0,
    segment_path=None,
    kind="",
    section_offset=0,
    section_size=0,
    data_offset=0,
    data_size=0,
    descriptor_checksum_valid=False,
    encoding=None,
    encoding_inferred=False,
    payload_size=None,
    status="invalid",
    problems=(),
)


def _section_kind(descriptor: SectionDescriptor) -> str:
    """Return the section type without failing on binary garbage in the type field."""
    try:
        return descriptor.type
    except UnicodeDecodeError:
        return descriptor.descriptor.type.rstrip(b"\x00").decode("latin-1")


def _segment_path(ewf: EWF, segment_index: int) -> str | None:
    fh = ewf.fh[segment_index]
    if isinstance(fh, Path):
        return str(fh)

    name = getattr(fh, "name", None)
    return str(name) if name is not None and not isinstance(name, int) else None


def _normalized(value: str | None) -> str | None:
    return value.strip() if value is not None else None


def _rejection_reason(field: HeaderField, selected_value: str | None) -> str:
    if not field.source.usable:
        return "source header failed integrity or structure checks"
    if field.is_empty:
        if selected_value is None:
            return "empty declaration; no usable non-empty declaration exists"
        return "empty declaration; a non-empty declaration exists"
    if _normalized(field.value) == selected_value:
        return "duplicate of the selected declaration"
    return "conflicting declaration retained as evidence"


def _candidate_sort_key(candidate: FieldCandidate) -> tuple[int, int, int, int]:
    source = candidate.field.source
    return (
        source.segment_index,
        -HEADER_KIND_PRIORITY.get(source.kind, 0),
        source.section_offset,
        candidate.field.field_index,
    )


def _decode_header(payload: bytes) -> tuple[str, str, bool]:
    """Decode a decompressed header payload and return text, encoding and inferred flag."""
    if payload.startswith(codecs.BOM_UTF16_LE):
        return payload.decode("utf-16"), "utf-16-le", False

    if payload.startswith(codecs.BOM_UTF16_BE):
        return payload.decode("utf-16"), "utf-16-be", False

    if payload.startswith(codecs.BOM_UTF8):
        return payload.decode("utf-8-sig"), "utf-8", False

    # Some writers emit UTF-16 without a byte order mark. The header text is ASCII-oriented,
    # so a NUL byte in every other position is a reliable signal for the byte order.
    utf16 = _decode_unmarked_utf16(payload)
    if utf16 is not None:
        return utf16

    try:
        return payload.decode("utf-8"), "utf-8", False
    except UnicodeDecodeError:
        pass

    try:
        return payload.decode("cp1252"), "cp1252", True
    except UnicodeDecodeError:
        return payload.decode("latin-1"), "latin-1", True


def _decode_unmarked_utf16(payload: bytes) -> tuple[str, str, bool] | None:
    if len(payload) < 4 or len(payload) % 2:
        return None

    even_nuls = payload[0::2].count(0)
    odd_nuls = payload[1::2].count(0)
    pairs = len(payload) // 2

    if odd_nuls >= pairs * 0.8 and even_nuls == 0:
        encoding = "utf-16-le"
    elif even_nuls >= pairs * 0.8 and odd_nuls == 0:
        encoding = "utf-16-be"
    else:
        return None

    try:
        return payload.decode(encoding), encoding, True
    except UnicodeDecodeError:
        return None


def _split_lines(text: str) -> list[tuple[str, int]]:
    lines: list[tuple[str, int]] = []
    start = 0
    for match in re.finditer(r"\r\n|\r|\n", text):
        lines.append((text[start : match.start()], start))
        start = match.end()
    lines.append((text[start:], start))
    return lines


def _split_cells(line: str, start: int) -> list[tuple[str, int, int]]:
    cells: list[tuple[str, int, int]] = []
    offset = 0
    for value in line.split("\t"):
        cells.append((value, start + offset, start + offset + len(value)))
        offset += len(value) + 1
    return cells


def _parse_header_text(text: str, payload: bytes, encoding: str) -> tuple[str | None, list[HeaderField], list[str]]:
    lines = _split_lines(text)
    version = lines[0][0].strip() if lines else None
    issues: list[str] = []

    main_index = next((index for index, (line, _) in enumerate(lines) if line.strip() == "main"), None)
    if main_index is None:
        return version, [], ["missing main section"]

    if main_index + 1 >= len(lines):
        return version, [], ["missing key row after main section"]

    key_line, key_start = lines[main_index + 1]
    keys = _split_cells(key_line, key_start)
    if not any(key.strip() for key, _, _ in keys):
        return version, [], ["key row is empty"]

    if main_index + 2 >= len(lines):
        return version, [], ["missing value row after key row"]

    value_line, value_start = lines[main_index + 2]
    values = _split_cells(value_line, value_start)

    if len(values) > len(keys):
        issues.append(f"value row has {len(values)} cells but key row has {len(keys)}")

    fields: list[HeaderField] = []
    seen: dict[str, int] = {}
    for index, (key_cell, _, _) in enumerate(keys):
        key = key_cell.strip()
        if not key:
            issues.append(f"empty key at column {index}")
            continue

        name = FIELD_NAMES.get(key, FIELD_ALIASES.get(key, key))
        seen[name] = seen.get(name, 0) + 1
        if seen[name] > 1:
            issues.append(f"duplicate key {key!r} at column {index}")

        if index < len(values):
            raw_value, value_start_char, value_end_char = values[index]
            value: str | None = raw_value
            payload_offset, payload_size = _raw_value_span(payload, encoding, text, value_start_char, value_end_char)
            raw_value_bytes = text[value_start_char:value_end_char].encode(encoding)
            missing = False
        else:
            value = None
            payload_offset = None
            payload_size = None
            raw_value_bytes = None
            missing = True
            issues.append(f"missing value for key {key!r} at column {index}")

        fields.append(
            HeaderField(
                key=key,
                name=name,
                value=value,
                line_index=main_index + 2,
                field_index=index,
                payload_offset=payload_offset,
                payload_size=payload_size,
                raw_value=raw_value_bytes,
                source=_PLACEHOLDER_SOURCE,
                missing=missing,
            )
        )

    return version, fields, issues


def _raw_value_span(payload: bytes, encoding: str, text: str, start: int, end: int) -> tuple[int | None, int | None]:
    try:
        prefix = text[:start].encode(encoding)
        value = text[start:end].encode(encoding)
    except UnicodeEncodeError:
        return None, None

    bom_size = 0
    if encoding in ("utf-16-le", "utf-16-be") and payload.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        bom_size = 2
    elif encoding == "utf-8" and payload.startswith(codecs.BOM_UTF8):
        bom_size = 3

    return bom_size + len(prefix), len(value)


def parse_time(value: str) -> ParsedTime:
    """Interpret a verbatim header time declaration without inventing a timezone.

    Args:
        value: The exact text from the header.
    """
    raw = value
    stripped = value.strip()

    if re.fullmatch(r"\d{9,11}", stripped):
        try:
            parsed = datetime.fromtimestamp(int(stripped), timezone.utc)
        except (OverflowError, OSError, ValueError):
            return ParsedTime(
                raw=raw,
                datetime=None,
                timezone_known=False,
                interpretation="integer is outside the representable Unix epoch range",
            )

        return ParsedTime(
            raw=raw,
            datetime=parsed,
            timezone_known=True,
            interpretation="integer interpreted as Unix epoch seconds in UTC",
        )

    try:
        parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    else:
        if parsed.tzinfo is not None:
            return ParsedTime(
                raw=raw,
                datetime=parsed,
                timezone_known=True,
                interpretation="ISO 8601 value with an explicit UTC offset",
            )

        return ParsedTime(
            raw=raw,
            datetime=parsed,
            timezone_known=False,
            interpretation="date/time parsed from text; no timezone designator is present",
        )

    for fmt, description in (
        ("%Y %m %d %H %M %S", "space separated EWF v1 date/time"),
        ("%Y-%m-%d %H:%M:%S", "dash separated date/time"),
        ("%m/%d/%Y %I:%M:%S %p", "localized acquisition tool date/time"),
    ):
        try:
            # The declaration carries no timezone, so the parsed value is deliberately naive
            parsed = datetime.strptime(stripped, fmt)  # noqa: DTZ007
        except ValueError:
            continue

        return ParsedTime(
            raw=raw,
            datetime=parsed,
            timezone_known=False,
            interpretation=f"{description}; no timezone designator is present",
        )
    return ParsedTime(
        raw=raw,
        datetime=None,
        timezone_known=False,
        interpretation="value is not a recognized time format; retained verbatim",
    )
