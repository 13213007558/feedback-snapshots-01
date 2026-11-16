"""Read-only recovery scanning for unreferenced CIM objects.

The regular :class:`~dissect.cim.cim.CIM` API only exposes records that are reachable through the current
``INDEX.BTR``. When a WMI persistence item is deleted, the index entries are removed but the underlying
``OBJECTS.DATA`` data pages may still contain the record in their physical table of contents (TOC). This module
provides a separate, read-only entry point that inspects those physical TOCs without changing normal namespace
enumeration.

Records are reported as one of three classifications:

``reachable``
    The TOC record is referenced by the current index. These records are included so callers can compare the raw
    bytes seen by the scanner with the regular API.

``unreferenced``
    The TOC record is structurally valid, is not referenced by the current index, and validates as a class
    definition or class instance. For instances, the class definition must be available and the instance name hash
    must match. This is a *candidate*, not proof that a specific object was deleted.

``fragment``
    The TOC record cannot be validated as a complete object. Reasons include missing class definitions, failed
    structure or hash checks, records that fall in free space, records whose continuation pages are missing, and
    data left behind on pages with an empty TOC. Fragments are evidence of residual data only.

Typical usage::

    result = cim.scan_unreferenced()
    for candidate in result.unreferenced:
        print(candidate.physical_page, candidate.record_id, candidate.length, candidate.class_name)
        raw = candidate.data  # raw bytes, not interpreted

Nothing in this module evaluates, executes or otherwise acts on consumer properties. Returned data is raw bytes
only, and :meth:`ScanResult.to_dict` omits record contents by default.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from dissect.cim.c_cim import DATA_PAGE_SIZE, MAPPING_PAGE_ID_MASK, UNMAPPED_PAGE_VALUE
from dissect.cim.exceptions import Error

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cim.cim import CIM

MAX_NAME_LENGTH = 512
MAX_PROPERTY_COUNT = 100_000
MAX_RECORD_SIZE = 32 * 1024 * 1024


class RecordClassification(str, Enum):
    """Classification of a scanned data page record."""

    REACHABLE = "reachable"
    UNREFERENCED = "unreferenced"
    FRAGMENT = "fragment"


class RecordKind(str, Enum):
    """Best-effort structural kind of a scanned record."""

    CLASS_DEFINITION = "class_definition"
    CLASS_INSTANCE = "class_instance"
    UNKNOWN = "unknown"


class FragmentReason(str, Enum):
    """Why a scanned record is an unverifiable fragment."""

    STRUCTURE_INVALID = "structure_invalid"
    HASH_MISMATCH = "hash_mismatch"
    CLASS_DEFINITION_MISSING = "class_definition_missing"
    RECORD_TRUNCATED = "record_truncated"
    RECORD_IN_FREE_SPACE = "record_in_free_space"
    PAGE_REUSED = "page_reused"
    CROSS_PAGE_RECORD = "cross_page_record"
    UNMAPPED_PAGE = "unmapped_page"


class SchemaSource(str, Enum):
    """Where the class definition used to validate a record came from."""

    RECORD = "record"
    INDEX = "index"
    RECOVERY = "recovery"
    NONE = "none"


class Reliability(str, Enum):
    """How strongly the classification is supported by the available evidence."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class RecordLocation:
    """Physical location of a record in ``OBJECTS.DATA``."""

    physical_page: int
    logical_page: int
    record_id: int
    offset: int
    length: int
    toc_crc: int = 0


@dataclass
class ScanRecord:
    """A single TOC record discovered while scanning data pages.

    Attributes:
        location: Physical page, logical page, record id, offset, length and TOC CRC.
        classification: ``reachable``, ``unreferenced`` or ``fragment``.
        kind: Best-effort structural kind of the record.
        data: Raw record bytes exactly as read from ``OBJECTS.DATA``. Never interpreted or executed.
        class_name: Class name if it could be determined, otherwise ``None``.
        class_hash: Name hash of the class if it could be determined, otherwise ``None``.
        schema_source: Source of the class definition used to validate the record.
        schema_physical_page: Physical page of the class definition record, if known.
        schema_record_id: TOC record id of the class definition record, if known.
        fragment_reason: Reason for a ``fragment`` classification, if applicable.
        reliability: How strongly the classification is supported.
        index_keys: Current index keys that reference this record.
        cross_page: Whether the TOC record extends beyond its first data page. Such records are reconstructed from
            the logical page chain and, if valid, are reported as ``unreferenced`` with ``medium`` reliability.
        page_reused: Whether the physical page is mapped to multiple logical pages in the available mappings.
        in_free_space: Whether the record overlaps the free space reported for the page.
    """

    location: RecordLocation
    classification: RecordClassification
    kind: RecordKind
    data: bytes
    class_name: str | None = None
    class_hash: str | None = None
    schema_source: SchemaSource = SchemaSource.NONE
    schema_physical_page: int | None = None
    schema_record_id: int | None = None
    fragment_reason: FragmentReason | None = None
    reliability: Reliability = Reliability.LOW
    index_keys: list[str] = field(default_factory=list)
    cross_page: bool = False
    page_reused: bool = False
    in_free_space: bool = False

    def __repr__(self) -> str:
        return (
            f"<ScanRecord {self.classification.value} {self.kind.value} "
            f"page={self.physical_page} id={self.record_id} length={self.length} "
            f"class={self.class_name!r} reason={self.fragment_reason.value if self.fragment_reason else None}>"
        )

    @property
    def physical_page(self) -> int:
        return self.location.physical_page

    @property
    def logical_page(self) -> int:
        return self.location.logical_page

    @property
    def record_id(self) -> int:
        return self.location.record_id

    @property
    def offset(self) -> int:
        return self.location.offset

    @property
    def length(self) -> int:
        return self.location.length

    @property
    def raw(self) -> bytes:
        """Alias for :attr:`data`: the raw record bytes."""
        return self.data

    @property
    def is_reachable(self) -> bool:
        return self.classification is RecordClassification.REACHABLE

    @property
    def is_unreferenced(self) -> bool:
        return self.classification is RecordClassification.UNREFERENCED

    @property
    def is_fragment(self) -> bool:
        return self.classification is RecordClassification.FRAGMENT

    @property
    def schema_available(self) -> bool:
        return self.schema_source in (SchemaSource.INDEX, SchemaSource.RECOVERY, SchemaSource.RECORD)

    def to_dict(self, include_data: bool = False) -> dict[str, object]:
        """Return a JSON-serializable dictionary.

        Record contents are omitted by default. Pass ``include_data=True`` to include the raw bytes as base64.
        """
        result: dict[str, object] = {
            "physical_page": self.physical_page,
            "logical_page": self.logical_page,
            "record_id": self.record_id,
            "offset": self.offset,
            "length": self.length,
            "toc_crc": self.location.toc_crc,
            "classification": self.classification.value,
            "kind": self.kind.value,
            "class_name": self.class_name,
            "class_hash": self.class_hash,
            "schema_source": self.schema_source.value,
            "schema_physical_page": self.schema_physical_page,
            "schema_record_id": self.schema_record_id,
            "reliability": self.reliability.value,
            "fragment_reason": self.fragment_reason.value if self.fragment_reason else None,
            "index_keys": list(self.index_keys),
            "cross_page": self.cross_page,
            "page_reused": self.page_reused,
            "in_free_space": self.in_free_space,
            "data_sha256": hashlib.sha256(self.data).hexdigest(),
        }
        if include_data:
            result["data"] = base64.b64encode(self.data).decode("ascii")
        return result


@dataclass(frozen=True)
class ResidualPage:
    """A data page whose TOC is empty but whose payload still contains non-zero bytes.

    There is no record id or TOC length to report for such a page, so the whole post-TOC payload is treated as
    unverifiable residual data. It must not be interpreted as a specific object.
    """

    physical_page: int
    logical_page: int
    offset: int
    length: int
    data_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "physical_page": self.physical_page,
            "logical_page": self.logical_page,
            "offset": self.offset,
            "length": self.length,
            "data_sha256": self.data_sha256,
        }


@dataclass
class ScanResult:
    """Result of :meth:`dissect.cim.cim.CIM.scan_unreferenced`."""

    records: list[ScanRecord] = field(default_factory=list)
    skipped_pages: dict[int, str] = field(default_factory=dict)
    residual_pages: list[ResidualPage] = field(default_factory=list)
    scanned_pages: int = 0
    scanned_records: int = 0
    reused_physical_pages: set[int] = field(default_factory=set)

    def __iter__(self) -> Iterator[ScanRecord]:
        return iter(self.records)

    @property
    def reachable(self) -> list[ScanRecord]:
        return [record for record in self.records if record.classification is RecordClassification.REACHABLE]

    @property
    def unreferenced(self) -> list[ScanRecord]:
        return [record for record in self.records if record.classification is RecordClassification.UNREFERENCED]

    @property
    def fragments(self) -> list[ScanRecord]:
        return [record for record in self.records if record.classification is RecordClassification.FRAGMENT]

    @property
    def candidates(self) -> list[ScanRecord]:
        """Alias for :attr:`unreferenced`, for callers that use candidate terminology."""
        return self.unreferenced

    def for_class(self, class_name: str) -> list[ScanRecord]:
        """Return records whose resolved class name matches ``class_name`` (case-insensitive)."""
        needle = class_name.lower()
        return [record for record in self.records if record.class_name and record.class_name.lower() == needle]

    def summary(self) -> dict[str, object]:
        """Return aggregate counts without record contents."""
        reasons: dict[str, int] = {}
        for record in self.fragments:
            if record.fragment_reason is not None:
                reasons[record.fragment_reason.value] = reasons.get(record.fragment_reason.value, 0) + 1

        return {
            "scanned_pages": self.scanned_pages,
            "scanned_records": self.scanned_records,
            "skipped_pages": len(self.skipped_pages),
            "reachable": len(self.reachable),
            "unreferenced": len(self.unreferenced),
            "fragment": len(self.fragments),
            "fragment_reasons": reasons,
            "residual_pages": len(self.residual_pages),
        }

    def to_dict(self, include_data: bool = False) -> dict[str, object]:
        """Return a JSON-serializable dictionary.

        Record contents are omitted by default. Pass ``include_data=True`` to include raw bytes as base64.
        """
        return {
            "summary": self.summary(),
            "skipped_pages": dict(self.skipped_pages),
            "reused_physical_pages": sorted(self.reused_physical_pages),
            "residual_pages": [page.to_dict() for page in self.residual_pages],
            "records": [record.to_dict(include_data=include_data) for record in self.records],
        }


@dataclass(frozen=True)
class _Page:
    logical_page: int
    physical_page: int
    free_space: int | None


@dataclass
class _RawRecord:
    page: _Page
    record_id: int
    offset: int
    size: int
    crc: int
    data: bytes
    cross_page: bool
    in_free_space: bool
    page_reused: bool
    index_keys: list[str]
    kind: RecordKind = RecordKind.UNKNOWN
    class_name: str | None = None
    class_hash: str | None = None
    hash_mismatch: bool = False
    schema_physical_page: int | None = None
    schema_record_id: int | None = None


def _u32(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(buf):
        raise ValueError("read out of bounds")
    return struct.unpack_from("<I", buf, offset)[0]


def _decode_data_region_string(data: bytes, offset: int) -> str:
    """Decode a string from a CIM data region with strict bounds checking."""
    if offset < 0 or offset >= len(data):
        raise ValueError("string offset out of bounds")

    flag = data[offset]
    if flag == 0:
        end = data.find(b"\x00", offset + 1)
        if end < 0:
            raise ValueError("unterminated string")
        value = data[offset + 1 : end].decode("latin1")
    elif flag == 1:
        end = offset + 1
        while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
            end += 2
        if end + 1 >= len(data):
            raise ValueError("unterminated wide string")
        value = data[offset + 1 : end].decode("utf-16-le")
    else:
        raise ValueError(f"invalid string encoding flag {flag}")

    if not value or len(value) > MAX_NAME_LENGTH:
        raise ValueError("invalid string length")

    return value


def _name_hash(name: str, xp: bool) -> str:
    payload = name.upper().encode("utf-16-le")
    return (hashlib.md5(payload) if xp else hashlib.sha256(payload)).hexdigest().upper()


def _parse_class_definition(data: bytes) -> str:
    """Parse a class definition record and return its class name."""
    size = len(data)
    if size < 32:
        raise ValueError("class definition too short")

    super_name_length = _u32(data, 0)
    if super_name_length > MAX_NAME_LENGTH:
        raise ValueError("invalid super class name length")

    offset = 4 + super_name_length * 2
    if offset + 25 > size:
        raise ValueError("class definition header truncated")

    data[4 : 4 + super_name_length * 2].decode("utf-16-le")

    class_name_offset = _u32(data, offset + 13)
    default_values_size = _u32(data, offset + 17)
    offset += 21

    class_name_record_size = _u32(data, offset)
    if class_name_record_size < 4 or class_name_record_size > size - offset:
        raise ValueError("invalid class name record size")
    offset += class_name_record_size

    qualifier_length = _u32(data, offset)
    if qualifier_length < 4 or offset + qualifier_length > size:
        raise ValueError("invalid qualifier list length")
    offset += qualifier_length

    if offset + 4 > size:
        raise ValueError("missing property count")

    property_count = _u32(data, offset) & 0x7FFFFFFF
    if property_count > MAX_PROPERTY_COUNT or offset + 4 + property_count * 8 > size:
        raise ValueError("invalid property count")
    offset += 4 + property_count * 8

    if default_values_size > size - offset:
        raise ValueError("invalid default values size")
    offset += default_values_size

    if offset + 4 > size:
        raise ValueError("missing property data size")

    property_data_size = _u32(data, offset) & 0x7FFFFFFF
    if offset + 4 + property_data_size > size:
        raise ValueError("invalid property data size")
    property_data = data[offset + 4 : offset + 4 + property_data_size]
    offset += 4 + property_data_size

    if offset + 4 > size:
        raise ValueError("missing method data size")
    method_data_size = _u32(data, offset) & 0x7FFFFFFF
    if offset + method_data_size != size:
        raise ValueError("class definition trailing data mismatch")

    return _decode_data_region_string(property_data, class_name_offset)


class _InstanceHashMismatch(ValueError):
    """The class instance structure is valid but its name hash does not match its class name."""


def _parse_class_instance(data: bytes, xp: bool) -> tuple[str, str]:
    """Parse a class instance record and return its class name and name hash."""
    header_size = (0x20 if xp else 0x40) * 2
    fixed_size = header_size + 25
    size = len(data)
    if size < fixed_size:
        raise ValueError("class instance too short")

    name_hash = data[:header_size].decode("utf-16-le")
    expected_hash_size = 32 if xp else 64
    if len(name_hash) != expected_hash_size or any(char not in "0123456789ABCDEF" for char in name_hash):
        raise ValueError("invalid class instance name hash")

    data_size = _u32(data, header_size + 16)
    class_name_offset = _u32(data, header_size + 20)
    if data_size < 9 or fixed_size + data_size - 9 != size:
        raise ValueError("class instance length mismatch")

    data_region = None
    for offset in range(size - 4, fixed_size - 1, -1):
        region_size = _u32(data, offset) & 0x7FFFFFFF
        if region_size and offset + 4 + region_size == size:
            data_region = (offset, region_size)
            break

    if data_region is None:
        raise ValueError("class instance data region not found")

    offset, region_size = data_region
    region = data[offset + 4 : offset + 4 + region_size]
    class_name = _decode_data_region_string(region, class_name_offset)

    if _name_hash(class_name, xp) != name_hash:
        raise _InstanceHashMismatch("class instance name hash mismatch")

    return class_name, name_hash


def _toc_entries(buf: bytes) -> tuple[list[tuple[int, int, int, int]], bool]:
    """Read a data page TOC and return its entries and whether a terminator was found."""
    entries = []
    offset = 0
    while offset + 16 <= len(buf):
        record_id, data_offset, size, crc = struct.unpack_from("<IIII", buf, offset)
        if record_id == 0 and data_offset == 0 and size == 0 and crc == 0:
            return entries, True
        entries.append((record_id, data_offset, size, crc))
        offset += 16

    return entries, False


def _toc_chain_is_valid(entries: list[tuple[int, int, int, int]]) -> bool:
    """Check the structural invariants of a data page TOC chain."""
    if not entries:
        return True

    expected_offset = (len(entries) + 1) * 16
    for record_id, offset, size, _ in entries:
        if not record_id or not size or size > MAX_RECORD_SIZE or offset != expected_offset:
            return False
        expected_offset += size

    return True


class RecoveryScanner:
    """Scan data page TOCs for records that are not referenced by the current index.

    The scanner is read-only and does not modify the CIM database or its indices.
    """

    def __init__(self, cim: CIM):
        self.cim = cim
        self.xp = cim.type_xp
        self.store = cim.objects.store
        self.mapping = self.store.map

        self.references = self._build_reference_map()
        self.current_physical_pages = self._current_physical_pages()
        self.reused_physical_pages = self._find_reused_physical_pages()

    def _iter_index_keys(self) -> Iterator[str]:
        """Walk the complete index tree and yield all key strings."""
        index_store = self.cim.index.store
        seen: set[int] = set()
        stack = [index_store.root_page]

        while stack:
            page = stack.pop()
            if page.logical_num in seen:
                continue
            seen.add(page.logical_num)

            yield from (str(key) for key in page.keys())

            for child in page.children():
                if child in (0xFFFFFFFF, 0):
                    continue
                try:
                    stack.append(index_store.page(child))
                except (Error, EOFError, IndexError):
                    continue

    def _build_reference_map(self) -> dict[tuple[int, int], list[str]]:
        references: dict[tuple[int, int], list[str]] = {}

        for key in self._iter_index_keys():
            try:
                parsed = self.cim.key(*key.split("/"))
            except (Error, ValueError):
                continue
            if not parsed.is_data_reference:
                continue

            try:
                location = (parsed.data_page, parsed.data_id)
            except ValueError:
                continue

            references.setdefault(location, []).append(key)

        return references

    def _current_physical_pages(self) -> dict[int, int]:
        physical_to_logical: dict[int, int] = {}

        for logical_page in range(self.mapping.mapping.mapping_entry_count):
            try:
                entry = self.mapping.get_entry(logical_page)
            except (Error, IndexError):
                continue
            if entry.is_mapped:
                physical_to_logical[entry.page_number] = logical_page

        return physical_to_logical

    def _find_reused_physical_pages(self) -> set[int]:
        """Find physical pages that map to multiple logical pages across the available mappings."""
        physical_to_logical: dict[int, set[int]] = defaultdict(set)
        physical_to_crc: dict[int, set[int]] = defaultdict(set)

        for fh in self.cim._fmappings:
            try:
                position = fh.tell()
            except (OSError, ValueError):
                position = None

            try:
                fh.seek(0)
                mapping = self.cim.map_type(fh)
            except (Error, OSError, ValueError, EOFError):
                continue
            finally:
                if position is not None:
                    try:
                        fh.seek(position)
                    except (OSError, ValueError):
                        pass

            if getattr(mapping, "signature", None) != 0xABCD:
                continue

            for logical_page, entry in enumerate(mapping.entries):
                if isinstance(entry, int):
                    physical_page = entry & MAPPING_PAGE_ID_MASK
                    page_crc = None
                else:
                    physical_page = entry.page_number & MAPPING_PAGE_ID_MASK
                    page_crc = entry.page_crc

                if physical_page == UNMAPPED_PAGE_VALUE:
                    continue

                physical_to_logical[physical_page].add(logical_page)
                if page_crc is not None:
                    physical_to_crc[physical_page].add(page_crc)

        reused = {page for page, logicals in physical_to_logical.items() if len(logicals) > 1}
        reused |= {page for page, crcs in physical_to_crc.items() if len(crcs) > 1}
        # A physical page mapped as a different logical page by the current mapping is also reused.
        for physical, logicals in physical_to_logical.items():
            current = self.current_physical_pages.get(physical)
            if current is not None and logicals - {current}:
                reused.add(physical)
        return reused

    def _pages(self) -> Iterator[_Page]:
        for logical_page in range(self.mapping.mapping.mapping_entry_count):
            try:
                entry = self.mapping.get_entry(logical_page)
            except (Error, IndexError):
                continue
            if not entry.is_mapped:
                continue

            yield _Page(logical_page, entry.page_number, entry.free_space)

    def _read_record(self, logical_page: int, record_id: int, offset: int, size: int, buf: bytes) -> tuple[bytes, bool]:
        """Read a record, reconstructing cross-page records through the logical page chain."""
        first_page_length = DATA_PAGE_SIZE - offset
        if size <= first_page_length:
            return buf[offset : offset + size], False

        if size > MAX_RECORD_SIZE:
            return buf[offset:], True

        try:
            return self.cim.objects.get_record(logical_page, record_id, size).getvalue(), True
        except (Error, EOFError, IndexError, ValueError, OSError):
            return buf[offset:], True

    def _identify(self, data: bytes) -> tuple[RecordKind, str | None, str | None, bool]:
        """Best-effort identification of a raw record without requiring reachability.

        Returns the record kind, class name, class hash and whether the class instance hash mismatched.
        """
        try:
            class_name = _parse_class_definition(data)
            return RecordKind.CLASS_DEFINITION, class_name, _name_hash(class_name, self.xp), False
        except (ValueError, UnicodeDecodeError):
            pass

        try:
            class_name, class_hash = _parse_class_instance(data, self.xp)
            return RecordKind.CLASS_INSTANCE, class_name, class_hash, False
        except _InstanceHashMismatch:
            return RecordKind.CLASS_INSTANCE, None, None, True
        except (ValueError, UnicodeDecodeError):
            pass

        return RecordKind.UNKNOWN, None, None, False

    def _class_from_index_key(self, keys: list[str]) -> tuple[RecordKind, str | None]:
        """Derive a record kind and class hash from current index keys."""
        for key in keys:
            tail = key.rsplit("/", 1)[-1]
            if tail.startswith("CD_"):
                return RecordKind.CLASS_DEFINITION, tail[3:].split(".", 1)[0]
            if tail.startswith("CI_"):
                return RecordKind.CLASS_INSTANCE, tail[3:].split(".", 1)[0]
        return RecordKind.UNKNOWN, None

    def _collect(self, result: ScanResult) -> list[_RawRecord]:
        records: list[_RawRecord] = []
        skip_until = -1

        for page in self._pages():
            if page.logical_page <= skip_until:
                result.skipped_pages[page.logical_page] = FragmentReason.CROSS_PAGE_RECORD.value
                continue

            try:
                buf = self.store.physical_page(page.physical_page)
            except (Error, OSError):
                result.skipped_pages[page.logical_page] = FragmentReason.UNMAPPED_PAGE.value
                continue

            if len(buf) < DATA_PAGE_SIZE:
                result.skipped_pages[page.logical_page] = FragmentReason.RECORD_TRUNCATED.value
                continue

            entries, terminated = _toc_entries(buf)
            if not terminated or not _toc_chain_is_valid(entries):
                result.skipped_pages[page.logical_page] = FragmentReason.STRUCTURE_INVALID.value
                continue

            if page.free_space is not None and page.free_space > DATA_PAGE_SIZE:
                result.skipped_pages[page.logical_page] = FragmentReason.STRUCTURE_INVALID.value
                continue

            if not entries and page.free_space is not None and page.free_space != DATA_PAGE_SIZE - 16:
                result.skipped_pages[page.logical_page] = FragmentReason.STRUCTURE_INVALID.value
                continue

            used_end = DATA_PAGE_SIZE - page.free_space if page.free_space is not None else DATA_PAGE_SIZE
            page_reused = page.physical_page in self.reused_physical_pages
            result.scanned_pages += 1

            if not entries and any(buf[16:]):
                payload = buf[16:]
                result.residual_pages.append(
                    ResidualPage(
                        physical_page=page.physical_page,
                        logical_page=page.logical_page,
                        offset=16,
                        length=len(payload),
                        data_sha256=hashlib.sha256(payload).hexdigest(),
                    )
                )

            for record_id, offset, size, crc in entries:
                data, cross_page = self._read_record(page.logical_page, record_id, offset, size, buf)
                in_free_space = offset + size <= DATA_PAGE_SIZE and offset + size > used_end

                if cross_page:
                    extra_pages = (offset + size - DATA_PAGE_SIZE + DATA_PAGE_SIZE - 1) // DATA_PAGE_SIZE
                    # Never let a corrupt length skip beyond the mapped page space.
                    extra_pages = min(extra_pages, self.mapping.mapping.mapping_entry_count - page.logical_page - 1)
                    skip_until = max(skip_until, page.logical_page + extra_pages)

                records.append(
                    _RawRecord(
                        page=page,
                        record_id=record_id,
                        offset=offset,
                        size=size,
                        crc=crc,
                        data=data,
                        cross_page=cross_page,
                        in_free_space=in_free_space,
                        page_reused=page_reused,
                        index_keys=self.references.get((page.logical_page, record_id), []),
                    )
                )

        result.scanned_records = len(records)
        result.reused_physical_pages = set(self.reused_physical_pages)
        return records

    def _build_schema_catalog(self, records: list[_RawRecord]) -> dict[str, tuple[str, int, int]]:
        """Build a class hash to (name, physical page, record id) catalog from valid class definitions."""
        catalog: dict[str, tuple[str, int, int]] = {}

        for record in records:
            if record.kind is not RecordKind.CLASS_DEFINITION or record.class_hash is None:
                continue
            if record.cross_page or record.in_free_space or record.page_reused:
                continue
            if not record.class_name:
                continue
            if _name_hash(record.class_name, self.xp) != record.class_hash:
                continue

            catalog[record.class_hash] = (record.class_name, record.page.physical_page, record.record_id)

        return catalog

    def _schema_source(
        self,
        class_hash: str | None,
        catalog: dict[str, tuple[str, int, int]],
        reachable: dict[str, tuple[str, int, int]],
    ) -> SchemaSource:
        if class_hash is None:
            return SchemaSource.NONE
        if class_hash in reachable:
            return SchemaSource.INDEX
        if class_hash in catalog:
            return SchemaSource.RECOVERY
        return SchemaSource.NONE

    def scan(self) -> ScanResult:
        """Scan all mapped data pages and classify their TOC records."""
        result = ScanResult()
        records = self._collect(result)

        for record in records:
            record.kind, record.class_name, record.class_hash, record.hash_mismatch = self._identify(record.data)

        catalog = self._build_schema_catalog(records)
        reachable_definitions = {
            record.class_hash: (record.class_name, record.page.physical_page, record.record_id)
            for record in records
            if record.index_keys
            and record.kind is RecordKind.CLASS_DEFINITION
            and record.class_hash is not None
            and record.class_name
        }

        for record in records:
            result.records.append(self._classify(record, catalog, reachable_definitions))

        # Recompute the summary after classification.
        result.scanned_records = len(records)
        return result

    def _classify(
        self,
        record: _RawRecord,
        catalog: dict[str, tuple[str, int, int]],
        reachable_definitions: dict[str, tuple[str, int, int]],
    ) -> ScanRecord:
        kind = record.kind
        class_name = record.class_name
        class_hash = record.class_hash

        if kind is RecordKind.UNKNOWN and record.index_keys:
            kind, class_hash = self._class_from_index_key(record.index_keys)

        if class_hash is not None:
            schema = reachable_definitions.get(class_hash) or catalog.get(class_hash)
            if schema is not None:
                if class_name is None:
                    class_name = schema[0]
                record.schema_physical_page = schema[1]
                record.schema_record_id = schema[2]

        schema_source = self._schema_source(class_hash, catalog, reachable_definitions)
        classification = RecordClassification.FRAGMENT
        reason: FragmentReason | None = None
        reliability = Reliability.LOW

        if record.index_keys:
            classification = RecordClassification.REACHABLE
            reliability = Reliability.HIGH
            if kind is RecordKind.CLASS_DEFINITION and class_name is not None:
                schema_source = SchemaSource.RECORD
        elif record.page_reused:
            reason = FragmentReason.PAGE_REUSED
        elif record.hash_mismatch:
            reason = FragmentReason.HASH_MISMATCH
        elif record.in_free_space:
            reason = FragmentReason.RECORD_IN_FREE_SPACE
        elif kind is RecordKind.CLASS_DEFINITION:
            classification = RecordClassification.UNREFERENCED
            reliability = Reliability.MEDIUM
            schema_source = SchemaSource.RECORD
            record.schema_physical_page = record.page.physical_page
            record.schema_record_id = record.record_id
        elif kind is RecordKind.CLASS_INSTANCE:
            if class_hash is None:
                reason = FragmentReason.STRUCTURE_INVALID
            elif schema_source is SchemaSource.NONE:
                reason = FragmentReason.CLASS_DEFINITION_MISSING
            else:
                classification = RecordClassification.UNREFERENCED
                reliability = Reliability.HIGH
        else:
            reason = FragmentReason.STRUCTURE_INVALID

        if record.size > MAX_RECORD_SIZE or (record.cross_page and len(record.data) < record.size):
            classification = RecordClassification.FRAGMENT
            reason = FragmentReason.CROSS_PAGE_RECORD if record.cross_page else FragmentReason.RECORD_TRUNCATED
            reliability = Reliability.LOW
        elif record.cross_page and classification is not RecordClassification.REACHABLE:
            # The record was reconstructed from a chain of logical pages. It validates as a complete record, but
            # page continuity is not covered by an index reference, so lower the confidence.
            if classification is RecordClassification.UNREFERENCED:
                reliability = Reliability.MEDIUM
            else:
                reason = FragmentReason.CROSS_PAGE_RECORD

        return ScanRecord(
            location=RecordLocation(
                physical_page=record.page.physical_page,
                logical_page=record.page.logical_page,
                record_id=record.record_id,
                offset=record.offset,
                length=record.size,
                toc_crc=record.crc,
            ),
            classification=classification,
            kind=kind,
            data=record.data,
            class_name=class_name,
            class_hash=class_hash,
            schema_source=schema_source,
            schema_physical_page=record.schema_physical_page,
            schema_record_id=record.schema_record_id,
            fragment_reason=reason,
            reliability=reliability,
            index_keys=record.index_keys,
            cross_page=record.cross_page,
            page_reused=record.page_reused,
            in_free_space=record.in_free_space,
        )


def scan_unreferenced(cim: CIM) -> ScanResult:
    """Scan a :class:`~dissect.cim.cim.CIM` database for unreferenced data page records."""
    return RecoveryScanner(cim).scan()


scan = scan_unreferenced
