"""
Metadata sanitization for pcap-ng capture files.

The sanitizer rewrites a capture while keeping packet bytes and packet order
unchanged.  Metadata that can identify the capture host, its interfaces, or
internal names is removed unless the caller explicitly asks to keep it.

Unknown block types and vendor-defined options are never considered safe by
default.  They can only be retained by explicitly naming their block type or
option code, and every retention of opaque data is reported separately.

The implementation works at the byte level: blocks that do not need changes
are copied verbatim, and blocks whose options change keep their original
non-option bytes (including packet data) exactly.  It does not re-encode
packets or renumber interfaces.
"""

import io
import json
import os
import struct

import pcapng.blocks as blocks
from pcapng._compat import namedtuple
from pcapng.exceptions import PcapngException
from pcapng.scanner import FileScanner


class SanitizationError(PcapngException):
    """Raised when a capture cannot be sanitized without changing its meaning."""


# Block kind names used in the policy and in the report.
KIND_SECTION = "section"
KIND_INTERFACE = "interface"
KIND_PACKET = "packet"
KIND_SIMPLE_PACKET = "simple_packet"
KIND_OBSOLETE_PACKET = "obsolete_packet"
KIND_NAME_RESOLUTION = "name_resolution"
KIND_INTERFACE_STATISTICS = "interface_statistics"
KIND_UNKNOWN = "unknown"

_BLOCK_KINDS = {
    blocks.SectionHeader: KIND_SECTION,
    blocks.InterfaceDescription: KIND_INTERFACE,
    blocks.EnhancedPacket: KIND_PACKET,
    blocks.SimplePacket: KIND_SIMPLE_PACKET,
    blocks.ObsoletePacket: KIND_OBSOLETE_PACKET,
    blocks.NameResolution: KIND_NAME_RESOLUTION,
    blocks.InterfaceStatistics: KIND_INTERFACE_STATISTICS,
}

_KIND_ALIASES = {
    "section": KIND_SECTION,
    "shb": KIND_SECTION,
    "interface": KIND_INTERFACE,
    "idb": KIND_INTERFACE,
    "packet": KIND_PACKET,
    "epb": KIND_PACKET,
    "simple_packet": KIND_SIMPLE_PACKET,
    "spb": KIND_SIMPLE_PACKET,
    "obsolete_packet": KIND_OBSOLETE_PACKET,
    "pb": KIND_OBSOLETE_PACKET,
    "name_resolution": KIND_NAME_RESOLUTION,
    "nrb": KIND_NAME_RESOLUTION,
    "interface_statistics": KIND_INTERFACE_STATISTICS,
    "isb": KIND_INTERFACE_STATISTICS,
}

# Options that are required to interpret the packet stream rather than to
# describe the capture host or its interface names.  if_tsresol must survive
# or all timestamps would be reinterpreted with the wrong resolution;
# if_tsoffset and if_fcslen also affect packet/frame interpretation.
_STRUCTURAL_OPTIONS = {
    (KIND_INTERFACE, 9),  # if_tsresol
    (KIND_INTERFACE, 13),  # if_fcslen
    (KIND_INTERFACE, 14),  # if_tsoffset
}

# Options present on every option-bearing block (pcapng spec section 2.5).
_COMMON_OPTION_NAMES = {
    1: "opt_comment",
    2988: "custom_str_safe",
    2989: "custom_bytes_safe",
    19372: "custom_str",
    19373: "custom_bytes",
}

# Options whose contents are opaque vendor-defined data.
_VENDOR_OPTION_CODES = {2988, 2989, 19372, 19373}

# Convenient names for groups of metadata.  Each maps directly to option
# (block kind, code) pairs and is only a shorthand for the caller.
_METADATA_CATEGORIES = {
    "section.comment": {(KIND_SECTION, 1)},
    "section.hardware": {(KIND_SECTION, 2)},
    "section.os": {(KIND_SECTION, 3)},
    "section.userappl": {(KIND_SECTION, 4)},
    "interface.comment": {(KIND_INTERFACE, 1)},
    "interface.name": {(KIND_INTERFACE, 2)},
    "interface.description": {(KIND_INTERFACE, 3)},
    "interface.ipv4": {(KIND_INTERFACE, 4)},
    "interface.ipv6": {(KIND_INTERFACE, 5)},
    "interface.mac": {(KIND_INTERFACE, 6)},
    "interface.eui": {(KIND_INTERFACE, 7)},
    "interface.addresses": {
        (KIND_INTERFACE, 4),
        (KIND_INTERFACE, 5),
        (KIND_INTERFACE, 6),
        (KIND_INTERFACE, 7),
    },
    "interface.filter": {(KIND_INTERFACE, 11)},
    "interface.os": {(KIND_INTERFACE, 12)},
    "interface.hardware": {(KIND_INTERFACE, 15)},
    "name_resolution.comment": {(KIND_NAME_RESOLUTION, 1)},
    "name_resolution.dns_name": {(KIND_NAME_RESOLUTION, 2)},
    "name_resolution.dns_ipv4": {(KIND_NAME_RESOLUTION, 3)},
    "name_resolution.dns_ipv6": {(KIND_NAME_RESOLUTION, 4)},
    "comments": {
        (KIND_SECTION, 1),
        (KIND_INTERFACE, 1),
        (KIND_PACKET, 1),
        (KIND_OBSOLETE_PACKET, 1),
        (KIND_NAME_RESOLUTION, 1),
        (KIND_INTERFACE_STATISTICS, 1),
    },
    "packet.flags": {(KIND_PACKET, 2), (KIND_OBSOLETE_PACKET, 2)},
    "packet.hash": {(KIND_PACKET, 3), (KIND_OBSOLETE_PACKET, 3)},
}

_OPTION_HEADER_LEN = 4
_OPTION_END = b"\x00\x00\x00\x00"


def _has_options(block_cls):
    return any(name == "options" for name, _field, _default in block_cls.schema)


def _schema_options(block_cls):
    for name, field, _default in block_cls.schema:
        if name == "options":
            return field.options_schema
    return []


def _block_option_names(block_cls):
    """Map a block's option names to codes, including common options."""
    names = {option.name: option.code for option in _schema_options(block_cls)}
    if _has_options(block_cls):
        for code, name in _COMMON_OPTION_NAMES.items():
            names.setdefault(name, code)
    return names


def _block_option_codes(block_cls):
    return {code: name for name, code in _block_option_names(block_cls).items()}


def _option_name(block_cls, code):
    return _block_option_codes(block_cls).get(code)


def _endianness(block):
    if isinstance(block, blocks.SectionHeader):
        return block.endianness
    return block.section.endianness


def _padded_length(length):
    return length + ((4 - (length % 4)) % 4)


class SanitizationPolicy(object):
    """
    Explicit allow-list for capture metadata.

    By default no identifying metadata is retained.  ``keep_metadata`` is an
    iterable of option names (for example ``"if_name"`` or ``"opt_comment"``),
    block-qualified option names (for example ``"interface.if_name"``), or one
    of the documented group names such as ``"interface.addresses"`` or
    ``"comments"``.

    ``keep_option_codes`` is a mapping from block kind to a set of numeric
    option codes.  It is the only way to retain options whose code is not in
    the library schema.  Block kinds are ``section``, ``interface``,
    ``packet``, ``simple_packet``, ``obsolete_packet``, ``name_resolution``
    and ``interface_statistics``.

    ``name_resolution`` controls Name Resolution Block records:

    * ``"none"`` (default) - remove address/name records entirely
    * ``"addresses"`` - keep the address part of each record, but remove names
    * ``"records"`` - keep complete address/name records

    Unknown Name Resolution record types are separate from known records and
    are dropped unless ``keep_unknown_name_resolution_records`` is true.

    Unknown block types (including future or vendor extension blocks) are
    dropped unless their numeric type is listed in
    ``keep_unknown_block_types``.

    Retaining an opaque option, unknown block, or unknown name-resolution
    record is reported in :attr:`SanitizationReport.retained_opaque`.
    """

    __slots__ = [
        "keep_metadata",
        "keep_option_codes",
        "keep_unknown_block_types",
        "name_resolution",
        "keep_unknown_name_resolution_records",
        "_allowed_options",
    ]

    def __init__(
        self,
        keep_metadata=(),
        keep_option_codes=None,
        keep_unknown_block_types=(),
        name_resolution="none",
        keep_unknown_name_resolution_records=False,
    ):
        self.keep_metadata = tuple(keep_metadata)
        self.keep_option_codes = keep_option_codes or {}
        self.keep_unknown_block_types = frozenset(
            int(block_type) for block_type in keep_unknown_block_types
        )
        if name_resolution not in ("none", "addresses", "records"):
            raise ValueError("name_resolution must be 'none', 'addresses' or 'records'")
        self.name_resolution = name_resolution
        self.keep_unknown_name_resolution_records = bool(
            keep_unknown_name_resolution_records
        )

        allowed = set(_STRUCTURAL_OPTIONS)
        for item in self.keep_metadata:
            allowed.update(self._resolve_metadata_item(item))
        allowed.update(self._resolve_option_codes(self.keep_option_codes))

        for block_type in self.keep_unknown_block_types:
            if block_type in blocks.KNOWN_BLOCKS:
                raise ValueError(
                    "block type 0x{0:08X} is a known block, not an unknown "
                    "block".format(block_type)
                )
            if block_type == blocks.SectionHeader.magic_number:
                raise ValueError(
                    "the Section Header Block cannot be retained as an " "unknown block"
                )
        self._allowed_options = frozenset(allowed)

    def _resolve_metadata_item(self, item):
        if not isinstance(item, str):
            raise TypeError("metadata names must be strings")
        if item in _METADATA_CATEGORIES:
            return _METADATA_CATEGORIES[item]

        if "." in item:
            kind_name, option_name = item.split(".", 1)
            kind = _KIND_ALIASES.get(kind_name)
            if kind is None:
                raise ValueError(
                    "unknown block kind in metadata name: {!r}".format(item)
                )
            return self._resolve_option_for_kind(kind, option_name)

        matches = set()
        for block_cls, kind in _BLOCK_KINDS.items():
            names = _block_option_names(block_cls)
            if item in names:
                matches.add((kind, names[item]))
        if not matches:
            raise ValueError(
                "unknown metadata name {!r}; use an option name, a qualified "
                "name, a documented group, or keep_option_codes for vendor "
                "option codes".format(item)
            )
        return matches

    def _resolve_option_for_kind(self, kind, option_name):
        for block_cls, block_kind in _BLOCK_KINDS.items():
            if block_kind != kind:
                continue
            names = _block_option_names(block_cls)
            if option_name in names:
                return {(kind, names[option_name])}
            try:
                code = int(option_name, 0)
            except (TypeError, ValueError):
                raise ValueError(
                    "unknown option {!r} for block kind {!r}".format(option_name, kind)
                )
            self._validate_option_code(kind, code)
            return {(kind, code)}
        return set()

    def _resolve_option_codes(self, codes_by_kind):
        resolved = set()
        if not hasattr(codes_by_kind, "items"):
            raise TypeError(
                "keep_option_codes must be a mapping of block kind to " "option codes"
            )
        for kind_name, codes in codes_by_kind.items():
            kind = _KIND_ALIASES.get(kind_name)
            if kind is None:
                raise ValueError("unknown block kind: {!r}".format(kind_name))
            for code in codes:
                code = int(code)
                self._validate_option_code(kind, code)
                resolved.add((kind, code))
        return resolved

    @staticmethod
    def _validate_option_code(kind, code):
        if code <= 0 or code > 0xFFFF:
            raise ValueError("invalid option code: {!r}".format(code))
        if kind == KIND_SIMPLE_PACKET:
            raise ValueError("Simple Packet Blocks do not have options")

    def allows_option(self, kind, code):
        """Return whether the given option may be retained."""
        return (kind, code) in self._allowed_options

    def allows_unknown_block(self, block_type):
        """Return whether an unknown block type may be retained verbatim."""
        return block_type in self.keep_unknown_block_types

    def is_opaque_option(self, kind, code):
        """Return whether the option's content is vendor-defined or unknown."""
        if code in _VENDOR_OPTION_CODES:
            return True
        for block_cls, block_kind in _BLOCK_KINDS.items():
            if block_kind == kind:
                return code not in _block_option_codes(block_cls)
        return True

    def summary(self):
        return {
            "allowed_options": sorted(
                "{}.{}".format(kind, code) for kind, code in self._allowed_options
            ),
            "name_resolution": self.name_resolution,
            "unknown_block_types": sorted(self.keep_unknown_block_types),
            "keep_unknown_name_resolution_records": (
                self.keep_unknown_name_resolution_records
            ),
        }


SanitizationChange = namedtuple(
    "SanitizationChange",
    (
        "action",
        "block_index",
        "section_index",
        "block_offset",
        "block_type",
        "block_type_code",
        "block_length",
        "item",
        "item_offset",
        "item_length",
        "option_code",
        "option_name",
        "record_index",
        "occurrence",
        "old_value",
        "new_value",
        "note",
    ),
    defaults=(None,) * 17,
)


class SanitizationReport(object):
    """Report describing every removal/change made to the capture."""

    __slots__ = [
        "changes",
        "retained_opaque",
        "blocks_read",
        "blocks_written",
        "sections",
        "input_bytes",
        "output_bytes",
        "policy",
    ]

    def __init__(self):
        self.changes = []
        self.retained_opaque = []
        self.blocks_read = 0
        self.blocks_written = 0
        self.sections = 0
        self.input_bytes = 0
        self.output_bytes = 0
        self.policy = {}

    def __len__(self):
        return len(self.changes)

    def __iter__(self):
        return iter(self.changes)

    def to_dict(self):
        return {
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
            "blocks_read": self.blocks_read,
            "blocks_written": self.blocks_written,
            "sections": self.sections,
            "policy": self.policy,
            "changes": [change._asdict() for change in self.changes],
            "retained_opaque": [change._asdict() for change in self.retained_opaque],
        }

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)

    def format(self):
        """Return a short, value-free text summary of the changes."""
        lines = [
            "pcapng sanitization: {0} blocks read, {1} written, "
            "{2} section(s)".format(
                self.blocks_read, self.blocks_written, self.sections
            ),
            "{0} removal/change(s), {1} opaque retention(s)".format(
                len(self.changes), len(self.retained_opaque)
            ),
        ]
        for change in self.changes:
            lines.append("  " + self._format_change(change))
        for change in self.retained_opaque:
            lines.append("  " + self._format_change(change))
        return "\n".join(lines)

    @staticmethod
    def _format_change(change):
        parts = []
        if change.item_offset is not None:
            parts.append("item_offset={0}".format(change.item_offset))
        if change.item_length is not None:
            parts.append("item_length={0}".format(change.item_length))
        if change.option_code is not None:
            parts.append("code={0}".format(change.option_code))
        if change.option_name:
            parts.append("name={0}".format(change.option_name))
        if change.record_index is not None:
            parts.append("record={0}".format(change.record_index))
        if change.note:
            parts.append("note={0}".format(change.note))
        return (
            "{action} block={block_index} offset={block_offset} "
            "type={block_type} item={item}{extra}".format(
                action=change.action,
                block_index=change.block_index,
                block_offset=change.block_offset,
                block_type=change.block_type,
                item=change.item,
                extra="" if not parts else " ({0})".format(", ".join(parts)),
            )
        )

    def __repr__(self):
        return (
            "<SanitizationReport blocks={0} written={1} changes={2} "
            "opaque={3}>".format(
                self.blocks_read,
                self.blocks_written,
                len(self.changes),
                len(self.retained_opaque),
            )
        )


class _Record(object):
    __slots__ = (
        "block",
        "start",
        "end",
        "section_index",
        "kind",
        "block_type_code",
        "frame",
    )

    def __init__(self, block, start, end, section_index, frame):
        self.block = block
        self.start = start
        self.end = end
        self.section_index = section_index
        self.kind = _BLOCK_KINDS.get(type(block), KIND_UNKNOWN)
        if self.kind == KIND_UNKNOWN:
            self.block_type_code = block.block_type
        else:
            self.block_type_code = block.magic_number
        self.frame = frame

    def describe(self):
        if self.kind == KIND_UNKNOWN:
            return "UnknownBlock(0x{0:08X})".format(self.block_type_code)
        return type(self.block).__name__

    def change(self, action, block_index, **kwargs):
        return SanitizationChange(
            action=action,
            block_index=block_index,
            section_index=self.section_index,
            block_offset=self.start,
            block_type=self.describe(),
            block_type_code=self.block_type_code,
            block_length=self.end - self.start,
            **kwargs,
        )


class _Option(object):
    __slots__ = ("code", "payload", "raw", "offset")

    def __init__(self, code, payload, raw, offset):
        self.code = code
        self.payload = payload
        self.raw = raw
        self.offset = offset  # block-relative


class _NameResolutionRecord(object):
    __slots__ = ("record_type", "payload", "raw", "offset")

    def __init__(self, record_type, payload, raw, offset):
        self.record_type = record_type
        self.payload = payload
        self.raw = raw
        self.offset = offset  # block-relative


def _scan(data):
    stream = io.BytesIO(data)
    scanner = FileScanner(stream)
    records = []
    section_index = -1
    start = 0
    iterator = iter(scanner)
    while True:
        try:
            block = next(iterator)
        except StopIteration:
            break
        except ValueError as exc:
            raise SanitizationError(str(exc)) from exc
        end = stream.tell()
        if isinstance(block, blocks.SectionHeader):
            section_index += 1
        if section_index < 0:
            raise SanitizationError("capture does not start with a section header")
        records.append(_Record(block, start, end, section_index, data[start:end]))
        start = end
    return records


def _options_start(record):
    """Return the block-relative offset where the options field starts."""
    kind = record.kind
    if kind == KIND_SECTION:
        return 24  # type+length + BOM + version + section length
    if kind == KIND_INTERFACE:
        return 16
    if kind == KIND_INTERFACE_STATISTICS:
        return 20
    if kind in (KIND_PACKET, KIND_OBSOLETE_PACKET):
        block = record.block
        return 28 + _padded_length(block.captured_len)
    if kind == KIND_NAME_RESOLUTION:
        return _nrb_records_end(record)[0]
    if kind == KIND_SIMPLE_PACKET:
        return None
    return None


def _parse_options(record, options_start):
    """Parse the raw options field, preserving each option's exact bytes."""
    frame = record.frame
    endianness = _endianness(record.block)
    limit = len(frame) - 4  # block trailer
    position = options_start
    options = []
    while position + _OPTION_HEADER_LEN <= limit:
        code, length = struct.unpack_from(endianness + "HH", frame, position)
        if code == 0:
            if length != 0:
                raise SanitizationError(
                    "invalid end-of-options marker at block offset {0}".format(position)
                )
            return options
        padded = _padded_length(length)
        if position + _OPTION_HEADER_LEN + padded > limit:
            raise SanitizationError(
                "truncated option {0} at block offset {1}".format(code, position)
            )
        raw = frame[position : position + _OPTION_HEADER_LEN + padded]
        payload = frame[
            position + _OPTION_HEADER_LEN : position + _OPTION_HEADER_LEN + length
        ]
        options.append(_Option(code, payload, raw, position))
        position += _OPTION_HEADER_LEN + padded
    # No end-of-options marker: the field was empty or omitted.  Anything
    # between the expected start and the trailer is malformed.
    if position != limit:
        raise SanitizationError(
            "malformed options field at block offset {0}".format(options_start)
        )
    return options


def _nrb_records_end(record):
    """Return (options start, records) for a Name Resolution Block."""
    frame = record.frame
    endianness = _endianness(record.block)
    limit = len(frame) - 4
    position = 8  # type + length
    records = []
    while position + 4 <= limit:
        record_type, length = struct.unpack_from(endianness + "HH", frame, position)
        if record_type == 0:
            if length != 0:
                raise SanitizationError(
                    "invalid end-of-records marker at block offset {0}".format(position)
                )
            return position + 4, records
        padded = _padded_length(length)
        if position + 4 + padded > limit:
            raise SanitizationError(
                "truncated name resolution record at block offset {0}".format(position)
            )
        raw = frame[position : position + 4 + padded]
        payload = frame[position + 4 : position + 4 + length]
        records.append(_NameResolutionRecord(record_type, payload, raw, position))
        position += 4 + padded
    return position, records


def _filter_options(record, block_index, policy, report):
    """Return the raw option entries that are explicitly allowed."""
    if record.kind == KIND_SIMPLE_PACKET:
        return None, 0
    start = _options_start(record)
    if start is None:
        return None, 0
    options = _parse_options(record, start)
    kept = []
    dropped = 0
    block_cls = type(record.block)
    for occurrence, option in enumerate(options):
        name = _option_name(block_cls, option.code)
        opaque = policy.is_opaque_option(record.kind, option.code)
        if policy.allows_option(record.kind, option.code):
            kept.append(option.raw)
            if opaque:
                report.retained_opaque.append(
                    record.change(
                        "retain-opaque-option",
                        block_index=block_index,
                        item="option",
                        item_offset=record.start + option.offset,
                        item_length=len(option.raw),
                        option_code=option.code,
                        option_name=name,
                        occurrence=occurrence,
                        note="opaque option retained by explicit policy",
                    )
                )
        else:
            dropped += 1
            report.changes.append(
                record.change(
                    "drop-option",
                    block_index=block_index,
                    item="option",
                    item_offset=record.start + option.offset,
                    item_length=len(option.raw),
                    option_code=option.code,
                    option_name=name,
                    occurrence=occurrence,
                    note=(
                        "vendor/unknown option not explicitly retained"
                        if opaque
                        else "metadata option not in retention policy"
                    ),
                )
            )
    return kept, dropped


def _assemble(record, options_start, options, records_bytes=None):
    """Build a block frame from original bytes plus filtered fields."""
    frame = record.frame
    endianness = _endianness(record.block)
    if records_bytes is not None:
        # Name Resolution Blocks have records before their options.
        prefix = frame[:8] + records_bytes
    else:
        prefix = frame[:options_start]
    trailer = frame[-4:]
    if options:
        result = prefix + b"".join(options) + _OPTION_END + trailer
    else:
        result = prefix + trailer

    block_length = len(result)
    patched = bytearray(result)
    struct.pack_into(endianness + "I", patched, 4, block_length)
    struct.pack_into(endianness + "I", patched, block_length - 4, block_length)
    return bytes(patched)


def _sanitize_name_resolution(record, block_index, policy, report):
    frame = record.frame
    options_start, raw_records = _nrb_records_end(record)
    endianness = _endianness(record.block)
    kept_options, dropped_options = _filter_options(record, block_index, policy, report)

    kept_records = []
    changed = bool(dropped_options)

    for record_index, nrb_record in enumerate(raw_records):
        if nrb_record.record_type in (1, 2):
            if policy.name_resolution == "none":
                report.changes.append(
                    record.change(
                        "drop-name-resolution-record",
                        block_index=block_index,
                        item="name_resolution_record",
                        item_offset=record.start + nrb_record.offset,
                        item_length=len(nrb_record.raw),
                        option_code=nrb_record.record_type,
                        record_index=record_index,
                        note="name resolution records are disabled",
                    )
                )
                changed = True
                continue

            if policy.name_resolution == "addresses":
                address_len = 4 if nrb_record.record_type == 1 else 16
                payload = nrb_record.payload
                if len(payload) < address_len:
                    raise SanitizationError(
                        "truncated name resolution address record at block "
                        "offset {0}".format(nrb_record.offset)
                    )
                names_payload = payload[address_len:]
                if names_payload.strip(b"\x00"):
                    report.changes.append(
                        record.change(
                            "drop-name-resolution-name",
                            block_index=block_index,
                            item="name_resolution_name",
                            item_offset=record.start
                            + nrb_record.offset
                            + 4
                            + address_len,
                            item_length=len(names_payload),
                            option_code=nrb_record.record_type,
                            record_index=record_index,
                            note="host name removed; address retained",
                        )
                    )
                    changed = True
                    address = payload[:address_len]
                    new_payload = address
                    raw = (
                        struct.pack(
                            endianness + "HH",
                            nrb_record.record_type,
                            len(new_payload),
                        )
                        + new_payload
                        + b"\x00" * ((4 - len(new_payload) % 4) % 4)
                    )
                    kept_records.append(raw)
                    continue
            kept_records.append(nrb_record.raw)
        else:
            if policy.keep_unknown_name_resolution_records:
                kept_records.append(nrb_record.raw)
                report.retained_opaque.append(
                    record.change(
                        "retain-opaque-record",
                        block_index=block_index,
                        item="name_resolution_record",
                        item_offset=record.start + nrb_record.offset,
                        item_length=len(nrb_record.raw),
                        option_code=nrb_record.record_type,
                        record_index=record_index,
                        note="unknown name resolution record retained verbatim",
                    )
                )
            else:
                report.changes.append(
                    record.change(
                        "drop-name-resolution-record",
                        block_index=block_index,
                        item="name_resolution_record",
                        item_offset=record.start + nrb_record.offset,
                        item_length=len(nrb_record.raw),
                        option_code=nrb_record.record_type,
                        record_index=record_index,
                        note=(
                            "unknown name resolution record not explicitly " "retained"
                        ),
                    )
                )
                changed = True

    if not kept_records and not kept_options:
        if not raw_records and not _parse_options(record, options_start):
            return frame
        report.changes.append(
            record.change(
                "drop-block",
                block_index=block_index,
                item="block",
                item_offset=record.start,
                item_length=len(frame),
                note="name resolution block has no retainable content",
            )
        )
        return None

    if not changed:
        return frame

    records_bytes = b"".join(kept_records) + struct.pack(endianness + "HH", 0, 0)
    return _assemble(record, options_start, kept_options, records_bytes)


def _sanitize_options_only(record, block_index, policy, report):
    kept, dropped = _filter_options(record, block_index, policy, report)
    if not dropped:
        return record.frame
    return _assemble(record, _options_start(record), kept)


def _sanitize_section(record, block_index, policy, report):
    kept, dropped = _filter_options(record, block_index, policy, report)
    if not dropped:
        return record.frame
    return _assemble(record, _options_start(record), kept)


def _patch_section_length(frame, endianness, length):
    patched = bytearray(frame)
    struct.pack_into(endianness + "q", patched, 16, length)
    return bytes(patched)


def _sanitize_data(data, policy):
    records = _scan(data)
    report = SanitizationReport()
    report.blocks_read = len(records)
    report.input_bytes = len(data)
    report.policy = policy.summary()

    outputs = [None] * len(records)
    section_starts = []

    for block_index, record in enumerate(records):
        if isinstance(record.block, blocks.SectionHeader):
            outputs[block_index] = _sanitize_section(
                record, block_index, policy, report
            )
            section_starts.append(block_index)
        elif isinstance(record.block, blocks.UnknownBlock):
            if policy.allows_unknown_block(record.block.block_type):
                outputs[block_index] = record.frame
                report.retained_opaque.append(
                    record.change(
                        "retain-opaque-block",
                        block_index=block_index,
                        item="block",
                        item_offset=record.start,
                        item_length=len(record.frame),
                        note="unknown block retained verbatim by explicit policy",
                    )
                )
            else:
                report.changes.append(
                    record.change(
                        "drop-block",
                        block_index=block_index,
                        item="block",
                        item_offset=record.start,
                        item_length=len(record.frame),
                        note="unknown block type not explicitly retained",
                    )
                )
        elif isinstance(record.block, blocks.NameResolution):
            outputs[block_index] = _sanitize_name_resolution(
                record, block_index, policy, report
            )
        elif isinstance(record.block, blocks.SimplePacket):
            outputs[block_index] = record.frame
        else:
            outputs[block_index] = _sanitize_options_only(
                record, block_index, policy, report
            )

    # Recompute declared section lengths without touching packet blocks.
    for position, start_index in enumerate(section_starts):
        end_index = (
            section_starts[position + 1]
            if position + 1 < len(section_starts)
            else len(records)
        )
        total = sum(
            len(outputs[i])
            for i in range(start_index + 1, end_index)
            if outputs[i] is not None
        )
        record = records[start_index]
        block = record.block
        if block.section_length == -1:
            continue
        if block.section_length != total:
            report.changes.append(
                record.change(
                    "change-section-length",
                    block_index=start_index,
                    item="section_length",
                    item_offset=record.start + 16,
                    item_length=8,
                    old_value=block.section_length,
                    new_value=total,
                    note="section length recomputed after removals",
                )
            )
        outputs[start_index] = _patch_section_length(
            outputs[start_index], block.endianness, total
        )

    result = b"".join(frame for frame in outputs if frame is not None)
    report.output_bytes = len(result)
    report.blocks_written = sum(1 for frame in outputs if frame is not None)
    report.sections = len(section_starts)
    return result, report


def _path_types():
    path_types = (str, bytes)
    if hasattr(os, "PathLike"):
        path_types += (os.PathLike,)
    return path_types


def _read_source(source):
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    if isinstance(source, _path_types()):
        with open(source, "rb") as fp:
            return fp.read()
    read = getattr(source, "read", None)
    if read is None:
        raise TypeError("source must be a path, bytes-like object or binary stream")
    tell = getattr(source, "tell", None)
    position = None
    if tell is not None:
        try:
            position = tell()
        except (OSError, IOError):
            position = None
    data = read()
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("source stream must be opened in binary mode")
    if position is not None:
        seek = getattr(source, "seek", None)
        if seek is not None:
            try:
                seek(position)
            except (OSError, IOError):
                pass
    return bytes(data)


def _same_path(source, target):
    if isinstance(source, (bytes, bytearray, memoryview)):
        return False
    candidates = [source]
    name = getattr(source, "name", None)
    if isinstance(name, _path_types()):
        candidates.append(name)
    for candidate in candidates:
        try:
            if os.path.abspath(os.fspath(candidate)) == os.path.abspath(
                os.fspath(target)
            ):
                return True
        except (AttributeError, TypeError):
            continue
    return False


def _write_target(target, data, source):
    if isinstance(target, _path_types()):
        if _same_path(source, target):
            raise ValueError("source and target refer to the same file")
        with open(target, "wb") as fp:
            fp.write(data)
        return
    write = getattr(target, "write", None)
    if write is None:
        raise TypeError("target must be a path or a binary stream")
    if target is source:
        raise ValueError("source and target must be different streams")
    write(data)


def sanitize_capture(source, target, policy=None):
    """
    Sanitize a pcap-ng capture without modifying the input.

    :param source:
        path, bytes-like object, or binary stream to read.  The input is
        never written to.
    :param target:
        path or binary stream to write the derived capture to.
    :param policy:
        a :class:`SanitizationPolicy`; the default removes all non-structural
        metadata and all unknown/vendor data.
    :returns: a :class:`SanitizationReport` containing every deletion/change
        and every explicitly retained opaque item.
    """
    if policy is None:
        policy = SanitizationPolicy()
    if not isinstance(policy, SanitizationPolicy):
        raise TypeError("policy must be a SanitizationPolicy")

    original = _read_source(source)
    data, report = _sanitize_data(original, policy)
    _write_target(target, data, source)
    return report


def sanitize_bytes(source, policy=None):
    """
    Sanitize an in-memory capture.

    :returns: ``(sanitized_bytes, report)``
    """
    if policy is None:
        policy = SanitizationPolicy()
    if not isinstance(policy, SanitizationPolicy):
        raise TypeError("policy must be a SanitizationPolicy")
    original = _read_source(source)
    return _sanitize_data(original, policy)
