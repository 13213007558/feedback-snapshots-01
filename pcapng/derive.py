"""
Derive a filtered pcap-ng capture from an existing one.

The API is designed for evidence handling: a caller predicate decides which
packets are delivered, while the returned manifest records, for every block
written, the exact byte range of the source block it came from.  The
manifest is bound to a digest of the *input bytes*, never to a file name or
a temporary path, so it keeps identifying the original capture after either
file has been moved or renamed.

Duplicate packets are evidence too
----------------------------------

Selection is performed independently for every source packet block, by
object identity -- not by content.  Two packets carrying identical bytes
with identical timestamps remain two distinct records: they have different
source block indexes and different source byte offsets, and they are never
merged or deduplicated.  A predicate that wants to keep only specific
occurrences among several identical ones can count occurrences in its own
closure, e.g.::

    seen = 0

    def keep(block):
        global seen
        if block.packet_data != interesting_payload:
            return False
        seen += 1
        return seen in (2, 3)

    manifest = derive_capture(source, destination, keep)

Interfaces
----------

Only interface description blocks (IDBs) referenced by at least one selected
packet are written to the derived file.  Interface identifiers are renumbered
in the output section in order of first use by a selected packet; the manifest
records the ``source_interface_id`` / ``output_interface_id`` pair for every
packet and for every emitted IDB.

Simple Packet Blocks (SPB) do not carry an interface identifier: the format
requires them to belong to the first interface of their section.  If a
selected SPB cannot be represented that way in the derived section (because
more than one interface is needed, or because its source interface would be
renumbered), a :py:class:`~pcapng.exceptions.DeriveError` is raised rather
than silently rewriting the evidence.  Obsolete Packet Blocks (PB) are
converted to Enhanced Packet Blocks (EPB) so the derived file is valid
pcap-ng; the manifest keeps the original block type and flags the conversion.

Global blocks
-------------

Name Resolution Blocks (NRB) and Interface Statistics Blocks (ISB) describe
the *whole original capture*, not the selected subset.  They are omitted by
default.  Passing ``include_name_resolution=True`` and/or
``include_interface_statistics=True`` copies the corresponding blocks
verbatim (ISBs only for interfaces referenced by selected packets, with their
interface identifiers remapped).  Retained blocks are **not** recomputed:
their counts and names still describe the original capture, so they must not
be interpreted as statistics or name resolution of the filtered output.
The manifest states this explicitly via
``retained["..."]["represent_filtered_output"] = False``.

All other non-packet blocks that are not explicitly retained (for example
unknown/experimental blocks) are omitted.
"""

import copy
import hashlib
import io
from contextlib import contextmanager

import pcapng.blocks as blocks
from pcapng.exceptions import DeriveError
from pcapng.scanner import FileScanner


DIGEST_ALGORITHM = "sha256"

_KIND_BY_CLASS = {
    blocks.SectionHeader: "section_header",
    blocks.InterfaceDescription: "interface_description",
    blocks.EnhancedPacket: "enhanced_packet",
    blocks.SimplePacket: "simple_packet",
    blocks.ObsoletePacket: "obsolete_packet",
    blocks.NameResolution: "name_resolution",
    blocks.InterfaceStatistics: "interface_statistics",
    blocks.UnknownBlock: "unknown",
}

_PACKET_CLASSES = (blocks.EnhancedPacket, blocks.SimplePacket, blocks.ObsoletePacket)


class ManifestEntry(object):
    """
    One source block -> output block correspondence.

    ``source_offset`` / ``source_length`` identify the whole source block
    (header included) in the input file whose digest is
    :py:attr:`source_digest`.  ``output_offset`` / ``output_length`` do the
    same for the derived file.  ``source_block_index`` and
    ``output_block_index`` are zero-based positions in scan order and are
    also unique within the corresponding file.
    """

    __slots__ = [
        "kind",
        "source_digest",
        "source_section_index",
        "source_block_index",
        "source_offset",
        "source_length",
        "source_block_type",
        "output_section_index",
        "output_block_index",
        "output_offset",
        "output_length",
        "output_block_type",
        "source_interface_id",
        "output_interface_id",
        "retained",
        "converted",
    ]

    def __init__(self, kind, source_digest, **kwargs):
        self.kind = kind
        self.source_digest = source_digest
        for name in self.__slots__[2:]:
            default = False if name in ("retained", "converted") else None
            setattr(self, name, kwargs.pop(name, default))
        if kwargs:
            raise TypeError("unexpected manifest fields: {}".format(sorted(kwargs)))

    def as_dict(self):
        return {name: getattr(self, name) for name in self.__slots__}

    def __getitem__(self, name):
        if name not in self.__slots__:
            raise KeyError(name)
        return getattr(self, name)

    def __eq__(self, other):
        return (
            isinstance(other, ManifestEntry) and self.as_dict() == other.as_dict()
        )

    def __repr__(self):
        return (
            "<{cls} kind={kind!r} src={digest}:{off}+{length} out={ooff}+{olength}>"
        ).format(
            cls=self.__class__.__name__,
            kind=self.kind,
            digest=(self.source_digest or "")[:16],
            off=self.source_offset,
            length=self.source_length,
            ooff=self.output_offset,
            olength=self.output_length,
        )


class _HashingWriter(object):
    """
    Pass-through writer hashing and counting everything written to it.

    Counting here (rather than calling ``tell()`` on the destination) keeps
    the recorded output offsets correct even for non-seekable streams.
    """

    __slots__ = ["stream", "hasher", "offset"]

    def __init__(self, stream):
        self.stream = stream
        self.hasher = hashlib.sha256()
        self.offset = 0

    def write(self, data):
        self.hasher.update(data)
        self.offset += len(data)
        return self.stream.write(data)

    def tell(self):
        return self.offset

    def flush(self):
        flush = getattr(self.stream, "flush", None)
        if flush is not None:
            flush()


class DeriveManifest(object):
    """
    Source block to output block mapping returned by
    :py:func:`derive_capture`.

    The manifest is bound to ``source_digest``, the SHA-256 of the input
    file bytes; it never contains a source file name or a temporary path as
    identity.  Every entry carries the same digest, so an entry can be
    authenticated even when copied out of the manifest.  ``output_digest``
    is the SHA-256 of the derived file bytes, letting reviewers confirm that
    the offsets apply to the file actually examined.
    """

    __slots__ = [
        "source_digest",
        "output_digest",
        "digest_algorithm",
        "entries",
        "sections",
        "retained",
        "selected_packets",
    ]

    def __init__(
        self,
        source_digest,
        entries,
        sections,
        retained,
        selected_packets,
        output_digest=None,
        digest_algorithm=DIGEST_ALGORITHM,
    ):
        self.source_digest = source_digest
        self.output_digest = output_digest
        self.digest_algorithm = digest_algorithm
        self.entries = entries
        self.sections = sections
        self.retained = retained
        self.selected_packets = selected_packets

    def as_dict(self):
        return {
            "source_digest": self.source_digest,
            "output_digest": self.output_digest,
            "digest_algorithm": self.digest_algorithm,
            "selected_packets": self.selected_packets,
            "sections": self.sections,
            "retained": self.retained,
            "entries": [entry.as_dict() for entry in self.entries],
        }

    def to_json(self, indent=None):
        """Serialize the manifest to a JSON string."""
        import json

        return json.dumps(self.as_dict(), indent=indent, sort_keys=True)

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def entry_for_output_offset(self, offset):
        """Return the entry whose output block starts at ``offset``."""
        for entry in self.entries:
            if entry.output_offset == offset:
                return entry
        raise KeyError(offset)

    def entries_for_packets(self):
        """Return only the packet entries, in output order."""
        return [
            entry
            for entry in self.entries
            if entry.kind in ("enhanced_packet", "simple_packet", "obsolete_packet")
        ]

    def __repr__(self):
        return "<{cls} digest={digest} entries={n} packets={p}>".format(
            cls=self.__class__.__name__,
            digest=self.source_digest,
            n=len(self.entries),
            p=self.selected_packets,
        )


def _is_packet(block):
    return isinstance(block, _PACKET_CLASSES)


def _kind(block):
    return _KIND_BY_CLASS.get(type(block), "unknown")


def _copy_options(src_options):
    return {name: list(values) for name, values in src_options.iter_all_items()}


def _hash_stream(stream):
    """
    Return (sha256 hex digest, stream positioned at the beginning).

    If the stream cannot be rewound, its content is buffered into a
    ``BytesIO`` and that buffer is returned instead.
    """
    try:
        stream.seek(0)
    except (AttributeError, OSError, io.UnsupportedOperation):
        data = stream.read()
        buffer = io.BytesIO(data)
        return hashlib.sha256(data).hexdigest(), buffer

    digest = hashlib.sha256()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest(), stream


@contextmanager
def _opened(path_or_stream, mode):
    """
    Open a path for the given mode, or use a caller-provided stream as-is.

    Streams owned by the caller are left open; paths are closed here.
    """
    if isinstance(path_or_stream, (str, bytes)) or hasattr(
        path_or_stream, "__fspath__"
    ):
        with open(path_or_stream, mode) as fp:
            yield fp
    else:
        yield path_or_stream


def _scan_sections(stream, predicate):
    """
    Read the source and group block records by source section.

    Every record stores its own scanner-provided position; records are
    compared by identity, so identical packets always stay separate.
    """
    sections = []
    current = None
    scanner = FileScanner(stream)

    for block in scanner:
        record = {
            "block": block,
            "source_block_index": scanner.block_index,
            "source_offset": scanner.block_offset,
            "source_length": scanner.block_length,
            "source_block_type": scanner.block_type,
        }
        if isinstance(block, blocks.SectionHeader):
            current = {
                "source_section_index": len(sections),
                "shb": record,
                "blocks": [],
                "has_selection": False,
            }
            sections.append(current)
            continue

        if current is None:
            raise DeriveError("source does not start with a section header")

        record["selected"] = _is_packet(block) and bool(predicate(block))
        if record["selected"]:
            current["has_selection"] = True
        current["blocks"].append(record)

    return sections


def _interface_map(section, selected_records):
    """
    Compute the interface closure and output renumbering for a section.

    Returns ``(ordered_source_ids, {source_interface_id: output_interface_id})``;
    the order follows the first selected packet using each interface, so IDBs
    are emitted deterministically and renumbered from zero.
    """
    source_interfaces = section["shb"]["block"].interfaces
    ordered = []
    mapping = {}
    for record in selected_records:
        source_id = record["block"].interface_id
        if source_id not in source_interfaces:
            raise DeriveError(
                "selected packet at source offset {off} refers to unknown "
                "interface {iid}".format(off=record["source_offset"], iid=source_id)
            )
        if source_id not in mapping:
            mapping[source_id] = len(mapping)
            ordered.append(source_id)
    return ordered, mapping


def _validate_interface_map(section, interface_map):
    """
    Refuse selections that cannot be represented faithfully in the output.

    Currently this concerns Simple Packet Blocks, which always refer to the
    first interface of their section.  Validation runs before anything is
    written so a rejected selection never leaves a partial derived file.
    """
    for record in section["blocks"]:
        if not record["selected"]:
            continue
        block = record["block"]
        if not isinstance(block, blocks.SimplePacket):
            continue
        if len(interface_map) != 1 or interface_map.get(0) != 0:
            raise DeriveError(
                "selected SimplePacket at source offset {off} cannot be "
                "represented in the derived section: Simple Packet Blocks "
                "always refer to the first interface, but the section needs "
                "interface mapping {mapping}".format(
                    off=record["source_offset"], mapping=interface_map
                )
            )


def _build_section_header(source_shb):
    return blocks.SectionHeader(
        endianness=source_shb.endianness,
        version_major=source_shb.version_major,
        version_minor=source_shb.version_minor,
        options=_copy_options(source_shb.options),
    )


def _build_interface(out_shb, source_idb):
    return out_shb.new_member(
        blocks.InterfaceDescription,
        link_type=source_idb.link_type,
        reserved=source_idb.reserved,
        snaplen=source_idb.snaplen,
        options=_copy_options(source_idb.options),
    )


def _build_packet(out_shb, record, interface_map):
    """Return (output block, source interface id, output interface id, converted)."""
    source = record["block"]
    source_interface_id = source.interface_id
    output_interface_id = interface_map[source_interface_id]

    if isinstance(source, blocks.ObsoletePacket):
        options = _copy_options(source.options)
        for old, new in (("pack_flags", "epb_flags"), ("pack_hash", "epb_hash")):
            if old in options:
                options[new] = options.pop(old)
        if source.drops_count:
            options["epb_dropcount"] = [source.drops_count]
        return (
            out_shb.new_member(
                blocks.EnhancedPacket,
                interface_id=output_interface_id,
                timestamp_high=source.timestamp_high,
                timestamp_low=source.timestamp_low,
                packet_len=source.packet_len,
                packet_data=bytes(source.packet_data),
                options=options,
            ),
            source_interface_id,
            output_interface_id,
            True,
        )

    if isinstance(source, blocks.SimplePacket):
        # Validated before writing; see _validate_interface_map().
        return (
            out_shb.new_member(
                blocks.SimplePacket,
                packet_len=source.packet_len,
                packet_data=bytes(source.packet_data),
            ),
            source_interface_id,
            output_interface_id,
            False,
        )

    return (
        out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=output_interface_id,
            timestamp_high=source.timestamp_high,
            timestamp_low=source.timestamp_low,
            packet_len=source.packet_len,
            packet_data=bytes(source.packet_data),
            options=_copy_options(source.options),
        ),
        source_interface_id,
        output_interface_id,
        False,
    )


def _build_retained(out_shb, source, interface_map):
    """Copy a retained NRB/ISB; return the output block or None if not applicable."""
    if isinstance(source, blocks.NameResolution):
        return out_shb.new_member(
            blocks.NameResolution,
            records=copy.deepcopy(source.records),
            options=_copy_options(source.options),
        )
    if isinstance(source, blocks.InterfaceStatistics):
        if source.interface_id not in interface_map:
            return None
        return out_shb.new_member(
            blocks.InterfaceStatistics,
            interface_id=interface_map[source.interface_id],
            timestamp_high=source.timestamp_high,
            timestamp_low=source.timestamp_low,
            options=_copy_options(source.options),
        )
    return None


def _derive_section(
    outstream,
    section,
    source_digest,
    output_section_index,
    entries,
    include_name_resolution,
    include_interface_statistics,
):
    selected_records = [record for record in section["blocks"] if record["selected"]]
    ordered_ids, interface_map = _interface_map(section, selected_records)
    source_shb = section["shb"]["block"]
    out_shb = _build_section_header(source_shb)

    def emit(block, record, kind, **kwargs):
        offset = outstream.tell()
        block._write(outstream)
        entries.append(
            ManifestEntry(
                kind=kind,
                source_digest=source_digest,
                source_section_index=section["source_section_index"],
                source_block_index=record["source_block_index"],
                source_offset=record["source_offset"],
                source_length=record["source_length"],
                source_block_type=record["source_block_type"],
                output_section_index=output_section_index,
                output_block_index=len(entries),
                output_offset=offset,
                output_length=outstream.tell() - offset,
                output_block_type=block.magic_number,
                **kwargs
            )
        )

    emit(out_shb, section["shb"], "section_header")

    source_interfaces = source_shb.interfaces
    interface_records = []
    for source_id in ordered_ids:
        idb_record = None
        for record in section["blocks"]:
            block = record["block"]
            if (
                isinstance(block, blocks.InterfaceDescription)
                and block.interface_id == source_id
            ):
                idb_record = record
                break
        if idb_record is None:
            raise DeriveError(
                "source interface {iid} is not described by an IDB".format(
                    iid=source_id
                )
            )
        emit(
            _build_interface(out_shb, source_interfaces[source_id]),
            idb_record,
            "interface_description",
            source_interface_id=source_id,
            output_interface_id=interface_map[source_id],
        )
        interface_records.append(
            {
                "source_interface_id": source_id,
                "output_interface_id": interface_map[source_id],
            }
        )

    packets_in_section = 0
    retained_in_section = 0
    retained_by_kind = {"name_resolution": 0, "interface_statistics": 0}
    retained_skipped = {"name_resolution": 0, "interface_statistics": 0}

    for record in section["blocks"]:
        block = record["block"]

        if record["selected"]:
            out_block, source_id, output_id, converted = _build_packet(
                out_shb, record, interface_map
            )
            emit(
                out_block,
                record,
                _kind(block),
                source_interface_id=source_id,
                output_interface_id=output_id,
                converted=converted,
            )
            packets_in_section += 1
            continue

        if isinstance(block, blocks.NameResolution):
            if not include_name_resolution:
                continue
        elif isinstance(block, blocks.InterfaceStatistics):
            if not include_interface_statistics:
                continue
        else:
            continue

        out_block = _build_retained(out_shb, block, interface_map)
        if out_block is None:
            # An ISB for an interface with no selected packets is dropped:
            # retaining it would need an IDB that the closure excludes.
            retained_skipped["interface_statistics"] += 1
            continue
        is_stats = isinstance(block, blocks.InterfaceStatistics)
        emit(
            out_block,
            record,
            _kind(block),
            source_interface_id=block.interface_id if is_stats else None,
            output_interface_id=interface_map[block.interface_id] if is_stats else None,
            retained=True,
        )
        retained_in_section += 1
        retained_by_kind[
            "name_resolution"
            if isinstance(block, blocks.NameResolution)
            else "interface_statistics"
        ] += 1

    return {
        "source_section_index": section["source_section_index"],
        "output_section_index": output_section_index,
        "source_shb_block_index": section["shb"]["source_block_index"],
        "interfaces": interface_records,
        "packets": packets_in_section,
        "retained_blocks": retained_in_section,
        "retained": retained_by_kind,
        "retained_skipped": retained_skipped,
    }


def derive_capture(
    source,
    destination,
    predicate,
    include_name_resolution=False,
    include_interface_statistics=False,
):
    """
    Write a filtered copy of a pcap-ng capture and return its manifest.

    :param source:
        input file path, or a seekable binary file-like object.
        The object is not closed by this function.
    :param destination:
        output file path, or a binary file-like object.
        The object is not closed (but is flushed) by this function.
    :param predicate:
        callable invoked once for every packet block (EnhancedPacket,
        SimplePacket, ObsoletePacket) in source order.  Returning true
        selects the packet.  Occurrence identity is preserved: packets are
        never deduplicated by content.
    :param include_name_resolution:
        copy Name Resolution Blocks verbatim.  They continue to describe the
        original capture, not the filtered subset.
    :param include_interface_statistics:
        copy Interface Statistics Blocks verbatim for interfaces used by
        selected packets.  Values are not recomputed and still describe the
        original capture.

    :return: a :py:class:`DeriveManifest` binding every output block to the
        source block byte range, and the input and output files to their
        SHA-256 digests.
    """
    if not callable(predicate):
        raise TypeError("predicate must be callable")

    with _opened(source, "rb") as source_stream:
        source_digest, scan_stream = _hash_stream(source_stream)
        sections = _scan_sections(scan_stream, predicate)
        if not sections:
            raise DeriveError("source stream contains no pcap-ng section header")

        # A capture with no selected packets still gets a valid, readable
        # output: the first section header is copied so the derived file
        # remains a pcap-ng capture with zero packets and zero interfaces.
        targets = [section for section in sections if section["has_selection"]]
        if not targets:
            targets = sections[:1]

        # Validate everything that could make faithful output impossible
        # before opening the destination, so failures leave no partial file.
        for section in targets:
            selected_records = [
                record for record in section["blocks"] if record["selected"]
            ]
            _validate_interface_map(
                section, _interface_map(section, selected_records)[1]
            )

        entries = []
        section_summaries = []
        retained_summary = {
            "name_resolution": {
                "requested": bool(include_name_resolution),
                "blocks_copied": 0,
                "blocks_skipped": 0,
                "represent_filtered_output": False,
            },
            "interface_statistics": {
                "requested": bool(include_interface_statistics),
                "blocks_copied": 0,
                "blocks_skipped": 0,
                "represent_filtered_output": False,
            },
        }

        with _opened(destination, "wb") as destination_stream:
            destination_stream = _HashingWriter(destination_stream)
            for section in targets:
                summary = _derive_section(
                    destination_stream,
                    section,
                    source_digest,
                    len(section_summaries),
                    entries,
                    include_name_resolution,
                    include_interface_statistics,
                )
                section_summaries.append(summary)
                for kind, count in summary["retained"].items():
                    retained_summary[kind]["blocks_copied"] += count
                for kind, count in summary["retained_skipped"].items():
                    retained_summary[kind]["blocks_skipped"] += count

            try:
                destination_stream.flush()
            except AttributeError:
                pass
            output_digest = destination_stream.hasher.hexdigest()

    return DeriveManifest(
        source_digest=source_digest,
        output_digest=output_digest,
        entries=entries,
        sections=section_summaries,
        retained=retained_summary,
        selected_packets=sum(section["packets"] for section in section_summaries),
    )


def _index_blocks(stream):
    """
    Scan a capture and return (digest, {offset: (block, type, length, index)}).
    """
    digest, scan_stream = _hash_stream(stream)
    index = {}
    scanner = FileScanner(scan_stream)
    for block in scanner:
        index[scanner.block_offset] = (
            block,
            scanner.block_type,
            scanner.block_length,
            scanner.block_index,
        )
    return digest, index


def _check_entry(entry, source_index, output_index):
    if entry.source_offset not in source_index:
        raise DeriveError(
            "source offset {0} not found for output block {1}".format(
                entry.source_offset, entry.output_block_index
            )
        )
    if entry.output_offset not in output_index:
        raise DeriveError(
            "output offset {0} not found for source block {1}".format(
                entry.output_offset, entry.source_block_index
            )
        )

    s_block, s_type, s_length, s_index = source_index[entry.source_offset]
    o_block, o_type, o_length, o_index = output_index[entry.output_offset]

    if s_type != entry.source_block_type or s_length != entry.source_length:
        raise DeriveError(
            "source block at offset {0} does not match manifest".format(
                entry.source_offset
            )
        )
    if o_type != entry.output_block_type or o_length != entry.output_length:
        raise DeriveError(
            "output block at offset {0} does not match manifest".format(
                entry.output_offset
            )
        )
    if s_index != entry.source_block_index or o_index != entry.output_block_index:
        raise DeriveError(
            "block index mismatch at source offset {0} / output offset {1}".format(
                entry.source_offset, entry.output_offset
            )
        )

    if entry.kind in ("enhanced_packet", "simple_packet", "obsolete_packet"):
        if bytes(s_block.packet_data) != bytes(o_block.packet_data):
            raise DeriveError(
                "packet data differs between source offset {0} and output "
                "offset {1}".format(entry.source_offset, entry.output_offset)
            )
        if s_block.packet_len != o_block.packet_len:
            raise DeriveError(
                "original packet length differs between source offset {0} and "
                "output offset {1}".format(entry.source_offset, entry.output_offset)
            )
        if entry.kind != "simple_packet":
            if (s_block.timestamp_high, s_block.timestamp_low) != (
                o_block.timestamp_high,
                o_block.timestamp_low,
            ):
                raise DeriveError(
                    "packet timestamp differs between source offset {0} and "
                    "output offset {1}".format(
                        entry.source_offset, entry.output_offset
                    )
                )
        if s_block.interface_id != entry.source_interface_id:
            raise DeriveError(
                "source interface differs from manifest at offset {0}".format(
                    entry.source_offset
                )
            )
        if o_block.interface_id != entry.output_interface_id:
            raise DeriveError(
                "output interface differs from manifest at offset {0}".format(
                    entry.output_offset
                )
            )

    if entry.kind == "interface_description":
        if (
            s_block.interface_id != entry.source_interface_id
            or o_block.interface_id != entry.output_interface_id
        ):
            raise DeriveError(
                "interface identifier mismatch for IDB mapping {0} -> {1}".format(
                    entry.source_interface_id, entry.output_interface_id
                )
            )

    return True


def verify_derived_capture(source, derived, manifest):
    """
    Re-read both captures and check the manifest against them.

    Confirms that:

    * the SHA-256 of the source matches ``manifest.source_digest``;
    * the SHA-256 of the derived file matches ``manifest.output_digest``
      (when the manifest recorded one);
    * every manifest entry points at existing, non-overlapping source and
      output blocks with the recorded type and length;
    * both source and output block indexes are unique;
    * packet payloads are byte-identical between source and output, and the
      interface identifiers match the manifest mapping.

    :return: ``True`` when everything matches.
    :raises: :py:class:`~pcapng.exceptions.DeriveError` on the first
        inconsistency.
    """
    with _opened(source, "rb") as source_stream:
        source_digest, source_index = _index_blocks(source_stream)
    with _opened(derived, "rb") as derived_stream:
        derived_digest, output_index = _index_blocks(derived_stream)

    if source_digest != manifest.source_digest:
        raise DeriveError(
            "source digest {0} does not match manifest digest {1}".format(
                source_digest, manifest.source_digest
            )
        )
    if manifest.output_digest is not None and derived_digest != manifest.output_digest:
        raise DeriveError(
            "derived digest {0} does not match manifest digest {1}".format(
                derived_digest, manifest.output_digest
            )
        )

    source_offsets = set()
    output_offsets = set()
    source_indexes = set()
    output_indexes = set()
    for entry in manifest.entries:
        if entry.source_digest != manifest.source_digest:
            raise DeriveError("manifest entry has a different source digest")
        if entry.source_offset in source_offsets:
            raise DeriveError(
                "duplicate source offset {0} in manifest".format(entry.source_offset)
            )
        if entry.output_offset in output_offsets:
            raise DeriveError(
                "duplicate output offset {0} in manifest".format(entry.output_offset)
            )
        if entry.source_block_index in source_indexes:
            raise DeriveError(
                "duplicate source block index {0} in manifest".format(
                    entry.source_block_index
                )
            )
        if entry.output_block_index in output_indexes:
            raise DeriveError(
                "duplicate output block index {0} in manifest".format(
                    entry.output_block_index
                )
            )
        source_offsets.add(entry.source_offset)
        output_offsets.add(entry.output_offset)
        source_indexes.add(entry.source_block_index)
        output_indexes.add(entry.output_block_index)
        _check_entry(entry, source_index, output_index)

    if len(output_index) != len(manifest.entries):
        raise DeriveError(
            "derived file has {0} blocks but manifest describes {1}".format(
                len(output_index), len(manifest.entries)
            )
        )

    return True
