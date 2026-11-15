"""
Merge multiple pcap-ng capture segments into a single output file.

The merge entry point uses an *explicit* interface mapping supplied by
the caller: interfaces coming from different sources are only merged
when the caller's mapping declares them to be the same logical
interface *and* their capture metadata is compatible.  Interface id,
interface name or link type alone are never considered sufficient
proof of identity.

Packets are written to the output in input order -- sources in the
order they were given, blocks in file order within each source.  No
timestamp-based reordering is ever attempted.

Interface statistics blocks are copied verbatim (with the interface
reference rewritten); counters from different sources are never summed
into a single cumulative value.
"""

from collections import namedtuple

import pcapng.blocks as blocks
from pcapng.exceptions import PcapngException
from pcapng.scanner import FileScanner
from pcapng.structs import write_bytes_padded, write_int
from pcapng.writer import FileWriter

PROVENANCE_COMMENT_PREFIX = "pcapng-merge:"


class MergeError(PcapngException):
    """Base class for errors raised while merging capture files"""

    pass


class MergeConflictError(MergeError):
    """
    Raised when interfaces the caller mapped together have incompatible
    capture metadata and ``on_conflict="raise"`` was requested.
    """

    pass


class CaptureSource(namedtuple("CaptureSource", ["source_id", "stream"])):
    """
    A named pcap-ng input stream to merge.

    ``source_id`` is the caller-provided identity of the capture source;
    it is used as part of the interface mapping keys and recorded in the
    merge report and in the output file provenance comments.
    """

    __slots__ = ()


class InterfaceMergeRecord(object):
    """
    Record of the merge decision taken for one source interface.

    ``action`` is one of:

    - ``"new"``: a fresh output interface was created
    - ``"merged"``: the interface was merged into an existing output
      interface, as requested by the caller's mapping
    - ``"separate"``: the caller's mapping requested a merge, but the
      capture metadata was incompatible, so a separate output interface
      was kept (see ``reasons``)
    """

    __slots__ = [
        "source_id",
        "source_interface_id",
        "output_interface_id",
        "action",
        "reasons",
    ]

    def __init__(
        self, source_id, source_interface_id, output_interface_id, action, reasons
    ):
        self.source_id = source_id
        self.source_interface_id = source_interface_id
        self.output_interface_id = output_interface_id
        self.action = action
        self.reasons = list(reasons)

    def __repr__(self):
        return (
            "<InterfaceMergeRecord source={0.source_id!r} "
            "interface={0.source_interface_id} -> "
            "output={0.output_interface_id} action={0.action!r} "
            "reasons={0.reasons!r}>"
        ).format(self)


class MergeReport(object):
    """
    Outcome of a merge: one record per source interface, plus the
    reverse mapping of output interfaces to their contributing sources.
    """

    __slots__ = ["interfaces", "output_interface_sources"]

    def __init__(self):
        self.interfaces = []
        self.output_interface_sources = {}

    def record_for(self, source_id, interface_id):
        """Return the decision record for the given source interface"""
        for record in self.interfaces:
            if (
                record.source_id == source_id
                and record.source_interface_id == interface_id
            ):
                return record
        return None


def _normalize_source(source, index):
    if isinstance(source, CaptureSource):
        return source
    if isinstance(source, (tuple, list)) and len(source) == 2:
        return CaptureSource(source[0], source[1])
    if hasattr(source, "read"):
        return CaptureSource(index, source)
    raise TypeError("cannot use {0!r} as a capture source".format(source))


def _unknown_options(options):
    """Return the raw values of options not described by the schema"""
    return {
        code: list(values)
        for code, values in options.data.items()
        if code not in options.schema
    }


def interface_conflicts(first, second):
    """
    Compare the capture metadata of two interfaces and return a list of
    human-readable incompatibility reasons (empty when compatible).

    Only metadata that affects how packets are interpreted is considered:
    link type, snaplen, timestamp resolution, capture filter and any
    unknown (schema-less) options.  Descriptive options such as the
    interface name may differ freely.
    """
    reasons = []
    if first.link_type != second.link_type:
        reasons.append(
            "link_type differs: {0} != {1}".format(first.link_type, second.link_type)
        )
    if first.snaplen != second.snaplen:
        reasons.append(
            "snaplen differs: {0} != {1}".format(first.snaplen, second.snaplen)
        )
    if first.timestamp_resolution != second.timestamp_resolution:
        reasons.append(
            "timestamp resolution differs: {0!r} != {1!r}".format(
                first.timestamp_resolution, second.timestamp_resolution
            )
        )
    if first.options.get_all("if_filter") != second.options.get_all("if_filter"):
        reasons.append(
            "if_filter differs: {0!r} != {1!r}".format(
                first.options.get_all("if_filter"),
                second.options.get_all("if_filter"),
            )
        )
    unknown_first = _unknown_options(first.options)
    unknown_second = _unknown_options(second.options)
    for code in sorted(set(unknown_first) | set(unknown_second)):
        if unknown_first.get(code) != unknown_second.get(code):
            reasons.append(
                "unknown option {0} differs: {1!r} != {2!r}".format(
                    code, unknown_first.get(code), unknown_second.get(code)
                )
            )
    return reasons


def _copy_options(options):
    return {name: values for name, values in options.iter_all_items()}


def _provenance_comment(source_id, interface_id):
    return "{0} source {1!r} interface {2}".format(
        PROVENANCE_COMMENT_PREFIX, source_id, interface_id
    )


def merge_capture_files(
    sources,
    output,
    interface_map=None,
    on_conflict="separate",
    shb_options=None,
    endianness="<",
):
    """
    Merge several pcap-ng capture segments into one output stream.

    :param sources:
        an iterable of :py:class:`CaptureSource` (or ``(source_id,
        stream)`` tuples, or bare streams, which get numbered).
        Sources are written to the output in the given order.

    :param output:
        a file-like object the merged capture is written to.

    :param interface_map:
        an explicit mapping of ``{(source_id, interface_id): key}``.
        Interfaces mapped to the same key are merged into a single
        output interface, provided their capture metadata is compatible
        (see :py:func:`interface_conflicts`).  Interfaces not present in
        the mapping are always kept separate -- identity is never
        guessed from interface ids, names or link types.

    :param on_conflict:
        what to do when interfaces mapped together have incompatible
        metadata: ``"separate"`` (default) keeps them as independent
        output interfaces; ``"raise"`` raises
        :py:class:`MergeConflictError`.

    :param shb_options:
        options for the output section header.

    :param endianness:
        endianness of the output file.

    :returns:
        a :py:class:`MergeReport` describing every merge decision and
        the reasons for any conflict, so the result can be reviewed.

    .. note::

        Packet order follows the input order; packets are *not*
        reordered by timestamp.  Interface statistics blocks are copied
        per source with their interface reference rewritten -- counters
        from different sources are never combined into one value.
    """
    if on_conflict not in ("separate", "raise"):
        raise ValueError("on_conflict must be 'separate' or 'raise'")
    interface_map = interface_map or {}
    sources = [_normalize_source(source, i) for i, source in enumerate(sources)]

    out_shb = blocks.SectionHeader(endianness=endianness, options=shb_options or {})
    report = MergeReport()

    # Phase 1: scan all sources.  Interfaces are registered in order of
    # first appearance; every other block is buffered for the replay.
    pending = []  # (source_id, block), in input order
    key_to_output = {}  # merge key -> (output idb, representative source idb)
    id_map = {}  # (source_id, source interface_id) -> output interface_id

    def register_interface(source_id, src_idb):
        src_ifid = src_idb.interface_id
        key = interface_map.get(
            (source_id, src_ifid), ("__unique__", source_id, src_ifid)
        )
        existing = key_to_output.get(key)
        if existing is None:
            out_idb = _create_output_interface(out_shb, src_idb, source_id, src_ifid)
            key_to_output[key] = (out_idb, src_idb)
            action, reasons = "new", []
        else:
            out_idb, representative = existing
            reasons = interface_conflicts(representative, src_idb)
            if not reasons:
                action = "merged"
                out_idb.options.add(
                    "opt_comment", _provenance_comment(source_id, src_ifid)
                )
            elif on_conflict == "raise":
                raise MergeConflictError(
                    "interfaces mapped together are incompatible: "
                    + "; ".join(reasons)
                )
            else:
                out_idb = _create_output_interface(
                    out_shb, src_idb, source_id, src_ifid
                )
                action = "separate"
        id_map[(source_id, src_ifid)] = out_idb.interface_id
        report.interfaces.append(
            InterfaceMergeRecord(
                source_id, src_ifid, out_idb.interface_id, action, reasons
            )
        )
        report.output_interface_sources.setdefault(out_idb.interface_id, []).append(
            (source_id, src_ifid)
        )

    for source in sources:
        for blk in FileScanner(source.stream):
            if isinstance(blk, blocks.SectionHeader):
                continue
            if isinstance(blk, blocks.InterfaceDescription):
                register_interface(source.source_id, blk)
            else:
                pending.append((source.source_id, blk))

    # Phase 2: write the output section, then replay the buffered
    # blocks in input order with interface references rewritten.
    # (FileWriter writes the section header and all registered
    # interface descriptions right away.)
    writer = FileWriter(output, out_shb)

    for source_id, blk in pending:
        _replay_block(writer, out_shb, id_map, source_id, blk)

    return report


def _create_output_interface(out_shb, src_idb, source_id, src_ifid):
    options = _copy_options(src_idb.options)
    comments = list(options.get("opt_comment", []))
    comments.append(_provenance_comment(source_id, src_ifid))
    options["opt_comment"] = comments
    return out_shb.new_member(
        blocks.InterfaceDescription,
        link_type=src_idb.link_type,
        reserved=src_idb.reserved,
        snaplen=src_idb.snaplen,
        options=options,
    )


def _output_interface_id(id_map, source_id, src_ifid):
    try:
        return id_map[(source_id, src_ifid)]
    except KeyError:
        raise MergeError(
            "no interface description found for interface {0} of "
            "source {1!r}".format(src_ifid, source_id)
        )


def _replay_block(writer, out_shb, id_map, source_id, blk):
    if isinstance(blk, blocks.EnhancedPacket):
        out_blk = out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=_output_interface_id(id_map, source_id, blk.interface_id),
            timestamp_high=blk.timestamp_high,
            timestamp_low=blk.timestamp_low,
            packet_len=blk.packet_len,
            packet_data=blk.packet_data,
            options=_copy_options(blk.options),
        )
    elif isinstance(blk, blocks.ObsoletePacket):
        options = _copy_options(blk.options)
        for name in ("flags", "hash"):
            try:
                options["epb_" + name] = options.pop("pack_" + name)
            except KeyError:
                pass
        options["epb_dropcount"] = [blk.drops_count]
        out_blk = out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=_output_interface_id(id_map, source_id, blk.interface_id),
            timestamp_high=blk.timestamp_high,
            timestamp_low=blk.timestamp_low,
            packet_len=blk.packet_len,
            packet_data=blk.packet_data,
            options=options,
        )
    elif isinstance(blk, blocks.SimplePacket):
        out_ifid = _output_interface_id(id_map, source_id, 0)
        if out_ifid == 0:
            out_blk = out_shb.new_member(
                blocks.SimplePacket,
                packet_len=blk.packet_len,
                packet_data=blk.packet_data,
            )
        else:
            # A SimplePacket always refers to the first interface of its
            # section; convert to an enhanced packet to preserve the
            # interface reference.
            out_blk = out_shb.new_member(
                blocks.EnhancedPacket,
                interface_id=out_ifid,
                timestamp_high=0,
                timestamp_low=0,
                packet_len=blk.packet_len,
                packet_data=blk.packet_data,
            )
    elif isinstance(blk, blocks.InterfaceStatistics):
        # Copied verbatim (interface reference rewritten); counters from
        # different sources are never summed into one cumulative value.
        out_blk = out_shb.new_member(
            blocks.InterfaceStatistics,
            interface_id=_output_interface_id(id_map, source_id, blk.interface_id),
            timestamp_high=blk.timestamp_high,
            timestamp_low=blk.timestamp_low,
            options=_copy_options(blk.options),
        )
    elif isinstance(blk, blocks.NameResolution):
        out_blk = out_shb.new_member(
            blocks.NameResolution,
            records=blk.records,
            options=_copy_options(blk.options),
        )
    elif isinstance(blk, blocks.UnknownBlock):
        _write_unknown_block(writer.stream, blk, out_shb.endianness)
        return
    else:
        raise MergeError("don't know how to merge block {0!r}".format(blk))
    writer.write_block(out_blk)


def _write_unknown_block(stream, blk, endianness):
    payload = blk.data
    block_length = 12 + len(payload)
    if len(payload) % 4 != 0:
        block_length += 4 - (len(payload) % 4)
    write_int(blk.block_type, stream, 32, endianness=endianness)
    write_int(block_length, stream, 32, endianness=endianness)
    write_bytes_padded(stream, payload)
    write_int(block_length, stream, 32, endianness=endianness)
