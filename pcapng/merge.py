"""
Merge several pcap-ng streams into a single capture, using an explicit,
caller-provided interface mapping.

The merger never *guesses* which interfaces are the same: two interfaces
are merged only when the caller explicitly declares them identical (via
``interface_groups``) **and** their capture metadata turns out to be
compatible.  Interface id, interface name or link type alone are never
considered sufficient proof of identity.

Packets are written to the output in input order (the order in which the
input streams are passed, and the block order within each stream); no
timestamp-based reordering is ever performed.

Every merge decision is recorded in the returned :py:class:`MergeReport`,
and provenance information is embedded in the output itself (as
``opt_comment`` options on the generated interface description and
statistics blocks), so that renumbering interface ids never loses track
of where the data came from.
"""

from pcapng import blocks
from pcapng.exceptions import InterfaceMergeConflict
from pcapng.scanner import FileScanner
from pcapng.writer import FileWriter

#: Decision actions recorded in the merge report
ACTION_CREATED = "created"
ACTION_MERGED = "merged"
ACTION_KEPT_SEPARATE = "kept-separate"

#: Merge policies for conflicting interfaces
POLICY_SEPARATE = "separate"
POLICY_ERROR = "error"

#: Tag used in opt_comment provenance records
PROVENANCE_TAG = "pcapng-merge"

#: Interface options whose values must match for two interfaces to be
#: considered the same.  Codes: 9 = if_tsresol, 11 = if_filter,
#: 14 = if_tsoffset.
_CRITICAL_OPTION_CODES = (
    (11, "if_filter"),
    (14, "if_tsoffset"),
)


class InterfaceDecision(object):
    """
    Record of how one source interface was mapped to the output.

    Attributes:

    - ``source``: caller-provided identity of the input stream
    - ``section``: index of the section within that stream
    - ``interface_id``: id of the interface within the source section
    - ``action``: one of ``created``, ``merged`` or ``kept-separate``
    - ``output_interface_id``: id of the interface in the merged output
    - ``group``: index of the caller-provided interface group, if any
    - ``reasons``: tuple of conflict descriptions (empty unless the
      action is ``kept-separate``)
    """

    __slots__ = (
        "source",
        "section",
        "interface_id",
        "action",
        "output_interface_id",
        "group",
        "reasons",
    )

    def __init__(
        self,
        source,
        section,
        interface_id,
        action,
        output_interface_id,
        group=None,
        reasons=(),
    ):
        self.source = source
        self.section = section
        self.interface_id = interface_id
        self.action = action
        self.output_interface_id = output_interface_id
        self.group = group
        self.reasons = tuple(reasons)

    def __repr__(self):
        return (
            "<InterfaceDecision source={0.source!r} section={0.section} "
            "interface={0.interface_id} action={0.action!r} "
            "output_interface={0.output_interface_id} reasons={0.reasons!r}>"
        ).format(self)


class MergeReport(object):
    """
    Outcome of a :py:func:`merge_streams` call.

    - ``decisions``: list of :py:class:`InterfaceDecision`, one per
      source interface encountered
    - ``statistics``: list of ``(source, section, interface_id,
      output_interface_id)`` for every Interface Statistics Block that
      was remapped (counters are always preserved verbatim, never
      combined)
    - ``packet_count``: number of packet blocks written to the output
    - ``notes``: human-readable notes about other events (eg. simple
      packet blocks converted to enhanced packet blocks, unknown blocks
      skipped)
    """

    __slots__ = ("decisions", "statistics", "packet_count", "notes")

    def __init__(self):
        self.decisions = []
        self.statistics = []
        self.packet_count = 0
        self.notes = []

    @property
    def merged(self):
        """Decisions for interfaces merged into an existing interface"""
        return [d for d in self.decisions if d.action == ACTION_MERGED]

    @property
    def kept_separate(self):
        """Decisions for interfaces kept separate due to conflicts"""
        return [d for d in self.decisions if d.action == ACTION_KEPT_SEPARATE]

    @property
    def conflicts(self):
        """Conflict reasons, keyed by (source, section, interface_id)"""
        return {
            (d.source, d.section, d.interface_id): d.reasons
            for d in self.kept_separate
        }

    def decision_for(self, source, section, interface_id):
        """Return the decision for the given source interface"""
        for decision in self.decisions:
            if (
                decision.source == source
                and decision.section == section
                and decision.interface_id == interface_id
            ):
                return decision
        raise KeyError((source, section, interface_id))

    def __repr__(self):
        return "<MergeReport {0} decisions, {1} packets, {2} conflicts>".format(
            len(self.decisions), self.packet_count, len(self.kept_separate)
        )


def _option_values(idb, code):
    # Note: use ``data.get()`` to avoid polluting the defaultdict
    return idb.options.data.get(code) or []


def _unknown_options(idb):
    """Options whose code is not described by the IDB options schema"""
    known = set(idb.options.schema)
    return {
        code: values
        for code, values in idb.options.data.items()
        if code not in known and values
    }


def interface_conflicts(first, second):
    """
    Compare two :py:class:`pcapng.blocks.InterfaceDescription` blocks and
    return a list of human-readable conflict descriptions.  An empty list
    means the two interfaces may refer to the same capture interface.

    Checked metadata: link type, snaplen, timestamp resolution (clock
    units), timestamp offset, capture filter, and any unknown options.
    The interface *name* is deliberately not considered: names are not
    a reliable identity.
    """
    conflicts = []

    if first.link_type != second.link_type:
        conflicts.append(
            "link_type differs: {0} vs {1}".format(first.link_type, second.link_type)
        )

    if first.snaplen != second.snaplen:
        conflicts.append(
            "snaplen differs: {0} vs {1}".format(first.snaplen, second.snaplen)
        )

    if first.timestamp_resolution != second.timestamp_resolution:
        conflicts.append(
            "timestamp resolution differs: {0!r} vs {1!r}".format(
                first.timestamp_resolution, second.timestamp_resolution
            )
        )

    for code, name in _CRITICAL_OPTION_CODES:
        values_first = _option_values(first, code)
        values_second = _option_values(second, code)
        if values_first != values_second:
            conflicts.append(
                "{0} differs: {1!r} vs {2!r}".format(name, values_first, values_second)
            )

    unknown_first = _unknown_options(first)
    unknown_second = _unknown_options(second)
    for code in sorted(set(unknown_first) | set(unknown_second)):
        if unknown_first.get(code) != unknown_second.get(code):
            conflicts.append(
                "unknown option {0} differs: {1!r} vs {2!r}".format(
                    code,
                    unknown_first.get(code),
                    unknown_second.get(code),
                )
            )

    return conflicts


def _provenance_comment(source, section, interface_id):
    return "{0}: source={1!r} section={2} interface={3}".format(
        PROVENANCE_TAG, source, section, interface_id
    )


def _copy_options(block):
    return dict(block.options.iter_all_items())


def _clone_interface(idb, out_shb, source, section):
    """Create a copy of the given IDB in the output section"""
    clone = out_shb.new_member(
        blocks.InterfaceDescription,
        link_type=idb.link_type,
        reserved=idb.reserved,
        snaplen=idb.snaplen,
        options=_copy_options(idb),
    )
    clone.options.add(
        "opt_comment", _provenance_comment(source, section, idb.interface_id)
    )
    return clone


def _read_sections(stream):
    """Read a whole stream, returning a list of sections (block lists)"""
    sections = []
    current = None
    for block in FileScanner(stream):
        if isinstance(block, blocks.SectionHeader):
            current = []
            sections.append(current)
        else:
            current.append(block)
    return sections


def merge_streams(
    inputs,
    output,
    interface_groups=(),
    on_conflict=POLICY_SEPARATE,
    shb_options=None,
    endianness="<",
):
    """
    Merge several pcap-ng streams into a single one-section output stream.

    :param inputs:
        iterable of ``(source, stream)`` pairs.  ``source`` is any
        hashable, caller-provided identity for the stream (eg. a host or
        probe name); ``stream`` is a file-like object positioned at the
        start of a pcap-ng capture.  Input order defines the packet order
        in the output; packets are never reordered by timestamp.

    :param output:
        a file-like object to which the merged capture is written.

    :param interface_groups:
        iterable of groups; each group is an iterable of
        ``(source, interface_id)`` pairs explicitly declared by the
        caller to be the same capture interface.  Interfaces not listed
        in any group are always kept separate.  Declared interfaces are
        merged only if their metadata is compatible (see
        :py:func:`interface_conflicts`).

    :param on_conflict:
        what to do when interfaces declared identical have conflicting
        metadata: ``"separate"`` (default) keeps them as distinct output
        interfaces and records the reasons in the report; ``"error"``
        raises :py:class:`pcapng.exceptions.InterfaceMergeConflict`.

    :param shb_options:
        options for the output Section Header Block.

    :param endianness:
        endianness of the output section (``"<"`` or ``">"``).

    :return:
        a :py:class:`MergeReport` describing every merge decision.
    """
    if on_conflict not in (POLICY_SEPARATE, POLICY_ERROR):
        raise ValueError("on_conflict must be 'separate' or 'error'")

    inputs = list(inputs)
    group_of = {}
    for group_index, group in enumerate(interface_groups):
        for key in group:
            if len(key) != 2:
                raise ValueError(
                    "interface group entries must be (source, interface_id) pairs"
                )
            if key in group_of:
                raise ValueError(
                    "interface {0!r} appears in more than one group".format(key)
                )
            group_of[key] = group_index

    # Read all inputs up-front: the interface mapping must be fully
    # resolved before anything is written, so that provenance comments
    # on merged interfaces are complete.
    prepared = [(source, _read_sections(stream)) for source, stream in inputs]

    out_shb = blocks.SectionHeader(endianness=endianness, options=shb_options or {})
    report = MergeReport()

    id_map = {}  # (source, section_idx, interface_id) -> output interface_id
    group_targets = {}  # group_index -> output IDB

    # ---- Pass 1: resolve the interface mapping ----------------------
    for source, sections in prepared:
        for section_index, section_blocks in enumerate(sections):
            for block in section_blocks:
                if not isinstance(block, blocks.InterfaceDescription):
                    continue
                key = (source, section_index, block.interface_id)
                group_index = group_of.get((source, block.interface_id))
                target = None
                if group_index is not None:
                    target = group_targets.get(group_index)

                if target is not None:
                    conflicts = interface_conflicts(target, block)
                    if conflicts:
                        if on_conflict == POLICY_ERROR:
                            raise InterfaceMergeConflict(
                                source, block.interface_id, conflicts
                            )
                        clone = _clone_interface(block, out_shb, source, section_index)
                        id_map[key] = clone.interface_id
                        report.decisions.append(
                            InterfaceDecision(
                                source,
                                section_index,
                                block.interface_id,
                                ACTION_KEPT_SEPARATE,
                                clone.interface_id,
                                group=group_index,
                                reasons=conflicts,
                            )
                        )
                        continue
                    # Compatible: merge into the existing output interface
                    target.options.add(
                        "opt_comment",
                        _provenance_comment(source, section_index, block.interface_id),
                    )
                    id_map[key] = target.interface_id
                    report.decisions.append(
                        InterfaceDecision(
                            source,
                            section_index,
                            block.interface_id,
                            ACTION_MERGED,
                            target.interface_id,
                            group=group_index,
                        )
                    )
                    continue

                clone = _clone_interface(block, out_shb, source, section_index)
                if group_index is not None:
                    group_targets[group_index] = clone
                id_map[key] = clone.interface_id
                report.decisions.append(
                    InterfaceDecision(
                        source,
                        section_index,
                        block.interface_id,
                        ACTION_CREATED,
                        clone.interface_id,
                        group=group_index,
                    )
                )

    # ---- Pass 2: write the merged stream ----------------------------
    # The writer immediately emits the section header and all interfaces
    # registered on it (in id order); packet/statistics blocks follow.
    writer = FileWriter(output, out_shb)
    for source, sections in prepared:
        for section_index, section_blocks in enumerate(sections):
            for block in section_blocks:
                if isinstance(block, blocks.InterfaceDescription):
                    continue  # already emitted (possibly remapped) above
                out_block = _remap_block(
                    block, source, section_index, id_map, out_shb, report
                )
                if out_block is not None:
                    writer.write_block(out_block)

    return report


def _remap_block(block, source, section_index, id_map, out_shb, report):
    """Create a copy of a block in the output section, with interface
    references rewritten according to the computed mapping."""

    def mapped(interface_id):
        return id_map[(source, section_index, interface_id)]

    if isinstance(block, blocks.EnhancedPacket):
        report.packet_count += 1
        return out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=mapped(block.interface_id),
            timestamp_high=block.timestamp_high,
            timestamp_low=block.timestamp_low,
            packet_len=block.packet_len,
            packet_data=block.packet_data,
            options=_copy_options(block),
        )

    if isinstance(block, blocks.ObsoletePacket):
        report.packet_count += 1
        options = _copy_options(block)
        for old, new in (("pack_flags", "epb_flags"), ("pack_hash", "epb_hash")):
            if old in options:
                options[new] = options.pop(old)
        options["epb_dropcount"] = [block.drops_count]
        return out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=mapped(block.interface_id),
            timestamp_high=block.timestamp_high,
            timestamp_low=block.timestamp_low,
            packet_len=block.packet_len,
            packet_data=block.packet_data,
            options=options,
        )

    if isinstance(block, blocks.SimplePacket):
        report.packet_count += 1
        interface_id = mapped(block.interface_id)
        if interface_id == 0:
            return out_shb.new_member(
                blocks.SimplePacket,
                packet_len=block.packet_len,
                packet_data=block.packet_data,
            )
        # A simple packet block implicitly refers to interface 0; if the
        # source interface was mapped elsewhere it must be converted to
        # an enhanced packet block to keep pointing at its interface.
        report.notes.append(
            "simple packet from source={0!r} section={1} converted to "
            "enhanced packet (interface remapped to {2})".format(
                source, section_index, interface_id
            )
        )
        return out_shb.new_member(
            blocks.EnhancedPacket,
            interface_id=interface_id,
            timestamp_high=0,
            timestamp_low=0,
            packet_len=block.packet_len,
            packet_data=block.packet_data,
        )

    if isinstance(block, blocks.InterfaceStatistics):
        interface_id = mapped(block.interface_id)
        report.statistics.append(
            (source, section_index, block.interface_id, interface_id)
        )
        stats = out_shb.new_member(
            blocks.InterfaceStatistics,
            interface_id=interface_id,
            timestamp_high=block.timestamp_high,
            timestamp_low=block.timestamp_low,
            options=_copy_options(block),
        )
        # Counters from different sources are never combined into a
        # single cumulative record; each statistics block is copied
        # verbatim and tagged with its origin.
        stats.options.add(
            "opt_comment",
            "{0}: statistics from source={1!r} section={2} interface={3}; "
            "counters preserved as captured, not combined".format(
                PROVENANCE_TAG, source, section_index, block.interface_id
            ),
        )
        return stats

    if isinstance(block, blocks.NameResolution):
        return out_shb.new_member(
            blocks.NameResolution,
            records=block.records,
            options=_copy_options(block),
        )

    report.notes.append(
        "skipped unsupported block {0!r} from source={1!r} section={2}".format(
            block, source, section_index
        )
    )
    return None
