import io

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter, merge_streams
from pcapng.exceptions import InterfaceMergeConflict
from pcapng.merge import (
    ACTION_CREATED,
    ACTION_KEPT_SEPARATE,
    ACTION_MERGED,
    interface_conflicts,
)
from pcapng.utils import pack_timestamp_resolution


def make_segment(
    packets=(b"packet-one", b"packet-two"),
    if_name="eth0",
    link_type=1,
    snaplen=65535,
    tsresol=None,
    if_filter=None,
    extra_options=None,
    timestamps=None,
    isb_options=None,
):
    """Build an in-memory pcapng segment with a single interface."""
    shb = blocks.SectionHeader()
    idb_options = {"if_name": if_name}
    if tsresol is not None:
        idb_options["if_tsresol"] = pack_timestamp_resolution(*tsresol)
    if if_filter is not None:
        idb_options["if_filter"] = [if_filter]
    if extra_options:
        idb_options.update(extra_options)
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=link_type,
        snaplen=snaplen,
        options=idb_options,
    )
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for index, data in enumerate(packets):
        timestamp = (timestamps or {}).get(index, index + 1)
        writer.write_block(
            shb.new_member(
                blocks.EnhancedPacket,
                interface_id=0,
                timestamp_high=timestamp >> 32,
                timestamp_low=timestamp & 0xFFFFFFFF,
                packet_data=data,
            )
        )
    if isb_options is not None:
        writer.write_block(
            shb.new_member(
                blocks.InterfaceStatistics, interface_id=0, options=isb_options
            )
        )
    return stream.getvalue()


def merge_segments(segments, **kwargs):
    """Merge ``{source: data}`` segments; return (output_bytes, report)."""
    output = io.BytesIO()
    inputs = [(source, io.BytesIO(data)) for source, data in segments]
    report = merge_streams(inputs, output, **kwargs)
    return output.getvalue(), report


def read_output(data):
    """Read back a merged capture, grouped as (interfaces, packets, stats)."""
    interfaces = []
    packets = []
    stats = []
    for block in FileScanner(io.BytesIO(data)):
        if isinstance(block, blocks.InterfaceDescription):
            interfaces.append(block)
        elif isinstance(block, blocks.EnhancedPacket):
            packets.append(block)
        elif isinstance(block, blocks.InterfaceStatistics):
            stats.append(block)
    return interfaces, packets, stats


def test_merge_explicitly_confirmed_same_interface():
    """Two segments the caller confirms are the same interface are merged,
    even though the interface names differ (names are not identity)."""
    segments = [
        ("probe-a", make_segment(if_name="eth0", packets=[b"a1", b"a2"])),
        ("probe-b", make_segment(if_name="renamed-eth0", packets=[b"b1"])),
    ]
    output, report = merge_segments(
        segments, interface_groups=[[("probe-a", 0), ("probe-b", 0)]]
    )

    interfaces, packets, _ = read_output(output)
    assert len(interfaces) == 1
    assert [pkt.interface_id for pkt in packets] == [0, 0, 0]
    assert [pkt.packet_data for pkt in packets] == [b"a1", b"a2", b"b1"]
    assert packets[2].interface is interfaces[0]

    # The merge decision is recorded and reviewable
    decision = report.decision_for("probe-b", 0, 0)
    assert decision.action == ACTION_MERGED
    assert decision.output_interface_id == 0
    assert report.kept_separate == []

    # Provenance survives the id renumbering, embedded in the output itself
    comments = interfaces[0].options.get_all("opt_comment")
    assert any("source='probe-a'" in c and "interface=0" in c for c in comments)
    assert any("source='probe-b'" in c and "interface=0" in c for c in comments)


def test_merge_preserves_input_order_without_timestamp_sorting():
    """Packets follow input order; no speculative timestamp reordering."""
    segments = [
        ("late", make_segment(packets=[b"late-one"], timestamps={0: 10**9})),
        ("early", make_segment(packets=[b"early-one"], timestamps={0: 1})),
    ]
    output, _ = merge_segments(segments)
    _, packets, _ = read_output(output)
    assert [pkt.packet_data for pkt in packets] == [b"late-one", b"early-one"]


def test_same_name_conflicting_settings_are_kept_separate():
    """Two interfaces both named eth0 but with different capture settings
    must not be merged, even if the caller declares them identical."""
    segments = [
        (
            "host-a",
            make_segment(
                if_name="eth0",
                snaplen=65535,
                tsresol=(10, 6),
                if_filter=(0, b"tcp port 80"),
                packets=[b"from-a"],
            ),
        ),
        (
            "host-b",
            make_segment(
                if_name="eth0",
                snaplen=262144,
                tsresol=(10, 9),
                if_filter=(0, b"udp"),
                packets=[b"from-b"],
            ),
        ),
    ]
    output, report = merge_segments(
        segments, interface_groups=[[("host-a", 0), ("host-b", 0)]]
    )

    interfaces, packets, _ = read_output(output)
    assert len(interfaces) == 2
    assert [pkt.interface_id for pkt in packets] == [0, 1]
    assert packets[0].interface is interfaces[0]
    assert packets[1].interface is interfaces[1]

    # The conflict reasons are recorded and reviewable
    decision = report.decision_for("host-b", 0, 0)
    assert decision.action == ACTION_KEPT_SEPARATE
    reasons = " ".join(decision.reasons)
    assert "snaplen" in reasons
    assert "timestamp resolution" in reasons
    assert "if_filter" in reasons
    assert report.conflicts[("host-b", 0, 0)] == decision.reasons

    # Each output interface keeps its own provenance
    for index, source in enumerate(("host-a", "host-b")):
        comments = interfaces[index].options.get_all("opt_comment")
        assert any("source='{0}'".format(source) in c for c in comments)


def test_conflicting_interfaces_with_error_policy():
    """With on_conflict='error' the merge is explicitly refused."""
    segments = [
        ("host-a", make_segment(snaplen=65535)),
        ("host-b", make_segment(snaplen=1500)),
    ]
    with pytest.raises(InterfaceMergeConflict) as excinfo:
        merge_segments(
            segments,
            interface_groups=[[("host-a", 0), ("host-b", 0)]],
            on_conflict="error",
        )
    assert excinfo.value.source == "host-b"
    assert any("snaplen" in reason for reason in excinfo.value.conflicts)


def test_no_implicit_merge_without_explicit_group():
    """Identical name, link type and settings are not enough: without an
    explicit caller-provided group, interfaces stay separate."""
    segment = make_segment(if_name="eth0")
    output, report = merge_segments([("host-a", segment), ("host-b", segment)])

    interfaces, packets, _ = read_output(output)
    assert len(interfaces) == 2
    assert [pkt.interface_id for pkt in packets] == [0, 0, 1, 1]
    assert all(d.action == ACTION_CREATED for d in report.decisions)


def test_statistics_remapped_but_never_combined():
    """Statistics from two merged sources keep their own counters."""
    segments = [
        ("probe-a", make_segment(isb_options={"isb_ifrecv": 100, "isb_ifdrop": 5})),
        ("probe-b", make_segment(isb_options={"isb_ifrecv": 250, "isb_ifdrop": 7})),
    ]
    output, report = merge_segments(
        segments, interface_groups=[[("probe-a", 0), ("probe-b", 0)]]
    )

    interfaces, _, stats = read_output(output)
    assert len(interfaces) == 1
    assert len(stats) == 2
    # Both statistics blocks point at the merged interface...
    assert [blk.interface_id for blk in stats] == [0, 0]
    # ...but the two counting sources are kept as distinct records,
    # not summed into one cumulative value.
    assert sorted(blk.options["isb_ifrecv"] for blk in stats) == [100, 250]
    assert sorted(blk.options["isb_ifdrop"] for blk in stats) == [5, 7]
    for blk in stats:
        comments = blk.options.get_all("opt_comment")
        assert any("not combined" in c for c in comments)
    assert sorted(report.statistics) == [
        ("probe-a", 0, 0, 0),
        ("probe-b", 0, 0, 0),
    ]


def test_unknown_option_conflict_kept_separate_and_preserved():
    """Conflicting unknown options prevent merging; matching ones pass
    through to the output unchanged."""
    segments = [
        ("host-a", make_segment(extra_options={4000: [b"vendor-a"]})),
        ("host-b", make_segment(extra_options={4000: [b"vendor-b"]})),
    ]
    output, report = merge_segments(
        segments, interface_groups=[[("host-a", 0), ("host-b", 0)]]
    )

    interfaces, _, _ = read_output(output)
    assert len(interfaces) == 2
    decision = report.decision_for("host-b", 0, 0)
    assert decision.action == ACTION_KEPT_SEPARATE
    assert any("unknown option 4000" in reason for reason in decision.reasons)
    # Unknown options survive the round trip
    assert interfaces[0].options[4000] == b"vendor-a"
    assert interfaces[1].options[4000] == b"vendor-b"


def test_matching_unknown_options_do_not_prevent_merge():
    segments = [
        ("host-a", make_segment(extra_options={4000: [b"same"]})),
        ("host-b", make_segment(extra_options={4000: [b"same"]})),
    ]
    output, report = merge_segments(
        segments, interface_groups=[[("host-a", 0), ("host-b", 0)]]
    )
    interfaces, _, _ = read_output(output)
    assert len(interfaces) == 1
    assert interfaces[0].options[4000] == b"same"
    assert report.merged


def test_interface_conflicts_detects_metadata_differences():
    shb = blocks.SectionHeader()
    base = shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_name": "eth0"},
    )
    same = shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_name": "completely-different-name"},
    )
    assert interface_conflicts(base, same) == []

    other_linktype = shb.new_member(
        blocks.InterfaceDescription, link_type=147, snaplen=65535
    )
    assert any("link_type" in c for c in interface_conflicts(base, other_linktype))


def test_invalid_group_entries_rejected():
    with pytest.raises(ValueError):
        merge_streams(
            [("a", io.BytesIO(make_segment()))],
            io.BytesIO(),
            interface_groups=[[("a", 0), ("a", 0)]],
        )


def test_multi_interface_source_remapping():
    """Only grouped interfaces are merged; other interfaces of the same
    source stay separate, and packet references follow the mapping."""

    def two_iface_segment(first_packets, second_packets):
        shb = blocks.SectionHeader()
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            snaplen=65535,
            options={"if_name": "mgmt0"},
        )
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            snaplen=65535,
            options={"if_name": "eth0"},
        )
        stream = io.BytesIO()
        writer = FileWriter(stream, shb)
        for data in first_packets:
            writer.write_block(
                shb.new_member(
                    blocks.EnhancedPacket, interface_id=0, packet_data=data
                )
            )
        for data in second_packets:
            writer.write_block(
                shb.new_member(
                    blocks.EnhancedPacket, interface_id=1, packet_data=data
                )
            )
        return stream.getvalue()

    segments = [
        ("host-a", two_iface_segment([b"a-mgmt"], [b"a-eth"])),
        ("host-b", two_iface_segment([b"b-mgmt"], [b"b-eth"])),
    ]
    output, report = merge_segments(
        segments, interface_groups=[[("host-a", 1), ("host-b", 1)]]
    )

    interfaces, packets, _ = read_output(output)
    # mgmt0 interfaces stay separate; the two eth0 interfaces are merged
    assert len(interfaces) == 3
    assert [pkt.packet_data for pkt in packets] == [
        b"a-mgmt",
        b"a-eth",
        b"b-mgmt",
        b"b-eth",
    ]
    assert [pkt.interface_id for pkt in packets] == [0, 1, 2, 1]
    assert report.decision_for("host-b", 0, 1).action == ACTION_MERGED
    assert report.decision_for("host-b", 0, 0).action == ACTION_CREATED
    # Packets read back point at the interface carrying their provenance
    for pkt, source in zip(packets, ("host-a", "host-a", "host-b", "host-b")):
        comments = pkt.interface.options.get_all("opt_comment")
        assert any("source='{0}'".format(source) in c for c in comments)


def test_simple_packet_converted_when_interface_remapped():
    """A simple packet block implicitly refers to interface 0; if that
    interface is remapped the packet is converted to an enhanced one."""
    shb = blocks.SectionHeader()
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=65535,
        options={"if_name": "eth0"},
    )
    segment = io.BytesIO()
    writer = FileWriter(segment, shb)
    writer.write_block(shb.new_member(blocks.SimplePacket, packet_data=b"simple"))

    # Another source occupies output interface 0 first
    output, report = merge_segments(
        [("first", make_segment()), ("second", segment.getvalue())]
    )

    interfaces, packets, _ = read_output(output)
    assert len(interfaces) == 2
    assert [pkt.packet_data for pkt in packets][-1] == b"simple"
    assert packets[-1].interface_id == 1
    assert packets[-1].interface is interfaces[1]
    assert any("converted to enhanced packet" in note for note in report.notes)
