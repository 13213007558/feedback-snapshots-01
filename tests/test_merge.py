import io

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter, merge_capture_files
from pcapng.merge import (
    CaptureSource,
    MergeConflictError,
    MergeError,
    interface_conflicts,
)


def make_capture(interfaces, packets=(), stats=(), endianness="<"):
    """
    Build an in-memory pcapng capture.

    :param interfaces: list of kwargs dicts for InterfaceDescription
    :param packets: list of (interface_id, timestamp_low, packet_data)
    :param stats: list of (interface_id, isb options dict)
    """
    shb = blocks.SectionHeader(endianness=endianness)
    for kwargs in interfaces:
        shb.new_member(blocks.InterfaceDescription, **kwargs)
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for interface_id, timestamp_low, data in packets:
        writer.write_block(
            shb.new_member(
                blocks.EnhancedPacket,
                interface_id=interface_id,
                timestamp_low=timestamp_low,
                packet_data=data,
            )
        )
    for interface_id, options in stats:
        writer.write_block(
            shb.new_member(
                blocks.InterfaceStatistics, interface_id=interface_id, options=options
            )
        )
    stream.seek(0)
    return stream


def read_back(stream):
    stream.seek(0)
    return list(FileScanner(stream))


def packets_of(blocks_list):
    return [b for b in blocks_list if isinstance(b, blocks.EnhancedPacket)]


def interfaces_of(blocks_list):
    return [b for b in blocks_list if isinstance(b, blocks.InterfaceDescription)]


def stats_of(blocks_list):
    return [b for b in blocks_list if isinstance(b, blocks.InterfaceStatistics)]


ETH0_BASE = {
    "link_type": 1,
    "snaplen": 65535,
    "options": {
        "if_name": "eth0",
        "if_tsresol": b"\x06",
        "if_filter": [(0, b"tcp port 80")],
    },
}


def eth0_with(**overrides):
    kwargs = {
        "link_type": overrides.pop("link_type", ETH0_BASE["link_type"]),
        "snaplen": overrides.pop("snaplen", ETH0_BASE["snaplen"]),
        "options": dict(ETH0_BASE["options"]),
    }
    kwargs["options"].update(overrides.pop("options", {}))
    kwargs.update(overrides)
    return kwargs


# --------------------------------------------------------------------
# Contrast case 1: two sources both calling their interface "eth0",
# but with different capture settings -- they must not be merged.
# --------------------------------------------------------------------


def test_same_name_different_settings_kept_separate():
    source_a = make_capture(
        [eth0_with()], packets=[(0, 100, b"packet-a1"), (0, 200, b"packet-a2")]
    )
    source_b = make_capture(
        [eth0_with(snaplen=128, options={"if_tsresol": b"\x09"})],
        packets=[(0, 50, b"packet-b1")],
    )

    output = io.BytesIO()
    report = merge_capture_files(
        [CaptureSource("sensor-a", source_a), CaptureSource("sensor-b", source_b)],
        output,
        interface_map={
            ("sensor-a", 0): "wan",
            ("sensor-b", 0): "wan",
        },
    )

    # Both interfaces survive, with reviewable conflict reasons
    record_b = report.record_for("sensor-b", 0)
    assert report.record_for("sensor-a", 0).action == "new"
    assert record_b.action == "separate"
    assert record_b.output_interface_id == 1
    assert any("snaplen" in reason for reason in record_b.reasons)
    assert any("timestamp resolution" in reason for reason in record_b.reasons)

    read = read_back(output)
    idbs = interfaces_of(read)
    assert len(idbs) == 2
    # The name alone was not enough to merge them
    assert idbs[0].options["if_name"] == idbs[1].options["if_name"] == "eth0"
    assert idbs[0].snaplen == 65535
    assert idbs[1].snaplen == 128

    # Packets still point at the interface they were captured on
    pkts = packets_of(read)
    assert [(p.interface_id, p.packet_data) for p in pkts] == [
        (0, b"packet-a1"),
        (0, b"packet-a2"),
        (1, b"packet-b1"),
    ]


def test_conflicting_merge_can_be_refused():
    source_a = make_capture([eth0_with()])
    source_b = make_capture([eth0_with(snaplen=128)])

    with pytest.raises(MergeConflictError, match="snaplen"):
        merge_capture_files(
            [("a", source_a), ("b", source_b)],
            io.BytesIO(),
            interface_map={("a", 0): "wan", ("b", 0): "wan"},
            on_conflict="raise",
        )


@pytest.mark.parametrize(
    "options_b",
    [
        {"if_filter": [(0, b"udp port 53")]},
        {"if_tsresol": b"\x0a"},
    ],
    ids=["filter", "tsresol"],
)
def test_filter_and_clock_conflicts_prevent_merge(options_b):
    source_a = make_capture([eth0_with()])
    source_b = make_capture([eth0_with(options=options_b)])

    report = merge_capture_files(
        [("a", source_a), ("b", source_b)],
        io.BytesIO(),
        interface_map={("a", 0): "x", ("b", 0): "x"},
    )
    assert report.record_for("b", 0).action == "separate"
    assert len(report.output_interface_sources) == 2


def test_unknown_option_conflict_prevents_merge():
    source_a = make_capture([eth0_with(options={5000: b"raw-a"})])
    source_b = make_capture([eth0_with(options={5000: b"raw-b"})])

    output = io.BytesIO()
    report = merge_capture_files(
        [("a", source_a), ("b", source_b)],
        output,
        interface_map={("a", 0): "x", ("b", 0): "x"},
    )

    record_b = report.record_for("b", 0)
    assert record_b.action == "separate"
    assert any("unknown option 5000" in reason for reason in record_b.reasons)

    # The unknown options survive the round trip on their own interfaces
    idbs = interfaces_of(read_back(output))
    assert idbs[0].options[5000] == b"raw-a"
    assert idbs[1].options[5000] == b"raw-b"


# --------------------------------------------------------------------
# Contrast case 2: two segments explicitly confirmed by the caller to
# come from the same interface -- they are merged.
# --------------------------------------------------------------------


def test_confirmed_same_interface_is_merged():
    # Note: source B's packets have *earlier* timestamps than source A's;
    # the merge must keep input order and not re-sort by time.
    source_a = make_capture(
        [eth0_with()], packets=[(0, 300, b"packet-a1"), (0, 400, b"packet-a2")]
    )
    source_b = make_capture(
        [eth0_with(options={"if_description": "second segment"})],
        packets=[(0, 100, b"packet-b1"), (0, 200, b"packet-b2")],
    )

    output = io.BytesIO()
    report = merge_capture_files(
        [CaptureSource("segment-1", source_a), CaptureSource("segment-2", source_b)],
        output,
        interface_map={("segment-1", 0): "wan", ("segment-2", 0): "wan"},
    )

    assert report.record_for("segment-1", 0).action == "new"
    assert report.record_for("segment-2", 0).action == "merged"
    assert report.output_interface_sources == {
        0: [("segment-1", 0), ("segment-2", 0)]
    }

    read = read_back(output)
    idbs = interfaces_of(read)
    assert len(idbs) == 1

    # Input order is the packet order -- no timestamp reordering
    pkts = packets_of(read)
    assert [p.packet_data for p in pkts] == [
        b"packet-a1",
        b"packet-a2",
        b"packet-b1",
        b"packet-b2",
    ]
    assert [p.interface_id for p in pkts] == [0, 0, 0, 0]
    assert [p.timestamp_low for p in pkts] == [300, 400, 100, 200]

    # Provenance survives the interface id compression
    comments = idbs[0].options.get_all("opt_comment")
    assert any("segment-1" in c for c in comments)
    assert any("segment-2" in c for c in comments)


def test_interface_statistics_are_not_summed():
    source_a = make_capture(
        [eth0_with()],
        packets=[(0, 100, b"a")],
        stats=[(0, {"isb_ifrecv": 100, "isb_ifdrop": 5})],
    )
    source_b = make_capture(
        [eth0_with()],
        packets=[(0, 200, b"b")],
        stats=[(0, {"isb_ifrecv": 250, "isb_ifdrop": 7})],
    )

    output = io.BytesIO()
    merge_capture_files(
        [("a", source_a), ("b", source_b)],
        output,
        interface_map={("a", 0): "wan", ("b", 0): "wan"},
    )

    isbs = stats_of(read_back(output))
    # Two separate counting sources stay two separate records, both
    # pointing at the merged interface -- never one cumulative value.
    assert len(isbs) == 2
    assert [b.interface_id for b in isbs] == [0, 0]
    assert sorted(b.options["isb_ifrecv"] for b in isbs) == [100, 250]
    assert sorted(b.options["isb_ifdrop"] for b in isbs) == [5, 7]


def test_statistics_follow_remapped_interface():
    source_a = make_capture([eth0_with()], stats=[(0, {"isb_ifrecv": 10})])
    source_b = make_capture(
        [eth0_with(snaplen=128)], stats=[(0, {"isb_ifrecv": 20})]
    )

    output = io.BytesIO()
    merge_capture_files(
        [("a", source_a), ("b", source_b)],
        output,
        interface_map={("a", 0): "wan", ("b", 0): "wan"},
    )

    isbs = stats_of(read_back(output))
    by_count = {b.options["isb_ifrecv"]: b.interface_id for b in isbs}
    assert by_count == {10: 0, 20: 1}


# --------------------------------------------------------------------
# Default behaviour: nothing is merged unless the caller says so.
# --------------------------------------------------------------------


def test_no_merge_without_explicit_mapping():
    # Identical name, link type and metadata -- still not merged,
    # because identity is never guessed.
    source_a = make_capture([eth0_with()], packets=[(0, 100, b"a")])
    source_b = make_capture([eth0_with()], packets=[(0, 200, b"b")])

    output = io.BytesIO()
    report = merge_capture_files([("a", source_a), ("b", source_b)], output)

    assert [r.action for r in report.interfaces] == ["new", "new"]
    read = read_back(output)
    assert len(interfaces_of(read)) == 2
    assert [p.interface_id for p in packets_of(read)] == [0, 1]


def test_provenance_comment_on_unmerged_interfaces():
    source_a = make_capture([eth0_with()])
    source_b = make_capture([eth0_with()])

    output = io.BytesIO()
    merge_capture_files([("sensor-a", source_a), ("sensor-b", source_b)], output)

    idbs = interfaces_of(read_back(output))
    assert any("sensor-a" in c for c in idbs[0].options.get_all("opt_comment"))
    assert any("sensor-b" in c for c in idbs[1].options.get_all("opt_comment"))


def test_simple_packet_converted_when_interface_remapped():
    shb = blocks.SectionHeader()
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(shb.new_member(blocks.SimplePacket, packet_data=b"spb-data"))
    stream.seek(0)

    other = make_capture([eth0_with()])

    output = io.BytesIO()
    merge_capture_files([("first", other), ("second", stream)], output)

    read = read_back(output)
    # The SPB referred to interface 0 of its own capture, which lands on
    # output interface 1 -- it must become an EPB to keep that reference.
    pkts = packets_of(read)
    assert len(pkts) == 1
    assert pkts[0].interface_id == 1
    assert pkts[0].packet_data == b"spb-data"


def test_dangling_packet_reference_raises():
    # A packet referring to an interface with no description block
    raw = io.BytesIO()
    shb = blocks.SectionHeader()
    idb = shb.new_member(blocks.InterfaceDescription, link_type=1)  # noqa: F841
    writer = FileWriter(raw, shb)
    pkt = shb.new_member(blocks.EnhancedPacket, interface_id=7, packet_data=b"x")
    # Bypass the writer's consistency check to simulate a broken capture
    pkt._write(raw)

    raw.seek(0)
    with pytest.raises(MergeError, match="no interface description"):
        merge_capture_files([("broken", raw)], io.BytesIO())


def test_interface_conflicts_helper():
    idb_kwargs = eth0_with()
    shb = blocks.SectionHeader()
    first = shb.new_member(blocks.InterfaceDescription, **idb_kwargs)
    same = shb.new_member(
        blocks.InterfaceDescription, **eth0_with(options={"if_name": "renamed"})
    )
    different = shb.new_member(
        blocks.InterfaceDescription, **eth0_with(link_type=147)
    )

    assert interface_conflicts(first, same) == []
    reasons = interface_conflicts(first, different)
    assert any("link_type" in reason for reason in reasons)
