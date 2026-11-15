"""
Tests for counter interpretation across consecutive Interface Statistics
Blocks: normal growth, missing counters (unknown, not zero) and counter
resets (no negative drops).
"""

import pytest

import pcapng.blocks as blocks
from pcapng.stats import (
    COUNTER_FIELDS,
    DROP_COUNTER_FIELDS,
    compute_intervals,
    count_packets,
    counter_delta,
    get_counter,
    observation_counters,
)


def make_section(observations):
    """observations: list of (timestamp_low, options-dict)."""
    shb = blocks.SectionHeader(endianness="<")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    isbs = []
    for timestamp_low, options in observations:
        isbs.append(
            shb.new_member(
                blocks.InterfaceStatistics,
                interface_id=0,
                timestamp_high=0,
                timestamp_low=timestamp_low,
                options=options,
            )
        )
    return shb, isbs


def test_continuous_observations_produce_deltas_without_summing():
    shb, isbs = make_section([
        (1000, {"isb_ifrecv": 100, "isb_ifdrop": 2,
                "isb_filteraccept": 98, "isb_osdrop": 0,
                "isb_usrdeliv": 98}),
        (2000, {"isb_ifrecv": 200, "isb_ifdrop": 5,
                "isb_filteraccept": 195, "isb_osdrop": 3,
                "isb_usrdeliv": 192}),
    ])
    interval = list(compute_intervals(isbs))[0]

    assert interval.interface_id == 0
    # Default timestamp resolution is microseconds: 1000 ticks = 1 ms.
    assert interval.elapsed == pytest.approx(0.001)

    deltas = {name: d.delta for name, d in interval.deltas.items()}
    assert deltas == {
        "isb_ifrecv": 100,
        "isb_ifdrop": 3,
        "isb_filteraccept": 97,
        "isb_osdrop": 3,
        "isb_usrdeliv": 94,
    }
    assert interval.inconclusive_counters() == {}

    # These are independent counters of different stages; they must not be
    # added together and presented as a packet total.
    assert sum(deltas.values()) != deltas["isb_ifrecv"]


def test_missing_counter_is_unknown_not_zero():
    shb, isbs = make_section([
        (1000, {"isb_ifrecv": 100}),  # ifdrop etc. absent
        (2000, {"isb_ifrecv": 200, "isb_ifdrop": 5}),
    ])

    assert get_counter(isbs[0], "isb_ifdrop") is None
    counters = observation_counters(isbs[0])
    assert counters["isb_ifrecv"] == 100
    assert counters["isb_ifdrop"] is None

    interval = list(compute_intervals(isbs))[0]
    recv = interval.deltas["isb_ifrecv"]
    drop = interval.deltas["isb_ifdrop"]

    # ifrecv is present in both -> conclusive...
    assert recv.conclusive is True
    assert recv.delta == 100
    # ...but ifdrop is missing from the first -> inconclusive, not a delta
    # computed against an assumed zero.
    assert drop.conclusive is False
    assert drop.delta is None
    assert "missing" in drop.reason
    assert set(interval.inconclusive_counters()) == {
        name for name in COUNTER_FIELDS if name != "isb_ifrecv"
    }


def test_missing_counter_in_later_observation_is_inconclusive_too():
    shb, isbs = make_section([
        (1000, {"isb_ifrecv": 100, "isb_ifdrop": 2}),
        (2000, {"isb_ifrecv": 200}),  # ifdrop dropped from later record
    ])
    interval = list(compute_intervals(isbs))[0]
    drop = interval.deltas["isb_ifdrop"]
    assert drop.conclusive is False
    assert drop.delta is None
    assert drop.previous == 2 and drop.current is None


def test_counter_reset_is_inconclusive_never_negative():
    shb, isbs = make_section([
        (1000, {"isb_ifrecv": 500, "isb_ifdrop": 50}),
        # Counters reset (e.g. capture restarted / wrapped).
        (2000, {"isb_ifrecv": 10, "isb_ifdrop": 0}),
    ])
    interval = list(compute_intervals(isbs))[0]
    recv = interval.deltas["isb_ifrecv"]
    drop = interval.deltas["isb_ifdrop"]

    for delta in (recv, drop):
        assert delta.conclusive is False
        assert delta.delta is None
        assert "decreased" in delta.reason

    # Explicitly: no negative "drop" is fabricated.
    assert drop.delta is None and not isinstance(drop.delta, int)


def test_zero_delta_is_still_conclusive():
    shb, isbs = make_section([
        (1000, {"isb_ifdrop": 5}),
        (2000, {"isb_ifdrop": 5}),  # unchanged -> legitimate zero delta
    ])
    delta = counter_delta(isbs[0], isbs[1], "isb_ifdrop")
    assert delta.conclusive is True
    assert delta.delta == 0


def test_series_with_reset_reports_one_bad_interval_and_good_others():
    shb, isbs = make_section([
        (1000, {"isb_ifrecv": 100, "isb_ifdrop": 1}),
        (2000, {"isb_ifrecv": 200, "isb_ifdrop": 4}),  # +100 / +3
        (3000, {"isb_ifrecv": 50, "isb_ifdrop": 1}),   # reset -> inconclusive
        (4000, {"isb_ifrecv": 80, "isb_ifdrop": 2}),   # +30 / +1 after reset
    ])
    intervals = list(compute_intervals(isbs))
    assert len(intervals) == 3

    good_before = intervals[0].deltas["isb_ifrecv"]
    reset = intervals[1].deltas["isb_ifrecv"]
    good_after = intervals[2].deltas["isb_ifrecv"]

    assert good_before.delta == 100 and good_before.conclusive
    assert reset.delta is None and not reset.conclusive
    assert good_after.delta == 30 and good_after.conclusive


def test_single_observation_has_no_interval():
    shb, isbs = make_section([(1000, {"isb_ifrecv": 100})])
    assert list(compute_intervals(isbs)) == []


def test_drop_counters_are_a_defined_subset():
    assert set(DROP_COUNTER_FIELDS) == {"isb_ifdrop", "isb_osdrop"}
    assert set(DROP_COUNTER_FIELDS).issubset(set(COUNTER_FIELDS))


def test_count_packets_matches_only_same_interface_and_interval():
    shb = blocks.SectionHeader(endianness="<")
    idb0 = shb.new_member(blocks.InterfaceDescription, link_type=1,
                          snaplen=65535)
    idb1 = shb.new_member(blocks.InterfaceDescription, link_type=1,
                          snaplen=65535)

    isb_start = shb.new_member(blocks.InterfaceStatistics, interface_id=0,
                               timestamp_low=1000, options={"isb_ifrecv": 0})
    epb_in_0 = shb.new_member(blocks.EnhancedPacket, interface_id=0)
    epb_in_0.packet_data = b"abc"
    epb_in_1 = shb.new_member(blocks.EnhancedPacket, interface_id=1)
    epb_in_1.packet_data = b"def"
    spb_in_0 = shb.new_member(blocks.SimplePacket, packet_len=3,
                              packet_data=b"ghi")
    isb_end = shb.new_member(blocks.InterfaceStatistics, interface_id=0,
                             timestamp_low=2000, options={"isb_ifrecv": 2})
    epb_after = shb.new_member(blocks.EnhancedPacket, interface_id=0)
    epb_after.packet_data = b"jkl"

    all_blocks = [shb, idb0, idb1, isb_start, epb_in_0, epb_in_1, spb_in_0,
                  isb_end, epb_after]

    # Whole section, one interface only.
    assert count_packets(all_blocks, 0) == 3
    assert count_packets(all_blocks, 1) == 1

    # Restricted to the interval between the two ISBs.
    assert count_packets(all_blocks, 0, start=isb_start, end=isb_end) == 2
