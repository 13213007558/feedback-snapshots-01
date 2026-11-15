"""
Tests covering captures that contain several Interface Statistics Blocks
for the same interface. Earlier observations must not be overwritten by
later ones, and the legacy convenience accessors must keep their old,
documented behavior.
"""

import io

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter


def build_capture(observations, interface_count=1, endianness="<"):
    """Build an in-memory pcapng with ISB observations.

    ``observations`` is a list of dicts with keys ``interface_id``,
    ``timestamp_low`` and ``options``. Returns the parsed block list.
    """
    shb = blocks.SectionHeader(endianness=endianness)
    for _ in range(interface_count):
        shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for obs in observations:
        isb = shb.new_member(
            blocks.InterfaceStatistics,
            interface_id=obs["interface_id"],
            timestamp_high=0,
            timestamp_low=obs["timestamp_low"],
            options=obs["options"],
        )
        writer.write_block(isb)

    stream.seek(0)
    return list(FileScanner(stream))


def make_observations():
    return [
        {
            "interface_id": 0,
            "timestamp_low": 1000,
            "options": {
                "isb_ifrecv": 100,
                "isb_ifdrop": 2,
                "isb_filteraccept": 98,
            },
        },
        {
            "interface_id": 0,
            "timestamp_low": 2000,
            "options": {
                "isb_ifrecv": 200,
                "isb_ifdrop": 5,
                "isb_filteraccept": 195,
            },
        },
        {
            "interface_id": 0,
            "timestamp_low": 3000,
            "options": {
                "isb_ifrecv": 300,
                "isb_ifdrop": 9,
                "isb_filteraccept": 291,
            },
        },
    ]


def test_all_observations_are_retained():
    parsed = build_capture(make_observations())
    shb = parsed[0]
    idb = parsed[1]
    isbs = [b for b in parsed if isinstance(b, blocks.InterfaceStatistics)]

    # Nothing lost: all three ISBs are still reachable.
    assert len(isbs) == 3
    assert len(idb.statistics_history) == 3
    assert len(list(shb.iter_interface_stats(0))) == 3
    assert len(shb.interface_statistics) == 3

    # File order is preserved, including the early observation.
    ifrecv = [b.options["isb_ifrecv"] for b in idb.statistics_history]
    assert ifrecv == [100, 200, 300]
    assert idb.statistics_history[0] is isbs[0]


def test_early_observation_not_erased_by_later_one():
    parsed = build_capture(make_observations())
    idb = parsed[1]
    history = idb.statistics_history

    # Re-reading later does not mutate the already-collected history.
    first = history[0]
    assert first.options["isb_ifrecv"] == 100
    assert history[-1].options["isb_ifrecv"] == 300
    assert first is not history[-1]


def test_legacy_statistics_property_keeps_last_observation():
    parsed = build_capture(make_observations())
    shb = parsed[0]
    idb = parsed[1]
    last = [b for b in parsed if isinstance(b, blocks.InterfaceStatistics)][-1]

    # Explicit compatibility rule: legacy accessors expose only the latest.
    assert idb.statistics is last
    assert shb.interface_stats[0] is last
    assert idb.statistics is idb.statistics_history[-1]


def test_legacy_mapping_still_overwrites_but_history_does_not():
    parsed = build_capture(make_observations())
    shb = parsed[0]

    # The legacy dict keeps one entry per interface (latest)...
    assert shb.interface_stats == {0: shb.interface_stats[0]}
    # ...while history keeps the full series.
    assert len(shb.interface_stats_history[0]) == 3


def test_no_statistics_returns_empty_history_and_none_legacy():
    parsed = build_capture([])
    idb = parsed[1]
    assert idb.statistics is None
    assert idb.statistics_history == []
    assert list(parsed[0].iter_interface_stats(0)) == []


def test_histories_are_separated_by_interface():
    observations = [
        {"interface_id": 0, "timestamp_low": 1000,
         "options": {"isb_ifrecv": 10}},
        {"interface_id": 1, "timestamp_low": 1100,
         "options": {"isb_ifrecv": 20}},
        {"interface_id": 0, "timestamp_low": 2000,
         "options": {"isb_ifrecv": 30}},
        {"interface_id": 1, "timestamp_low": 2100,
         "options": {"isb_ifrecv": 40}},
    ]
    parsed = build_capture(observations, interface_count=2)
    shb = parsed[0]

    iface0 = [b.options["isb_ifrecv"]
              for b in shb.iter_interface_stats(0)]
    iface1 = [b.options["isb_ifrecv"]
              for b in shb.iter_interface_stats(1)]
    assert iface0 == [10, 30]
    assert iface1 == [20, 40]

    # Global iteration keeps strict file order across interfaces.
    assert [b.interface_id for b in shb.interface_statistics] == [0, 1, 0, 1]


def test_history_both_endiannesses():
    for endianness in ("<", ">"):
        parsed = build_capture(make_observations(), endianness=endianness)
        idb = parsed[1]
        assert [b.options["isb_ifrecv"]
                for b in idb.statistics_history] == [100, 200, 300]


def test_compute_intervals_rejects_mixed_interfaces():
    observations = [
        {"interface_id": 0, "timestamp_low": 1000,
         "options": {"isb_ifrecv": 10}},
        {"interface_id": 1, "timestamp_low": 2000,
         "options": {"isb_ifrecv": 20}},
    ]
    parsed = build_capture(observations, interface_count=2)
    from pcapng.stats import compute_intervals

    with pytest.raises(ValueError):
        list(compute_intervals(parsed[0].interface_statistics))
