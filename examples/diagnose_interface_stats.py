#!/usr/bin/env python
"""
Reproducible diagnostics for Interface Statistics Block (ISB) handling.

Run with no arguments to build a synthetic, in-memory pcapng capture that
contains the three tricky situations and analyze it:

    1. continuous observations (several ISBs for one interface);
    2. a counter that is missing from an observation (unknown, not zero);
    3. a counter that resets / wraps (no negative "drop" is invented).

Pass a pcapng file path to analyze a real capture instead:

    python examples/diagnose_interface_stats.py capture.pcapng

The report distinguishes the independent counters (received, interface
dropped, filter accepted, OS dropped, user delivered) without adding them
together, keeps every observation instead of only the last one, and marks
every interval whose delta cannot be concluded together with the reason.
"""

from __future__ import print_function

import io
import sys

from pcapng import FileScanner, FileWriter
from pcapng import blocks
from pcapng.stats import (
    COUNTER_DESCRIPTIONS,
    COUNTER_FIELDS,
    compute_intervals,
    count_packets,
    get_counter,
)


def title(text):
    print("=" * 72)
    print(text)
    print("=" * 72)


def explain_counters():
    title("What the ISB counters mean (independent stages; never summed)")
    for name in COUNTER_FIELDS:
        print("  {0:18s} {1}".format(name, COUNTER_DESCRIPTIONS[name].description))


def add_packet(shb, writer, interface_id):
    packet = shb.new_member(blocks.EnhancedPacket, interface_id=interface_id)
    packet.packet_data = b"diagnostic-payload"
    writer.write_block(packet)


def build_synthetic_capture():
    """Build three sections, one per diagnostic scenario."""
    stream = io.BytesIO()

    # --- Scenario 1: continuous observations, plus packets in an interval ---
    shb = blocks.SectionHeader(endianness="<")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    writer = FileWriter(stream, shb)
    writer.write_block(
        shb.new_member(
            blocks.InterfaceStatistics, interface_id=0, timestamp_low=1000,
            options={"isb_ifrecv": 100, "isb_ifdrop": 2,
                     "isb_filteraccept": 98, "isb_osdrop": 0,
                     "isb_usrdeliv": 98},
        )
    )
    add_packet(shb, writer, 0)
    add_packet(shb, writer, 0)
    writer.write_block(
        shb.new_member(
            blocks.InterfaceStatistics, interface_id=0, timestamp_low=2000,
            options={"isb_ifrecv": 200, "isb_ifdrop": 5,
                     "isb_filteraccept": 195, "isb_osdrop": 3,
                     "isb_usrdeliv": 192},
        )
    )
    writer.write_block(
        shb.new_member(
            blocks.InterfaceStatistics, interface_id=0, timestamp_low=3000,
            options={"isb_ifrecv": 300, "isb_ifdrop": 9,
                     "isb_filteraccept": 291, "isb_osdrop": 7,
                     "isb_usrdeliv": 284},
        )
    )

    # --- Scenario 2: missing fields (absent means unknown, not zero) ---
    shb = blocks.SectionHeader(endianness="<")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    writer = FileWriter(stream, shb)
    writer.write_block(
        shb.new_member(
            blocks.InterfaceStatistics, interface_id=0, timestamp_low=1000,
            options={"isb_ifrecv": 100},  # all other counters absent
        )
    )
    writer.write_block(
        shb.new_member(
            blocks.InterfaceStatistics, interface_id=0, timestamp_low=2000,
            options={"isb_ifrecv": 200, "isb_ifdrop": 5,
                     "isb_filteraccept": 195},
        )
    )

    # --- Scenario 3: counter reset / wrap-around ---
    shb = blocks.SectionHeader(endianness="<")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    writer = FileWriter(stream, shb)
    for timestamp_low, ifrecv, ifdrop in (
        (1000, 500, 50),
        (2000, 600, 54),
        (3000, 50, 1),    # counters reset here
        (4000, 80, 2),
    ):
        writer.write_block(
            shb.new_member(
                blocks.InterfaceStatistics, interface_id=0,
                timestamp_low=timestamp_low,
                options={"isb_ifrecv": ifrecv, "isb_ifdrop": ifdrop},
            )
        )

    stream.seek(0)
    return stream


def print_raw_observations(section):
    print("-- Raw observations (every ISB retained; None = absent/unknown) --")
    for interface_id in sorted(section.interface_stats_history):
        history = list(section.iter_interface_stats(interface_id))
        print("  interface {0}: {1} observation(s)".format(
            interface_id, len(history)))
        for index, isb in enumerate(history):
            values = {name: get_counter(isb, name) for name in COUNTER_FIELDS}
            print("    [{0}] ts_low={1} {2}".format(
                index, isb.timestamp_low, values))

        # Prove the legacy property only sees the last record.
        legacy = section.interfaces[interface_id].statistics
        print("    legacy .statistics -> only latest ts_low={0}".format(
            legacy.timestamp_low))


def print_intervals(section, all_blocks):
    print("-- Per-interval deltas (same interface, consecutive observations) --")
    for interface_id in sorted(section.interface_stats_history):
        history = list(section.iter_interface_stats(interface_id))
        intervals = list(compute_intervals(history))
        if not intervals:
            print("  interface {0}: not enough observations for an interval".format(
                interface_id))
            continue

        for index, interval in enumerate(intervals):
            print("  interface {0} interval {1}: ts_low {2} -> {3} "
                  "({4:.6f}s)".format(
                      interface_id, index,
                      interval.start.timestamp_low,
                      interval.end.timestamp_low, interval.elapsed))
            for name in COUNTER_FIELDS:
                delta = interval.deltas[name]
                if delta.conclusive:
                    print("      {0:18s} {1} -> {2}  delta={3}".format(
                        name, delta.previous, delta.current, delta.delta))
                else:
                    print("      {0:18s} {1} -> {2}  INCONCLUSIVE ({3})".format(
                        name, delta.previous, delta.current, delta.reason))

        # Cross-check against stored packets only inside a comparable interval
        # (same interface, between two ISBs of that interface).
        if len(history) >= 2:
            start, end = history[0], history[1]
            stored = count_packets(all_blocks, interface_id,
                                   start=start, end=end)
            recv = intervals[0].deltas["isb_ifrecv"]
            print("  cross-check interval 0: stored packet blocks={0}; "
                  "isb_ifrecv delta={1}".format(
                      stored,
                      recv.delta if recv.conclusive else "inconclusive"))
            print("    (comparable only on this interface/interval; counters "
                  "measure capture stages, not stored blocks)")


def analyze(stream):
    all_blocks = list(FileScanner(stream))
    explain_counters()

    section_index = 0
    current = None
    section_blocks = []

    def flush(section, blocks_in_section):
        if section is None:
            return
        title("Section {0}".format(section_index))
        print_raw_observations(section)
        print_intervals(section, blocks_in_section)
        print()

    for block in all_blocks:
        if isinstance(block, blocks.SectionHeader):
            flush(current, section_blocks)
            section_index += 1
            current = block
            section_blocks = []
        section_blocks.append(block)
    flush(current, section_blocks)


def main(argv):
    if len(argv) > 1:
        with open(argv[1], "rb") as fp:
            analyze(fp)
    else:
        print("No file given; analyzing a built-in synthetic capture.\n")
        analyze(build_synthetic_capture())


if __name__ == "__main__":
    main(sys.argv)
