#!/usr/bin/env python
"""
Minimal raw-view vs edit-view sample for lazy metadata in pcap-ng.

Builds a capture whose timestamp resolution and snap length come from the
interface block, then edits that interface after parsing.  The raw view keeps
describing the bytes that were read; the edit view follows the new metadata.
"""

import io

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.utils import pack_timestamp_resolution


def build_capture():
    shb = blocks.SectionHeader()
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=8,
        options={"if_tsresol": pack_timestamp_resolution(10, 6)},
    )
    epb = shb.new_member(
        blocks.EnhancedPacket,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=123456,
    )
    epb.packet_data = b"A" * 10
    epb.packet_len = 12
    spb = shb.new_member(blocks.SimplePacket, packet_data=b"B" * 10)

    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(epb)
    writer.write_block(spb)
    stream.seek(0)
    return list(FileScanner(stream))


def scenario(access_first):
    """Read the packet, then edit the interface (or the other way around)."""
    shb, idb, epb, spb = build_capture()
    if access_first:
        epb.timestamp, spb.captured_len
    idb.options["if_tsresol"] = pack_timestamp_resolution(10, 3)
    idb.snaplen = 4
    return (
        epb.raw_view.timestamp,
        epb.raw_view.timestamp_resolution,
        spb.raw_view.captured_len,
        spb.raw_view.packet_len,
    )


if __name__ == "__main__":
    print("raw view, edit first:", scenario(access_first=False))
    print("raw view, access first:", scenario(access_first=True))

    shb, idb, epb, spb = build_capture()
    idb.options["if_tsresol"] = pack_timestamp_resolution(10, 3)
    idb.snaplen = 4
    print("edit view:", epb.edit_view.timestamp, spb.edit_view.captured_len)
    print("difference:", epb.raw_view.diff())
    print("interface edit log:", idb.edit_log)
