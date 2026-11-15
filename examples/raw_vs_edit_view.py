"""
Minimal runnable sample separating the "raw read view" from the
"explicit edit view" of a parsed capture.

It builds one tiny in-memory pcapng stream (one section, one interface
with snaplen=10 and microsecond timestamp resolution, one simple packet,
one enhanced packet) and then runs the same workload in two orders:

1. read packet attributes first, then edit the interface metadata
2. edit the interface metadata first, then read packet attributes

The raw view (packet length, decoded timestamp) must be identical in
both orders; the edit view (the interface metadata itself, and any
reinterpretation explicitly computed from it) tracks the edits.
"""

import io
import struct

from pcapng.scanner import FileScanner
from pcapng.utils import pack_timestamp_resolution


def _block(magic, body):
    pad = (4 - len(body) % 4) % 4
    body += b"\x00" * pad
    length = 12 + len(body)
    return struct.pack("<II", magic, length) + body + struct.pack("<I", length)


def build_stream():
    """One SHB + IDB (snaplen 10, tsresol 10^-6) + SPB + EPB."""
    out = io.BytesIO()
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"\x00\x00\x00\x00"
    out.write(_block(0x0A0D0D0A, shb))
    options = struct.pack("<HH", 9, 1) + pack_timestamp_resolution(10, 6)
    options += b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb = struct.pack("<HHI", 1, 0, 10) + options  # snaplen = 10
    out.write(_block(0x00000001, idb))
    spb = struct.pack("<I", 20) + b"\xaa" * 10  # 20 on wire, 10 captured
    out.write(_block(0x00000003, spb))
    epb = struct.pack("<IIIII", 0, 0, 1000000, 4, 4) + b"\xde\xad\xbe\xef"
    epb += struct.pack("<HH", 0, 0)
    out.write(_block(0x00000006, epb))
    out.seek(0)
    return out


def edit_interface_metadata(section):
    """The 'explicit edit': change tsresol (us -> ns) and snaplen (10 -> 4)."""
    interface = section.interfaces[0]
    interface.options["if_tsresol"] = pack_timestamp_resolution(10, 9)
    interface.snaplen = 4


def raw_view(simple_packet, enhanced_packet):
    """Capture-time facts as decoded from the file."""
    return {
        "spb.captured_len": simple_packet.captured_len,
        "spb.packet_len": simple_packet.packet_len,
        "spb len(packet_data)": len(simple_packet.packet_data),
        "epb.timestamp": enhanced_packet.timestamp,
    }


def edit_view(section, enhanced_packet):
    """Live values, computed from the current (edited) metadata."""
    interface = section.interfaces[0]
    raw_ts = (enhanced_packet.timestamp_high << 32) + enhanced_packet.timestamp_low
    return {
        "idb.timestamp_resolution": interface.timestamp_resolution,
        "idb.snaplen": interface.snaplen,
        "epb reinterpreted timestamp": raw_ts * interface.timestamp_resolution,
    }


def run(order):
    section, _idb, spb, epb = list(FileScanner(build_stream()))
    if order == "edit-first":
        edit_interface_metadata(section)
    raw = raw_view(spb, epb)
    if order == "read-first":
        edit_interface_metadata(section)
    raw_after_edit = raw_view(spb, epb)
    return raw, raw_after_edit, edit_view(section, epb)


for order in ("read-first", "edit-first"):
    raw, raw_after_edit, edited = run(order)
    print("=== Order: %s ===" % order)
    for key, value in raw_after_edit.items():
        stable = "stable" if raw[key] == value else "CHANGED!"
        print("  raw view   %-24s %-12s (%s)" % (key, value, stable))
    for key, value in edited.items():
        print("  edit view  %-24s %s" % (key, value))
