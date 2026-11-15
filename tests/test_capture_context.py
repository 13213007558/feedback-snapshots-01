"""
Tests for the capture-time interpretation context ("raw view" vs "edit view").

Blocks decoded from a capture snapshot the section/interface metadata used
to interpret them, so swapping the order of "read packet attributes" and
"edit interface metadata" must not change the decoded view. Blocks created
programmatically are interpreted live against current metadata.
"""

import copy
import io
import struct

import pytest

from pcapng.blocks import EnhancedPacket, InterfaceDescription, SimplePacket
from pcapng.scanner import FileScanner
from pcapng.utils import pack_timestamp_resolution


def _block(magic, body):
    pad = (4 - len(body) % 4) % 4
    body += b"\x00" * pad
    length = 12 + len(body)
    return struct.pack("<II", magic, length) + body + struct.pack("<I", length)


def build_stream(tsresol_exponent=6, snaplen=10):
    out = io.BytesIO()
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"\x00\x00\x00\x00"
    out.write(_block(0x0A0D0D0A, shb))
    options = struct.pack("<HH", 9, 1) + pack_timestamp_resolution(10, tsresol_exponent)
    options += b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb = struct.pack("<HHI", 1, 0, snaplen) + options
    out.write(_block(0x00000001, idb))
    spb = struct.pack("<I", 20) + b"\xaa" * min(snaplen, 20)
    out.write(_block(0x00000003, spb))
    epb = struct.pack("<IIIII", 0, 0, 1000000, 4, 4) + b"\xde\xad\xbe\xef"
    epb += struct.pack("<HH", 0, 0)
    out.write(_block(0x00000006, epb))
    out.seek(0)
    return out


def scan():
    return list(FileScanner(build_stream()))


def edit_metadata(section):
    interface = section.interfaces[0]
    interface.options["if_tsresol"] = pack_timestamp_resolution(10, 9)
    interface.snaplen = 4


def raw_view(spb, epb):
    return {
        "captured_len": spb.captured_len,
        "packet_len": spb.packet_len,
        "data_len": len(spb.packet_data),
        "timestamp": epb.timestamp,
        "timestamp_resolution": epb.timestamp_resolution,
    }


def test_raw_view_stable_when_read_before_edit():
    section, _idb, spb, epb = scan()
    before = raw_view(spb, epb)
    edit_metadata(section)
    assert raw_view(spb, epb) == before


def test_raw_view_stable_when_edit_before_read():
    section, _idb, spb, epb = scan()
    edit_metadata(section)
    assert raw_view(spb, epb) == {
        "captured_len": 10,
        "packet_len": 20,
        "data_len": 10,
        "timestamp": 1.0,
        "timestamp_resolution": 1e-6,
    }


def test_raw_view_identical_in_both_orders():
    section, _idb, spb, epb = scan()
    read_first = raw_view(spb, epb)
    edit_metadata(section)
    read_first_after = raw_view(spb, epb)

    section2, _idb2, spb2, epb2 = scan()
    edit_metadata(section2)
    edit_first = raw_view(spb2, epb2)

    assert read_first == read_first_after == edit_first


def test_edit_view_reflects_metadata_changes():
    section, _idb, spb, epb = scan()
    edit_metadata(section)
    interface = section.interfaces[0]
    assert interface.timestamp_resolution == 1e-9
    assert interface.snaplen == 4
    # Explicit reinterpretation from live metadata differs from the
    # capture-time fact, and the two are clearly distinguishable.
    raw_ts = (epb.timestamp_high << 32) + epb.timestamp_low
    assert raw_ts * interface.timestamp_resolution == 0.001
    assert epb.timestamp == 1.0


def test_captured_len_consistent_with_packet_data_after_edit():
    section, _idb, spb, epb = scan()
    edit_metadata(section)
    assert spb.captured_len == len(spb.packet_data) == 10


def test_manually_created_blocks_interpret_live():
    section, idb, _spb, _epb = scan()
    epb = section.new_member(
        EnhancedPacket,
        interface_id=0,
        timestamp_high=0,
        timestamp_low=1000000,
        packet_data=b"\xde\xad\xbe\xef",
    )
    assert epb.timestamp == 1.0
    edit_metadata(section)
    # No capture-time snapshot: the edit view is live.
    assert epb.timestamp == 0.001


def test_manually_created_simple_packet_interprets_live():
    section, idb, _spb, _epb = scan()
    spb = section.new_member(SimplePacket, packet_len=20, packet_data=b"\xaa" * 10)
    assert spb.captured_len == 10
    edit_metadata(section)
    assert spb.captured_len == 4


@pytest.mark.parametrize("copier", [copy.copy, copy.deepcopy])
def test_copy_preserves_capture_context(copier):
    section, _idb, spb, epb = scan()
    epb_clone = copier(epb)
    spb_clone = copier(spb)
    edit_metadata(section)
    assert epb_clone.timestamp == 1.0
    assert spb_clone.captured_len == 10


def test_missing_interface_still_raises():
    out = io.BytesIO()
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"\x00\x00\x00\x00"
    out.write(_block(0x0A0D0D0A, shb))
    epb = struct.pack("<IIIII", 0, 0, 1000000, 4, 4) + b"\xde\xad\xbe\xef"
    epb += struct.pack("<HH", 0, 0)
    out.write(_block(0x00000006, epb))
    out.seek(0)
    _section, epb = list(FileScanner(out))
    with pytest.raises(KeyError):
        epb.timestamp
