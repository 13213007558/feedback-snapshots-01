"""
Tests for the packet-length handling and FCS metadata of the Enhanced
Packet Block (EPB) and Simple Packet Block (SPB).

These tests distinguish three different sizes that must never be
confused with each other:

* the bytes actually captured and stored in the block
* the on-wire (original) packet length
* the zero/non-zero alignment padding that rounds the packet data up
  to a 32-bit boundary inside the block
"""

import io
import struct

import pytest

from pcapng import FileScanner, FileWriter
from pcapng.blocks import (
    EnhancedPacket,
    InterfaceDescription,
    SectionHeader,
    SimplePacket,
)
from pcapng.exceptions import BadPacketLength, TruncatedFile
from pcapng.structs import EPBFlags

ENDIANNESS = "<"


# ---------------------------------------------------------------------------
# Low level block builders. These give full control over the on-disk bytes,
# including deliberately malformed length fields and non-zero padding.
# ---------------------------------------------------------------------------


def _pack(block_type, body):
    total = 12 + len(body)
    return (
        struct.pack(ENDIANNESS + "II", block_type, total)
        + body
        + struct.pack(ENDIANNESS + "I", total)
    )


def build_shb():
    body = struct.pack(ENDIANNESS + "IHH", 0x1A2B3C4D, 1, 0)
    body += struct.pack(ENDIANNESS + "q", -1)
    body += struct.pack(ENDIANNESS + "I", 0)  # end of options
    return _pack(0x0A0D0D0A, body)


def build_idb(snaplen=0, fcs_bits=None, link_type=1):
    body = struct.pack(ENDIANNESS + "HHI", link_type, 0, snaplen)
    options = b""
    if fcs_bits is not None:
        options += struct.pack(ENDIANNESS + "HH", 13, 1)
        options += struct.pack(ENDIANNESS + "B", fcs_bits)
        options += b"\x00\x00\x00"  # option padding
    options += struct.pack(ENDIANNESS + "I", 0)  # end of options
    return _pack(0x00000001, body + options)


def build_epb(
    captured_len,
    packet_len,
    packet_data,
    padding=b"\x00\x00\x00\x00",
    epb_flags=None,
):
    body = struct.pack(ENDIANNESS + "I", 0)  # interface id
    body += struct.pack(ENDIANNESS + "Q", 0)  # timestamp
    body += struct.pack(ENDIANNESS + "II", captured_len, packet_len)
    pad_len = (-len(packet_data)) % 4
    body += packet_data + padding[:pad_len]
    if epb_flags is not None:
        value = struct.pack(ENDIANNESS + "I", int(epb_flags))
        body += struct.pack(ENDIANNESS + "HH", 2, len(value)) + value
    body += struct.pack(ENDIANNESS + "I", 0)  # end of options
    return _pack(0x00000006, body)


def build_spb(packet_len, packet_data, padding=b"\x00\x00\x00\x00"):
    body = struct.pack(ENDIANNESS + "I", packet_len)
    pad_len = (-len(packet_data)) % 4
    body += packet_data + padding[:pad_len]
    return _pack(0x00000003, body)


def scan(blob):
    return list(FileScanner(io.BytesIO(blob)))


# ---------------------------------------------------------------------------
# Enhanced Packet Block
# ---------------------------------------------------------------------------


def test_epb_full_frame_byte_for_byte():
    frame = bytes(range(60))
    blob = build_shb() + build_idb() + build_epb(60, 60, frame)
    shb, idb, epb = scan(blob)

    assert isinstance(epb, EnhancedPacket)
    assert epb.captured_len == 60
    assert epb.packet_len == 60
    assert epb.packet_data == frame  # exact bytes, no padding leaked in
    assert epb.packet_truncated is False


def test_epb_nonzero_padding_is_stripped():
    frame = bytes(range(17))
    # The padding bytes are deliberately non-zero: they must still be
    # recognised as alignment padding and discarded.
    blob = build_shb() + build_idb() + build_epb(
        17, 17, frame, padding=b"\xAB\xCD\xEF\x01"
    )
    _, _, epb = scan(blob)

    assert epb.captured_len == 17
    assert epb.packet_data == frame
    assert not epb.packet_data.endswith(b"\xAB\xCD\xEF")


def test_epb_snaplen_truncated_frame():
    full_frame = bytes(range(100))
    snap = 40
    blob = build_shb() + build_idb(snaplen=snap)
    blob += build_epb(snap, 100, full_frame[:snap])
    _, _, epb = scan(blob)

    assert epb.captured_len == snap
    assert epb.packet_len == 100
    assert epb.packet_data == full_frame[:snap]
    assert epb.packet_truncated is True


def test_epb_contradictory_lengths_raise_bad_packet_length():
    # Captured length greater than the on-wire length is impossible.
    frame = bytes(range(20))
    blob = build_shb() + build_idb() + build_epb(20, 10, frame)
    with pytest.raises(BadPacketLength):
        scan(blob)


def test_epb_physically_truncated_block_raises_truncated_file():
    # The length fields are self-consistent, but the stream ends before
    # the advertised packet data can be read.
    frame = bytes(range(20))
    blob = build_shb() + build_idb() + build_epb(32, 32, frame)
    # Chop off the final 12 bytes (missing packet tail + trailing length)
    with pytest.raises(TruncatedFile):
        scan(blob[:-12])


def test_epb_fcs_from_interface_when_complete():
    frame = bytes(range(60))
    # if_fcslen is expressed in *bits*: 32 bits == 4 bytes
    blob = build_shb() + build_idb(fcs_bits=32)
    blob += build_epb(60, 60, frame)
    _, _, epb = scan(blob)

    assert epb.fcs_length == 4
    assert epb.fcs_present is True
    assert epb.fcs == frame[-4:]
    # The FCS bytes must remain part of packet_data (no stripping)
    assert epb.packet_data == frame


def test_epb_truncated_frame_never_claims_fcs():
    full_frame = bytes(range(100))
    snap = 40
    blob = build_shb() + build_idb(snaplen=snap, fcs_bits=32)
    blob += build_epb(snap, 100, full_frame[:snap])
    _, _, epb = scan(blob)

    # The interface advertises a 4-byte FCS, but we don't hold the tail
    assert epb.fcs_length == 4
    assert epb.fcs_present is False
    assert epb.fcs is None


def test_epb_packet_flags_fcslen_overrides_interface():
    frame = bytes(range(60))
    flags = EPBFlags(0)
    flags.fcslen = 2  # bytes, per the epb_flags definition
    blob = build_shb() + build_idb(fcs_bits=32)  # interface says 4 bytes
    blob += build_epb(60, 60, frame, epb_flags=flags)
    _, _, epb = scan(blob)

    assert epb.fcs_length == 2
    assert epb.fcs_present is True
    assert epb.fcs == frame[-2:]


def test_epb_zero_packet_fcslen_falls_back_to_interface():
    frame = bytes(range(60))
    flags = EPBFlags(0)  # fcslen == 0 -> not stated at packet level
    blob = build_shb() + build_idb(fcs_bits=32)
    blob += build_epb(60, 60, frame, epb_flags=flags)
    _, _, epb = scan(blob)

    assert epb.fcs_length == 4
    assert epb.fcs_present is True
    assert epb.fcs == frame[-4:]


def test_epb_packet_fcslen_on_truncated_packet_not_present():
    full_frame = bytes(range(100))
    snap = 50
    flags = EPBFlags(0)
    flags.fcslen = 4
    blob = build_shb() + build_idb(snaplen=snap)
    blob += build_epb(snap, 100, full_frame[:snap], epb_flags=flags)
    _, _, epb = scan(blob)

    assert epb.fcs_length == 4  # metadata still says 4
    assert epb.fcs_present is False  # ...but the bytes aren't held
    assert epb.fcs is None


def test_epb_no_fcs_metadata():
    frame = bytes(range(60))
    blob = build_shb() + build_idb() + build_epb(60, 60, frame)
    _, _, epb = scan(blob)

    assert epb.fcs_length == 0
    assert epb.fcs_present is False
    assert epb.fcs is None


def test_epb_plausible_length_is_not_enough_to_claim_fcs():
    # The captured length is itself a perfectly valid frame size and the
    # interface advertises an FCS, but because the frame was snap-length
    # truncated the trailing bytes are payload, not a check sequence.
    snap = 64
    full_frame = bytes(range(128))
    blob = build_shb() + build_idb(snaplen=snap, fcs_bits=32)
    blob += build_epb(snap, 128, full_frame[:snap])
    _, _, epb = scan(blob)

    assert epb.captured_len == snap  # looks like a legal packet length
    assert epb.packet_truncated is True
    assert epb.fcs_length == 4
    assert epb.fcs_present is False
    assert epb.fcs is None
    # packet_data must not have four bytes peeled off the end
    assert epb.packet_data == full_frame[:snap]


# ---------------------------------------------------------------------------
# Simple Packet Block
# ---------------------------------------------------------------------------


def test_spb_full_frame_snaplen_zero():
    frame = bytes(range(100))  # multiple of 4, no padding
    blob = build_shb() + build_idb(snaplen=0) + build_spb(100, frame)
    _, _, spb = scan(blob)

    assert isinstance(spb, SimplePacket)
    assert spb.packet_len == 100
    assert spb.captured_len == 100
    assert spb.packet_data == frame
    assert spb.packet_truncated is False


def test_spb_full_frame_with_nonzero_padding():
    frame = bytes(range(17))
    blob = build_shb() + build_idb(snaplen=0)
    blob += build_spb(17, frame, padding=b"\x5A\x5A\x5A\x5A")
    _, _, spb = scan(blob)

    assert spb.captured_len == 17
    assert spb.packet_len == 17
    assert spb.packet_data == frame
    assert not spb.packet_data.endswith(b"\x5A")


def test_spb_snaplen_truncated():
    full_frame = bytes(range(100))
    snap = 32
    blob = build_shb() + build_idb(snaplen=snap)
    blob += build_spb(100, full_frame[:snap])
    _, _, spb = scan(blob)

    assert spb.packet_len == 100
    assert spb.captured_len == snap
    assert spb.packet_data == full_frame[:snap]
    assert spb.packet_truncated is True
    assert spb.fcs_present is False


def test_spb_block_with_more_bytes_than_snaplen_implies():
    # Real-world captures sometimes store more packet bytes than the snap
    # length implies. The reader must use the snap-length-implied amount and
    # not treat the extra bytes as packet data.
    frame = bytes(range(123))
    snap = 96
    blob = build_shb() + build_idb(snaplen=snap) + build_spb(1000, frame)
    _, _, spb = scan(blob)

    assert spb.packet_len == 1000
    assert spb.captured_len == snap
    assert spb.packet_data == frame[:snap]
    assert spb.packet_truncated is True


def test_spb_contradictory_length_raises_bad_packet_length():
    # snap length implies 32 captured bytes, but the block stores only 20
    frame = bytes(range(20))
    blob = build_shb() + build_idb(snaplen=32) + build_spb(100, frame)
    with pytest.raises(BadPacketLength):
        scan(blob)


def test_spb_physically_truncated_block_raises_truncated_file():
    # Self-consistent block on paper, but the file ends mid-block.
    frame = bytes(range(40))
    blob = build_shb() + build_idb(snaplen=0) + build_spb(60, frame)
    with pytest.raises(TruncatedFile):
        scan(blob[:-8])


def test_spb_fcs_only_when_full_frame_held():
    frame = bytes(range(60))
    blob = build_shb() + build_idb(snaplen=0, fcs_bits=32)
    blob += build_spb(60, frame)
    _, _, spb = scan(blob)

    assert spb.fcs_length == 4
    assert spb.fcs_present is True
    assert spb.fcs == frame[-4:]


def test_spb_truncated_contradiction_distinct_from_physical_truncation():
    # A complete block whose payload contradicts its lengths is
    # BadPacketLength, whereas a block cut off by EOF is TruncatedFile.
    contradictory = (
        build_shb() + build_idb(snaplen=64) + build_spb(100, bytes(range(20)))
    )
    physical = (
        build_shb()
        + build_idb(snaplen=0)
        + build_spb(100, bytes(range(40)))
    )
    with pytest.raises(BadPacketLength):
        scan(contradictory)
    with pytest.raises(TruncatedFile):
        scan(physical[:-8])


# ---------------------------------------------------------------------------
# Round trip through the writer: padding must be pure alignment, never
# zero-fill to reach the on-wire length.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_writer_does_not_zero_fill_to_wire_length(endianness):
    shb = SectionHeader(endianness=endianness)
    shb.new_member(InterfaceDescription, snaplen=32)
    packet = shb.new_member(SimplePacket, packet_data=bytes(range(33)))

    out = io.BytesIO()
    FileWriter(out, shb).write_block(packet)
    raw = out.getvalue()

    # Locate the SPB (last block) and inspect its payload directly.
    block_len = struct.unpack_from(endianness + "I", raw, len(raw) - 4)[0]
    spb_start = len(raw) - block_len
    packet_len = struct.unpack_from(endianness + "I", raw, spb_start + 8)[0]
    assert packet_len == 33  # on-wire length is preserved
    # 4 (packet_len field) + 32 captured bytes + 0 padding == 36 payload bytes
    assert block_len == 12 + 4 + 32

    _, _, reread = scan(raw)
    assert reread.packet_len == 33
    assert reread.captured_len == 32
    assert reread.packet_data == bytes(range(32))


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_writer_pads_non_aligned_spb_to_32_bits(endianness):
    shb = SectionHeader(endianness=endianness)
    shb.new_member(InterfaceDescription)  # snaplen 0 -> unlimited
    frame = bytes(range(256))
    packet = shb.new_member(SimplePacket, packet_data=frame)

    out = io.BytesIO()
    FileWriter(out, shb).write_block(packet)
    raw = out.getvalue()

    block_len = struct.unpack_from(endianness + "I", raw, len(raw) - 4)[0]
    # 4-byte packet_len + 256 data bytes + 0 padding (256 is 4-aligned)
    assert block_len == 12 + 4 + 256

    # And a deliberately misaligned frame gets exactly the needed padding
    odd_frame = bytes(range(255))
    packet2 = shb.new_member(SimplePacket, packet_data=odd_frame)
    out2 = io.BytesIO()
    FileWriter(out2, shb).write_block(packet2)
    raw2 = out2.getvalue()
    block_len2 = struct.unpack_from(endianness + "I", raw2, len(raw2) - 4)[0]
    assert block_len2 == 12 + 4 + 255 + 1

    _, _, reread = scan(raw2)
    assert reread.packet_data == odd_frame
    assert reread.captured_len == 255
