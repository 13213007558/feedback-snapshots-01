"""
Tests for the packet hash verification and editing contract
(``pcapng.pkthash``), covering reading, in-place modification and
writing back of packets carrying ``epb_hash`` declarations.
"""

import hashlib
import io
import struct
import zlib

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning
from pcapng.exceptions import StaleHashError
from pcapng.pkthash import HashOrigin, HashStatus
from pcapng.strictness import Strictness, set_strictness

PAYLOAD = (
    b"\x00\x02\x157\xa2D\x00\xae\xf3R\xaa\xd1\x08\x00"  # Ethernet
    b"E\x00\x00C\x00\x01\x00\x00@\x06x<\xc0\xa8\x05\x15B#\xfa\x97"  # IP
    b"\x00\x14\x00P\x00\x00\x00\x00\x00\x00\x00\x00P\x02 "  # TCP
    b"\x00\xbb9\x00\x00"  # TCP(cont)
    b"GET /index.html HTTP/1.0 \n\n"  # HTTP
)

NEW_PAYLOAD = b"\xde\xad\xbe\xef" * 8 + b"derived sample"


def crc32_bytes(data):
    return struct.pack(">I", zlib.crc32(data) & 0xFFFFFFFF)


def supported_hashes(data):
    """Well-formed (algo, digest) declarations for all supported algorithms."""
    return [
        (2, crc32_bytes(data)),
        (3, hashlib.md5(data).digest()),
        (4, hashlib.sha1(data).digest()),
    ]


def build_capture(packet_data=PAYLOAD, hashes=None, endianness=">"):
    """Build an in-memory capture with one EPB; return the EPB as read back."""
    shb = blocks.SectionHeader(endianness=endianness)
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    epb = shb.new_member(blocks.EnhancedPacket, packet_data=packet_data)
    if hashes is not None:
        epb.options["epb_hash"] = hashes
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    writer.write_block(epb)
    stream.seek(0)
    return read_epb(stream)


def read_epb(stream):
    for block in FileScanner(stream):
        if isinstance(block, blocks.EnhancedPacket):
            return block
    raise AssertionError("no EnhancedPacket found")


def write_capture(epb):
    """Write the packet's section + the packet to a new stream."""
    stream = io.BytesIO()
    writer = FileWriter(stream, epb.section)
    writer.write_block(epb)
    stream.seek(0)
    return stream


@pytest.fixture
def restore_strictness():
    yield
    set_strictness(Strictness.FORBID)


def test_verify_distinguishes_match_mismatch_malformed_unverified():
    epb = build_capture(
        hashes=[
            (2, crc32_bytes(PAYLOAD)),  # match
            (3, b"\x00" * 16),  # well-formed but wrong -> mismatch
            (4, b"\x01\x02\x03"),  # wrong size for sha1 -> malformed
            (0, b"\x00\x00\x00\x00"),  # 2s-complement: not computable
            (0x99, b"\x42"),  # unknown algorithm
        ]
    )

    report = epb.verify_hashes()
    assert not report.stale
    assert report.valid
    report.assert_fresh()

    by_algo = {check.algorithm: check for check in report}
    assert by_algo[2].status is HashStatus.MATCH
    assert by_algo[2].computed == crc32_bytes(PAYLOAD)

    assert by_algo[3].status is HashStatus.MISMATCH
    assert by_algo[3].computed == hashlib.md5(PAYLOAD).digest()
    assert by_algo[3].declared == b"\x00" * 16

    assert by_algo[4].status is HashStatus.MALFORMED
    assert by_algo[4].computed == hashlib.sha1(PAYLOAD).digest()

    # Unsupported/unknown algorithms: declaration preserved, unverified
    assert by_algo[0].status is HashStatus.UNVERIFIED
    assert by_algo[0].computed is None
    assert by_algo[0].declared == b"\x00\x00\x00\x00"
    assert by_algo[0].algorithm_name == "2s-complement"
    assert by_algo[0x99].status is HashStatus.UNVERIFIED
    assert by_algo[0x99].computed is None
    assert by_algo[0x99].declared == b"\x42"
    assert by_algo[0x99].algorithm_name is None

    # Everything read from the file is original evidence
    assert all(check.origin is HashOrigin.ORIGINAL for check in report)
    assert not epb.hashes_derived
    assert len(epb.original_hashes) == 5
    assert not report.all_matched  # only 1 of 5 matched


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_verify_modify_recompute_save_readback(endianness):
    """
    The full contract scenario: one packet carrying multiple hashes is
    verified, its payload is modified, hashes are explicitly recomputed,
    then the packet is saved and read back.
    """
    unknown_decl = (0x99, b"\x13\x37")
    epb = build_capture(
        hashes=supported_hashes(PAYLOAD) + [unknown_decl], endianness=endianness
    )

    # --- verify first ---
    report = epb.verify_hashes()
    assert len(report) == 4
    assert {check.algorithm for check in report.matched} == {2, 3, 4}
    assert {check.algorithm for check in report.unverified} == {0x99}
    original_evidence = epb.original_hashes
    assert len(original_evidence) == 4

    # --- modify the payload: old conclusions are invalidated ---
    epb.packet_data = NEW_PAYLOAD
    assert report.stale
    assert not report.valid
    with pytest.raises(StaleHashError):
        report.assert_fresh()
    # The old report keeps referring to the old bytes even after recompute
    # (checked again below).

    # --- explicitly recompute the supported hashes ---
    derived_report = epb.recompute_hashes()
    assert derived_report.all_matched
    assert {check.algorithm for check in derived_report} == {2, 3, 4}
    assert all(check.origin is HashOrigin.DERIVED for check in derived_report)
    assert epb.hashes_derived
    # The unknown algorithm cannot be recomputed: no forged result for it
    assert 0x99 not in {check.algorithm for check in derived_report}
    # Original evidence is untouched and still traceable
    assert epb.original_hashes == original_evidence
    assert all(item.origin is HashOrigin.ORIGINAL for item in epb.original_hashes)
    assert (0x99, b"\x13\x37") in [
        (item.algorithm, item.digest) for item in epb.original_hashes
    ]
    # The old report is still stale -- old conclusions stay invalid
    assert report.stale

    # --- save and read back ---
    re_epb = read_epb(write_capture(epb))
    assert re_epb.packet_data == NEW_PAYLOAD
    re_report = re_epb.verify_hashes()
    assert re_report.all_matched
    # Recomputed values correspond to the new bytes
    by_algo = {check.algorithm: check for check in re_report}
    assert by_algo[2].declared == crc32_bytes(NEW_PAYLOAD)
    assert by_algo[3].declared == hashlib.md5(NEW_PAYLOAD).digest()
    assert by_algo[4].declared == hashlib.sha1(NEW_PAYLOAD).digest()
    # The derived declarations became the file's original declarations
    assert all(item.origin is HashOrigin.ORIGINAL for item in re_epb.original_hashes)
    assert len(re_epb.original_hashes) == 3


def test_comment_only_edit_is_not_a_packet_change():
    """Control case: editing only the comment must not invalidate hashes."""
    epb = build_capture(hashes=supported_hashes(PAYLOAD))
    report = epb.verify_hashes()
    assert report.all_matched

    epb.options["opt_comment"] = "annotated, not modified"

    assert not report.stale
    report.assert_fresh()
    assert report.all_matched
    # ...and writing the packet back does not raise or drop anything
    re_epb = read_epb(write_capture(epb))
    assert re_epb.options["opt_comment"] == "annotated, not modified"
    assert read_epb(write_capture(epb)).verify_hashes().all_matched
    assert len(re_epb.original_hashes) == 3


def test_stale_hashes_rejected_on_write_by_default(restore_strictness):
    """Old hashes must not follow new bytes into a derived file."""
    set_strictness(Strictness.FORBID)
    epb = build_capture(hashes=supported_hashes(PAYLOAD))
    epb.packet_data = NEW_PAYLOAD
    with pytest.raises(PcapngStrictnessError, match="stale 'epb_hash'"):
        write_capture(epb)


def test_stale_hashes_dropped_on_write_in_fix_mode(restore_strictness):
    set_strictness(Strictness.FIX)
    epb = build_capture(hashes=supported_hashes(PAYLOAD) + [(0x99, b"\x00")])
    epb.packet_data = NEW_PAYLOAD
    with pytest.warns(PcapngStrictnessWarning, match="stale 'epb_hash'"):
        stream = write_capture(epb)
    re_epb = read_epb(stream)
    # All declarations were stale -> none written; original evidence kept
    assert "epb_hash" not in re_epb.options
    assert len(epb.original_hashes) == 4


def test_unmodified_packet_roundtrip_preserves_declarations():
    """
    Declarations of an unmodified packet are written back as-is, even if
    they don't verify: they are the file's evidence, not ours.
    """
    epb = build_capture(hashes=[(3, b"\x00" * 16), (0x99, b"\x01\x02")])
    re_epb = read_epb(write_capture(epb))  # no strictness error
    report = re_epb.verify_hashes()
    by_algo = {check.algorithm: check for check in report}
    assert by_algo[3].status is HashStatus.MISMATCH
    assert by_algo[0x99].status is HashStatus.UNVERIFIED
    assert by_algo[0x99].declared == b"\x01\x02"


def test_recompute_rejects_unsupported_algorithms():
    epb = build_capture(hashes=supported_hashes(PAYLOAD))
    with pytest.raises(ValueError, match="unsupported algorithm"):
        epb.recompute_hashes(algorithms=[0x99])
    with pytest.raises(ValueError, match="unsupported algorithm"):
        epb.recompute_hashes(algorithms=[0])  # 2s-complement: not computable
    with pytest.raises(ValueError, match="unsupported algorithm"):
        epb.recompute_hashes(algorithms=["toeplitz"])
    # Failed recompute attempts leave the declarations untouched
    assert not epb.hashes_derived
    assert len(epb.verify_hashes()) == 3


def test_recompute_with_explicit_algorithms():
    epb = build_capture(hashes=supported_hashes(PAYLOAD))
    epb.packet_data = NEW_PAYLOAD
    report = epb.recompute_hashes(algorithms=["md5", 4])
    assert report.all_matched
    assert {check.algorithm for check in report} == {3, 4}
    re_epb = read_epb(write_capture(epb))
    assert {check.algorithm for check in re_epb.verify_hashes()} == {3, 4}


def test_manually_refreshed_hashes_are_accepted_on_write():
    """
    A caller setting well-formed, correct declarations for the new bytes
    by hand is not mistaken for a stale-hash writer.
    """
    epb = build_capture(hashes=supported_hashes(PAYLOAD))
    epb.packet_data = NEW_PAYLOAD
    epb.options["epb_hash"] = supported_hashes(NEW_PAYLOAD)
    re_epb = read_epb(write_capture(epb))  # no strictness error
    assert re_epb.verify_hashes().all_matched


def test_obsolete_packet_block_pack_hash():
    """The same contract applies to the obsolete packet block."""
    shb = blocks.SectionHeader(endianness=">")
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    pkt = shb.new_member(
        blocks.ObsoletePacket,
        packet_data=PAYLOAD,
        options={"pack_hash": supported_hashes(PAYLOAD)},
    )
    report = pkt.verify_hashes()
    assert report.all_matched
    pkt.packet_data = NEW_PAYLOAD
    assert report.stale
    derived = pkt.recompute_hashes()
    assert derived.all_matched
    assert len(pkt.original_hashes) == 3
