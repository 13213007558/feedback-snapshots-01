"""
Tests for migrating obsolete Packet Blocks (PB) to Enhanced Packet
Blocks (EPB), eg. when re-archiving captures produced by old probes.

Two conversion paths exist and must produce identical results:

1. explicit conversion via ``ObsoletePacket.enhanced()`` /
   ``ObsoletePacket.migrate()``
2. automatic fixing by the writer in ``Strictness.FIX`` mode

Information that has no equivalent in an EPB (eg. the "unknown" drop
count sentinel) must be listed in the migration report -- the absence
of exceptions is not proof of a lossless migration.
"""

import io
import struct

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.exceptions import PcapngStrictnessWarning
from pcapng.strictness import Strictness, set_strictness

TIMESTAMP_HIGH = 0x01234567
TIMESTAMP_LOW = 0x89ABCDEF
PACKET_DATA = bytes(range(8))
PACKET_LEN = 20  # original on-wire length, larger than the captured data
COMMENTS = ["first comment", "second comment"]
HASHES = [(2, b"\xaa" * 8), (5, b"\xbb" * 4)]  # (hash type, digest)
FLAGS = 0x12
UNKNOWN_OPT_CODE = 100
UNKNOWN_OPT_VALUE = b"unknown-opt"


@pytest.fixture
def strictness_fix():
    set_strictness(Strictness.FIX)
    yield
    set_strictness(Strictness.FORBID)


def _pack_option(endianness, code, value):
    pad = b"\x00" * ((4 - len(value) % 4) % 4)
    return struct.pack(endianness + "HH", code, len(value)) + value + pad


def make_packet_block_bytes(endianness, drops_count):
    """Craft the raw bytes of an obsolete Packet Block, as an old probe
    would have written it: repeated comments, repeated hashes, a flags
    option, an unknown option and the given drops count."""
    body = struct.pack(
        endianness + "HHIIII",
        0,  # interface_id
        drops_count,
        TIMESTAMP_HIGH,
        TIMESTAMP_LOW,
        len(PACKET_DATA),  # captured_len
        PACKET_LEN,  # packet_len
    )
    body += PACKET_DATA
    body += b"\x00" * ((4 - len(PACKET_DATA) % 4) % 4)
    for comment in COMMENTS:
        body += _pack_option(endianness, 1, comment.encode("utf-8"))
    for hash_type, digest in HASHES:
        body += _pack_option(endianness, 3, bytes([hash_type]) + digest)
    body += _pack_option(endianness, 2, struct.pack(endianness + "I", FLAGS))
    body += _pack_option(endianness, UNKNOWN_OPT_CODE, UNKNOWN_OPT_VALUE)
    body += struct.pack(endianness + "I", 0)  # opt_endofopt
    block_length = 12 + len(body)
    return (
        struct.pack(endianness + "II", 0x00000002, block_length)
        + body
        + struct.pack(endianness + "I", block_length)
    )


def read_packet_block(endianness="<", drops_count=blocks.DROPS_COUNT_UNKNOWN):
    """Read an obsolete Packet Block from a crafted capture file."""
    stream = io.BytesIO()
    shb = blocks.SectionHeader(endianness=endianness)
    shb.new_member(blocks.InterfaceDescription, link_type=1, snaplen=65535)
    FileWriter(stream, shb)
    stream.write(make_packet_block_bytes(endianness, drops_count))
    stream.seek(0)
    parsed = list(FileScanner(stream))
    packet = parsed[2]
    assert isinstance(packet, blocks.ObsoletePacket)
    return packet


def write_and_reread(blocks_to_write, shb):
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for blk in blocks_to_write:
        writer.write_block(blk)
    raw = stream.getvalue()
    stream.seek(0)
    return list(FileScanner(stream)), raw


def assert_same_epb(epb1, epb2):
    """Field-by-field comparison of two EPBs. Options are compared via
    their raw encoded values, as FlagWord does not implement __eq__."""
    for field in (
        "interface_id",
        "timestamp_high",
        "timestamp_low",
        "captured_len",
        "packet_len",
        "packet_data",
    ):
        assert getattr(epb1, field) == getattr(epb2, field), field
    assert set(epb1.options) == set(epb2.options)
    for key in epb1.options:
        assert epb1.options.get_all_raw(key) == epb2.options.get_all_raw(key), key


def check_migrated_epb(epb, source_pb):
    """Field-by-field comparison of a migrated EPB against the PB it
    came from. Every PB field that has an EPB equivalent must match."""
    assert isinstance(epb, blocks.EnhancedPacket)
    assert epb.interface_id == source_pb.interface_id
    assert epb.timestamp_high == source_pb.timestamp_high
    assert epb.timestamp_low == source_pb.timestamp_low
    assert epb.captured_len == len(source_pb.packet_data)
    assert epb.packet_len == source_pb.packet_len
    assert epb.packet_data == source_pb.packet_data
    # Repeated options must survive in full, not just their first item
    assert epb.options.get_all("opt_comment") == COMMENTS
    assert epb.options.get_all("epb_hash") == HASHES
    assert len(epb.options.get_all("epb_flags")) == 1
    assert int(epb.options["epb_flags"]) == FLAGS


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_migrate_both_paths_identical(endianness, strictness_fix):
    """Run the same PB (repeated options + unknown drop count) through
    the explicit conversion and the writer auto-fix, then compare the
    re-read results field by field."""
    pb = read_packet_block(endianness)

    # Path 1: explicit conversion
    migration = pb.migrate()
    epb_explicit = migration.block
    parsed_explicit, raw_explicit = write_and_reread([epb_explicit], pb.section)

    # Path 2: writer auto-fix of the obsolete block
    with pytest.warns(PcapngStrictnessWarning):
        parsed_autofix, raw_autofix = write_and_reread([pb], pb.section)

    epb_explicit = parsed_explicit[2]
    epb_autofix = parsed_autofix[2]

    # Both paths must yield the same, fully migrated EPB
    check_migrated_epb(epb_explicit, pb)
    check_migrated_epb(epb_autofix, pb)
    assert_same_epb(epb_explicit, epb_autofix)
    assert raw_explicit == raw_autofix

    # The unknown drop count sentinel must not become a real number
    assert "epb_dropcount" not in epb_explicit.options
    assert "epb_dropcount" not in epb_autofix.options

    # Non-migratable information must be listed in the report
    unmigrated = {item.field: item for item in migration.unmigrated}
    assert unmigrated["drops_count"].value == blocks.DROPS_COUNT_UNKNOWN
    assert unmigrated["drops_count"].reason
    assert unmigrated["options[{0!r}]".format(UNKNOWN_OPT_CODE)].value == [
        UNKNOWN_OPT_VALUE
    ]


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_migrate_known_drops_count(endianness, strictness_fix):
    """A real drops count is migrated to epb_dropcount; nothing is
    reported as unmigrated except unknown options."""
    pb = read_packet_block(endianness, drops_count=7)
    migration = pb.migrate()
    epb = write_and_reread([migration.block], pb.section)[0][2]
    assert epb.options["epb_dropcount"] == 7
    assert "drops_count" not in {item.field for item in migration.unmigrated}
    check_migrated_epb(epb, pb)


def test_enhanced_returns_block_only():
    """Backward compatibility: enhanced() returns just the EPB."""
    pb = read_packet_block()
    assert isinstance(pb.enhanced(), blocks.EnhancedPacket)
