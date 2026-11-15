"""
Tests for opaque preservation of :class:`pcapng.blocks.UnknownBlock`.

An unknown block has no schema, so its payload can only be copied verbatim.
These tests pin down the supported operations (byte-exact preservation in the
home section; same-byte-order relocation of standardized types) and the
operations that must be refused (any byte-order change; copying local-use
extensions between sections; laundering reserved block types).
"""

import io
import struct

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.constants.block_types import (
    is_corruption_detection_block_type,
    is_reserved_block_type,
)
from pcapng.exceptions import CorruptedFile, OpaqueBlockError, PcapngDumpError

STANDARD_UNKNOWN_TYPE = 0x00000009  # MSB clear: a not-locally-registered type
LOCAL_USE_TYPE = 0x80000001  # MSB set: private / local-use extension
PAYLOAD = b"OPAQUE-PAYLOAD"  # 14 bytes, forces two padding bytes


def shb_bytes(endianness):
    return (
        struct.pack(endianness + "II", 0x0A0D0D0A, 28)
        + struct.pack(endianness + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        + struct.pack(endianness + "I", 28)
    )


def idb_bytes(endianness):
    return (
        struct.pack(endianness + "IIHHI", 1, 20, 0, 0, 0)
        + struct.pack(endianness + "I", 20)
    )


def unknown_block_bytes(endianness, block_type, payload=PAYLOAD):
    padding = b"\x00" * ((-len(payload)) % 4)
    block_length = 12 + len(payload) + len(padding)
    return (
        struct.pack(endianness + "II", block_type, block_length)
        + payload
        + padding
        + struct.pack(endianness + "I", block_length)
    )


def scan(data):
    return list(FileScanner(io.BytesIO(data)))


def only_unknown(block_list):
    result = [b for b in block_list if isinstance(b, blocks.UnknownBlock)]
    assert len(result) == 1
    return result[0]


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_unknown_block_keeps_section_provenance(endianness):
    data = (
        shb_bytes(endianness)
        + idb_bytes(endianness)
        + unknown_block_bytes(endianness, STANDARD_UNKNOWN_TYPE)
    )
    shb, _idb, unknown = scan(data)

    assert isinstance(unknown, blocks.UnknownBlock)
    assert unknown.block_type == STANDARD_UNKNOWN_TYPE
    assert unknown.section is shb
    assert unknown.source_endianness == endianness
    assert unknown.data == PAYLOAD + b"\x00\x00"


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_in_place_write_preserves_payload_bytes(endianness):
    data = (
        shb_bytes(endianness)
        + idb_bytes(endianness)
        + unknown_block_bytes(endianness, STANDARD_UNKNOWN_TYPE)
        + unknown_block_bytes(endianness, LOCAL_USE_TYPE, b"LOCAL-DATA-XY")
    )
    shb, _idb, standard_unknown, local_unknown = scan(data)
    original_payloads = [standard_unknown.data, local_unknown.data]

    out = io.BytesIO()
    writer = FileWriter(out, shb)
    writer.write_block(standard_unknown)
    writer.write_block(local_unknown)

    # Byte-exact: same section byte order means framing and body are untouched
    assert out.getvalue() == data

    out.seek(0)
    roundtrip = [b for b in scan(out.getvalue()) if isinstance(b, blocks.UnknownBlock)]
    assert [b.data for b in roundtrip] == original_payloads
    assert all(b.source_endianness == endianness for b in roundtrip)


def test_local_use_block_stays_writable_in_home_section():
    data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", LOCAL_USE_TYPE)
    )
    shb, _idb, local_unknown = scan(data)

    out = io.BytesIO()
    writer = FileWriter(out, shb)
    writer.write_block(local_unknown)  # same section: must be allowed
    assert out.getvalue() == data


def test_same_endian_relocation_standard_type_is_supported():
    source_data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", STANDARD_UNKNOWN_TYPE)
    )
    source_shb, _idb, unknown = scan(source_data)
    target_shb = blocks.SectionHeader(endianness="<")

    assert unknown.move_to_section(target_shb) is unknown
    assert unknown.section is target_shb

    # It now writes through a writer opened on the target section, payload intact
    out = io.BytesIO()
    writer = FileWriter(out, target_shb)
    writer.write_block(unknown)
    out.seek(0)
    relocated = only_unknown(scan(out.getvalue()))
    assert relocated.data == unknown.data
    assert relocated.block_type == STANDARD_UNKNOWN_TYPE


def test_cross_section_write_without_relocation_is_rejected_by_writer():
    # The generic writer guard still applies: provenance must be changed
    # explicitly via move_to_section(), not silently by writing elsewhere.
    source_data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", STANDARD_UNKNOWN_TYPE)
    )
    _source_shb, _idb, unknown = scan(source_data)
    other_shb = blocks.SectionHeader(endianness="<")

    out = io.BytesIO()
    writer = FileWriter(out, other_shb)
    with pytest.raises(PcapngDumpError, match="block not from current section"):
        writer.write_block(unknown)


def test_relocation_across_byte_order_is_refused():
    source_data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", STANDARD_UNKNOWN_TYPE)
    )
    _source_shb, _idb, unknown = scan(source_data)
    big_endian_section = blocks.SectionHeader(endianness=">")

    with pytest.raises(OpaqueBlockError, match="cannot be byte-swapped"):
        unknown.move_to_section(big_endian_section)

    # The refused move must not have mutated provenance
    assert unknown.source_endianness == "<"
    assert unknown.section is not big_endian_section


def test_writer_refuses_cross_endian_opaque_payload():
    # Even if a block is (mis)attached to a section, an endianness mismatch
    # between payload provenance and target section is refused at write time.
    big_endian_section = blocks.SectionHeader(endianness=">")
    unknown = blocks.UnknownBlock(
        big_endian_section,
        STANDARD_UNKNOWN_TYPE,
        PAYLOAD + b"\x00\x00",
        endianness="<",
    )

    out = io.BytesIO()
    writer = FileWriter(out, big_endian_section)
    with pytest.raises(OpaqueBlockError, match="payload has no schema"):
        writer.write_block(unknown)

    # Nothing partial was written before the refusal (only the SHB is present)
    assert out.getvalue() == shb_bytes(">")


def test_local_use_block_cannot_be_copied_between_sections():
    source_data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", LOCAL_USE_TYPE)
    )
    _source_shb, _idb, local_unknown = scan(source_data)
    target_shb = blocks.SectionHeader(endianness="<")  # same byte order

    assert local_unknown.is_local_use is True
    with pytest.raises(OpaqueBlockError, match="local-use block type"):
        local_unknown.move_to_section(target_shb)
    assert local_unknown.section is not target_shb


def test_byte_order_change_takes_precedence_over_local_use_rule():
    # Both rules apply; the byte-order rule must be reported first because it
    # is the more fundamental impossibility.
    source_data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", LOCAL_USE_TYPE)
    )
    _source_shb, _idb, local_unknown = scan(source_data)
    big_endian_section = blocks.SectionHeader(endianness=">")

    with pytest.raises(OpaqueBlockError, match="cannot be byte-swapped"):
        local_unknown.move_to_section(big_endian_section)


@pytest.mark.parametrize("reserved_type", [0x00000000])
def test_reserved_block_type_cannot_be_constructed_opaquely(reserved_type):
    shb = blocks.SectionHeader(endianness="<")
    with pytest.raises(ValueError, match="reserved"):
        blocks.UnknownBlock(shb, reserved_type, b"whatever")


@pytest.mark.parametrize(
    "block_type",
    [
        0x0A0D0A00,  # base value of (0x0A0D0A00, 0x0A0D0AFF)
        0xFF0D0A00,  # same pattern, differing in the masked-in high bytes
        0x000A0D0A,  # exact match for a full-mask pattern
        0x000A0D0D,  # exact match for a full-mask pattern
        0x0D0D0A00,  # base value of (0x0D0D0A00, 0x0D0D0AFF)
    ],
)
def test_corruption_detection_types_are_rejected(block_type):
    assert is_corruption_detection_block_type(block_type)
    assert is_reserved_block_type(block_type)

    # The scanner rejects them while reading rather than wrapping them
    data = (
        shb_bytes("<")
        + idb_bytes("<")
        + unknown_block_bytes("<", block_type)
    )
    with pytest.raises(CorruptedFile, match="corrupted"):
        scan(data)

    # And they cannot be laundered through direct construction either
    shb = blocks.SectionHeader(endianness="<")
    with pytest.raises(ValueError, match="reserved"):
        blocks.UnknownBlock(shb, block_type, b"whatever")


def test_unknown_block_equality_includes_provenance():
    shb = blocks.SectionHeader(endianness="<")
    payload = PAYLOAD + b"\x00\x00"
    first = blocks.UnknownBlock(shb, STANDARD_UNKNOWN_TYPE, payload, endianness="<")
    second = blocks.UnknownBlock(shb, STANDARD_UNKNOWN_TYPE, payload, endianness="<")
    swapped = blocks.UnknownBlock(shb, STANDARD_UNKNOWN_TYPE, payload, endianness=">")

    assert first == second
    assert first != swapped
    assert hash(first) == hash(second)
