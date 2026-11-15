import io
import os
import struct

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner
from pcapng.sanitizer import (
    SanitizationError,
    SanitizationPolicy,
    sanitize_bytes,
    sanitize_capture,
)

SECRETS = [
    b"capture-host.internal",
    b"internal-os",
    b"internal-capture-tool",
    b"mgmt0-internal",
    b"uplink to internal-lab",
    b"internal-os-release",
    b"vendor-secret-value",
    b"resolver.internal.example",
    b"mail.internal.example",
    b"unknown-nrb-secret",
    b"opaque-extension-secret",
    b"packet-comment-secret",
    b"section-comment-secret",
    b"interface-comment-secret",
]

PACKETS = [b"PACKET-ONE-0123456789", b"PACKET-TWO-9876543210", b"PACKET-THREE"]


def _pad(data):
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _option(code, payload, endianness="<"):
    return struct.pack(endianness + "HH", code, len(payload)) + _pad(payload)


def _block(magic, payload, endianness="<"):
    payload = _pad(payload)
    return (
        struct.pack(endianness + "II", magic, 12 + len(payload))
        + payload
        + struct.pack(endianness + "I", 12 + len(payload))
    )


def _epb(interface_id, packet, options=b"", endianness="<"):
    payload = _pad(packet)
    header = struct.pack(
        endianness + "IIIII",
        interface_id,
        0,
        1,
        len(packet),
        len(packet),
    )
    return _block(6, header + payload + options, endianness)


def _name_resolution_record(record_type, payload, endianness="<"):
    return struct.pack(endianness + "HH", record_type, len(payload)) + _pad(payload)


def make_capture(endianness="<", declared_section_length=False):
    """Build an in-memory capture with every metadata source under test."""
    section_options = (
        _option(1, b"section-comment-secret", endianness)
        + _option(2, b"capture-host.internal", endianness)
        + _option(3, b"internal-os", endianness)
        + _option(4, b"internal-capture-tool", endianness)
    )
    interface_options = (
        _option(1, b"interface-comment-secret", endianness)
        + _option(3, b"uplink to internal-lab", endianness)
        + _option(4, bytes([10, 20, 30, 40, 255, 255, 255, 0]), endianness)
        + _option(6, bytes([2, 0, 0, 0, 0, 1]), endianness)
        + _option(9, b"\x06", endianness)
        + _option(12, b"internal-os-release", endianness)
        + _option(64999, b"vendor-secret-value", endianness)
        + _option(2, b"mgmt0-internal", endianness)
    )
    name_records = (
        _name_resolution_record(
            1,
            bytes([10, 20, 30, 40]) + b"mail.internal.example\x00",
            endianness,
        )
        + _name_resolution_record(99, b"unknown-nrb-secret", endianness)
        + struct.pack(endianness + "HH", 0, 0)
    )
    name_resolution_options = _option(2, b"resolver.internal.example", endianness)
    unknown_block = _block(0x00000BAD, b"opaque-extension-secret", endianness)

    idb = _block(
        1,
        struct.pack(endianness + "HHI", 1, 0, 65535) + interface_options,
        endianness,
    )
    nrb = _block(4, name_records + name_resolution_options, endianness)
    first_packet = _epb(
        0,
        PACKETS[0],
        _option(1, b"packet-comment-secret", endianness),
        endianness,
    )
    second_packet = _epb(0, PACKETS[1], endianness=endianness)
    third_packet = _epb(0, PACKETS[2], endianness=endianness)

    following = idb + nrb + first_packet + unknown_block + second_packet + third_packet
    section_length = len(following) if declared_section_length else -1
    shb = _block(
        0x0A0D0D0A,
        struct.pack(endianness + "IHHq", 0x1A2B3C4D, 1, 0, section_length)
        + section_options,
        endianness,
    )
    return shb + following, len(shb)


def _scan(data):
    return list(FileScanner(io.BytesIO(data)))


def test_default_removes_metadata_and_preserves_packet_bytes():
    original, _ = make_capture()
    sanitized, report = sanitize_bytes(original)

    positions = [sanitized.find(packet) for packet in PACKETS]
    assert all(position >= 0 for position in positions)
    assert positions == sorted(positions)

    for secret in SECRETS:
        assert secret not in sanitized

    parsed = _scan(sanitized)
    assert [type(block) for block in parsed] == [
        blocks.SectionHeader,
        blocks.InterfaceDescription,
        blocks.EnhancedPacket,
        blocks.EnhancedPacket,
        blocks.EnhancedPacket,
    ]
    assert [block.packet_data for block in parsed[2:]] == PACKETS
    assert parsed[1].options["if_tsresol"] == b"\x06"
    assert len(parsed[0].options) == 0
    assert len(parsed[1].options) == 1
    assert all(block.interface_id == 0 for block in parsed[2:])

    assert report.blocks_read == 7
    assert report.blocks_written == 5
    assert report.sections == 1
    assert len(report.changes) > 0
    assert not report.retained_opaque


def test_every_deletion_is_traceable_to_original_location():
    original, _ = make_capture()
    _, report = sanitize_bytes(original)

    assert report.changes
    for change in report.changes:
        assert change.block_index >= 0
        assert change.block_offset >= 0
        assert change.block_length > 0
        assert change.block_offset + change.block_length <= len(original)
        assert change.item_offset is not None
        assert change.item_length is not None
        assert change.item_offset >= change.block_offset
        assert (
            change.item_offset + change.item_length
            <= change.block_offset + change.block_length
        )

    # The reported option offsets point at the original option code and length.
    option_changes = [c for c in report.changes if c.action == "drop-option"]
    assert option_changes
    for change in option_changes:
        code, length = struct.unpack_from("<HH", original, change.item_offset)
        assert code == change.option_code
        assert length <= change.item_length - 4

    dropped_unknown = [
        c
        for c in report.changes
        if c.action == "drop-block" and c.block_type_code == 0x00000BAD
    ]
    assert len(dropped_unknown) == 1
    assert original[dropped_unknown[0].item_offset :][:4] == struct.pack(
        "<I", 0x00000BAD
    )


def test_policy_can_retain_named_metadata_and_opaque_data():
    original, _ = make_capture()
    policy = SanitizationPolicy(
        keep_metadata=("if_name", "opt_comment", "section.hardware"),
        keep_option_codes={"interface": [64999]},
        keep_unknown_block_types=(0x00000BAD,),
        name_resolution="records",
        keep_unknown_name_resolution_records=True,
    )
    sanitized, report = sanitize_bytes(original, policy)

    assert b"mgmt0-internal" in sanitized
    assert b"packet-comment-secret" in sanitized
    assert b"section-comment-secret" in sanitized
    assert b"capture-host.internal" in sanitized
    assert b"vendor-secret-value" in sanitized
    assert b"mail.internal.example" in sanitized
    assert b"unknown-nrb-secret" in sanitized
    assert b"opaque-extension-secret" in sanitized

    # Still not allowed, so still removed.
    assert b"internal-os" not in sanitized
    assert b"internal-capture-tool" not in sanitized
    assert b"internal-os-release" not in sanitized
    assert b"resolver.internal.example" not in sanitized

    actions = [change.action for change in report.retained_opaque]
    assert actions.count("retain-opaque-option") == 1
    assert actions.count("retain-opaque-record") == 1
    assert actions.count("retain-opaque-block") == 1

    parsed = _scan(sanitized)
    assert any(isinstance(block, blocks.UnknownBlock) for block in parsed)
    assert [
        block.packet_data
        for block in parsed
        if isinstance(block, blocks.BasePacketBlock)
    ] == PACKETS


def test_unknown_items_are_not_retained_by_default():
    original, _ = make_capture()
    sanitized, report = sanitize_bytes(original)

    assert b"vendor-secret-value" not in sanitized
    assert b"opaque-extension-secret" not in sanitized
    assert b"unknown-nrb-secret" not in sanitized
    assert b"resolver.internal.example" not in sanitized

    notes = " ".join(change.note for change in report.changes)
    assert "unknown block type" in notes
    assert "unknown name resolution record" in notes
    assert "vendor/unknown option" in notes


def test_name_resolution_addresses_policy_keeps_address_but_drops_name():
    original, _ = make_capture()
    sanitized, report = sanitize_bytes(
        original, SanitizationPolicy(name_resolution="addresses")
    )

    assert b"mail.internal.example" not in sanitized
    address_offset = original.find(bytes([10, 20, 30, 40]) + b"mail")
    assert address_offset >= 0
    assert bytes([10, 20, 30, 40]) in sanitized

    nrb = [
        block for block in _scan(sanitized) if isinstance(block, blocks.NameResolution)
    ]
    assert len(nrb) == 1
    assert nrb[0].records == [{"type": 1, "address": "10.20.30.40", "names": []}]
    assert any(
        change.action == "drop-name-resolution-name" for change in report.changes
    )


def test_section_length_is_recomputed_when_blocks_are_removed():
    original, shb_length = make_capture(declared_section_length=True)
    sanitized, report = sanitize_bytes(original)

    new_shb_length = struct.unpack_from("<I", sanitized, 4)[0]
    new_section_length = struct.unpack_from("<q", sanitized, 16)[0]
    assert new_section_length == len(sanitized) - new_shb_length
    assert any(change.action == "change-section-length" for change in report.changes)
    assert [type(block) for block in _scan(sanitized)] == [
        blocks.SectionHeader,
        blocks.InterfaceDescription,
        blocks.EnhancedPacket,
        blocks.EnhancedPacket,
        blocks.EnhancedPacket,
    ]


@pytest.mark.parametrize("endianness", ["<", ">"])
def test_big_endian_capture(endianness):
    original, _ = make_capture(endianness=endianness)
    sanitized, report = sanitize_bytes(original)

    assert report.sections == 1
    assert all(packet in sanitized for packet in PACKETS)
    blocks = _scan(sanitized)
    assert blocks[0].endianness == endianness
    assert [block.packet_data for block in blocks[2:]] == PACKETS


def test_multiple_sections_keep_interface_numbering_and_order():
    first, _ = make_capture(endianness="<")
    second, _ = make_capture(endianness=">")
    sanitized, report = sanitize_bytes(first + second)

    assert report.sections == 2
    blocks = _scan(sanitized)
    assert [type(block).__name__ for block in blocks] == [
        "SectionHeader",
        "InterfaceDescription",
        "EnhancedPacket",
        "EnhancedPacket",
        "EnhancedPacket",
        "SectionHeader",
        "InterfaceDescription",
        "EnhancedPacket",
        "EnhancedPacket",
        "EnhancedPacket",
    ]


def test_input_is_not_modified_and_files_work(tmp_path):
    original, _ = make_capture()
    source = tmp_path / "input.pcapng"
    target = tmp_path / "sanitized.pcapng"
    source.write_bytes(original)

    report = sanitize_capture(str(source), str(target))
    assert source.read_bytes() == original
    assert report.output_bytes == len(target.read_bytes())
    assert [block.packet_data for block in _scan(target.read_bytes())[2:]] == PACKETS

    with pytest.raises(ValueError, match="same file"):
        sanitize_capture(str(source), str(source))
    assert source.read_bytes() == original

    target.unlink()
    with open(source, "rb") as source_fp, open(target, "wb") as target_fp:
        report = sanitize_capture(source_fp, target_fp)
    assert target.read_bytes()
    assert source.read_bytes() == original


def test_stream_input_position_is_restored():
    original, _ = make_capture()
    source = io.BytesIO(original)
    sanitized, report = sanitize_bytes(source)
    assert source.tell() == 0
    assert report.blocks_read == 7
    assert all(packet in sanitized for packet in PACKETS)


def test_unknown_block_alone_can_be_dropped_without_changing_interface_references():
    original, _ = make_capture()
    sanitized, report = sanitize_bytes(original)

    assert b"opaque-extension-secret" not in sanitized
    # The unknown block and the metadata-only Name Resolution Block are removed.
    assert report.blocks_written == report.blocks_read - 2
    packets = [b for b in _scan(sanitized) if isinstance(b, blocks.EnhancedPacket)]
    assert [packet.interface_id for packet in packets] == [0, 0, 0]


def test_policy_validation():
    with pytest.raises(ValueError):
        SanitizationPolicy(name_resolution="names")
    with pytest.raises(ValueError):
        SanitizationPolicy(keep_metadata=("no_such_option",))
    with pytest.raises(ValueError):
        SanitizationPolicy(keep_metadata=("no_such_block.no_such_option",))
    with pytest.raises(ValueError):
        SanitizationPolicy(keep_option_codes={"no_such_block": [1]})
    with pytest.raises(ValueError):
        SanitizationPolicy(
            keep_unknown_block_types=(blocks.EnhancedPacket.magic_number,)
        )
    with pytest.raises(ValueError):
        SanitizationPolicy(keep_option_codes={"simple_packet": [1]})
    with pytest.raises(TypeError):
        sanitize_bytes(b"", policy=object())


def test_report_serialization_does_not_contain_removed_values():
    original, _ = make_capture()
    sanitized, report = sanitize_bytes(original)

    as_json = report.to_json()
    as_text = report.format()
    for secret in SECRETS:
        assert secret.decode() not in as_json
        assert secret.decode() not in as_text
    assert "drop-option" in as_json
    assert "drop-block" in as_json


def test_sanitize_bytes_rejects_non_pcapng():
    with pytest.raises(SanitizationError) as excinfo:
        sanitize_bytes(b"not a pcapng file")
    assert "section header" in str(excinfo.value)


def test_bundled_capture_round_trips_through_scanner():
    data = open(
        os.path.join(os.path.dirname(__file__), "..", "test_data", "test008.ntar"),
        "rb",
    ).read()
    sanitized, report = sanitize_bytes(data)
    assert report.blocks_read > 0
    assert report.blocks_written > 0
    _scan(sanitized)


def make_two_interface_capture():
    shb = _block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        + _option(2, b"capture-host.internal"),
    )
    first_interface = _block(
        1,
        struct.pack("<HHI", 1, 0, 65535)
        + _option(2, b"mgmt0-internal")
        + _option(9, b"\x06"),
    )
    second_interface = _block(
        1,
        struct.pack("<HHI", 1, 0, 65535)
        + _option(2, b"data1-internal")
        + _option(9, b"\x09"),
    )
    first_packet = _epb(0, b"FIRST-INTERFACE-PACKET")
    second_packet = _epb(1, b"SECOND-INTERFACE-PACKET")
    return shb + first_interface + second_interface + first_packet + second_packet


def test_interface_assignment_is_not_changed():
    original = make_two_interface_capture()
    sanitized, report = sanitize_bytes(original)

    parsed = _scan(sanitized)
    interfaces = [b for b in parsed if isinstance(b, blocks.InterfaceDescription)]
    packets = [b for b in parsed if isinstance(b, blocks.EnhancedPacket)]
    assert [interface.interface_id for interface in interfaces] == [0, 1]
    assert [packet.interface_id for packet in packets] == [0, 1]
    assert [packet.packet_data for packet in packets] == [
        b"FIRST-INTERFACE-PACKET",
        b"SECOND-INTERFACE-PACKET",
    ]
    assert [interface.options["if_tsresol"] for interface in interfaces] == [
        b"\x06",
        b"\x09",
    ]


def test_removed_names_are_not_reintroduced_by_retained_options():
    original, _ = make_capture()
    policy = SanitizationPolicy(
        keep_metadata=("opt_comment", "interface.description"),
    )
    sanitized, report = sanitize_bytes(original, policy)

    parsed = _scan(sanitized)
    for block in parsed:
        if not hasattr(block, "options"):
            continue
        for values in block.options.data.values():
            for value in values:
                if isinstance(value, bytes):
                    assert b"mail.internal.example" not in value
                    assert b"mgmt0-internal" not in value
                elif isinstance(value, str):
                    assert "mail.internal.example" not in value
                    assert "mgmt0-internal" not in value
    assert b"mail.internal.example" not in sanitized
    assert b"mgmt0-internal" not in sanitized
    # The explicitly retained comment was kept byte-for-byte, not rewritten.
    assert b"packet-comment-secret" in sanitized
