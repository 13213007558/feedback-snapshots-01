from __future__ import annotations

import struct
from pathlib import Path
from uuid import UUID

import pytest

from dissect.etl.exceptions import InvalidPayloadError, InvalidTemplateError
from dissect.etl.manifest import compile_xml, generate_from_xml, validate_payload

FIXTURE_DIR = Path(__file__).parent / "_manifests"

V1_GUID = UUID("aaaaaaaa-1111-1111-1111-111111111111")
V2_GUID = UUID("bbbbbbbb-2222-2222-2222-222222222222")

TAIL_MARKER = 0xA5A5A5A5

# Deterministic, unique module GUIDs per fixture; the value only names the compiled module.
FIXTURE_GUIDS = {
    "valid_v1.xml": V1_GUID,
    "valid_v2.xml": V2_GUID,
    "invalid_runtime_wchar_odd.xml": UUID("f1f1f1f1-6666-7777-8888-999999999999"),
}


def load_fixture(name: str) -> object:
    return compile_xml(FIXTURE_GUIDS[name], (FIXTURE_DIR / name).read_text())


def test_v1_template_generates_dynamic_arrays() -> None:
    code = generate_from_xml((FIXTURE_DIR / "valid_v1.xml").read_text())
    assert "uint32 Ids[IdCount];" in code
    assert "wchar Name[NameByteLength / 2];" in code
    assert "char Blob[BlobLength];" in code


def test_v2_template_generates_fixed_and_counted_fields() -> None:
    code = generate_from_xml((FIXTURE_DIR / "valid_v2.xml").read_text())
    assert "uint8 FixedFlags[4];" in code
    # count expresses a number of characters, so no byte conversion is emitted
    assert "wchar Name[NameCharCount];" in code
    # length expresses bytes, so the wchar element count is divided by the character width
    assert "char AnsiName[AnsiByteLength];" in code


def test_v1_payload_decodes_arrays_strings_and_tail_marker() -> None:
    module = load_fixture("valid_v1.xml")
    payload = b"".join(
        [
            struct.pack("<I", 3),
            struct.pack("<III", 10, 20, 30),
            struct.pack("<H", 10),
            "hello".encode("utf-16-le"),
            struct.pack("<I", 4),
            b"\xde\xad\xbe\xef",
            struct.pack("<I", TAIL_MARKER),
        ]
    )

    event = module.c_parser.SecurityEventV1Args(payload)
    values = event.__values__

    assert values["Ids"] == [10, 20, 30]
    assert values["Name"] == "hello"
    assert values["Blob"] == b"\xde\xad\xbe\xef"
    assert values["Trailer"] == TAIL_MARKER


def test_v2_payload_decodes_fixed_counted_and_ansi_fields() -> None:
    module = load_fixture("valid_v2.xml")
    payload = b"".join(
        [
            struct.pack("<I", 2),
            struct.pack("<II", 11, 22),
            b"\x01\x02\x03\x04",
            struct.pack("<I", 4),
            "four".encode("utf-16-le"),
            struct.pack("<I", 3),
            b"abc",
            struct.pack("<I", TAIL_MARKER),
        ]
    )

    event = module.c_parser.SecurityEventV2Args(payload)
    values = event.__values__

    assert values["Ids"] == [11, 22]
    assert list(values["FixedFlags"]) == [1, 2, 3, 4]
    assert values["Name"] == "four"
    assert bytes(values["AnsiName"]) == b"abc"
    assert values["Trailer"] == TAIL_MARKER


def test_zero_length_values_do_not_consume_later_fields() -> None:
    module = load_fixture("valid_v1.xml")
    payload = b"".join(
        [
            struct.pack("<I", 0),
            struct.pack("<H", 0),
            struct.pack("<I", 0),
            struct.pack("<I", TAIL_MARKER),
        ]
    )

    validate_payload(
        module.c_parser.SecurityEventV1Args,
        module.TEMPLATE_FIELDS["SecurityEventV1Args"],
        payload,
        4,
        "v1 zero",
    )
    event = module.c_parser.SecurityEventV1Args(payload)
    values = event.__values__

    assert values["Ids"] == []
    assert values["Name"] == ""
    assert bytes(values["Blob"]) == b""
    assert values["Trailer"] == TAIL_MARKER


def test_declared_count_does_not_leak_between_events() -> None:
    module = load_fixture("valid_v1.xml")
    declarations = module.TEMPLATE_FIELDS["SecurityEventV1Args"]

    first = b"".join(
        [
            struct.pack("<I", 2),
            struct.pack("<II", 1, 2),
            struct.pack("<H", 0),
            struct.pack("<I", 0),
            struct.pack("<I", TAIL_MARKER),
        ]
    )
    second = b"".join(
        [
            struct.pack("<I", 1),
            struct.pack("<I", 99),
            struct.pack("<H", 0),
            struct.pack("<I", 0),
            struct.pack("<I", TAIL_MARKER),
        ]
    )

    validate_payload(module.c_parser.SecurityEventV1Args, declarations, first, 4, "first event")
    validate_payload(module.c_parser.SecurityEventV1Args, declarations, second, 4, "second event")

    assert module.c_parser.SecurityEventV1Args(first).Ids == [1, 2]
    assert module.c_parser.SecurityEventV1Args(second).Ids == [99]


def test_overrun_is_rejected_with_field_and_event_context() -> None:
    module = load_fixture("valid_v1.xml")
    # IdCount claims 10 elements, but only a single uint32 follows in the payload.
    payload = struct.pack("<I", 10) + struct.pack("<I", 1)

    with pytest.raises(InvalidPayloadError) as exc_info:
        validate_payload(
            module.c_parser.SecurityEventV1Args,
            module.TEMPLATE_FIELDS["SecurityEventV1Args"],
            payload,
            4,
            "event symbol='SecurityEventV1' value=1 version=1 template='SecurityEventV1Args'",
        )

    message = str(exc_info.value)
    assert "Ids" in message
    assert "SecurityEventV1" in message
    assert "remain in the payload" in message


def test_tail_marker_keeps_its_own_bytes_after_declared_region() -> None:
    module = load_fixture("valid_v1.xml")
    # A blob that fills the payload up to the trailer must not swallow the marker.
    payload = b"".join(
        [
            struct.pack("<I", 0),
            struct.pack("<H", 0),
            struct.pack("<I", 4),
            b"\x01\x02\x03\x04",
            struct.pack("<I", TAIL_MARKER),
        ]
    )
    event = module.c_parser.SecurityEventV1Args(payload)
    assert event.Blob == b"\x01\x02\x03\x04"
    assert event.Trailer == TAIL_MARKER


@pytest.mark.parametrize(
    ("fixture_name", "field_name", "reference_name"),
    [
        ("invalid_forward_reference.xml", "Ids", "IdCount"),
        ("invalid_unknown_reference.xml", "Name", "LengthThatDoesNotExist"),
        ("invalid_cyclic_reference.xml", "First", "Second"),
    ],
)
def test_illegal_references_rejected_at_compile_time(
    fixture_name: str, field_name: str, reference_name: str
) -> None:
    with pytest.raises(InvalidTemplateError) as exc_info:
        compile_xml(UUID("00000000-0000-0000-0000-000000000001"), (FIXTURE_DIR / fixture_name).read_text())

    message = str(exc_info.value)
    assert field_name in message
    assert reference_name in message


def test_odd_wchar_byte_length_is_rejected_at_compile_time() -> None:
    with pytest.raises(InvalidTemplateError) as exc_info:
        compile_xml(
            UUID(int=1),
            (FIXTURE_DIR / "invalid_wchar_odd_length.xml").read_text(),
        )
    assert "Name" in str(exc_info.value)
    assert "UTF-16" in str(exc_info.value)


def test_odd_dynamic_wchar_length_is_rejected_at_runtime() -> None:
    module = load_fixture("invalid_runtime_wchar_odd.xml")
    payload = struct.pack("<H", 3) + b"abc"

    with pytest.raises(InvalidPayloadError) as exc_info:
        validate_payload(
            module.c_parser.RuntimeOddWcharArgs,
            module.TEMPLATE_FIELDS["RuntimeOddWcharArgs"],
            payload,
            4,
            "event symbol='RuntimeOddWcharEvent'",
        )
    message = str(exc_info.value)
    assert "Name" in message
    assert "UTF-16" in message


def test_runtime_overrun_references_actual_count_field() -> None:
    module = load_fixture("valid_v2.xml")
    # NameCharCount requests 8 characters (16 bytes) but the payload provides no string data.
    payload = b"".join(
        [
            struct.pack("<I", 0),
            b"\x00\x00\x00\x00",
            struct.pack("<I", 8),
        ]
    )
    with pytest.raises(InvalidPayloadError) as exc_info:
        validate_payload(
            module.c_parser.SecurityEventV2Args,
            module.TEMPLATE_FIELDS["SecurityEventV2Args"],
            payload,
            4,
            "event symbol='SecurityEventV2'",
        )
    assert "Name" in str(exc_info.value)


def test_field_declaration_tracks_count_and_length_units() -> None:
    module = load_fixture("valid_v1.xml")
    by_name = {decl.name: decl for decl in module.TEMPLATE_FIELDS["SecurityEventV1Args"]}

    ids = by_name["Ids"]
    assert ids.count_ref == "IdCount"
    assert ids.element_size == 4
    assert ids.declared_bytes({"IdCount": 3}, 4) == 12

    name = by_name["Name"]
    assert name.length_ref == "NameByteLength"
    assert name.is_wchar is True
    assert name.declared_bytes({"NameByteLength": 10}, 4) == 10

    blob = by_name["Blob"]
    assert blob.length_ref == "BlobLength"
    assert blob.is_wchar is False
    assert blob.declared_bytes({"BlobLength": 4}, 4) == 4


def test_negative_runtime_count_is_rejected() -> None:
    module = load_fixture("valid_v1.xml")
    # A negative element count cannot be represented honestly in the payload and must be rejected.
    payload = struct.pack("<i", -1)
    with pytest.raises(InvalidPayloadError) as exc_info:
        validate_payload(
            module.c_parser.SecurityEventV1Args,
            module.TEMPLATE_FIELDS["SecurityEventV1Args"],
            payload,
            4,
            "event symbol='SecurityEventV1'",
        )
    assert "Ids" in str(exc_info.value)
