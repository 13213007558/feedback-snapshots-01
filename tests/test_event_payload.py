from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID

import pytest

from dissect.etl.etl import Event
from dissect.etl.exceptions import InvalidPayloadError
from dissect.etl.manifest import compile_xml

V1_GUID = UUID("aaaaaaaa-1111-1111-1111-111111111111")
FIXTURE = Path(__file__).parent / "_manifests" / "valid_v1.xml"
TAIL_MARKER = 0xA5A5A5A5


@pytest.fixture()
def manifest_module() -> object:
    return compile_xml(V1_GUID, FIXTURE.read_text())


def make_header(payload: bytes, pointer_size: int = 4) -> MagicMock:
    header = MagicMock()
    header.opcode = 1
    header.version = 1
    header.payload = memoryview(payload)
    header._etl.pointer_size = pointer_size
    return header


def test_event_decodes_declared_payload(manifest_module: object) -> None:
    payload = b"".join(
        [
            struct.pack("<I", 2),
            struct.pack("<II", 7, 8),
            struct.pack("<H", 10),
            "hello".encode("utf-16-le"),
            struct.pack("<I", 0),
            struct.pack("<I", TAIL_MARKER),
        ]
    )

    event = Event(make_header(payload), manifest_module)

    assert event.symbol() == "SecurityEventV1"
    assert event.Ids == [7, 8]
    assert event.Name == "hello"
    assert event.Trailer == TAIL_MARKER


def test_event_overrun_raises_payload_error_not_raw_eof(manifest_module: object) -> None:
    payload = struct.pack("<I", 100) + struct.pack("<I", 1)

    with pytest.raises(InvalidPayloadError) as exc_info:
        Event(make_header(payload), manifest_module)

    message = str(exc_info.value)
    assert "Ids" in message
    assert "SecurityEventV1" in message
    assert "Internal-Security-Provider" in message
    # The declaration is rejected up front, so no low level EOFError is allowed to escape.
    assert exc_info.type is InvalidPayloadError


def test_32bit_pointer_array_uses_four_byte_elements() -> None:
    guid = UUID("99999999-aaaa-bbbb-cccc-dddddddddddd")
    xml = """<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
     <instrumentation><events><provider name="PointerProvider" guid="{99999999-aaaa-bbbb-cccc-dddddddddddd}">
     <templates><template tid="PointerArgs">
       <data name="N" inType="win:UInt32"/>
       <data name="Ptrs" inType="win:Pointer" count="N"/>
       <data name="Tail" inType="win:UInt32"/>
     </template></templates>
     <events><event value="1" symbol="PointerEvent" version="0" template="PointerArgs"/></events>
     </provider></events></instrumentation></instrumentationManifest>"""
    module = compile_xml(guid, xml)
    module.c_parser.EtwPointer.as_32bit()
    module.c_parser.UserSID_blob.as_32bit()

    payload = (
        struct.pack("<I", 2)
        + struct.pack("<II", 0x11111111, 0x22222222)
        + struct.pack("<I", TAIL_MARKER)
    )

    header = make_header(payload, pointer_size=4)
    header.opcode = 1
    header.version = 0
    event = Event(header, module)

    assert event.Ptrs == [0x11111111, 0x22222222]
    assert event.Tail == TAIL_MARKER
