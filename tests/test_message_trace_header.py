"""Tests for WPP ``MessageTrace`` records.

The record layout is derived from the record itself: an 8 byte ``MESSAGE_HEADER``,
then the optional values selected by the ``EventProperty`` flags in a fixed order,
then the untouched WPP message bytes.

All samples are built here from the declared layout instead of copying parser
output, so the tests detect a shifted or missing optional field.
"""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
from dissect.util.ts import wintimestamp

from dissect.etl.c_etl import c_etl
from dissect.etl.etl import Buffer
from dissect.etl.exceptions import InvalidHeaderError
from dissect.etl.headers.headers import MESSAGE_PROPERTY_LAYOUT, EventProperty, Marker, MessageTraceHeader
from dissect.etl.headers.utils import select_event_header

if TYPE_CHECKING:
    from dissect.etl.etl import ETL

MESSAGE_MARKER = 0x9000

GUID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
FILETIME = 132586490803526455  # 2021-02-24 14:04:40.352644 UTC

# Message bytes chosen to contain values that look like a record marker and a
# record header at the start and at the end of the message.
LEADING_MARKER = b"\x00\x10\x00\xc0"
TRAILING_MARKER = b"\xff\xff\xff\xff"


def build_record(event_property: int, optional: bytes, message: bytes, message_id: int = 7) -> bytes:
    """Build a syntactically complete message trace record."""
    total = 8 + len(optional) + len(message)
    return struct.pack("<HHHH", total, MESSAGE_MARKER, message_id, event_property) + optional + message


def build_optional(**values: object) -> bytes:
    """Build the optional header from the declared layout.

    The order comes from :data:`MESSAGE_PROPERTY_LAYOUT`, which is exactly what
    the parser must implement.
    """
    parts = []
    for flag, name, size in MESSAGE_PROPERTY_LAYOUT:
        if name not in values:
            continue
        value = values[name]

        if flag == EventProperty.GUID:
            parts.append(value.bytes_le)
        elif flag == EventProperty.COMPONENT_ID:
            parts.append(struct.pack("<H", value))
        elif flag == EventProperty.SYSTEMINFO:
            parts.append(struct.pack("<II", *value))
        else:
            parts.append(struct.pack("<Q" if size == 8 else "<I", value))

    return b"".join(parts)


def parse(data: bytes) -> MessageTraceHeader:
    header = select_event_header(memoryview(data), _mock_etl())
    assert isinstance(header, MessageTraceHeader)
    return header


def _mock_etl() -> ETL:
    class _ETL:
        pointer_size = 8
        is_64bit = True
        fh = None

    return _ETL()


@pytest.mark.parametrize(
    ("event_property", "values", "expected_offset"),
    [
        (0, {}, 8),
        (EventProperty.SEQUENCE, {"sequence_number": 0xAABBCCDD}, 12),
        (EventProperty.GUID, {"provider_id": GUID}, 24),
        (EventProperty.COMPONENT_ID, {"component_id": 0x1234}, 10),
        (EventProperty.TIMESTAMP, {"timestamp_filetime": FILETIME}, 16),
        (EventProperty.PERFORMANCE_TIMESTAMP, {"performance_timestamp": 0xDEAD}, 16),
        (EventProperty.SYSTEMINFO, {"system_info": (0xAABB, 0xCCDD)}, 16),
        (EventProperty.GUID | EventProperty.COMPONENT_ID, {"provider_id": GUID, "component_id": 0x1234}, 26),
        (
            EventProperty.SEQUENCE | EventProperty.TIMESTAMP | EventProperty.SYSTEMINFO,
            {"sequence_number": 0xAABBCCDD, "timestamp_filetime": FILETIME, "system_info": (0xAABB, 0xCCDD)},
            28,
        ),
        (
            EventProperty.SEQUENCE
            | EventProperty.GUID
            | EventProperty.COMPONENT_ID
            | EventProperty.TIMESTAMP
            | EventProperty.PERFORMANCE_TIMESTAMP
            | EventProperty.SYSTEMINFO,
            {
                "sequence_number": 1,
                "provider_id": GUID,
                "component_id": 2,
                "timestamp_filetime": FILETIME,
                "performance_timestamp": 3,
                "system_info": (4, 5),
            },
            54,
        ),
    ],
)
def test_optional_field_offsets(event_property: int, values: dict, expected_offset: int) -> None:
    optional = build_optional(**values)
    message = b"payload"
    record = build_record(event_property, optional, message)

    header = parse(record)
    assert header.message_offset == expected_offset
    assert header.message == message
    assert header.message_size == len(message)


def test_optional_values_in_declared_order() -> None:
    values = {
        "sequence_number": 0x01020304,
        "provider_id": GUID,
        "component_id": 0x05AF,
        "timestamp_filetime": FILETIME,
        "performance_timestamp": 0x0BADC0DE,
        "system_info": (0x0A0B, 0x0C0D),  # process id, thread id
    }
    event_property = (
        EventProperty.SEQUENCE
        | EventProperty.GUID
        | EventProperty.COMPONENT_ID
        | EventProperty.TIMESTAMP
        | EventProperty.PERFORMANCE_TIMESTAMP
        | EventProperty.SYSTEMINFO
    )
    header = parse(build_record(event_property, build_optional(**values), b"message"))

    assert header.sequence_number == 0x01020304
    assert header.provider_id == GUID
    assert header.guid == GUID
    assert header.component_id == 0x05AF
    assert header.timestamp_filetime == FILETIME
    assert header.timestamp == wintimestamp(FILETIME)
    assert header.performance_timestamp == 0x0BADC0DE
    assert header.process_id == 0x0A0B
    assert header.thread_id == 0x0C0D
    assert header.system_info == struct.pack("<II", 0x0A0B, 0x0C0D)


GOLDEN_RECORD = (
    # size 0x0041, marker 0x9000, id 0x0008, properties 0x003F
    b"\x41\x00\x00\x90\x08\x00\x3f\x00"
    # sequence number 0x01020304
    b"\x04\x03\x02\x01"
    # GUID 00112233-4455-6677-8899-aabbccddeeff in mixed-endian layout
    b"\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    # component id 0x05af
    b"\xaf\x05"
    # timestamp FILETIME 0x01d70ab5fe5c1b37
    b"\x37\x1b\x5c\xfe\xb5\x0a\xd7\x01"
    # performance timestamp 0x0badc0de
    b"\xde\xc0\xad\x0b\x00\x00\x00\x00"
    # system info: process 0x0c0d, then thread 0x0e0f
    b"\x0d\x0c\x00\x00\x0f\x0e\x00\x00"
    # message bytes, including marker-like values at both ends
    b"\xff\xff\xff\xffWPP\xff\xff\xff\xff"
)


def test_golden_record_pins_the_layout() -> None:
    """Literal bytes with hand-computed offsets, independent of the layout table."""
    header = parse(GOLDEN_RECORD)

    assert header.sequence_number == 0x01020304
    assert header.provider_id == GUID
    assert header.component_id == 0x05AF
    assert header.timestamp_filetime == FILETIME
    assert header.performance_timestamp == 0x0BADC0DE
    assert header.process_id == 0x0C0D
    assert header.thread_id == 0x0E0F
    assert header.message_offset == 8 + 4 + 16 + 2 + 8 + 8 + 8
    assert header.message == b"\xff\xff\xff\xffWPP\xff\xff\xff\xff"


def test_message_markers_are_not_consumed_by_the_header() -> None:
    message = LEADING_MARKER + b"\xaa\xbb" + TRAILING_MARKER
    header = parse(build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), message))

    assert header.message == message
    assert header.message[:4] == LEADING_MARKER
    assert header.message[-4:] == TRAILING_MARKER
    assert header.size == 8 + 8 + len(message)


@pytest.mark.parametrize(
    ("event_property", "values"),
    [
        (0, {}),
        (EventProperty.SEQUENCE, {"sequence_number": 7}),
        (EventProperty.TIMESTAMP, {"timestamp_filetime": FILETIME}),
        (EventProperty.GUID | EventProperty.SYSTEMINFO, {"provider_id": GUID, "system_info": (1, 2)}),
    ],
)
def test_message_can_contain_arbitrary_bytes(event_property: int, values: dict) -> None:
    """Any byte sequence, including marker-like values, survives unchanged."""
    message = bytes(range(256))
    header = parse(build_record(event_property, build_optional(**values), message))
    assert header.message == message


def test_no_timestamp_is_not_the_logfile_start() -> None:
    header = parse(build_record(EventProperty.SEQUENCE, build_optional(sequence_number=3), b"no time"))

    assert header.sequence_number == 3
    assert header.timestamp is None
    assert header.time_delta is None
    assert header.timestamp_filetime is None


def test_timestamp_does_not_become_a_logfile_delta() -> None:
    """The absolute FILETIME must never be routed through the logfile clock."""
    header = parse(build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"time"))

    assert header.timestamp == wintimestamp(FILETIME)
    assert header.time_delta is None
    # Feeding time_delta to the logfile clock would shift the event by the log start.
    assert header.timestamp != wintimestamp(header.time_delta or 0)


def test_timestamp_is_absolute_filetime() -> None:
    """TRACE_MESSAGE_TIMESTAMP is wall clock, so it must not be offset by the log start."""
    header = parse(build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"time"))

    assert header.timestamp_filetime == FILETIME
    assert header.timestamp == wintimestamp(FILETIME)
    assert header.timestamp.tzinfo == timezone.utc
    assert header.timestamp == datetime(2021, 2, 24, 14, 4, 40, 352644, tzinfo=timezone.utc)


def test_two_records_differ_only_in_timestamp() -> None:
    with_time = parse(build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"m"))
    without_time = parse(build_record(0, b"", b"m"))

    assert with_time.message == without_time.message == b"m"
    assert with_time.timestamp is not None
    assert without_time.timestamp is None


@pytest.mark.parametrize(
    ("event_property", "field", "required"),
    [
        (EventProperty.TIMESTAMP, "timestamp_filetime", 8),
        (EventProperty.SYSTEMINFO, "system_info", 8),
        (EventProperty.GUID, "provider_id", 16),
        (EventProperty.SEQUENCE, "sequence_number", 4),
        (EventProperty.COMPONENT_ID, "component_id", 2),
    ],
)
def test_single_truncated_field_is_named(event_property: int, field: str, required: int) -> None:
    record = build_record(event_property, b"\x00" * (required - 1), b"")
    header = parse(record)

    assert header.truncated_fields == (field,)
    assert field in header.truncation
    assert header.message_offset is None
    assert header.message == b""


def test_truncation_names_the_missing_tail() -> None:
    # Sequence fits, the timestamp is cut in half and the system info is absent.
    event_property = EventProperty.SEQUENCE | EventProperty.TIMESTAMP | EventProperty.SYSTEMINFO
    record = build_record(event_property, struct.pack("<I", 5) + b"\x00\x00\x00\x00", b"")

    header = parse(record)
    assert header.sequence_number == 5
    assert header.truncated_fields == ("timestamp_filetime", "system_info")
    assert header.truncation.startswith("optional header truncated at record offset 12")
    assert header.message_offset is None
    assert header.timestamp is None


def test_truncated_record_is_distinguished_from_truncated_header() -> None:
    record = build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"message")
    cut = record[:10]

    header = parse(cut)
    assert header.truncated_fields == ("timestamp_filetime",)
    assert header.truncation.startswith("record truncated")
    assert header.record_truncated
    assert header.message == b""


def test_conflicting_pointer_flags_are_preserved() -> None:
    event_property = EventProperty.POINTER32 | EventProperty.POINTER64
    header = parse(build_record(event_property, b"", b"body"))

    assert header.event_property == event_property
    assert header.pointer_size is None
    assert any("POINTER32 and POINTER64" in limitation for limitation in header.limitations)
    assert header.message == b"body"


@pytest.mark.parametrize(
    ("event_property", "expected"),
    [(EventProperty.POINTER32, 4), (EventProperty.POINTER64, 8), (0, None)],
)
def test_pointer_flags(event_property: int, expected: int | None) -> None:
    header = parse(build_record(event_property, b"", b"body"))
    assert header.pointer_size == expected


def test_unknown_property_bits_are_preserved() -> None:
    event_property = 0x8000 | EventProperty.SEQUENCE
    header = parse(build_record(event_property, build_optional(sequence_number=9), b"body"))

    assert header.event_property == event_property
    assert header.sequence_number == 9
    assert any("0x8000" in limitation for limitation in header.limitations)


def test_guid_and_component_id_coexist() -> None:
    event_property = EventProperty.GUID | EventProperty.COMPONENT_ID
    header = parse(build_record(event_property, build_optional(provider_id=GUID, component_id=3), b"body"))

    assert header.provider_id == GUID
    assert header.component_id == 3
    assert header.message_offset == 26
    assert header.message == b"body"


def test_performance_timestamp_is_not_wall_clock() -> None:
    header = parse(
        build_record(EventProperty.PERFORMANCE_TIMESTAMP, build_optional(performance_timestamp=0x12345678), b"body")
    )

    assert header.performance_timestamp == 0x12345678
    assert header.timestamp is None
    assert any("performance counter" in limitation for limitation in header.limitations)


def test_invalid_filetime_is_not_fabricated() -> None:
    invalid_filetime = 0xFFFFFFFFFFFFFFFF
    header = parse(build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=invalid_filetime), b"body"))

    assert header.timestamp_filetime == 0xFFFFFFFFFFFFFFFF
    assert header.timestamp is None
    assert any("not a representable FILETIME" in limitation for limitation in header.limitations)


def test_marker_flags_select_message_header() -> None:
    header = parse(build_record(0, b"", b"message"))
    assert header.marker & 0xFF000000 == 0x90000000
    assert header.version is None


def test_additional_header_fields_keep_absent_values_none() -> None:
    header = parse(build_record(EventProperty.SEQUENCE, build_optional(sequence_number=1), b"body"))
    fields = header.additional_header_fields()

    assert fields["SequenceNumber"] == 1
    assert fields["ThreadId"] is None
    assert fields["ProcessId"] is None
    assert fields["MessageOffset"] == 12


def test_raw_optional_header_is_available_for_rechecking() -> None:
    values = {"sequence_number": 1, "provider_id": GUID, "component_id": 2}
    event_property = EventProperty.SEQUENCE | EventProperty.GUID | EventProperty.COMPONENT_ID
    optional = build_optional(**values)
    header = parse(build_record(event_property, optional, b"body"))

    assert header.optional_header == optional
    # Each parsed value can be re-derived from the raw bytes.
    assert struct.unpack_from("<I", header.optional_header, 0)[0] == header.sequence_number
    assert uuid.UUID(bytes_le=header.optional_header[4:20]) == header.provider_id
    assert struct.unpack_from("<H", header.optional_header, 20)[0] == header.component_id


def test_payload_starts_after_the_optional_header() -> None:
    if_header = parse(build_record(0, b"", b"plain"))
    assert bytes(if_header.payload) == b"plain"
    assert if_header.data_size == 5

    guid_header = parse(build_record(EventProperty.GUID, build_optional(provider_id=GUID), b"payload"))
    assert bytes(guid_header.payload) == b"payload"
    assert guid_header.message == b"payload"

    truncated = parse(build_record(EventProperty.GUID, b"\x00" * 8, b""))
    assert bytes(truncated.payload) == b""
    assert truncated.data_size == 0


def test_header_size_smaller_than_minimal_size_rejected() -> None:
    data = struct.pack("<HHHH", 4, MESSAGE_MARKER, 1, 0)
    with pytest.raises(InvalidHeaderError):
        select_event_header(memoryview(data), _mock_etl())


def test_constructor_from_marker() -> None:
    record = build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"body")
    marker = Marker((MESSAGE_MARKER << 16) | len(record))
    header = MessageTraceHeader(marker, memoryview(record), _mock_etl())
    assert header.message == b"body"


# ---------------------------------------------------------------------------
# Integration: records inside a real buffer, adjacent records and the ETL API.
# ---------------------------------------------------------------------------


def build_buffer(records: list[bytes], padding: int = 0) -> bytes:
    data = b"".join(record + b"\x00" * ((-len(record)) % 8) for record in records)
    filler = data + b"\x00" * padding
    filled = 0x48 + len(filler)

    header = bytearray(0x48)
    struct.pack_into("<I", header, 0x00, 0x1000)
    struct.pack_into("<I", header, 0x08, filled)
    struct.pack_into("<I", header, 0x30, filled)
    struct.pack_into("<H", header, 0x36, 0x0004)
    return bytes(header) + filler


def make_buffer(records: list[bytes], padding: int = 0) -> Buffer:
    """Wrap records in a Buffer without depending on other tests' module patching.

    ``tests/test_etl_buffer.py`` replaces ``dissect.etl.etl.c_etl`` with a mock at
    module import time, so the header and data are set from the real definitions
    here.
    """
    blob = build_buffer(records, padding=padding)
    buffer = Buffer(_mock_etl(), 0)
    buffer._header = c_etl.BufferHeader(blob[:0x48])
    buffer._data = memoryview(blob[0x48:])
    return buffer


def test_adjacent_message_records_are_independent() -> None:
    first = build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), LEADING_MARKER + b"one")
    second = build_record(EventProperty.SEQUENCE, build_optional(sequence_number=2), b"two" + TRAILING_MARKER)
    third = build_record(0, b"", b"three")

    events = list(make_buffer([first, second, third]))

    assert len(events) == 3
    assert events[0].header.message == LEADING_MARKER + b"one"
    assert events[1].header.message == b"two" + TRAILING_MARKER
    assert events[2].header.message == b"three"
    assert events[1].header.sequence_number == 2
    assert events[0].header.timestamp is not None
    assert events[2].header.timestamp is None


def test_adjacent_records_have_stable_offsets() -> None:
    first = build_record(EventProperty.GUID, build_optional(provider_id=GUID), b"a" * 3)
    second = build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"b" * 5)

    buffer = make_buffer([first, second])

    event1 = buffer.read_record(0)
    event2 = buffer.read_record(event1.aligned_size)

    assert event1.header.message == b"a" * 3
    assert event2.header.message == b"b" * 5
    assert event2.header.timestamp == wintimestamp(FILETIME)
    assert event1.aligned_size == (len(first) + 7) & ~7
    assert event2.aligned_size == (len(second) + 7) & ~7


def test_end_marker_after_messages_stops_iteration() -> None:
    record = build_record(EventProperty.TIMESTAMP, build_optional(timestamp_filetime=FILETIME), b"message")
    # ``build_buffer`` pads the record to 8 bytes, then the end marker follows.
    blob = bytearray(build_buffer([record]) + b"\xff\xff\xff\xff\x00\x00\x00\x00")
    struct.pack_into("<I", blob, 0x08, len(blob))
    struct.pack_into("<I", blob, 0x30, len(blob))

    buffer = Buffer(_mock_etl(), 0)
    buffer._header = c_etl.BufferHeader(bytes(blob[:0x48]))
    buffer._data = memoryview(bytes(blob[0x48:]))

    events = list(buffer)
    assert len(events) == 1
    assert events[0].header.message == b"message"
