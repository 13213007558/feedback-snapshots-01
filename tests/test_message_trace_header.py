from __future__ import annotations

from struct import pack
from unittest.mock import Mock
from uuid import UUID

from dissect.etl.c_etl import c_etl
from dissect.etl.headers.headers import EventProperty, Marker, MessageTraceHeader
from dissect.etl.headers.utils import select_event_header

# A WPP message whose bytes deliberately start and end with the message marker byte
# (0x90) and even contain a full 0x90000000 marker, to prove message bytes are not
# mistaken for a header and are never swallowed.
MESSAGE_BYTES = b"\x90\x00\x00\x00WPP-MARKER-BYTES\x90\x00\x00\x90"
PROVIDER_GUID = UUID("12345678-1234-5678-9abc-def012345678")


def make_etl(timestamp_scale: int = 1, timestamp_base: int = 1000) -> Mock:
    etl = Mock()
    etl.logfile_header.timestamp_scale = timestamp_scale
    etl.logfile_header.timestamp_base = timestamp_base
    etl.calculate_timestamp = lambda delta: timestamp_base + int(
        timestamp_scale * delta
    )
    return etl


def build_message_record(
    properties: int,
    *,
    sequence: int = 0x11223344,
    guid: UUID = PROVIDER_GUID,
    component_id: int = 0x7788,
    time_delta: int = 0x0102030405060708,
    thread_id: int = 0x0A0B0C0D,
    process_id: int = 0x11223344,
    message: bytes = MESSAGE_BYTES,
    truncate: int = 0,
) -> bytes:
    optional = b""
    if properties & EventProperty.SEQUENCE:
        optional += pack("<I", sequence)
    if properties & EventProperty.GUID:
        optional += guid.bytes_le
    if properties & EventProperty.COMPONENT_ID:
        optional += pack("<H", component_id)
    if properties & EventProperty.TIMESTAMP:
        optional += pack("<Q", time_delta)
    if properties & EventProperty.SYSTEMINFO:
        optional += pack("<II", thread_id, process_id)

    body = optional + message
    # Simulate truncation by shrinking the declared size while the surrounding buffer
    # (the next record) still holds bytes. The parser must stop at the declared size and
    # name the missing part rather than read into the next record.
    size = 0x8 + len(body) - truncate
    # Message marker: high byte 0x90 (message flags), low 16 bits hold the record size.
    marker = 0x90000000 | size
    fixed = pack("<HHHH", size, (marker >> 16) & 0xFFFF, 0x0042, properties)
    return fixed + body


def parse(
    data: bytes, etl: Mock | None = None, view_size: int | None = None
) -> MessageTraceHeader:
    # A truncated buffer simply ends at (or before) the declared record size; model that
    # by limiting the view the parser receives.
    view = memoryview(data)[: view_size if view_size is not None else len(data)]
    return select_event_header(view, etl or make_etl())


def test_fixed_header_values() -> None:
    record = build_message_record(0)
    header = parse(record)
    assert header.minimal_size == 0x8
    assert header.size == len(record)
    assert header.id == 0x0042
    assert header.marker == 0x90000000 | len(record)
    assert header.version is None


def test_all_optional_fields_occupy_their_own_slots() -> None:
    properties = (
        EventProperty.SEQUENCE
        | EventProperty.GUID
        | EventProperty.TIMESTAMP
        | EventProperty.SYSTEMINFO
        | EventProperty.POINTER64
    )
    header = parse(build_message_record(properties))

    assert header.sequence_number == 0x11223344
    assert header.provider_id == PROVIDER_GUID
    assert header.time_delta == 0x0102030405060708
    assert header.thread_id == 0x0A0B0C0D
    assert header.process_id == 0x11223344
    assert header.pointer_size == 8
    assert header.component_id is None
    # The WPP message survives untouched after every optional field.
    assert bytes(header.message) == MESSAGE_BYTES
    assert bytes(header.payload) == MESSAGE_BYTES
    assert header.warnings == []


def test_component_id_replaces_guid_slot() -> None:
    properties = EventProperty.COMPONENT_ID | EventProperty.SEQUENCE
    header = parse(build_message_record(properties))

    assert header.component_id == 0x7788
    assert header.sequence_number == 0x11223344
    assert header.provider_id is None
    assert bytes(header.message) == MESSAGE_BYTES


def test_pointer32_flag_carries_no_bytes() -> None:
    with_flag = parse(
        build_message_record(EventProperty.POINTER32 | EventProperty.SYSTEMINFO)
    )
    without_flag = parse(build_message_record(EventProperty.SYSTEMINFO))

    assert with_flag.pointer_size == 4
    # POINTER32 must not consume a slot, so system info and message line up exactly.
    assert with_flag.thread_id == without_flag.thread_id
    assert with_flag.process_id == without_flag.process_id
    assert bytes(with_flag.message) == bytes(without_flag.message)


def test_timestamp_vs_no_timestamp() -> None:
    etl = make_etl(timestamp_scale=2, timestamp_base=1000)

    timed = parse(build_message_record(EventProperty.TIMESTAMP), etl)
    assert timed.timestamp == 1000 + 2 * 0x0102030405060708
    assert timed.time_delta == 0x0102030405060708

    untimed = parse(build_message_record(0), etl)
    # A record without a timestamp must not be reported as the logfile start.
    assert untimed.timestamp is None
    assert untimed.time_delta is None
    assert bytes(untimed.message) == MESSAGE_BYTES


def test_message_markers_are_not_treated_as_headers() -> None:
    # The payload embeds the exact message marker dword and 0xFFFFFFFF padding marker.
    message = b"\x90\x00\x00\x00\xff\xff\xff\xffTRAIL"
    header = parse(build_message_record(EventProperty.GUID, message=message))
    assert bytes(header.message) == message


def test_adjacent_records_remain_locatable() -> None:
    first = build_message_record(EventProperty.GUID | EventProperty.TIMESTAMP)
    second = build_message_record(EventProperty.SYSTEMINFO, message=b"SECOND\x90\x90")
    stream = memoryview(first + second)

    first_header = select_event_header(stream, make_etl())
    offset = (first_header.size + 7) & 0xFFFFFFF8
    assert offset == len(first)  # first record is 8-byte aligned already

    second_header = select_event_header(stream[offset:], make_etl())
    assert bytes(second_header.message) == b"SECOND\x90\x90"
    assert second_header.thread_id == 0x0A0B0C0D
    assert second_header.process_id == 0x11223344
    assert second_header.provider_id is None
    assert offset + second_header.size == len(stream)


def test_truncated_record_names_missing_part() -> None:
    # Remove the full 24-byte message plus 6 more, so the 8-byte timestamp loses its
    # tail while the preceding sequence number is still complete.
    record = build_message_record(
        EventProperty.SEQUENCE | EventProperty.TIMESTAMP,
        truncate=len(MESSAGE_BYTES) + 6,
    )
    declared_size = c_etl.uint16(record[:2])
    header = parse(record, view_size=declared_size)

    assert header.sequence_number == 0x11223344
    assert header.time_delta is None
    assert header.timestamp is None
    assert bytes(header.message) == b""
    truncation = [
        warning for warning in header.warnings if "Truncated WPP record" in warning
    ]
    assert len(truncation) == 1
    assert "TIMESTAMP" in truncation[0]
    assert "missing 6 of 8" in truncation[0]


def test_truncated_systeminfo_keeps_earlier_fields() -> None:
    # Remove the full 24-byte message plus 3 more, so the 8-byte SYSTEMINFO field is
    # missing 3 bytes while the preceding GUID is still complete.
    record = build_message_record(
        EventProperty.GUID | EventProperty.SYSTEMINFO, truncate=len(MESSAGE_BYTES) + 3
    )
    declared_size = c_etl.uint16(record[:2])
    header = parse(record, view_size=declared_size)

    assert header.provider_id == PROVIDER_GUID
    assert header.thread_id is None
    assert header.process_id is None
    assert any("SYSTEMINFO" in warning for warning in header.warnings)
    assert any("missing 3 of 8" in warning for warning in header.warnings)


def test_both_pointer_flags_are_ambiguous() -> None:
    header = parse(
        build_message_record(EventProperty.POINTER32 | EventProperty.POINTER64)
    )
    assert header.pointer_size is None
    assert any("POINTER32 and POINTER64" in warning for warning in header.warnings)
    assert bytes(header.message) == MESSAGE_BYTES


def test_guid_and_component_id_together_are_rejected() -> None:
    record = build_message_record(EventProperty.GUID | EventProperty.COMPONENT_ID)
    header = parse(record)
    assert header.provider_id is None
    assert header.component_id is None
    assert any("GUID and COMPONENT_ID" in warning for warning in header.warnings)


def test_unknown_and_performance_timestamp_flags_leave_raw_value() -> None:
    properties = EventProperty.PERFORMANCE_TIMESTAMP | 0x8000
    record = build_message_record(properties)
    header = parse(record)

    assert header.event_property == properties
    assert header.timestamp is None
    assert any("PERFORMANCE_TIMESTAMP" in warning for warning in header.warnings)
    assert any("0x8000" in warning for warning in header.warnings)
    # Unsupported flags carry no bytes, so the message stays at the fixed header.
    assert bytes(header.message) == MESSAGE_BYTES


def test_marker_still_identifies_message_type() -> None:
    marker = Marker(0x90000000 | 0x20)
    assert marker.header_type == c_etl.TRACE_HEADER_TYPE_MESSAGE


def test_buffer_iteration_walks_adjacent_wpp_records() -> None:
    from dissect.etl.etl import Buffer

    first = build_message_record(
        EventProperty.GUID | EventProperty.TIMESTAMP, message=b"FIRST\x90\x90"
    )
    second = build_message_record(EventProperty.SYSTEMINFO, message=b"SECOND")
    # Records are 8-byte aligned inside a buffer; pad the stream to match.
    first_aligned = first + b"\x00" * (((len(first) + 7) & 0xFFFFFFF8) - len(first))
    event_data = first_aligned + second
    total = len(c_etl.BufferHeader) + len(event_data)

    # Inject a parsed buffer header directly so this test does not depend on the global
    # c_etl module (other tests monkeypatch it without restoring the original).
    buffer = Buffer(make_etl(), 0)
    buffer._header = c_etl.BufferHeader(
        BufferSize=total,
        FilledBytes=total,
        BufferFlag=c_etl.ETW_BUFFER_FLAG.NORMAL,
        BufferType=c_etl.ETW_BUFFER_TYPE.GENERIC,
    )
    buffer._data = memoryview(event_data)

    records = list(buffer)

    assert len(records) == 2
    assert bytes(records[0].header.message) == b"FIRST\x90\x90"
    assert records[0].header.provider_id == PROVIDER_GUID
    assert records[0].header.timestamp is not None

    assert bytes(records[1].header.message) == b"SECOND"
    assert records[1].header.thread_id == 0x0A0B0C0D
    assert records[1].header.process_id == 0x11223344
    assert records[1].header.timestamp is None
