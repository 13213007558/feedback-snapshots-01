"""Offline investigation example for WPP MessageTrace records.

It builds two small WPP message records that differ only in whether they carry a
timestamp, parses them through the same ``dissect.etl`` reading path as a real ETL
buffer and prints an investigation-style summary.

Run it directly:

    python examples/wpp_message_trace.py
"""

from __future__ import annotations

from struct import pack
from unittest.mock import Mock
from uuid import UUID

from dissect.etl.headers.headers import EventProperty
from dissect.etl.headers.utils import select_event_header

PROVIDER_GUID = UUID("12345678-1234-5678-9abc-def012345678")
LOGFILE_BASE = 132_000_000_000  # A filetime-style base used by the mocked logfile.
TIME_SCALE = 1


def fake_etl() -> Mock:
    """A stand-in for :class:`dissect.etl.etl.ETL` providing the clock information."""
    etl = Mock()
    etl.logfile_header.timestamp_scale = TIME_SCALE
    etl.logfile_header.timestamp_base = LOGFILE_BASE
    etl.calculate_timestamp = lambda delta: LOGFILE_BASE + TIME_SCALE * delta
    return etl


def build_record(properties: int, time_delta: int, message: bytes) -> bytes:
    optional = b""
    if properties & EventProperty.SEQUENCE:
        optional += pack("<I", 4242)
    if properties & EventProperty.GUID:
        optional += PROVIDER_GUID.bytes_le
    if properties & EventProperty.TIMESTAMP:
        optional += pack("<Q", time_delta)
    if properties & EventProperty.SYSTEMINFO:
        optional += pack("<II", 952, 4112)  # thread id, process id

    size = 0x8 + len(optional) + len(message)
    marker = 0x90000000 | size
    fixed = pack("<HHHH", size, (marker >> 16) & 0xFFFF, 0x0042, properties)
    return fixed + optional + message


def investigate(data: bytes, etl: Mock) -> None:
    header = select_event_header(memoryview(data), etl)
    fields = header.additional_header_fields()

    print(f"record size           : {header.size} bytes")
    print(f"provider id           : {header.provider_id}")
    print(f"sequence / component  : {header.sequence_number} / {header.component_id}")
    print(f"process / thread      : {header.process_id} / {header.thread_id}")
    print(f"pointer width         : {header.pointer_size}")
    print(f"raw WPP message bytes : {fields['Message']!r}")
    if header.timestamp is None:
        # The record simply has no clock information; the logfile start time is not
        # substituted, so an analyst can tell the time is genuinely unknown.
        print(
            "timestamp             : NOT CARRIED BY RECORD (left unknown, no logfile start used)"
        )
    else:
        print(f"timestamp             : {header.timestamp} (delta={header.time_delta})")
    if header.warnings:
        for warning in header.warnings:
            print(f"warning               : {warning}")
    print("-" * 72)


def main() -> None:
    etl = fake_etl()
    common = (
        EventProperty.SEQUENCE
        | EventProperty.GUID
        | EventProperty.SYSTEMINFO
        | EventProperty.POINTER64
    )

    print("WPP MessageTrace investigation")
    print("=" * 72)
    print("[1] record that DOES carry a timestamp")
    investigate(
        build_record(common | EventProperty.TIMESTAMP, 5_000, b"\x90DBG-START\x90"), etl
    )

    print("[2] record that does NOT carry a timestamp")
    investigate(build_record(common, 0, b"\x90DBG-END\x90"), etl)


if __name__ == "__main__":
    main()
