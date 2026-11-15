"""Investigate WPP ``MessageTrace`` records in an ETL file.

Run with a real ETL file::

    python examples/message_trace_investigation.py <file.etl>

The example walks every record through the normal :class:`dissect.etl.ETL`
interface and prints what the record actually carries. Records without a
declared timestamp stay untimed; they are never anchored to the log start.

The module also exposes :func:`summarise` and :func:`build_demo_etl` so the
script can be run without an external sample::

    python examples/message_trace_investigation.py --demo
"""

from __future__ import annotations

import io
import struct
import sys
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.etl.c_etl import c_etl
from dissect.etl.etl import ETL
from dissect.etl.headers.headers import EventProperty, MessageTraceHeader

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.etl.etl import EventRecord

START_TIME = 132586490803526455  # 2021-02-24 14:04:40.352644 UTC
GUID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")


def summarise(records: Iterable[EventRecord]) -> list[dict[str, Any]]:
    """Turn each record into an investigation result.

    Message trace records are reported from their own declared properties only.
    Other header families are skipped here because they carry no WPP message.
    """
    results = []
    offset = 0
    for record in records:
        record_offset, offset = offset, offset + record.aligned_size
        header = record.header
        if not isinstance(header, MessageTraceHeader):
            continue

        if header.record_truncated or header.truncation:
            findings = {
                "record_offset": record_offset,
                "status": "incomplete",
                "missing": list(header.truncated_fields),
                "detail": header.truncation,
                "message": None,
                "timestamp": None,
            }
            results.append(findings)
            continue

        results.append(
            {
                "record_offset": record_offset,
                "status": "ok",
                "properties": list(header.property_names),
                "sequence_number": header.sequence_number,
                "guid": str(header.provider_id) if header.provider_id else None,
                "component_id": header.component_id,
                "process_id": header.process_id,
                "thread_id": header.thread_id,
                # A record without TRACE_MESSAGE_TIMESTAMP stays untimed.
                "timestamp": header.timestamp.isoformat() if header.timestamp else None,
                "timestamp_filetime": header.timestamp_filetime,
                "message_offset": header.message_offset,
                "message": header.message,
                "limitations": list(header.limitations),
            }
        )
    return results


def build_demo_etl() -> bytes:
    """Build a small ETL with one timed and one untimed message record."""
    message = b"\x00\x10\x00\xc0demo\xff\xff\xff\xff"  # marker-like bytes at both ends

    timed = _build_message(
        EventProperty.SEQUENCE | EventProperty.TIMESTAMP | EventProperty.SYSTEMINFO,
        struct.pack("<I", 1)
        + struct.pack("<Q", START_TIME)
        + struct.pack("<II", 0x1234, 0x5678),  # process id, thread id
        message,
    )
    untimed = _build_message(
        EventProperty.SEQUENCE | EventProperty.GUID,
        struct.pack("<I", 2) + GUID.bytes_le,
        message,
    )

    logfile = _build_logfile_record()
    data = b"".join(_align(record) for record in (logfile, timed, untimed))
    filled = 0x48 + len(data)

    buffer_header = bytearray(0x48)
    struct.pack_into("<I", buffer_header, 0x00, 0x1000)
    struct.pack_into("<I", buffer_header, 0x08, filled)
    struct.pack_into("<I", buffer_header, 0x30, filled)
    struct.pack_into("<H", buffer_header, 0x36, 0x0004)
    return bytes(buffer_header) + data


def _build_message(event_property: int, optional: bytes, message: bytes) -> bytes:
    total = 8 + len(optional) + len(message)
    return struct.pack("<HHHH", total, 0x9000, 0x0001, event_property) + optional + message


def _align(record: bytes) -> bytes:
    return record + b"\x00" * ((-len(record)) % 8)


def _build_logfile_record() -> bytes:
    header = bytearray(0x118)
    struct.pack_into("<I", header, 0x00, 0x1000)  # BufferSize
    struct.pack_into("<I", header, 0x04, 2)  # Version
    struct.pack_into("<I", header, 0x0C, 1)  # NumberOfProcessors
    struct.pack_into("<Q", header, 0x10, START_TIME + 10_000_000)  # EndTime
    struct.pack_into("<I", header, 0x24, 1)  # BuffersWritten
    struct.pack_into("<I", header, 0x2C, 8)  # PointerSize
    struct.pack_into("<I", header, 0x34, 1000)  # CpuSpeedInMHz
    struct.pack_into("<Q", header, 0xF8, 0)  # BootTime
    struct.pack_into("<Q", header, 0x100, 10_000_000)  # PerfFreq
    struct.pack_into("<Q", header, 0x108, START_TIME)  # StartTime
    struct.pack_into("<I", header, 0x110, 2)  # ReservedFlags: FILETIME
    names = "Demo\0".encode("utf-16-le") + "demo.etl\0".encode("utf-16-le")
    payload = bytes(header) + names
    size = 0x20 + len(payload)
    system_header = c_etl.SystemHeader(
        Version=2,
        Marker=0xC002,
        Size=size,
        OpCode=0,
        Group=0,
        ThreadId=0,
        ProcessId=0,
        TimeDelta=0,
        ProcessorTime=0,
    ).dumps()
    return system_header + payload


def print_result(index: int, result: dict[str, Any], log_start: str) -> None:
    print(f"record {index} at buffer offset 0x{result['record_offset']:x}: {result['status']}")
    if result["status"] != "ok":
        print(f"  missing: {', '.join(result['missing'])}")
        print(f"  detail:  {result['detail']}")
        return

    print(f"  properties:      {', '.join(result['properties']) or '(none)'}")
    print(f"  sequence number: {result['sequence_number']}")
    print(f"  guid:            {result['guid']}")
    print(f"  component id:    {result['component_id']}")
    print(f"  process/thread:  {result['process_id']} / {result['thread_id']}")
    if result["timestamp"]:
        print(f"  timestamp:       {result['timestamp']} (FILETIME {result['timestamp_filetime']})")
    else:
        print(f"  timestamp:       not carried by the record (log start is {log_start}, not used)")
    print(f"  message offset:  {result['message_offset']}")
    print(f"  message bytes:   {result['message']!r}")
    for limitation in result["limitations"]:
        print(f"  limitation:      {limitation}")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--demo":
        etl = ETL(io.BytesIO(build_demo_etl()))
    elif len(argv) == 2:
        with Path(argv[1]).open("rb") as fh:
            etl = ETL(fh)
    else:
        print(__doc__)
        return 2

    print(f"file start/end: {etl.start} .. {etl.end}")
    for index, result in enumerate(summarise(etl), start=1):
        print_result(index, result, etl.start.isoformat())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
