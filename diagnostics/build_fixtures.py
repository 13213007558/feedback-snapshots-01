"""Build small, self-contained ETL files that exercise manifest-version conflicts.

The output is intentionally tiny (one buffer, a handful of records) so the
files can be committed and inspected byte-for-byte.  Run from the repository
root:

    .venv/bin/python diagnostics/build_fixtures.py
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# A real provider that already has a bundled manifest in this repository.
ALPC_GUID = uuid.UUID("45d8cccd-539f-4b72-a8b7-5c683142609a")  # Windows Kernel / ALPC
SHELLCORE_GUID = uuid.UUID("30336ed4-e327-447c-9de0-51b652c86108")  # Microsoft-Windows-Shell-Core
POINTER_GUID = uuid.UUID("11111111-2222-3333-4444-555555555555")  # fixture-only provider
UNKNOWN_GUID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")  # deliberately absent
BROKEN_GUID = uuid.UUID("cbda4dbf-8d5d-4f69-9578-be14aa540d22")  # bundled XML that fails to compile
VERSIONED_GUID = uuid.UUID("13976d09-a327-438c-950b-7f03192815c7")  # two fixture manifests, v1/v2

START_TIME = 132_586_490_806_249_414
END_TIME = 132_586_490_816_249_414
BUFFER_SIZE = 0x1000
HEADER_SIZE = 0x48


def _put(buf: bytearray, offset: int, fmt: str, *values: object) -> None:
    struct.pack_into("<" + fmt, buf, offset, *values)


def logfile_payload(pointer_size: int = 8, buffers_written: int = 1) -> bytes:
    """Build a TRACE_LOGFILE_HEADER payload (the first SYSTEM record)."""
    buf = bytearray(0x118 if pointer_size == 8 else 0x110)
    _put(buf, 0x00, "I", BUFFER_SIZE)
    _put(buf, 0x04, "I", 4)  # Version 4
    _put(buf, 0x0C, "I", 4)  # NumberOfProcessors
    _put(buf, 0x10, "Q", END_TIME)
    _put(buf, 0x18, "I", 10_000)  # TimerResolution
    _put(buf, 0x24, "I", buffers_written)
    _put(buf, 0x28, "16s", b"\x00" * 16)  # LogInstanceGuid / StartBuffers
    _put(buf, 0x2C, "I", pointer_size)
    _put(buf, 0x34, "I", 2_400)  # CpuSpeedInMHz
    # TimeZone is zeroed; the layout offset depends on the pointer width.
    tz_offset = 0x48 if pointer_size == 8 else 0x40
    _put(buf, tz_offset, "172s", b"\x00" * 172)
    perf_offset = 0x100 if pointer_size == 8 else 0xF8
    _put(buf, perf_offset, "Q", 10_000_000)  # PerfFreq
    _put(buf, perf_offset + 8, "Q", START_TIME)
    _put(buf, perf_offset + 16, "I", 2)  # ReservedFlags = FILETIME
    names = ("fixture-machine\x00C:\\fixtures\\trace.etl\x00").encode("utf-16-le")
    return bytes(buf) + names


def system_record(payload: bytes, is_64_bit: bool = True) -> bytes:
    """Build a SYSTEM/LOGFILE record (hook_id == 0)."""
    marker = 0xC002 if is_64_bit else 0xC001
    return struct.pack("<HHHBBIIQQ", 2, marker, 0x20 + len(payload), 0, 0, 0x100, 0x200, 0, 0) + payload


def event_record(
    payload: bytes,
    provider: uuid.UUID,
    event_id: int,
    version: int,
    opcode: int,
    *,
    is_64_bit: bool = True,
    thread_id: int = 0x100,
    process_id: int = 0x200,
) -> bytes:
    """Build an EVENT_HEADER record with a 16-byte ProviderId."""
    size = 0x50 + len(payload)
    marker = (0xC013 if is_64_bit else 0xC012) << 16 | size
    header = struct.pack(
        "<IHHIIQ16sHBBBBHQQ16s",
        marker,
        0,  # Flags
        0,  # EventProperty
        thread_id,
        process_id,
        0,  # TimeDelta
        provider.bytes,
        event_id,
        version,
        0x0B,  # Channel
        0x04,  # Level (win:Informational)
        opcode,
        0,  # Task
        0,  # Keywords
        0,  # ProcessorTime
        b"\x00" * 16,  # ActivityId
    )
    assert len(header) == 0x50
    return header + payload


def buffer_file(records: list[bytes]) -> bytes:
    """Wrap records in one uncompressed buffer and pad records to 8 bytes."""
    body = b"".join(record + b"\x00" * (-len(record) % 8) for record in records)
    filled = HEADER_SIZE + len(body)
    buffer_header = struct.pack(
        "<IIIIQqQHHIIHHIIII",
        BUFFER_SIZE,
        filled,
        filled,
        0,  # ReferenceCounter
        0,  # TimeDelta
        0,  # SequenceNumber
        0,  # Defined_1
        0,  # ProcessorIndex
        1,  # LoggerId
        3,  # ETW_BUFFER_STATE
        filled,  # FilledBytes
        0,  # BufferFlag
        0,  # BufferType
        0,
        0,
        0,
        0,
    )
    return buffer_header + body


def write(name: str, data: bytes) -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    path = FIXTURES / name
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()[:16]
    print(f"{path.relative_to(Path.cwd())}  {len(data)} bytes  sha256={digest}")


def build_alpc_conflict() -> None:
    """Same provider GUID and same descriptor, four payload shapes.

    Record 0: 4 bytes   -> only the bundled 4-byte ALPC template consumes exactly.
    Record 1: 24 bytes  -> bundled leaves 20 bytes; exporter B and C both consume
                           exactly 24 bytes but with different field layouts.
    Record 2: 28 bytes  -> every candidate leaves bytes (no exact winner).
    Record 3: id/opcode 34 -> only the bundled manifest has (34, 2).
    Record 4: id=33, opcode=1 -> dissect looks up (1, 2), which no candidate has,
                           while the descriptor id 33 does have (33, 2).
    Record 5: id=99, opcode=99 -> only the probe_other_event.xml candidate defines
                           this event, showing source coverage gaps.
    """
    records = [
        system_record(logfile_payload()),
        event_record(struct.pack("<I", 0x11223344), ALPC_GUID, 33, 2, 33),
        event_record(
            struct.pack("<I", 0x11223344) + ALPC_GUID.bytes + struct.pack("<I", 0xAABBCCDD),
            ALPC_GUID,
            33,
            2,
            33,
        ),
        event_record(
            struct.pack("<I", 0x11223344) + ALPC_GUID.bytes + struct.pack("<II", 0xAABBCCDD, 0xDEADBEEF),
            ALPC_GUID,
            33,
            2,
            33,
        ),
        event_record(struct.pack("<I", 0x55667788), ALPC_GUID, 34, 2, 34),
        event_record(struct.pack("<I", 0x99), ALPC_GUID, 33, 2, 1),
        event_record(struct.pack("<I", 0x1234ABCD), ALPC_GUID, 99, 2, 99),
    ]
    write("alpc_conflict.etl", buffer_file(records))


def build_shellcore_collision() -> None:
    """A real opcode/id collision: event id 6206 with header OpCode 2.

    The bundled manifest has both (2, 0) and (6206, 0).  dissect uses
    (header.OpCode, header.Version) == (2, 0), so a 20-byte payload is consumed
    exactly by the unrelated AggregatePropertyProvider template.  With a 5-byte
    payload the same wrong lookup raises EOFError instead.  Neither outcome
    identifies the intended Thumbnails template; the descriptor id does.
    """
    records = [
        system_record(logfile_payload()),
        event_record(b"\x11" * 20, SHELLCORE_GUID, 6206, 0, 2),
        event_record(b"\x22" * 5, SHELLCORE_GUID, 6206, 0, 2),
    ]
    write("shellcore_collision.etl", buffer_file(records))


def build_pointer_width() -> None:
    """A 64-bit record followed by a 32-bit record for a pointer template.

    parse_payload mutates the cached module's EtwPointer class per record.  The
    32-bit branch calls EtwPointer.as_32bit(), which is missing @classmethod in
    the generated manifest, so the second record raises TypeError.
    """
    pointer_payload = struct.pack("<QI", 0x1122334455667788, 0x99)
    short_payload = struct.pack("<II", 0x11223344, 0x99)
    records = [
        system_record(logfile_payload()),
        event_record(pointer_payload, POINTER_GUID, 1, 0, 1),
        event_record(short_payload, POINTER_GUID, 1, 0, 1, is_64_bit=False),
    ]
    write("pointer_width.etl", buffer_file(records))


def build_manifest_versions() -> None:
    """The canonical conflict: one payload, two manifest versions, both exact.

    provider_v1.xml describes 4+4+string; provider_v2.xml describes
    16+8+4+string.  A 29-byte payload ending in NUL is consumed exactly by both
    templates, with no exception and no leftover bytes.  Only the field names
    and values differ, so bytes cannot decide which manifest the exporter used.
    """
    payload = (
        bytes.fromhex("00112233445566778899aabbccddeeff")  # 16 bytes
        + struct.pack("<Q", 0x0102030405060708)  # 8 bytes
        + struct.pack("<I", 0xDEADBEEF)  # 4 bytes
        + b"\x00"  # 1 byte terminator
    )
    assert len(payload) == 29
    records = [
        system_record(logfile_payload()),
        event_record(payload, VERSIONED_GUID, 32, 2, 32),
    ]
    write("manifest_v1_v2.etl", buffer_file(records))


def build_exporter_pair() -> None:
    """Two machines' exports for the same GUID, each self-consistent.

    exporter_a.etl carries the v1 layout (4+4+string, 14 bytes).
    exporter_b.etl carries the v2 layout (16+8+4+string, 33 bytes).
    Read together in one process, whichever manifest is cached first is used
    for both files.  This is the exact "two collection machines" situation.
    """
    payload_a = struct.pack("<II", 1, 2) + b"alpha\x00"
    payload_b = VERSIONED_GUID.bytes + struct.pack("<QI", 0x0102030405060708, 0xDEADBEEF) + b"beta\x00"
    assert len(payload_a) == 14
    assert len(payload_b) == 33
    write(
        "exporter_a.etl",
        buffer_file([system_record(logfile_payload()), event_record(payload_a, VERSIONED_GUID, 32, 2, 32)]),
    )
    write(
        "exporter_b.etl",
        buffer_file([system_record(logfile_payload()), event_record(payload_b, VERSIONED_GUID, 32, 2, 32)]),
    )


def build_unknown_provider() -> None:
    records = [
        system_record(logfile_payload()),
        event_record(struct.pack("<I", 1), UNKNOWN_GUID, 1, 0, 1),
    ]
    write("unknown_provider.etl", buffer_file(records))


def build_broken_manifest() -> None:
    """The bundled XML for this GUID exists but raises KeyError during compile.

    manifest.lookup() only converts IOError into ManifestNotFoundError, so a
    broken bundled manifest surfaces as KeyError('Binary') and is *not* caught
    by parse_payload's (ManifestNotFoundError, AttributeError) handler.
    """
    records = [
        system_record(logfile_payload()),
        event_record(b"\x01\x02\x03\x04", BROKEN_GUID, 1, 0, 1),
    ]
    write("broken_manifest.etl", buffer_file(records))


def main() -> None:
    build_alpc_conflict()
    build_shellcore_collision()
    build_pointer_width()
    build_manifest_versions()
    build_exporter_pair()
    build_unknown_provider()
    build_broken_manifest()


if __name__ == "__main__":
    main()
