"""Deterministic structural-mutation tests for the ETL backend entry point.

These tests exercise ``Buffer``/``select_event_header`` as the ingestion point for
externally produced ETL bytes. The focus is the interaction between the different
header families and record length, 8-byte alignment padding and the end-of-data
marker (0xFFFFFFFF).

Methodology:
  * All inputs are derived from the existing valid byte samples (``SYSTEM_EVENT``,
    ``EVENT_HEADER_EVENT``, ``RAW_BUFFER_HEADER``). Legal mutations only change
    padding bytes, padding length or buffer splitting, never the event content,
    so they must reproduce the exact same event sequence as the baseline stream.
  * Illegal mutations (short headers, length wraparound, fake end markers) are
    crafted independently and must terminate within a bounded number of read
    operations while reporting the offset of the corruption.
  * Everything is deterministic: no randomness, no timeouts, every failing
    sample is a named, minimal regression case reproducible with ``pytest -k``.

Per-mutation-class acceptance criteria are recorded in ``CRITERIA`` below.
"""

from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from dissect.etl.etl import Buffer, EventRecord
from dissect.etl.exceptions import (
    InvalidHeaderError,
    InvalidMarkerError,
    NoMoreEventsError,
)

from .test_event_header import EVENT_HEADER_EVENT
from .test_system_header import SYSTEM_EVENT
from .test_wmi_buffer_header import RAW_BUFFER_HEADER

if TYPE_CHECKING:
    from dissect.etl.headers.headers import Header

BUFFER_HEADER_SIZE = 0x48
BUFFER_SIZE_OFFSET = 0x00
FILLED_BYTES_OFFSET = 0x30

END_MARKER = b"\xff\xff\xff\xff"

# Bounded resources: a mutated stream may never yield more records or cause
# more read() calls than these limits. A correct parse needs 2 reads per buffer.
MAX_EVENTS = 32
MAX_READS = 8

CRITERIA = {
    "legal-padding": "event fingerprint sequence identical to the baseline stream",
    "buffer-split": "concatenated per-buffer event sequence equals the single-buffer baseline",
    "short-header": "InvalidHeaderError, reported at the offset of the truncated record",
    "length-wraparound": "iteration terminates within MAX_READS reads; overrun reported at the record offset",
    "fake-end-marker": "premature stop reported at the marker offset; trailing non-padding data detected",
    "alignment": "misaligned read cursors raise loudly (InvalidMarkerError), never silently misparse",
}


# ---------------------------------------------------------------------------
# Record builders (derived from the existing valid samples)
# ---------------------------------------------------------------------------


def _patch(data: bytes, offset: int, fmt: str, value: int) -> bytes:
    buf = bytearray(data)
    struct.pack_into(fmt, buf, offset, value)
    return bytes(buf)


def system_record() -> bytes:
    """SystemHeader record (type 0x02), declared size 0x44, not 8-byte aligned."""
    size = struct.unpack_from("<H", SYSTEM_EVENT, 4)[0]
    return SYSTEM_EVENT[:size]


def compact_record() -> bytes:
    """CompactSystemHeader (type 0x03) derived from SYSTEM_EVENT, same IDs/timestamp."""
    record = bytearray(system_record()[:0x18])
    struct.pack_into("<H", record, 2, 0xC003)
    struct.pack_into("<H", record, 4, 0x18)
    return bytes(record)


def perfinfo_record() -> bytes:
    """PerfinfoTraceHeader (type 0x10) derived from SYSTEM_EVENT."""
    record = bytearray(system_record()[:0x10])
    struct.pack_into("<H", record, 2, 0xC010)
    struct.pack_into("<H", record, 4, 0x10)
    return bytes(record)


def event_header_record() -> bytes:
    """EventHeader record (type 0x13); the sample is zero-padded to its declared size."""
    declared = struct.unpack_from("<H", EVENT_HEADER_EVENT, 0)[0]
    record = EVENT_HEADER_EVENT
    if len(record) < declared:
        record += b"\x00" * (declared - len(record))
    return record[:declared]


def message_record() -> bytes:
    """MessageTraceHeader (flags 0x90), size 0x10 carried in the marker remainder."""
    return struct.pack("<HHHH", 0x10, 0x9000, 0x0001, 0x0000) + b"\xde\xad\xbe\xef" * 2


ALL_RECORDS = [system_record(), compact_record(), perfinfo_record(), event_header_record(), message_record()]


def build_buffer(
    records: list[bytes],
    tail: bytes = b"",
    unfilled_tail: bytes = b"",
    pad_byte: int = 0x00,
) -> bytes:
    """Assemble a buffer: header + 8-byte aligned records + tail.

    ``tail`` is part of the filled region (aligned up to 8 first), while
    ``unfilled_tail`` sits beyond FilledBytes and must never be read.
    """
    data = bytearray()
    for index, record in enumerate(records):
        data += record
        if index < len(records) - 1:
            data += bytes([pad_byte]) * (-len(data) % 8)
    if tail:
        data += b"\x00" * (-len(data) % 8)
        data += tail
    filled = BUFFER_HEADER_SIZE + len(data)
    header = bytearray(RAW_BUFFER_HEADER)
    struct.pack_into("<I", header, BUFFER_SIZE_OFFSET, filled + len(unfilled_tail))
    struct.pack_into("<I", header, FILLED_BYTES_OFFSET, filled)
    return bytes(header) + bytes(data) + unfilled_tail


# ---------------------------------------------------------------------------
# Harness: bounded iteration driver that reports the corruption offset
# ---------------------------------------------------------------------------


class CountingIO(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        return super().read(size)


class FakeETL:
    """Minimal ETL stand-in: a file handle and a deterministic timestamp function."""

    def __init__(self, fh: CountingIO):
        self.fh = fh

    def calculate_timestamp(self, time_delta: int) -> int:
        return time_delta


def fingerprint(record: EventRecord) -> tuple:
    """Content fingerprint of a parsed record; equal events must hash equally."""
    header: Header = record.header
    raw = bytes(header.data[: record.size])
    return (type(header).__name__, header.marker, record.size, hashlib.sha256(raw).hexdigest())


@dataclass
class Corruption:
    kind: str
    offset: int
    detail: str


@dataclass
class RunResult:
    events: list[tuple]
    corruption: Corruption | None
    stop_offset: int
    stop_reason: str
    reads: int


def run_buffer(raw: bytes, offset: int = 0) -> RunResult:
    """Iterate one buffer with a bounded driver mirroring ``Buffer.__iter__``.

    Termination is guaranteed by construction: the cursor must strictly advance
    and the number of records is capped. Structural corruption is reported with
    the offset at which it was detected.
    """
    fh = CountingIO(raw)
    buffer = Buffer(FakeETL(fh), offset)
    data_len = len(buffer.data)

    events: list[tuple] = []
    corruption = None
    stop_reason = "filled-bytes-exhausted"
    cursor = 0

    while cursor < buffer.filled_bytes:
        if len(events) >= MAX_EVENTS:
            corruption = Corruption("runaway-iteration", cursor, "record cursor did not terminate the stream")
            stop_reason = "error"
            break
        try:
            record = buffer.read_record(cursor)
        except (EOFError, NoMoreEventsError) as exc:
            stop_reason = type(exc).__name__
            break
        except (InvalidHeaderError, InvalidMarkerError) as exc:
            corruption = Corruption("invalid-record", cursor, f"{type(exc).__name__}: {exc}")
            stop_reason = "error"
            break

        if cursor + record.size > data_len:
            corruption = Corruption(
                "record-overrun",
                cursor,
                f"declared size 0x{record.size:x} runs past the filled data ({data_len:#x})",
            )
        if record.aligned_size <= 0:
            corruption = corruption or Corruption("non-advancing-cursor", cursor, "aligned size is zero")
            stop_reason = "error"
            break

        events.append(fingerprint(record))
        cursor += record.aligned_size

    if corruption is None and stop_reason == "NoMoreEventsError":
        remainder = bytes(buffer.data[cursor + 4 :])
        if remainder.strip(b"\xff"):
            corruption = Corruption("premature-end-marker", cursor, "non-padding data follows the end marker")

    return RunResult(events, corruption, cursor, stop_reason, fh.reads)


def assert_clean(result: RunResult, expected_events: list[tuple]) -> None:
    assert result.corruption is None
    assert result.events == expected_events
    assert result.reads <= MAX_READS


@pytest.fixture(scope="module")
def baseline_events() -> list[tuple]:
    result = run_buffer(build_buffer(ALL_RECORDS, tail=END_MARKER))
    assert result.corruption is None
    assert len(result.events) == len(ALL_RECORDS)
    return result.events


# ---------------------------------------------------------------------------
# Legal mutations: identical event sequence required
# ---------------------------------------------------------------------------


def test_buffer_iterator_matches_reference_driver(baseline_events: list[tuple]) -> None:
    """The real ``Buffer.__iter__`` agrees with the harness on the baseline stream."""
    buffer = Buffer(FakeETL(CountingIO(build_buffer(ALL_RECORDS, tail=END_MARKER))), 0)
    assert [fingerprint(record) for record in buffer] == baseline_events


@pytest.mark.parametrize("pad_len", [4, 8, 16], ids=lambda n: f"end-marker-padding-{n}")
def test_legal_end_marker_padding_length(pad_len: int, baseline_events: list[tuple]) -> None:
    """Criterion (legal-padding): any length of 0xFF end padding is equivalent."""
    result = run_buffer(build_buffer(ALL_RECORDS, tail=END_MARKER * (pad_len // 4)))
    assert_clean(result, baseline_events)
    assert result.stop_reason == "NoMoreEventsError"


@pytest.mark.parametrize("pad_byte", [0x00, 0xAA, 0xFF], ids=lambda b: f"interrecord-pad-0x{b:02x}")
def test_legal_interrecord_padding_content(pad_byte: int, baseline_events: list[tuple]) -> None:
    """Criterion (legal-padding): alignment padding content between records is ignored."""
    result = run_buffer(build_buffer(ALL_RECORDS, tail=END_MARKER, pad_byte=pad_byte))
    assert_clean(result, baseline_events)


@pytest.mark.parametrize("tail_len", [1, 2, 3], ids=lambda n: f"partial-tail-{n}")
def test_legal_partial_tail(tail_len: int, baseline_events: list[tuple]) -> None:
    """Criterion (legal-padding): a trailing partial marker (< 4 bytes) ends the stream cleanly."""
    result = run_buffer(build_buffer(ALL_RECORDS, tail=b"\xff" * tail_len))
    assert_clean(result, baseline_events)
    assert result.stop_reason == "EOFError"


def test_legal_unfilled_tail(baseline_events: list[tuple]) -> None:
    """Criterion (legal-padding): bytes beyond FilledBytes are never read."""
    raw = build_buffer(ALL_RECORDS, unfilled_tail=b"\xde\xad\xbe\xef" * 64)
    result = run_buffer(raw)
    assert_clean(result, baseline_events)


@pytest.mark.parametrize("split", range(1, len(ALL_RECORDS)), ids=lambda n: f"split-after-record-{n}")
def test_legal_buffer_split(split: int, baseline_events: list[tuple]) -> None:
    """Criterion (buffer-split): splitting the record stream into two chained buffers
    at a record boundary yields the same event sequence as one buffer."""
    first = build_buffer(ALL_RECORDS[:split])
    second = build_buffer(ALL_RECORDS[split:], tail=END_MARKER)
    raw = first + second

    # The first buffer chains exactly onto the second via offset + BufferSize.
    assert Buffer(FakeETL(CountingIO(raw)), 0).next_buffer == len(first)

    first_result = run_buffer(raw, offset=0)
    assert first_result.corruption is None
    assert first_result.events == baseline_events[:split]

    second_result = run_buffer(raw, offset=len(first))
    assert second_result.corruption is None
    assert second_result.events == baseline_events[split:]
    assert first_result.events + second_result.events == baseline_events
    assert second_result.reads <= MAX_READS


# ---------------------------------------------------------------------------
# Illegal mutations: bounded termination + corruption offset required
# ---------------------------------------------------------------------------

SHORT_HEADER_CASES = {
    "system-size-below-minimum": _patch(system_record(), 4, "<H", 0x10),
    "compact-size-below-minimum": _patch(compact_record(), 4, "<H", 0x10),
    "perfinfo-size-below-minimum": _patch(perfinfo_record(), 4, "<H", 0x08),
    "event-header-remainder-below-minimum": _patch(event_header_record(), 0, "<H", 0x48),
    "message-remainder-below-minimum": _patch(message_record(), 0, "<H", 0x04),
    "system-zero-size": _patch(system_record(), 4, "<H", 0x00),
}


@pytest.mark.parametrize("record", SHORT_HEADER_CASES.values(), ids=SHORT_HEADER_CASES.keys())
def test_short_header_rejected_at_record_offset(record: bytes) -> None:
    """Criterion (short-header): a declared size below the family minimum raises
    InvalidHeaderError at the record offset, within bounded reads."""
    result = run_buffer(build_buffer([record], tail=END_MARKER))
    assert result.events == []
    assert result.corruption is not None
    assert result.corruption.kind == "invalid-record"
    assert result.corruption.offset == 0
    assert "InvalidHeaderError" in result.corruption.detail
    assert result.reads <= MAX_READS


def test_short_header_rejected_after_valid_record() -> None:
    """Criterion (short-header): corruption offset is the second record's aligned offset."""
    record = _patch(compact_record(), 4, "<H", 0x08)
    result = run_buffer(build_buffer([system_record(), record], tail=END_MARKER))
    assert len(result.events) == 1
    assert result.corruption is not None
    assert result.corruption.kind == "invalid-record"
    assert result.corruption.offset == 0x48  # aligned size of the leading 0x44 system record
    assert result.reads <= MAX_READS


LENGTH_WRAPAROUND_CASES = {
    "system-huge-size": _patch(system_record(), 4, "<H", 0xFFF9),
    "compact-huge-size": _patch(compact_record(), 4, "<H", 0xFFF8),
    "event-header-huge-remainder": _patch(event_header_record(), 0, "<H", 0xFFF8),
    "message-huge-remainder": _patch(message_record(), 0, "<H", 0xFFF8),
}


@pytest.mark.parametrize("record", LENGTH_WRAPAROUND_CASES.values(), ids=LENGTH_WRAPAROUND_CASES.keys())
def test_length_wraparound_terminates_and_reports(record: bytes) -> None:
    """Criterion (length-wraparound): a declared length that carries the read cursor
    out of the filled region terminates within bounded reads and is reported as an
    overrun at the record offset."""
    result = run_buffer(build_buffer([record], tail=END_MARKER))
    assert result.corruption is not None
    assert result.corruption.kind == "record-overrun"
    assert result.corruption.offset == 0
    assert len(result.events) <= 1  # the cursor jumped out of the buffer; no runaway
    assert result.reads <= MAX_READS


def test_fake_end_marker_truncates_stream(baseline_events: list[tuple]) -> None:
    """Criterion (fake-end-marker): 0xFFFFFFFF inserted before a real record stops
    iteration early; the harness reports the marker offset and the hidden data."""
    tail = END_MARKER + b"\x00" * 4 + compact_record() + END_MARKER
    result = run_buffer(build_buffer([system_record()], tail=tail))
    assert result.events == baseline_events[:1]
    assert result.corruption is not None
    assert result.corruption.kind == "premature-end-marker"
    assert result.corruption.offset == 0x48
    assert result.reads <= MAX_READS


def test_fake_end_marker_overwrites_record(baseline_events: list[tuple]) -> None:
    """Criterion (fake-end-marker): a record whose marker was overwritten with
    0xFFFFFFFF is reported instead of silently dropping the remaining records."""
    fake = END_MARKER + compact_record()[4:]
    result = run_buffer(build_buffer([system_record(), fake], tail=END_MARKER))
    assert result.events == baseline_events[:1]
    assert result.corruption is not None
    assert result.corruption.kind == "premature-end-marker"
    assert result.corruption.offset == 0x48
    assert result.reads <= MAX_READS


def test_unknown_marker_flags_reported() -> None:
    """Marker flags outside 0xC0/0x90 raise InvalidMarkerError at the record offset."""
    record = _patch(system_record(), 3, "<B", 0xD0)
    result = run_buffer(build_buffer([record], tail=END_MARKER))
    assert result.corruption is not None
    assert result.corruption.kind == "invalid-record"
    assert result.corruption.offset == 0
    assert "InvalidMarkerError" in result.corruption.detail
    assert result.reads <= MAX_READS


def test_unknown_header_type_reported() -> None:
    """An unimplemented header type raises InvalidHeaderError at the record offset."""
    record = _patch(system_record(), 2, "<B", 0xFF)
    result = run_buffer(build_buffer([record], tail=END_MARKER))
    assert result.corruption is not None
    assert result.corruption.kind == "invalid-record"
    assert result.corruption.offset == 0
    assert "InvalidHeaderError" in result.corruption.detail
    assert result.reads <= MAX_READS


# ---------------------------------------------------------------------------
# Alignment: a wrong implementation must be caught
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("size", "expected"),
    [
        (0x10, 0x10),
        (0x18, 0x18),
        (0x44, 0x48),
        (0x48, 0x48),
        (0x112, 0x118),
        (0xFFF9, 0x10000),
    ],
)
def test_aligned_size_formula(size: int, expected: int) -> None:
    """Criterion (alignment): aligned_size rounds up to 8 and is a no-op for aligned
    sizes. Catches 4-byte alignment and align-even-when-aligned implementations."""
    record = EventRecord()
    record._header = SimpleNamespace(size=size)
    assert record.aligned_size == expected


def test_misaligned_cursor_is_loudly_rejected() -> None:
    """Criterion (alignment): demonstrate that a wrong alignment implementation is
    caught. With a 0x44-sized record the next record starts at 0x48; cursors produced
    by no/4-byte alignment (0x44) land on padding and raise instead of silently
    misparsing. With an already-aligned 0x10-sized record, over-alignment (0x18)
    lands inside the next record and also raises."""
    record = system_record()
    assert len(record) == 0x44  # not 8-byte aligned: padding bytes follow

    raw = build_buffer([record, compact_record()], tail=END_MARKER, pad_byte=0xAA)
    result = run_buffer(raw)
    assert result.corruption is None
    assert len(result.events) == 2  # correct 8-byte alignment finds both records

    buffer = Buffer(FakeETL(CountingIO(raw)), 0)
    wrong_cursors = {
        "no-alignment": len(record),  # 0x44: inside the padding
        "4-byte-alignment": (len(record) + 3) & ~3,  # 0x44: inside the padding
    }
    for name, cursor in wrong_cursors.items():
        assert cursor != 0x48, name
        with pytest.raises((InvalidMarkerError, InvalidHeaderError)):
            buffer.read_record(cursor)


def test_over_alignment_is_loudly_rejected() -> None:
    """Criterion (alignment): an implementation that aligns even already-aligned
    sizes (size + 8) & ~7 skips 8 bytes into the next record and is caught."""
    record = message_record()
    assert len(record) == 0x10  # already 8-byte aligned

    raw = build_buffer([record, system_record()], tail=END_MARKER)
    result = run_buffer(raw)
    assert result.corruption is None
    assert len(result.events) == 2

    buffer = Buffer(FakeETL(CountingIO(raw)), 0)
    over_aligned = (len(record) + 8) & ~7  # 0x18: inside the second record
    assert over_aligned != 0x10
    with pytest.raises((InvalidMarkerError, InvalidHeaderError)):
        buffer.read_record(over_aligned)
