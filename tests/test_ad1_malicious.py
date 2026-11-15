"""Deterministic malicious input tests for the AD1 file reading path.

Every test derives its input from ``tests/_data/ad1/compressed.ad1`` and only rewrites the fields that are
relevant for the case. All samples are built in memory and stay under a few KiB, so these tests never need a
stress server and never depend on exhausting machine memory.

Resource usage is measured in two ways:

* :class:`CountingReader` counts how many ``read`` calls the parser performs on the underlying image and how
  many bytes it requests.
* :class:`DecompressionStats` records how many bytes were actually produced by zlib, including the maximum
  ``max_length`` that was passed to a single decompression call.

The tests go through :meth:`dissect.evidence.ad1.ad1.FileEntry.open`, so the chunk table is parsed and the
compressed chunks are actually run through zlib.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING, Any

import pytest

from dissect.evidence.ad1 import DecompressionBudgetExceeded, InvalidChunkTable
from dissect.evidence.ad1 import stream as ad1_stream
from dissect.evidence.ad1.ad1 import AD1
from dissect.evidence.ad1.c_ad1 import c_ad1
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.evidence.ad1.ad1 import FileEntry
    from dissect.evidence.ad1.stream import FileStream

SEGMENT_HEADER_SIZE = 512
BASE_IMAGE = absolute_path("_data/ad1/compressed.ad1").read_bytes()
REAL_DECOMPRESS = zlib.decompress


def _base_layout() -> tuple[int, int, bytes]:
    """Read the entry offset, chunk table offset and entry name from the normal sample."""
    fh = BytesIO(BASE_IMAGE)
    segment_header = c_ad1.SegmentedFileHeader(fh)
    fh.seek(segment_header.logical_image_offset)
    logical_image = c_ad1.LogicalImageHeader(fh)
    fh.seek(SEGMENT_HEADER_SIZE + logical_image.first_file_offset)
    entry = c_ad1.FileEntry(fh)
    return logical_image.first_file_offset, entry.zlib_meta, entry.name


ENTRY_OFFSET, CHUNK_TABLE_OFFSET, ENTRY_NAME = _base_layout()
ENTRY_PATH = f"E:/AD1_test/{ENTRY_NAME.decode()}"


@dataclass
class BuiltImage:
    """A generated AD1 image and the offsets that were used to build it."""

    data: bytes
    offsets: list[int]
    meta_offset: int


def build_image(
    chunks: list[bytes],
    declared_size: int,
    *,
    chunk_size: int = 4096,
    offsets: list[int] | None = None,
    num_chunks: int | None = None,
    meta_offset: int | None = None,
) -> BuiltImage:
    """Build a deterministic AD1 image with a single file entry.

    Args:
        chunks: Compressed chunk payloads, in file order.
        declared_size: Value of the ``FileSize`` metadata item.
        chunk_size: Value of the logical image ``chunk_size`` field.
        offsets: Chunk offsets to write into the chunk table. Defaults to the real positions of ``chunks``.
        num_chunks: Value of the ``num_chunks`` field. Defaults to ``len(chunks)``.
        meta_offset: Position of the ``FileMeta`` chain. Defaults to directly after the chunk data.
    """
    count = len(chunks) if num_chunks is None else num_chunks
    table_start = CHUNK_TABLE_OFFSET
    default_offsets = []
    cursor = table_start + 8 + 8 * len(chunks)
    for chunk in chunks:
        default_offsets.append(cursor)
        cursor += len(chunk)

    if offsets is None:
        offsets = default_offsets
    if meta_offset is None:
        meta_offset = cursor

    meta_data = str(declared_size).encode()
    meta = struct.pack("<QIII", 0, 3, int(c_ad1.MetaType.FileSize), len(meta_data)) + meta_data
    entry = (
        struct.pack("<QQQQQII", 0, 0, meta_offset, table_start, declared_size, 0, len(ENTRY_NAME))
        + ENTRY_NAME
        + struct.pack("<Q", 0)
    )

    body = bytearray(BASE_IMAGE[SEGMENT_HEADER_SIZE : SEGMENT_HEADER_SIZE + ENTRY_OFFSET])
    struct.pack_into("<I", body, 24, chunk_size)  # LogicalImageHeader.chunk_size
    body += entry
    body += struct.pack("<Q", count)
    body += b"".join(struct.pack("<Q", offset) for offset in offsets)
    body += b"".join(chunks)
    body += b"\0" * max(0, meta_offset + len(meta) - len(body))
    body[meta_offset : meta_offset + len(meta)] = meta

    header = bytearray(BASE_IMAGE[:SEGMENT_HEADER_SIZE])
    struct.pack_into("<Q", header, 32, SEGMENT_HEADER_SIZE + len(body))  # SegmentedFileHeader.segment_size

    return BuiltImage(bytes(header) + bytes(body), default_offsets, meta_offset)


class CountingReader(BytesIO):
    """In-memory image that records how the parser reads from it."""

    def __init__(self, data: bytes):
        super().__init__(data)
        self.reset()

    def reset(self) -> None:
        self.read_calls = 0
        self.bytes_read = 0
        self.max_read_size = 0

    def read(self, size: int = -1) -> bytes:
        data = super().read(size)
        self.read_calls += 1
        self.bytes_read += len(data)
        self.max_read_size = max(self.max_read_size, len(data))
        return data


@dataclass
class DecompressionStats:
    """Records how much data zlib actually produced."""

    calls: int = 0
    produced: int = 0
    max_request: int = 0
    max_output: int = 0

    def reset(self) -> None:
        self.calls = 0
        self.produced = 0
        self.max_request = 0
        self.max_output = 0


@pytest.fixture
def decompression_stats(monkeypatch: pytest.MonkeyPatch) -> DecompressionStats:
    """Instrument zlib so tests can assert on the actual decompressed byte count.

    Both the streaming and the one-shot zlib entry points are instrumented, so the accounting stays correct
    regardless of which one the implementation uses.
    """
    stats = DecompressionStats()
    real_decompressobj = getattr(ad1_stream, "decompressobj", zlib.decompressobj)
    real_decompress = zlib.decompress

    class MeteredDecompressor:
        def __init__(self) -> None:
            self._inner = real_decompressobj()
            stats.calls += 1

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            stats.max_request = max(stats.max_request, max_length)
            result = self._inner.decompress(data, max_length)
            stats.produced += len(result)
            stats.max_output = max(stats.max_output, len(result))
            return result

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    def metered_decompress(data: bytes, *args: Any, **kwargs: Any) -> bytes:
        result = real_decompress(data, *args, **kwargs)
        stats.calls += 1
        stats.produced += len(result)
        stats.max_output = max(stats.max_output, len(result))
        return result

    if hasattr(ad1_stream, "decompressobj"):
        monkeypatch.setattr(ad1_stream, "decompressobj", MeteredDecompressor)
    monkeypatch.setattr(zlib, "decompress", metered_decompress)
    return stats


@dataclass
class OpenedImage:
    reader: CountingReader
    fs: AD1
    entry: FileEntry

    def open(self, decompressed_bytes: int | None = None) -> FileStream:
        # Invalidate the alignment buffer so reads below are actually served from the counting reader.
        self.fs.stream._buf = None
        self.reader.reset()
        return self.entry.open(decompressed_bytes=decompressed_bytes)


def load(data: bytes) -> OpenedImage:
    reader = CountingReader(data)
    fs = AD1([reader])
    return OpenedImage(reader, fs, fs.get(ENTRY_PATH))


def chunks_for(payload: bytes, chunk_size: int = 4096) -> list[bytes]:
    return [zlib.compress(payload[offset : offset + chunk_size]) for offset in range(0, len(payload), chunk_size)]


def assert_bounded(reader: CountingReader, *, max_read_calls: int = 8, max_bytes: int = 4096) -> None:
    """Assert that a rejected sample did not cause large or numerous reads."""
    assert reader.read_calls <= max_read_calls
    assert reader.bytes_read <= max_bytes
    assert reader.max_read_size <= max_bytes


def test_ad1_empty_file_reads_correctly(decompression_stats: DecompressionStats) -> None:
    """An empty file has no chunk table entries and must read as an empty file."""
    image = load(build_image([], 0).data)
    stream = image.open()

    assert stream.read() == b""
    assert image.entry.size == 0
    assert decompression_stats.calls == 0
    assert image.reader.bytes_read < 512


def test_ad1_short_tail_chunk_reads_correctly(decompression_stats: DecompressionStats) -> None:
    """A chunk_size aligned file with a short final chunk must read correctly, also across the boundary."""
    payload = b"A" * 4096 + b"tail"
    image = load(build_image(chunks_for(payload), len(payload)).data)

    stream = image.open()
    assert stream.read() == payload
    assert decompression_stats.produced == len(payload)
    assert decompression_stats.max_request == 4096

    stream = image.open()
    stream.seek(4094)
    assert stream.read(10) == payload[4094:4104]


@pytest.mark.parametrize("case", ["reversed", "duplicate", "past-end"])
def test_ad1_invalid_chunk_offsets(case: str, decompression_stats: DecompressionStats) -> None:
    """Reversed, duplicated and past-the-end chunk offsets must be rejected before decompression."""
    payload = b"A" * 4096 + b"tail"
    chunks = chunks_for(payload)
    layout = build_image(chunks, len(payload))

    if case == "reversed":
        offsets = list(reversed(layout.offsets))
    elif case == "duplicate":
        offsets = [layout.offsets[0], layout.offsets[0]]
    else:
        offsets = [layout.offsets[0], layout.meta_offset + 8]

    image = load(build_image(chunks, len(payload), offsets=offsets).data)
    with pytest.raises(InvalidChunkTable, match="strictly increasing"):
        image.open()

    assert decompression_stats.calls == 0
    assert_bounded(image.reader)


@pytest.mark.parametrize("chunk_size", [0, 1, 2**31])
def test_ad1_invalid_chunk_size(chunk_size: int, decompression_stats: DecompressionStats) -> None:
    """A zero, tiny or enormous chunk size must be rejected before it is used for alignment or decompression."""
    payload = b"A" * 4096
    image = load(build_image([zlib.compress(payload)], len(payload), chunk_size=chunk_size).data)

    with pytest.raises(InvalidChunkTable, match="Invalid chunk size"):
        image.open()

    assert decompression_stats.calls == 0
    assert_bounded(image.reader)


def test_ad1_chunk_data_overlapping_table(decompression_stats: DecompressionStats) -> None:
    """A chunk offset pointing back into the chunk table must be rejected before it is read."""
    payload = b"A" * 4096
    image = load(build_image([zlib.compress(payload)], len(payload), offsets=[CHUNK_TABLE_OFFSET]).data)

    with pytest.raises(InvalidChunkTable, match="overlaps chunk table"):
        image.open()

    assert decompression_stats.calls == 0
    assert_bounded(image.reader)


def test_ad1_oversized_compressed_chunk_span(decompression_stats: DecompressionStats) -> None:
    """A chunk span far larger than the chunk can inflate to must be rejected instead of being read whole."""
    payload = b"A" * 4096
    chunks = [zlib.compress(payload)]
    layout = build_image(chunks, len(payload))
    # Move the metadata far away, so the single chunk claims an enormous compressed span.
    image = load(build_image(chunks, len(payload), meta_offset=layout.meta_offset + 2**20).data)

    with pytest.raises(InvalidChunkTable, match="Compressed chunk exceeds chunk size"):
        image.open()

    assert decompression_stats.calls == 0
    # The image reports a 1 MiB span; the parser must reject it after at most the fixed alignment buffer.
    assert_bounded(image.reader, max_read_calls=8, max_bytes=16 * 1024)


def test_ad1_declared_size_larger_than_chunk_table(decompression_stats: DecompressionStats) -> None:
    """A tiny chunk table that declares a much larger file must be rejected instead of returning short data."""
    payload = b"AAAA"
    data = build_image([zlib.compress(payload)], 1 << 20).data
    assert len(data) < 1024

    image = load(data)
    with pytest.raises(InvalidChunkTable, match="Invalid chunk count"):
        image.open()

    assert decompression_stats.calls == 0
    assert_bounded(image.reader)


def test_ad1_oversized_chunk_count(decompression_stats: DecompressionStats) -> None:
    """A chunk count of 2**32 in a small image must be rejected without reading or allocating the table."""
    payload = b"A" * 4096 + b"tail"
    data = build_image(chunks_for(payload), len(payload), num_chunks=2**32).data

    image = load(data)
    with pytest.raises(InvalidChunkTable, match="Invalid chunk count"):
        image.open()

    assert decompression_stats.calls == 0
    assert_bounded(image.reader)


@pytest.mark.parametrize("reversed_offsets", [False, True])
def test_ad1_missing_final_chunk_boundary(reversed_offsets: bool, decompression_stats: DecompressionStats) -> None:
    """A chunk table without a boundary for the final chunk must be rejected, also when offsets are reversed.

    The last table entry points at the metadata offset, so the final chunk has no boundary left and only the
    metadata offset terminates it. Reversing the offsets on top of that exercises both invariants at once.
    """
    payload = b"A" * 4096 + b"tail"
    chunks = chunks_for(payload)
    layout = build_image(chunks, len(payload))
    offsets = [layout.offsets[0], layout.meta_offset]
    if reversed_offsets:
        offsets.reverse()

    image = load(build_image(chunks, len(payload), offsets=offsets).data)
    with pytest.raises(InvalidChunkTable, match="strictly increasing"):
        image.open()

    assert decompression_stats.calls == 0
    assert_bounded(image.reader)


def test_ad1_short_file_with_inflating_chunk(decompression_stats: DecompressionStats) -> None:
    """A minimal image whose single chunk inflates to 1 MiB while the file declares 4 KiB must be bounded.

    The complete image is under 2 KiB, which makes this a small deterministic sample that exposes the
    amplification: the compressed chunk by itself expands to at least 1 MiB.
    """
    chunk = zlib.compress(b"\x00" * (1 << 20), 9)
    data = build_image([chunk], 4096).data

    assert len(data) < 4096
    assert len(chunk) < 2048
    assert len(REAL_DECOMPRESS(chunk)) >= 1 << 20

    image = load(data)
    with pytest.raises(DecompressionBudgetExceeded, match="budget exceeded"):
        image.open().read()

    assert decompression_stats.max_request == 4096
    assert decompression_stats.max_output <= 4096
    assert decompression_stats.produced <= 4096
    assert_bounded(image.reader)


def test_ad1_decompression_budget_refuses_complete_file(decompression_stats: DecompressionStats) -> None:
    """A budget rejection must raise instead of silently returning a short or seemingly complete file."""
    payload = b"B" * 8192
    image = load(build_image(chunks_for(payload), len(payload)).data)

    # A budget equal to the declared size is sufficient and must read the complete file.
    assert image.open(decompressed_bytes=len(payload)).read() == payload

    decompression_stats.reset()
    stream = image.open(decompressed_bytes=4096)
    with pytest.raises(DecompressionBudgetExceeded, match="budget exceeded"):
        stream.read()
    assert stream.tell() == 0
    assert decompression_stats.produced <= 4096

    decompression_stats.reset()
    stream = image.open(decompressed_bytes=4096)
    first = stream.read(4096)
    assert first == payload[:4096]
    with pytest.raises(DecompressionBudgetExceeded, match="budget exceeded"):
        stream.read()
    assert len(first) < image.entry.size
    assert decompression_stats.produced == 4096
