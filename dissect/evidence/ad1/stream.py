from __future__ import annotations

import struct
import zlib
from bisect import bisect_right
from itertools import pairwise
from typing import TYPE_CHECKING

from dissect.evidence.exception import InvalidChunk
from dissect.util.stream import AlignedStream

if TYPE_CHECKING:
    from dissect.evidence.ad1.ad1 import AD1, FileEntry

# Maximum size of a single zlib chunk. FTK Imager uses 64 KiB by default, but other
# implementations are known to use larger sizes. Anything beyond this is treated as hostile input.
MAX_CHUNK_SIZE = 64 * 1024 * 1024

# Maximum number of chunks in a single file chunk table. This bounds the amount of
# metadata we are willing to read before it is validated against the declared file size.
MAX_CHUNKS = 1 << 20

# Overhead of a zlib stream for incompressible data, from zlib's ``compressBound``.
ZLIB_BOUND_OVERHEAD = 13


def max_compressed_size(size: int) -> int:
    """Return the maximum compressed size of a zlib stream that expands to ``size`` bytes."""
    return size + (size >> 12) + (size >> 14) + (size >> 25) + ZLIB_BOUND_OVERHEAD


class AD1Stream(AlignedStream):
    """Provide a stitched stream over all AD1 segments."""

    def __init__(self, ad1: AD1):
        self.ad1 = ad1
        super().__init__(self.ad1.size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        idx = bisect_right(self.ad1._segment_offsets, offset)
        while length > 0:
            if idx > len(self.ad1._segment_offsets) - 1:
                break

            segment = self.ad1.segment(idx)
            segment_offset = 0 if idx == 0 else self.ad1._segment_offsets[idx - 1]
            offset_in_segment = offset - segment_offset
            read_size = min(length, segment.size - offset_in_segment)

            segment.fh.seek(512 + offset_in_segment)  # Skip segment header
            result.append(segment.fh.read(read_size))

            offset += read_size
            length -= read_size
            idx += 1

        return b"".join(result)


class FileStream(AlignedStream):
    """Custom stream implementation for AD1 :class:`FileEntry` file contents.

    The chunk table is fully validated before any chunk is decompressed. Chunks are
    decompressed with an output limit so a small, highly compressible chunk can never
    expand beyond the part of the file it represents.
    """

    def __init__(
        self,
        entry: FileEntry,
        *,
        max_reads: int | None = None,
        max_decompressed: int | None = None,
    ):
        self.entry = entry
        self.stream = self.entry.ad1.stream
        self.chunk_size = self.entry.ad1.logical_image.chunk_size
        self.max_reads = max_reads
        self.max_decompressed = max_decompressed

        if not 0 < self.chunk_size <= MAX_CHUNK_SIZE:
            raise InvalidChunk(f"Invalid AD1 chunk size: {self.chunk_size}")

        # Use the raw on-disk size as the authoritative declared size. The metadata
        # chain is attacker-controlled and may itself be unreadable when the final
        # chunk boundary is corrupted, so it must not be needed to validate the table.
        self.size = self.entry.entry.size

        self.reads = 0
        self.decompressed = 0

        # An empty file needs no chunk data, so never read a table for it. This keeps
        # valid empty entries working regardless of whether they carry a table pointer
        # and prevents an oversized count on such an entry from causing any I/O.
        self.chunks = [] if not self.size else self._read_chunk_table()

        super().__init__(self.size, self.chunk_size)

    def _read_source(self, offset: int, size: int) -> bytes:
        """Read ``size`` bytes from the source stream, charging the read budget."""
        if size < 0:
            raise InvalidChunk(f"Invalid AD1 chunk: negative read size {size}")

        if self.max_reads is not None and self.reads >= self.max_reads:
            raise InvalidChunk(f"AD1 read budget of {self.max_reads} reads exceeded")

        self.stream.seek(offset)
        data = self.stream.read(size)
        self.reads += 1
        return data

    def _account_decompressed(self, size: int) -> None:
        self.decompressed += size
        if self.max_decompressed is not None and self.decompressed > self.max_decompressed:
            raise InvalidChunk(f"AD1 decompression budget of {self.max_decompressed} bytes exceeded")

    def _read_chunk_table(self) -> list[int]:
        """Read and validate the chunk table for this entry."""
        entry = self.entry.entry
        size = self.size
        table_offset = entry.zlib_meta
        meta_offset = entry.meta

        if table_offset <= 0:
            raise InvalidChunk(f"Invalid AD1 chunk table offset: {table_offset}")
        if meta_offset <= 0:
            raise InvalidChunk(f"Invalid AD1 chunk table: missing metadata boundary ({meta_offset})")

        expected_chunks = (size + self.chunk_size - 1) // self.chunk_size
        if expected_chunks > MAX_CHUNKS:
            raise InvalidChunk(
                f"Invalid AD1 chunk table: {expected_chunks} chunks exceeds the {MAX_CHUNKS} chunk limit"
            )

        header = self._read_source(table_offset, 8)
        if len(header) != 8:
            raise InvalidChunk("Invalid AD1 chunk table: truncated chunk count")
        num_chunks = struct.unpack("<Q", header)[0]

        if num_chunks != expected_chunks:
            raise InvalidChunk(
                f"Invalid AD1 chunk table: {num_chunks} chunks, expected {expected_chunks} for {size} bytes"
            )

        raw_table = self._read_source(table_offset + 8, num_chunks * 8)
        if len(raw_table) != num_chunks * 8:
            raise InvalidChunk("Invalid AD1 chunk table: truncated chunk offsets")

        table_end = table_offset + 8 + num_chunks * 8
        chunks = [offset for (offset,) in struct.iter_unpack("<Q", raw_table)]
        chunks.append(meta_offset)

        if chunks[0] < table_end:
            raise InvalidChunk(
                f"Invalid AD1 chunk table: chunk offset {chunks[0]} overlaps the chunk table ending at {table_end}"
            )

        for i, (chunk_offset, next_offset) in enumerate(pairwise(chunks)):
            if next_offset <= chunk_offset:
                raise InvalidChunk(
                    f"Invalid AD1 chunk table: non-increasing chunk boundary {chunk_offset} -> {next_offset}"
                )

            expected_size = min(self.chunk_size, size - i * self.chunk_size)
            max_size = max_compressed_size(expected_size)
            if next_offset - chunk_offset > max_size:
                raise InvalidChunk(
                    f"Invalid AD1 chunk {i}: {next_offset - chunk_offset} compressed bytes exceeds the "
                    f"{max_size} byte maximum for {expected_size} bytes"
                )

        return chunks

    def _read_chunk(self, chunk_offset: int, next_offset: int, expected_size: int) -> bytes:
        """Read and decompress a single chunk, refusing output beyond ``expected_size`` bytes."""
        compressed_chunk_size = next_offset - chunk_offset
        if compressed_chunk_size <= 0:
            raise InvalidChunk(f"Invalid AD1 chunk: empty compressed chunk at offset {chunk_offset}")

        data = self._read_source(chunk_offset, compressed_chunk_size)
        if len(data) != compressed_chunk_size:
            raise InvalidChunk(f"Invalid AD1 chunk: truncated compressed chunk at offset {chunk_offset}")

        remaining = None
        if self.max_decompressed is not None:
            remaining = self.max_decompressed - self.decompressed
            if remaining < 0:
                raise InvalidChunk(f"AD1 decompression budget of {self.max_decompressed} bytes exceeded")

        limit = expected_size + 1
        if remaining is not None:
            limit = min(limit, remaining + 1)

        decompressor = zlib.decompressobj()
        try:
            buf = decompressor.decompress(data, limit)
        except zlib.error as e:
            raise InvalidChunk(f"Invalid AD1 chunk at offset {chunk_offset}: {e}") from e

        if remaining is not None and len(buf) > remaining:
            raise InvalidChunk(f"AD1 decompression budget of {self.max_decompressed} bytes exceeded")

        if len(buf) > expected_size:
            raise InvalidChunk(
                f"Invalid AD1 chunk at offset {chunk_offset}: decompresses beyond the {expected_size} byte chunk budget"
            )

        if decompressor.unconsumed_tail:
            raise InvalidChunk(f"Invalid AD1 chunk at offset {chunk_offset}: compressed chunk exceeds its boundary")

        if not decompressor.eof:
            raise InvalidChunk(f"Invalid AD1 chunk at offset {chunk_offset}: truncated zlib stream")

        self._account_decompressed(len(buf))
        return buf

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        chunk, offset_in_chunk = divmod(offset, self.chunk_size)
        chunk_count = (length + self.chunk_size - 1) // self.chunk_size
        chunk_offsets = self.chunks[chunk : chunk + chunk_count + 1]

        for i, chunk_offset in enumerate(chunk_offsets[:-1]):
            expected_size = min(self.chunk_size, self.size - (chunk + i) * self.chunk_size)
            buf = self._read_chunk(chunk_offset, chunk_offsets[i + 1], expected_size)

            # Every chunk must decompress to exactly its share of the declared file size.
            # Only the final chunk may be a short tail.
            if len(buf) != expected_size:
                raise InvalidChunk(f"AD1 chunk {chunk + i} decompresses to {len(buf)} bytes, expected {expected_size}")

            read_size = min(length, self.chunk_size - offset_in_chunk)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_size])

            offset += read_size
            length -= read_size
            offset_in_chunk = 0

        return b"".join(result)
