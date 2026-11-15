from __future__ import annotations

import struct
from bisect import bisect_right
from typing import TYPE_CHECKING
from zlib import decompressobj
from zlib import error as zlib_error

from dissect.util.stream import AlignedStream

from dissect.evidence.exception import DecompressionBudgetExceeded, InvalidChunkTable

if TYPE_CHECKING:
    from dissect.evidence.ad1.ad1 import AD1, FileEntry

# Bounds for the chunk size declared by a logical image. Real world images use 64 KiB.
MIN_CHUNK_SIZE = 512
MAX_CHUNK_SIZE = 2**20
# Upper bound for the number of chunk offsets we are willing to load for a single file entry.
MAX_CHUNKS = 2**20
# Slack for the zlib stream header, stored block headers and the adler32 checksum.
MAX_COMPRESSED_CHUNK_OVERHEAD = 64


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

    The chunk table of a file entry is untrusted input. Before any decompression happens it is validated
    against the declared file size and the surrounding metadata offsets. Decompression itself is bounded,
    both per chunk (``max_length``) and in total (``decompressed_bytes``), so a small chunk table can not
    be used to make this stream inflate an arbitrary amount of data.

    Args:
        entry: The file entry to read.
        decompressed_bytes: Optional maximum number of decompressed bytes this stream may produce across its
            lifetime. Reads that would exceed it raise :class:`DecompressionBudgetExceeded`. When omitted,
            every individual chunk is still bounded by its expected size.
    """

    def __init__(self, entry: FileEntry, decompressed_bytes: int | None = None):
        self.entry = entry
        self.stream = self.entry.ad1.stream
        self.chunk_size = self.entry.ad1.logical_image.chunk_size
        self.size = self.entry.size

        self.decompressed_bytes = decompressed_bytes
        self._decompressed = 0

        if self.chunk_size < MIN_CHUNK_SIZE:
            raise InvalidChunkTable(f"Invalid chunk size {self.chunk_size} for {self.entry.name!r}")
        if self.chunk_size > MAX_CHUNK_SIZE:
            raise InvalidChunkTable(f"Invalid chunk size {self.chunk_size} for {self.entry.name!r}")

        self.chunks = self._read_chunk_table()

        super().__init__(self.size, self.chunk_size)

    def _read_chunk_table(self) -> list[int]:
        """Load and validate the chunk table of the file entry."""
        # The last boundary of a chunk is always the offset of the file metadata.
        table_end = self.entry.entry.meta

        if self.size == 0:
            # Empty files have no data. Some real world images have a stale ``zlib_meta`` offset for them.
            return [table_end]

        # Read the chunk count manually so we never ask cstruct for an array based on an untrusted count.
        self.stream.seek(self.entry.entry.zlib_meta)
        num_chunks_buf = self.stream.read(8)
        if len(num_chunks_buf) != 8:
            raise InvalidChunkTable(f"Truncated chunk table for {self.entry.name!r}")

        num_chunks = struct.unpack("<Q", num_chunks_buf)[0]
        expected_chunks = (self.size + self.chunk_size - 1) // self.chunk_size
        if num_chunks != expected_chunks or num_chunks > MAX_CHUNKS:
            raise InvalidChunkTable(
                f"Invalid chunk count {num_chunks} for {self.entry.name!r}, expected {expected_chunks}"
            )

        table_size = num_chunks * 8
        if self.entry.entry.zlib_meta + 8 + table_size > table_end:
            raise InvalidChunkTable(f"Chunk table exceeds file metadata for {self.entry.name!r}")

        table_buf = self.stream.read(table_size)
        if len(table_buf) != table_size:
            raise InvalidChunkTable(f"Truncated chunk table for {self.entry.name!r}")

        chunks = [*struct.unpack(f"<{num_chunks}Q", table_buf), table_end]

        if chunks[0] < self.entry.entry.zlib_meta + 8 + table_size:
            raise InvalidChunkTable(f"Chunk data overlaps chunk table for {self.entry.name!r}")
        if any(current >= nxt for current, nxt in zip(chunks, chunks[1:], strict=False)):
            raise InvalidChunkTable(f"Chunk offsets are not strictly increasing for {self.entry.name!r}")

        for idx, (chunk_offset, next_offset) in enumerate(zip(chunks, chunks[1:], strict=False)):
            chunk_length = min(self.chunk_size, self.size - idx * self.chunk_size)
            # A chunk can not expand to much more than its expected size, so its compressed form can not be
            # arbitrarily large either. The slack covers stored blocks and writer alignment padding.
            max_compressed_size = chunk_length + chunk_length // 16 + MAX_COMPRESSED_CHUNK_OVERHEAD
            if next_offset - chunk_offset > max_compressed_size:
                raise InvalidChunkTable(f"Compressed chunk exceeds chunk size for {self.entry.name!r}")

        return chunks

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        chunk, offset_in_chunk = divmod(offset, self.chunk_size)
        chunk_count = (length + self.chunk_size - 1) // self.chunk_size

        for chunk_idx in range(chunk, chunk + chunk_count):
            chunk_offset = self.chunks[chunk_idx]
            compressed_chunk_size = self.chunks[chunk_idx + 1] - chunk_offset
            chunk_length = min(self.chunk_size, self.size - chunk_idx * self.chunk_size)

            if self.decompressed_bytes is not None and self._decompressed + chunk_length > self.decompressed_bytes:
                raise DecompressionBudgetExceeded(f"Decompression budget exceeded for {self.entry.name!r}")

            self.stream.seek(chunk_offset)
            compressed = self.stream.read(compressed_chunk_size)

            buf = self._decompress_chunk(compressed, chunk_length)
            self._decompressed += len(buf)

            read_size = min(length, self.chunk_size - offset_in_chunk)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_size])

            offset += read_size
            length -= read_size
            offset_in_chunk = 0

        return b"".join(result)

    def _decompress_chunk(self, data: bytes, expected_size: int) -> bytes:
        """Decompress a single chunk, never producing more data than ``expected_size``."""
        decompressor = decompressobj()

        try:
            buf = decompressor.decompress(data, expected_size)
        except zlib_error as e:
            raise InvalidChunkTable(f"Invalid zlib stream for {self.entry.name!r}: {e}") from e

        if not decompressor.eof:
            if decompressor.unconsumed_tail:
                raise DecompressionBudgetExceeded(f"Decompression budget exceeded for {self.entry.name!r}")

            raise InvalidChunkTable(f"Incomplete zlib stream for {self.entry.name!r}")

        if decompressor.unused_data.strip(b"\0"):
            raise InvalidChunkTable(f"Trailing data after zlib stream for {self.entry.name!r}")

        if len(buf) != expected_size:
            raise InvalidChunkTable(f"Unexpected chunk size for {self.entry.name!r}")

        return buf
