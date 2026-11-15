from __future__ import annotations

import zlib
from typing import TYPE_CHECKING

import pytest

from dissect.evidence.ad1.stream import MAX_CHUNK_SIZE, FileStream
from dissect.evidence.exception import InvalidChunk
from tests._ad1_builder import build, open_entry

if TYPE_CHECKING:
    from tests._ad1_builder import Sample


def read_file(sample: Sample) -> tuple[bytes, FileStream]:
    _, entry = open_entry(sample)
    stream = entry.open()
    return stream.read(), stream


def test_ad1_valid_empty_file() -> None:
    """A valid empty file has no chunk table and reads as empty without decompression."""
    _, entry = open_entry(build([]))
    assert entry.size == 0

    stream = entry.open()
    assert stream.chunks == []
    assert stream.read() == b""
    assert stream.reads == 0
    assert stream.decompressed == 0


def test_ad1_valid_empty_file_with_explicit_table() -> None:
    """An empty file may still carry a table pointer; it must not trigger table I/O."""
    _, entry = open_entry(build([], write_empty_table=True))
    assert entry.size == 0

    stream = entry.open()
    assert stream.chunks == []
    assert stream.read() == b""
    assert stream.reads == 0


def test_ad1_valid_short_tail() -> None:
    """A final chunk smaller than the chunk size is valid and must be read in full."""
    chunks = [b"A" * 0x1000, b"B" * 0x123]
    data, stream = read_file(build(chunks))
    assert data == b"".join(chunks)
    assert len(data) == sum(map(len, chunks))
    assert stream.decompressed == len(data)


def test_ad1_reversed_chunk_offsets() -> None:
    """Reversed chunk offsets would make a negative-size chunk; reject before decompression."""
    sample = build([b"A" * 0x1000, b"B" * 0x1000])
    first, second = sample.table_u64(0), sample.table_u64(1)
    sample.patch_table(0, second)
    sample.patch_table(1, first)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="non-increasing chunk boundary"):
        entry.open()


def test_ad1_duplicate_chunk_offsets() -> None:
    """Duplicate offsets describe an empty compressed chunk, which is always invalid."""
    sample = build([b"A" * 0x1000, b"B" * 0x1000])
    sample.patch_table(1, sample.table_u64(0))

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="non-increasing chunk boundary"):
        entry.open()


def test_ad1_oversized_chunk_size() -> None:
    """An oversized chunk size must be rejected, not used to inflate read lengths."""
    sample = build([b"A" * 0x10])
    sample.set_chunk_size(MAX_CHUNK_SIZE + 1)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="chunk size"):
        entry.open()


def test_ad1_oversized_compressed_chunk() -> None:
    """A boundary far past the chunk payload must be rejected before reading it."""
    sample = build([b"A" * 0x1000])
    sample.set_meta(0x100000)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="compressed bytes exceeds"):
        entry.open()


def test_ad1_short_declared_size_cannot_inflate() -> None:
    """A chunk that decompresses past the declared file size must be rejected.

    The compressed payload for one 4096-byte chunk is only 26 bytes, so this is a
    minimal compressed-bomb sample: small on disk, but it expands to 4096 bytes while
    the entry claims only 16.
    """
    bomb = zlib.compress(b"\x00" * 0x1000, 9)
    assert len(bomb) < 64

    sample = build([b"\x00" * 0x1000])
    sample.set_size(0x10)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="chunks, expected|decompresses beyond"):
        entry.open().read()


def test_ad1_declared_short_multichunk_inflation() -> None:
    """A declared-short file must not decompress all of its chunks."""
    chunks = [b"\x00" * 0x1000] * 4
    sample = build(chunks)
    sample.set_size(0x1000)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="chunks, expected"):
        entry.open().read()


def test_ad1_missing_final_boundary() -> None:
    """Without the metadata boundary the last chunk has no end; reject the image."""
    sample = build([b"A" * 0x1000, b"tail"])
    sample.set_meta(0)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk):
        entry.open()


def test_ad1_metadata_equals_last_chunk() -> None:
    """A zero-length final chunk must be rejected rather than yielding a short read."""
    sample = build([b"A" * 0x1000, b"tail"])
    sample.set_meta(sample.table_u64(1))

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="non-increasing chunk boundary"):
        entry.open()


def test_ad1_chunk_count_mismatch() -> None:
    """The chunk count is attacker controlled and must match the declared size."""
    sample = build([b"A" * 0x1000])
    sample.set_num_chunks(2**40)

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="chunks, expected"):
        entry.open()


def test_ad1_budget_rejects_without_partial_file() -> None:
    """A decompression-budget failure must not return a plausible-looking full file."""
    chunks = [bytes([i]) * 0x1000 for i in range(4)]
    sample = build(chunks)
    expected = b"".join(chunks)

    _, entry = open_entry(sample)
    stream = entry.open(max_decompressed=0x2000)
    with pytest.raises(InvalidChunk, match="decompression budget"):
        stream.read()

    # No partial data was handed back, and the stream did not reach the declared end.
    assert stream.decompressed <= 0x2000
    assert stream.tell() == 0
    assert stream.size == len(expected)


def test_ad1_read_budget() -> None:
    """The read budget bounds source reads, including table and chunk reads."""
    sample = build([b"A" * 0x1000, b"tail"])

    _, entry = open_entry(sample)
    with pytest.raises(InvalidChunk, match="read budget"):
        entry.open(max_reads=1)

    stream = entry.open(max_reads=4)
    assert stream.read() == b"A" * 0x1000 + b"tail"
    assert stream.reads == 4


def test_ad1_short_tail_with_budget() -> None:
    """A valid short tail fits exactly in a budget equal to the file size."""
    chunks = [b"A" * 0x1000, b"tail"]
    expected = b"".join(chunks)

    _, entry = open_entry(build(chunks))
    stream = entry.open(max_decompressed=len(expected))
    assert stream.read() == expected
    assert stream.decompressed == len(expected)
