from __future__ import annotations

import struct
import zlib
from io import BytesIO
from unittest.mock import patch

import pytest

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import Error
from dissect.apfs.stream import DecmpfsStream

BLOCK_SIZE = c_apfs.DECMPFS_BLOCK_SIZE
HEADER_SIZE = len(c_apfs.decmpfs_header)

# Algorithm numbers: the odd variants store their payload inline in the decmpfs xattr,
# the even variants store it in the com.apple.ResourceFork xattr.
ZLIB = (c_apfs.DECMPFS_ZLIB_ATTR, c_apfs.DECMPFS_ZLIB_RSRC)
LZVN = (c_apfs.DECMPFS_LZVN_ATTR, c_apfs.DECMPFS_LZVN_RSRC)
LZFSE = (c_apfs.DECMPFS_LZFSE_ATTR, c_apfs.DECMPFS_LZFSE_RSRC)
PLAIN = (c_apfs.DECMPFS_PLAIN_ATTR, c_apfs.DECMPFS_PLAIN_RSRC)

INLINE_ALGORITHMS = [ZLIB[0], LZVN[0], LZFSE[0], PLAIN[0]]
FORK_LENGTH_TABLE = [ZLIB[1], PLAIN[1]]
FORK_OFFSET_TABLE = [LZVN[1], LZFSE[1]]


def _sample_content() -> bytes:
    """Deterministic multi-block content with a deliberately short final block."""
    blocks = [bytes((i * 7 + j) & 0xFF for j in range(BLOCK_SIZE)) for i in range(2)]
    tail = (b"forensic-decmpfs-tail" * ((BLOCK_SIZE // 4) // 22 + 1))[: BLOCK_SIZE // 4]
    blocks.append(tail)
    return b"".join(blocks)


CONTENT = _sample_content()
SHORT_CONTENT = b"Compressed data in xattr " + b"a" * 94 + b"\n"


def _encode_block(algorithm: int, block: bytes) -> bytes:
    """Encode one logical block the way macOS decmpfs stores it."""
    if algorithm in (ZLIB[0], ZLIB[1]):
        compressed = zlib.compress(block)
        # A block that does not compress is stored raw with a 0x0f-style leading marker.
        return compressed if len(compressed) < len(block) else b"\x0f" + block
    if algorithm in (LZVN[0], LZVN[1]):
        # The dissect decoders are decompress-only; exercise the raw marker path.
        return b"\x06" + block
    if algorithm in (LZFSE[0], LZFSE[1]):
        return b"\xff" + block
    if algorithm in (PLAIN[0], PLAIN[1]):
        return b"\x0f" + block
    raise ValueError(f"Unsupported algorithm {algorithm}")


def _decmpfs_header(algorithm: int, uncompressed_size: int) -> bytes:
    return c_apfs.decmpfs_header(
        magic=int.from_bytes(c_apfs.DECMPFS_MAGIC, "big"),
        algorithm=algorithm,
        uncompressed_size=uncompressed_size,
    ).dumps()


def _build_inline(algorithm: int, content: bytes, declared_size: int) -> bytes:
    return _decmpfs_header(algorithm, declared_size) + _encode_block(algorithm, content)


def _build_length_table_fork(chunks: list[bytes]) -> bytes:
    """Build a classic resource fork (zlib/plain) with an explicit (offset, length) table."""
    data_offset = 0x100
    table_offset = 4
    # The data area starts with a 4-byte table offset, 4-byte entry count and one 8-byte pair per
    # chunk. The reader resolves an entry offset as data_offset + 4 + offset, so stored offsets are
    # the payload position inside the data area minus 4.
    payload_position = 8 + len(chunks) * 8
    first_payload_relative = payload_position - 4

    data = bytearray(data_offset)
    data.extend(b"\x00" * payload_position)
    struct.pack_into(">IIII", data, 0, data_offset, 0, 0, 0)
    struct.pack_into("<II", data, data_offset, table_offset, len(chunks))

    # Table offsets are relative to the start of the data area.
    relative_cursor = first_payload_relative
    for index, chunk in enumerate(chunks):
        struct.pack_into("<II", data, data_offset + 8 + index * 8, relative_cursor, len(chunk))
        data.extend(chunk)
        relative_cursor += len(chunk)

    struct.pack_into(">I", data, 8, relative_cursor + 4)
    return bytes(data)


def _build_offset_table_fork(chunks: list[bytes]) -> bytes:
    """Build a raw resource fork (lzvn/lzfse/lzbitmap) with an array of uint32 offsets."""
    offsets = []
    cursor = 4 * (len(chunks) + 1)
    for chunk in chunks:
        offsets.append(cursor)
        cursor += len(chunk)
    offsets.append(cursor)

    return b"".join(struct.pack("<I", offset) for offset in offsets) + b"".join(chunks)


def _build_fork(algorithm: int, chunks: list[bytes]) -> bytes:
    if algorithm in FORK_LENGTH_TABLE:
        return _build_length_table_fork(chunks)
    return _build_offset_table_fork(chunks)


def _replace_offset_table(fork: bytes, offsets: list[int]) -> bytes:
    """Overwrite the leading uint32 offset table of a raw resource fork."""
    table = b"".join(struct.pack("<I", offset) for offset in offsets)
    return table + fork[len(table) :]


class FakeXAttr:
    def __init__(self, data: bytes):
        self._data = data

    def open(self) -> BytesIO:
        return BytesIO(self._data)


class FakeInode:
    """Minimal inode stand-in exposing only what DecmpfsStream touches."""

    def __init__(self, decmpfs: bytes, resource_fork: bytes | None = None, inode_size: int | None = None):
        self.xattr = {"com.apple.decmpfs": FakeXAttr(decmpfs)}
        if resource_fork is not None:
            self.xattr["com.apple.ResourceFork"] = FakeXAttr(resource_fork)

        self.inode = c_apfs.j_inode_val()
        if inode_size is not None:
            self.inode.internal_flags = c_apfs.INODE.HAS_UNCOMPRESSED_SIZE
            self.inode.uncompressed_size = inode_size

    def __repr__(self) -> str:
        return "<FakeInode>"


def _chunks_for(algorithm: int, content: bytes) -> list[bytes]:
    return [_encode_block(algorithm, content[i : i + BLOCK_SIZE]) for i in range(0, len(content), BLOCK_SIZE)]


def _make_stream(
    algorithm: int,
    content: bytes,
    *,
    declared_size: int | None = None,
    inode_size: int | None = -1,
    decmpfs_override: bytes | None = None,
    fork_override: bytes | None = None,
) -> DecmpfsStream:
    size = len(content) if declared_size is None else declared_size

    if algorithm & 1:
        decmpfs, fork = _build_inline(algorithm, content, size), None
    else:
        decmpfs = _decmpfs_header(algorithm, size)
        fork = _build_fork(algorithm, _chunks_for(algorithm, content))

    if decmpfs_override is not None:
        decmpfs = decmpfs_override
    if fork_override is not None:
        fork = fork_override
    if inode_size == -1:
        inode_size = size

    return DecmpfsStream(FakeInode(decmpfs, fork, inode_size=inode_size))


def _random_reads(stream: DecmpfsStream, content: bytes) -> None:
    """Reconstruct the file through scattered, unaligned, block-boundary-crossing reads."""
    rebuilt = bytearray(len(content))
    ranges = [
        (0, 1),
        (13, 37),
        (BLOCK_SIZE - 5, 10),
        (BLOCK_SIZE, BLOCK_SIZE),
        (BLOCK_SIZE + 99, 257),
        (2 * BLOCK_SIZE - 3, 3 + len(content) % BLOCK_SIZE),
        (len(content) - 7, 7),
        (len(content) - 1, 1),
    ]
    # Cover every byte so a wrong block anywhere fails the comparison.
    ranges += [(start, min(4096, len(content) - start)) for start in range(0, len(content), 4096)]
    for offset, length in ranges:
        stream.seek(offset)
        rebuilt[offset : offset + length] = stream.read(length)
    assert bytes(rebuilt) == content


@pytest.mark.parametrize("algorithm", INLINE_ALGORITHMS, ids=lambda a: f"inline-algo{a}")
def test_inline_roundtrip_sequential_and_random(algorithm: int) -> None:
    """Inline xattr payloads rebuild the same file via sequential and random reads."""
    stream = _make_stream(algorithm, SHORT_CONTENT)

    assert stream.size == len(SHORT_CONTENT)
    assert stream.read() == SHORT_CONTENT

    _random_reads(_make_stream(algorithm, SHORT_CONTENT), SHORT_CONTENT)


@pytest.mark.parametrize("algorithm", FORK_LENGTH_TABLE + FORK_OFFSET_TABLE, ids=lambda a: f"fork-algo{a}")
def test_resource_fork_roundtrip_sequential_and_random(algorithm: int) -> None:
    """Resource fork payloads (length and offset tables) rebuild the same multi-block file."""
    stream = _make_stream(algorithm, CONTENT)

    assert stream.size == len(CONTENT)
    assert stream.read() == CONTENT

    _random_reads(_make_stream(algorithm, CONTENT), CONTENT)


def test_short_final_block_is_not_flagged() -> None:
    """A legitimate short final block must not be reported as a logical length mismatch."""
    assert len(CONTENT) % BLOCK_SIZE != 0

    for algorithm in (ZLIB[1], LZVN[1]):
        stream = _make_stream(algorithm, CONTENT)
        assert stream.read() == CONTENT


def test_duplicate_offset_in_offset_table() -> None:
    """A duplicated block offset points two blocks at the same payload region."""
    algorithm = LZVN[1]
    chunks = _chunks_for(algorithm, CONTENT)
    fork = _build_offset_table_fork(chunks)
    count = len(chunks) + 1
    original = list(struct.unpack_from(f"<{count}I", fork, 0))
    # Point the second block at the first block's payload, keeping the end offset intact.
    corrupted_offsets = original[:1] + original[:1] + original[2:]

    with pytest.raises(Error, match="block table.*duplicate"):
        _make_stream(algorithm, CONTENT, fork_override=_replace_offset_table(fork, corrupted_offsets))


def test_out_of_order_offset_in_offset_table() -> None:
    """Reversed offsets make two table entries describe overlapping, unsorted regions."""
    algorithm = LZFSE[1]
    chunks = _chunks_for(algorithm, CONTENT)
    fork = _build_offset_table_fork(chunks)
    count = len(chunks) + 1
    original = list(struct.unpack_from(f"<{count}I", fork, 0))
    corrupted_offsets = [original[1], original[0]] + original[2:]

    with pytest.raises(Error, match="block table.*out-of-order"):
        _make_stream(algorithm, CONTENT, fork_override=_replace_offset_table(fork, corrupted_offsets))


def test_overlapping_offset_in_length_table() -> None:
    """Two length-table entries whose (offset, length) regions overlap are rejected."""
    algorithm = ZLIB[1]
    chunks = _chunks_for(algorithm, CONTENT)
    fork = bytearray(_build_length_table_fork(chunks))
    data_offset = 0x100
    first_offset, first_length = struct.unpack_from("<II", fork, data_offset + 8)
    # Rewrite the second entry to start inside the first entry while keeping a positive length.
    struct.pack_into("<II", fork, data_offset + 16, first_offset + 4, first_length)

    with pytest.raises(Error, match="block table.*overlapping"):
        _make_stream(algorithm, CONTENT, fork_override=bytes(fork))


def test_length_table_entry_points_outside_fork() -> None:
    """A length-table (offset, length) pair extending past the fork is a block table error."""
    algorithm = ZLIB[1]
    fork = bytearray(_build_length_table_fork(_chunks_for(algorithm, CONTENT)))
    data_offset = 0x100
    offset, _length = struct.unpack_from("<II", fork, data_offset + 8)
    struct.pack_into("<II", fork, data_offset + 8, offset, len(fork) * 2)

    with pytest.raises(Error, match="block table.*outside the resource fork"):
        _make_stream(algorithm, CONTENT, fork_override=bytes(fork))


def test_missing_final_block_entry() -> None:
    """Declaring more logical blocks than the table contains must not silently truncate."""
    algorithm = LZVN[1]
    chunks = _chunks_for(algorithm, CONTENT)
    fork = _build_offset_table_fork(chunks)
    count = len(chunks) + 1
    # Physically remove the trailing end offset: the parser can only derive count - 1 entries
    # while the declared uncompressed size still requires count - 1 blocks.
    truncated = fork[: 4 * (count - 1)]

    with pytest.raises(Error, match="block table.*expected"):
        _make_stream(algorithm, CONTENT, fork_override=truncated)


def test_missing_final_block_fails_on_random_read() -> None:
    """A table missing its final offset is rejected even for a two-block file."""
    algorithm = LZVN[1]
    two_blocks = CONTENT[: 2 * BLOCK_SIZE]
    chunks = _chunks_for(algorithm, two_blocks)
    fork = _build_offset_table_fork(chunks)
    count = len(chunks) + 1
    truncated = fork[: 4 * (count - 1)]
    header = _decmpfs_header(algorithm, 2 * BLOCK_SIZE)

    with pytest.raises(Error, match="block table.*expected"):
        DecmpfsStream(FakeInode(header, truncated, inode_size=2 * BLOCK_SIZE))


def test_decompressed_block_does_not_match_logical_length() -> None:
    """An intact table whose payload decompresses short is a logical length error."""
    algorithm = ZLIB[1]
    blocks = [CONTENT[i : i + BLOCK_SIZE] for i in range(0, len(CONTENT), BLOCK_SIZE)]
    blocks[-1] = blocks[-1][: len(blocks[-1]) // 2]
    fork = _build_length_table_fork([_encode_block(algorithm, block) for block in blocks])

    stream = _make_stream(algorithm, CONTENT, fork_override=fork)
    with pytest.raises(Error, match="logical length"):
        stream.read()


def test_corrupt_compressed_payload() -> None:
    """Garbled compressed bytes that fail to decode are reported as payload corruption."""
    algorithm = ZLIB[0]
    decmpfs = _build_inline(algorithm, SHORT_CONTENT, len(SHORT_CONTENT))
    corrupted = decmpfs[:HEADER_SIZE] + b"\x78\x9c" + b"\xff" * (len(decmpfs) - HEADER_SIZE - 2)

    stream = _make_stream(algorithm, SHORT_CONTENT, decmpfs_override=corrupted)
    with pytest.raises(Error, match="compressed payload"):
        stream.read()


def test_truncated_compressed_payload_in_fork() -> None:
    """A block read that returns fewer bytes than its table entry is a payload failure."""
    algorithm = LZVN[1]
    stream = _make_stream(algorithm, CONTENT)
    target_offset, target_length = stream._entries[-1]

    real_read = stream._fork.read

    def short_read(length: int) -> bytes:
        # Only the final block read is shortened; the table itself stays valid and in-bounds.
        if stream._fork.tell() == target_offset and length == target_length:
            return real_read(length - 5)
        return real_read(length)

    with (
        patch.object(stream._fork, "read", side_effect=short_read),
        pytest.raises(Error, match="compressed payload.*short read"),
    ):
        stream.read()


def test_declared_size_inconsistent_with_block_table() -> None:
    """Inflating the decmpfs declared size requires a block the table does not provide."""
    algorithm = LZVN[1]
    two_blocks = CONTENT[: 2 * BLOCK_SIZE]
    chunks = _chunks_for(algorithm, two_blocks)
    fork = _build_offset_table_fork(chunks)
    # Keep just the first block's start offset plus one end offset: the parser derives a single
    # entry, while the inflated header claims a size needing two blocks.
    truncated = fork[:8]
    header = _decmpfs_header(algorithm, BLOCK_SIZE + 1)

    with pytest.raises(Error, match="block table.*expected"):
        DecmpfsStream(FakeInode(header, truncated, inode_size=BLOCK_SIZE + 1))


def test_inode_size_contradicts_decmpfs_header() -> None:
    """An inode size that disagrees with the decmpfs logical length is rejected."""
    algorithm = ZLIB[0]
    decmpfs = _build_inline(algorithm, SHORT_CONTENT, len(SHORT_CONTENT))

    with pytest.raises(Error, match="logical length.*inode reports"):
        DecmpfsStream(FakeInode(decmpfs, None, inode_size=len(SHORT_CONTENT) + 1))


def test_inline_payload_cannot_span_multiple_blocks() -> None:
    """An inline xattr claiming a multi-block logical size cannot be a valid single chunk."""
    algorithm = ZLIB[0]
    decmpfs = _build_inline(algorithm, SHORT_CONTENT, BLOCK_SIZE + 1)

    with pytest.raises(Error, match="block table.*inline"):
        DecmpfsStream(FakeInode(decmpfs, None, inode_size=BLOCK_SIZE + 1))
