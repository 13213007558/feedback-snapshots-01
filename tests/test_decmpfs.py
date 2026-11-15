"""End-to-end integrity checks for forensic reads of APFS compressed (decmpfs) files.

The samples below reproduce the on-disk byte layouts produced by macOS: an inline
decmpfs xattr, a resource fork with a classic ``(offset, length)`` length table
(zlib/plain) and a resource fork with a raw trailing-offset table (lzvn/lzfse/
lzbitmap). Every corruption case must be attributed to either the block table, the
compressed payload or the declared logical length rather than being truncated into
apparently successful output.
"""

from __future__ import annotations

import gzip
import struct
import zlib
from contextlib import contextmanager
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import (
    DecmpfsBlockTableError,
    DecmpfsLogicalLengthError,
    DecmpfsPayloadError,
)
from dissect.apfs.stream import DecmpfsStream
from dissect.util.stream import BufferedStream
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

BLOCK_SIZE = 0x10000
FORK_DATA_OFFSET = 0x100
STORED_MARKERS = {
    c_apfs.DECMPFS_LZVN_ATTR: 0x06,
    c_apfs.DECMPFS_LZVN_RSRC: 0x06,
    c_apfs.DECMPFS_LZFSE_ATTR: 0xFF,
    c_apfs.DECMPFS_LZFSE_RSRC: 0xFF,
}


class FakeXAttr:
    """Minimal XAttr stand-in that serves its data from an in-memory buffer."""

    def __init__(self, name: str, data: bytes):
        self.name = name
        self._data = data

    def open(self) -> BufferedStream:
        return BufferedStream(BytesIO(self._data), size=len(self._data))


class FakeInode:
    """INode stand-in carrying the decmpfs state inspected by DecmpfsStream."""

    def __init__(
        self,
        decmpfs: bytes,
        resource_fork: bytes | None = None,
        reported_size: int | None = None,
        report_flag: bool = True,
    ):
        self.xattr = {"com.apple.decmpfs": FakeXAttr("com.apple.decmpfs", decmpfs)}
        if resource_fork is not None:
            self.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", resource_fork)

        self.internal_flags = c_apfs.INODE.HAS_UNCOMPRESSED_SIZE if report_flag else c_apfs.INODE(0)
        self.inode = type("InodeRecord", (), {"uncompressed_size": reported_size})()

    def __repr__(self) -> str:
        return "<FakeInode decmpfs>"


@contextmanager
def small_block_size() -> Iterator[None]:
    """Keep multi-block samples tiny while retaining the real block-table logic."""
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(c_apfs, "DECMPFS_BLOCK_SIZE", BLOCK_SIZE)
        yield


def sample_data(size: int, seed: int = 7) -> bytes:
    """Deterministic, highly compressible data of exactly ``size`` bytes.

    The rotating counter keeps the stream compressible while keeping block
    boundaries and offsets distinguishable.
    """
    pattern = (f"APFS forensic decmpfs integrity sample {seed:02d} " * 4096).encode()
    return (pattern * (size // len(pattern) + 1))[:size]


def decmpfs_header(algorithm: int, uncompressed_size: int) -> bytes:
    return c_apfs.decmpfs_header(
        magic=struct.unpack(">I", c_apfs.DECMPFS_MAGIC)[0],
        algorithm=algorithm,
        uncompressed_size=uncompressed_size,
    ).dumps()


def encode_block(algorithm: int, block: bytes) -> bytes:
    """Encode one logical block the way macOS stores it for ``algorithm``.

    zlib uses real deflate streams; the other algorithms have no compressor in this
    environment, so their stored (uncompressed) block form is used, which exercises
    the same marker-stripping code paths as a real compressed block.
    """
    if algorithm in (c_apfs.DECMPFS_ZLIB_ATTR, c_apfs.DECMPFS_ZLIB_RSRC):
        return zlib.compress(block)

    if algorithm in (c_apfs.DECMPFS_PLAIN_ATTR, c_apfs.DECMPFS_PLAIN_RSRC):
        return b"\x00" + block

    return bytes([STORED_MARKERS[algorithm]]) + block


def build_inline(algorithm: int, data: bytes, *, reported_size: int | None = None) -> FakeInode:
    payload = encode_block(algorithm, data)
    decmpfs = decmpfs_header(algorithm, len(data)) + payload
    return FakeInode(decmpfs, reported_size=len(data) if reported_size is None else reported_size)


def build_length_table_fork(blocks: list[bytes]) -> bytes:
    """Build a resource fork using the classic zlib/plain length table layout.

    On disk the first entry offset points at the payload body, which starts right
    after the full table (8-byte header plus 8 bytes per entry). The parser resolves
    entries as ``data_offset + 4 + offset``, so offsets use a body-relative base of
    ``table_size - 4``.
    """
    table_size = 8 + 8 * len(blocks)
    table = struct.pack("<II", 0, len(blocks))
    body = bytearray()
    for block in blocks:
        table += struct.pack("<II", table_size - 4 + len(body), len(block))
        body += block

    fork = bytearray(FORK_DATA_OFFSET)
    fork += table
    fork += body
    data_size = len(table) + len(body)
    fork[:16] = struct.pack(">IIII", FORK_DATA_OFFSET, 0, data_size, 0)
    return bytes(fork)


def build_offset_table_fork(blocks: list[bytes]) -> bytes:
    """Build a resource fork using the raw uint32 trailing-offset table layout.

    The table occupies the start of the fork (four bytes per block plus a trailing
    end offset); the payload body follows it, mirroring the real on-disk layout.
    """
    table_size = (len(blocks) + 1) * 4
    body = b"".join(blocks)
    offsets = [table_size + len(b"".join(blocks[:i])) for i in range(len(blocks))]
    offsets.append(table_size + len(body))

    table = b"".join(struct.pack("<I", offset) for offset in offsets)
    return table + body


def build_fork_inode(
    algorithm: int,
    data: bytes,
    *,
    table: str = "length",
    reported_size: int | None = None,
) -> FakeInode:
    blocks = [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    encoded = [encode_block(algorithm, block) for block in blocks]

    fork = build_length_table_fork(encoded) if table == "length" else build_offset_table_fork(encoded)
    decmpfs = decmpfs_header(algorithm, len(data))
    return FakeInode(decmpfs, fork, reported_size=len(data) if reported_size is None else reported_size)


def split_logical(data: bytes) -> list[bytes]:
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def assert_sequential_and_random_match(stream: DecmpfsStream, expected: bytes) -> None:
    assert stream.size == len(expected)

    sequential = stream.read()
    assert sequential == expected

    # Random reads over block boundaries and inside the (short) final block must
    # reconstruct the same bytes as a sequential read.
    random_stream = type(stream)(stream.inode)
    candidate_offsets = (0, 1, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 137, len(expected) - 1)
    for offset in candidate_offsets:
        if offset >= len(expected):
            continue
        for read_length in (1, 5, min(BLOCK_SIZE, len(expected) - offset)):
            assert random_stream.readoffset(offset, read_length) == expected[offset : offset + read_length]


INLINE_ALGORITHMS = [
    c_apfs.DECMPFS_ZLIB_ATTR,
    c_apfs.DECMPFS_LZVN_ATTR,
    c_apfs.DECMPFS_PLAIN_ATTR,
    c_apfs.DECMPFS_LZFSE_ATTR,
]

LENGTH_TABLE_ALGORITHMS = [c_apfs.DECMPFS_ZLIB_RSRC, c_apfs.DECMPFS_PLAIN_RSRC]
OFFSET_TABLE_ALGORITHMS = [c_apfs.DECMPFS_LZVN_RSRC, c_apfs.DECMPFS_LZFSE_RSRC]


def test_inline_single_block_roundtrip() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE // 2)
        for algorithm in INLINE_ALGORITHMS:
            inode = build_inline(algorithm, data)
            assert_sequential_and_random_match(DecmpfsStream(inode), data)


def test_resource_fork_length_table_roundtrip() -> None:
    with small_block_size():
        # Two full blocks and a deliberately short final block.
        data = sample_data(2 * BLOCK_SIZE + 4096)
        assert len(split_logical(data)) == 3
        assert len(split_logical(data)[-1]) == 4096

        for algorithm in LENGTH_TABLE_ALGORITHMS:
            inode = build_fork_inode(algorithm, data, table="length")
            assert_sequential_and_random_match(DecmpfsStream(inode), data)


def test_resource_fork_offset_table_roundtrip() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 4096)
        for algorithm in OFFSET_TABLE_ALGORITHMS:
            inode = build_fork_inode(algorithm, data, table="offset")
            assert_sequential_and_random_match(DecmpfsStream(inode), data)


def test_normal_short_final_block_is_not_flagged() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE + 17)
        inode = build_fork_inode(c_apfs.DECMPFS_ZLIB_RSRC, data, table="length")

        stream = DecmpfsStream(inode)
        assert stream.read() == data
        assert stream.readoffset(BLOCK_SIZE, 17) == data[BLOCK_SIZE:]


def test_real_image_compressed_files_roundtrip() -> None:
    """Sequential and random reads of real macOS images reconstruct identical files."""
    with gzip.open(absolute_path("_data/case_sensitive.bin.gz"), "rb") as fh:
        volume = APFS(fh).volumes[0]
        fork_names = [
            "compressed-zlib-fork",
            "compressed-lzvn-fork",
            "compressed-lzfse-fork",
        ]
        inline_names = [
            "compressed-zlib-xattr",
            "compressed-lzvn-xattr",
            "compressed-lzfse-xattr",
        ]

        for name in fork_names + inline_names:
            node = volume.get(f"dir/{name}")
            expected = node.open().read()
            assert len(expected) == node.size

            stream = node.open()
            assert stream.read() == expected

            random_stream = node.open()
            offsets = (0, 1, min(0x100, len(expected) - 1), len(expected) - 1)
            for offset in offsets:
                read_length = min(0x1000, len(expected) - offset)
                assert random_stream.readoffset(offset, read_length) == expected[offset : offset + read_length]

            # A read starting at the declared EOF is empty: the logical length is the
            # hard boundary and no extra bytes are invented beyond it.
            assert random_stream.seek(len(expected)) == len(expected)
            assert random_stream.read(1) == b""


def test_inline_multiblock_logical_length_rejected() -> None:
    # The monkeypatched block size makes the declared length span two blocks, while
    # an inline xattr can only ever hold a single block.
    with small_block_size():
        data = sample_data(BLOCK_SIZE + 100)
        decmpfs = decmpfs_header(c_apfs.DECMPFS_ZLIB_ATTR, len(data)) + encode_block(
            c_apfs.DECMPFS_ZLIB_ATTR, data[:BLOCK_SIZE]
        )
        inode = FakeInode(decmpfs, reported_size=len(data))

        with pytest.raises(DecmpfsLogicalLengthError, match="Inline decmpfs"):
            DecmpfsStream(inode)


def test_inode_size_contradicts_header() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE)
        inode = build_inline(c_apfs.DECMPFS_ZLIB_ATTR, data, reported_size=len(data) + 1)

        with pytest.raises(DecmpfsLogicalLengthError, match="Inode-reported size"):
            DecmpfsStream(inode)


def test_inline_payload_length_mismatch_is_not_truncated() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE)
        # A stored zlib block (0x0f prefix) that only holds half the declared block length.
        decmpfs = decmpfs_header(c_apfs.DECMPFS_ZLIB_ATTR, len(data)) + b"\x0f" + data[: BLOCK_SIZE // 2]
        inode = FakeInode(decmpfs, reported_size=len(data))

        stream = DecmpfsStream(inode)
        with pytest.raises(DecmpfsPayloadError, match="logical length requires"):
            stream.read()


def test_inline_corrupt_zlib_payload() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE)
        payload = bytearray(zlib.compress(data))
        payload[5] ^= 0x5A
        decmpfs = decmpfs_header(c_apfs.DECMPFS_ZLIB_ATTR, len(data)) + bytes(payload)
        inode = FakeInode(decmpfs, reported_size=len(data))

        stream = DecmpfsStream(inode)
        with pytest.raises(DecmpfsPayloadError, match="Failed to decompress block"):
            stream.read()


def test_length_table_duplicate_offset() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_ZLIB_RSRC, data, table="length")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        # Point the second entry at the start of the first entry: duplicate/overlapping
        # offsets violate the strictly increasing block table layout.
        first_offset = struct.unpack_from("<I", fork, FORK_DATA_OFFSET + 8)[0]
        struct.pack_into("<I", fork, FORK_DATA_OFFSET + 16, first_offset)

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="overlaps or precedes"):
            DecmpfsStream(inode)


def test_length_table_missing_final_block() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_ZLIB_RSRC, data, table="length")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        struct.pack_into("<I", fork, FORK_DATA_OFFSET + 4, 2)  # Claim two blocks instead of three.

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="describes 2 blocks"):
            DecmpfsStream(inode)


def test_length_table_zero_length_entry() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_ZLIB_RSRC, data, table="length")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        struct.pack_into("<I", fork, FORK_DATA_OFFSET + 12, 0)  # Zero out first entry length.

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="zero length"):
            DecmpfsStream(inode)


def test_offset_table_reversed_offsets() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_LZVN_RSRC, data, table="offset")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        # Swap the second and third offsets so block 1's end precedes its start.
        second = struct.unpack_from("<I", fork, 4)[0]
        third = struct.unpack_from("<I", fork, 8)[0]
        struct.pack_into("<I", fork, 4, third)
        struct.pack_into("<I", fork, 8, second)

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="not strictly increasing"):
            DecmpfsStream(inode)


def test_offset_table_duplicate_offsets() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_LZVN_RSRC, data, table="offset")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        struct.pack_into("<I", fork, 4, struct.unpack_from("<I", fork, 0)[0])

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="not strictly increasing"):
            DecmpfsStream(inode)


def test_offset_table_missing_final_block() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_LZVN_RSRC, data, table="offset")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        # Shrink the trailing end offset so the last block is no longer covered.
        block_offsets = [struct.unpack_from("<I", fork, i * 4)[0] for i in range(4)]
        struct.pack_into("<I", fork, 3 * 4, block_offsets[2])

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="not strictly increasing"):
            DecmpfsStream(inode)


def test_block_table_entry_points_outside_fork() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_LZVN_RSRC, data, table="offset")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        struct.pack_into("<I", fork, 4, len(fork) + 100)

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        with pytest.raises(DecmpfsBlockTableError, match="extends beyond the resource fork"):
            DecmpfsStream(inode)


def test_fork_payload_corruption() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_ZLIB_RSRC, data, table="length")

        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        entry_offset, entry_length = struct.unpack_from("<II", fork, FORK_DATA_OFFSET + 8)
        absolute = FORK_DATA_OFFSET + 4 + entry_offset
        fork[absolute + min(8, entry_length - 1)] ^= 0x5A

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        stream = DecmpfsStream(inode)
        with pytest.raises(DecmpfsPayloadError, match="Failed to decompress block 0"):
            stream.read()


def test_fork_block_decodes_to_wrong_length() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_ZLIB_RSRC, data, table="length")

        # Replace the final block's payload with a stored block of the wrong length; the
        # table stays valid so this is purely a payload/logical-length contradiction.
        fork = bytearray(inode.xattr["com.apple.ResourceFork"].open().read())
        final_entry = FORK_DATA_OFFSET + 8 + 2 * 8
        entry_offset, entry_length = struct.unpack_from("<II", fork, final_entry)
        absolute = FORK_DATA_OFFSET + 4 + entry_offset
        replacement = b"\x0f" + b"\x00" * (entry_length - 1)
        fork[absolute : absolute + entry_length] = replacement

        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", bytes(fork))
        stream = DecmpfsStream(inode)
        with pytest.raises(DecmpfsPayloadError, match="Decompressed block 2"):
            stream.read()


def test_truncated_fork_body_rejected_by_table_bounds() -> None:
    with small_block_size():
        data = sample_data(2 * BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_LZVN_RSRC, data, table="offset")

        # Keep the offset table intact but truncate the body so the final chunk is cut short.
        fork = inode.xattr["com.apple.ResourceFork"].open().read()
        end_offset = struct.unpack_from("<I", fork, 3 * 4)[0]
        truncated = fork[: end_offset - 5]
        inode.xattr["com.apple.ResourceFork"] = FakeXAttr("com.apple.ResourceFork", truncated)

        with pytest.raises(DecmpfsBlockTableError, match="extends beyond the resource fork"):
            DecmpfsStream(inode)


def test_runtime_short_read_is_payload_error() -> None:
    with small_block_size():
        data = sample_data(BLOCK_SIZE + 1)
        inode = build_fork_inode(c_apfs.DECMPFS_LZVN_RSRC, data, table="offset")

        # A fork whose table fits and points inside the buffer, while the backing stream
        # serves one byte fewer than advertised: the short read surfaces as a payload
        # error rather than a truncated, apparently successful result.
        fork = inode.xattr["com.apple.ResourceFork"].open().read()
        end_offset = struct.unpack_from("<I", fork, 2 * 4)[0]

        class ShrinkingStream(BufferedStream):
            def read(self, n: int = -1) -> bytes:
                remaining = end_offset - self.tell()
                return super().read(min(n, max(0, remaining - 1)))

        class ShrinkingXAttr:
            name = "com.apple.ResourceFork"

            def open(self) -> ShrinkingStream:
                return ShrinkingStream(BytesIO(fork), size=len(fork))

        inode.xattr["com.apple.ResourceFork"] = ShrinkingXAttr()
        stream = DecmpfsStream(inode)
        with pytest.raises(DecmpfsPayloadError, match="Short read for block"):
            stream.read()
