from __future__ import annotations

import random
import struct
import zlib
from io import BytesIO

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import (
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.squashfs import SquashFS


def _verify_filesystem(sqfs: SquashFS) -> None:
    assert sqfs.root.is_dir()
    assert sorted(sqfs.root.listdir().keys()) == [
        "dir",
        "file-with-xattr",
        "large-file",
        "small-file",
        "symlink-1",
        "symlink-2",
        "symlink-with-xattr",
    ]

    f1 = sqfs.get("small-file")
    assert f1.is_file()
    assert f1.size == 9
    assert str(f1.mtime) == "2022-12-05 18:53:05+00:00"
    assert f1.open().read() == b"contents\n"
    f2 = sqfs.get("large-file")
    assert f2.is_file()
    assert f2.size == 4177920
    assert f2.open().read() == b"".join([bytes([i] * 4096) for i in range(255)]) * 4

    s1 = sqfs.get("symlink-1")
    assert s1.is_symlink()
    assert s1.link == "small-file"
    s2 = sqfs.get("symlink-2")
    assert s2.is_symlink()
    assert s2.link == "dir/file_69"

    d1 = sqfs.get("dir")
    assert d1.is_dir()
    assert d1.size == 1507
    assert len(list(d1.iterdir())) == 100

    assert sqfs.get("dir/file_69").inode_number == s2.link_inode.inode_number

    with pytest.raises(NotAFileError):
        sqfs.get("dir").open()

    with pytest.raises(NotADirectoryError):
        sqfs.get("small-file").listdir()

    with pytest.raises(NotASymlinkError):
        assert sqfs.get("large-file").link


@pytest.mark.parametrize(
    ("sqfs", "compression_id"),
    [
        ("gzip_sqfs", c_squashfs.ZLIB_COMPRESSION),
        ("gzip_opts_sqfs", c_squashfs.ZLIB_COMPRESSION),
        ("lz4_sqfs", c_squashfs.LZ4_COMPRESSION),
        # Whether LZMA works seems to depend on if your machine has been blessed by the compression gods
        # Include the test data for reference material, but don't test against it
        # ("lzma_sqfs", c_squashfs.LZMA_COMPRESSION),
        ("lzo_sqfs", c_squashfs.LZO_COMPRESSION),
        ("xz_sqfs", c_squashfs.XZ_COMPRESSION),
        ("zstd_sqfs", c_squashfs.ZSTD_COMPRESSION),
    ],
)
def test_squashfs(sqfs: str, compression_id: int, request: pytest.FixtureRequest) -> None:
    sqfs = SquashFS(request.getfixturevalue(sqfs))
    assert sqfs.sb.compression == compression_id
    _verify_filesystem(sqfs)


def test_squashfs_unsupported_bigendian_3_0() -> None:
    """Test if we correctly detect a SquashFS 3.0 big-endian filesystem."""
    # Random SquashFS version 3.0 big-endian header found on binwalk GitHub issue tracker.
    buf = bytes.fromhex(
        "73717368000000b60000002042010d364200bc844200339440016800000300006b0400104003004ae64f330000000000"
        "001623000100000000001177ff8e0800000000000e303100000000000e3025000000000000000000000000000e234c00"
    )

    sb = c_squashfs.squashfs_super_block(buf)
    assert sb.s_magic == c_squashfs.SQUASHFS_MAGIC_SWAP
    assert sb.s_major == 0x300

    with pytest.raises(NotImplementedError, match=r"Unsupported squashfs pre-4.0 big-endian filesystem"):
        SquashFS(BytesIO(buf))


BLOCK_SIZE = 4096
MARKER_A = b"<<<SENSITIVE-A-END>>>"
MARKER_B = b"!!!SENSITIVE-B-TAIL!!!"


def _build_squashfs(files: list[tuple[str, bytes]]) -> tuple[bytes, dict[str, int]]:
    """Build a minimal SquashFS 4 image with a shared, gzip compressed fragment block.

    Every file gets regular full blocks (compressed when possible) and its final partial block is placed
    in the shared fragment block. A file named ``sparse`` gets two sparse blocks in the middle.
    Returns the image and a mapping of file name to its offset in the shared fragment block.
    """

    class Builder:
        def __init__(self) -> None:
            self.data = bytearray(b"\0" * 96)
            self.block_lists: dict[str, tuple[int, list[int]]] = {}
            self.fragment_offsets: dict[str, int] = {}
            self.fragment = bytearray()

        def add_data(self) -> None:
            for name, content in files:
                entries = []
                start = None
                for pos in range(0, len(content) // BLOCK_SIZE * BLOCK_SIZE, BLOCK_SIZE):
                    if name == "sparse" and pos in (BLOCK_SIZE, 2 * BLOCK_SIZE):
                        entries.append(0)
                        continue
                    if start is None:
                        start = len(self.data)
                    chunk = content[pos : pos + BLOCK_SIZE]
                    compressed = zlib.compress(chunk)
                    if len(compressed) < len(chunk):
                        self.data += compressed
                        entries.append(len(compressed))
                    else:
                        self.data += chunk
                        entries.append(BLOCK_SIZE | (1 << 24))
                self.block_lists[name] = (start or 0, entries)

        def add_fragment(self) -> None:
            for name, content in files:
                tail = content[len(content) // BLOCK_SIZE * BLOCK_SIZE :]
                self.fragment_offsets[name] = len(self.fragment)
                self.fragment += tail
            payload = zlib.compress(bytes(self.fragment))
            self.fragment_start = len(self.data)
            self.data += payload
            self.fragment_size = len(payload)

    builder = Builder()
    builder.add_data()
    builder.add_fragment()

    def metadata(data: bytes) -> bytes:
        return struct.pack("<H", len(data) | (1 << 15)) + data

    inode_start = len(builder.data)
    inodes = bytearray()
    inodes += struct.pack("<HHHHII", 1, 0o755, 0, 0, 1670000000, 1)
    inodes += struct.pack("<IIHHI", 0, 2, 0, 0, 1)
    inode_offsets: dict[str, int] = {}
    inode_number = 2

    for name, content in files:
        inode_offsets[name] = len(inodes)
        start, entries = builder.block_lists[name]
        inodes += struct.pack("<HHHHII", 9, 0o755, 0, 0, 1670000000, inode_number)
        inodes += struct.pack(
            "<qqqIIII",
            start,
            len(content),
            0,
            1,
            0,
            builder.fragment_offsets[name],
            c_squashfs.SQUASHFS_INVALID_XATTR,
        )
        inodes += b"".join(struct.pack("<I", entry) for entry in entries)
        inode_number += 1

    directory = bytearray(struct.pack("<III", len(files) - 1, 0, 2))
    for index, (name, _) in enumerate(files):
        directory += struct.pack("<HhHH", inode_offsets[name], index, 2, len(name) - 1) + name.encode()
    inodes[24:26] = struct.pack("<H", 3 + len(directory))

    builder.data += metadata(bytes(inodes))
    directory_start = len(builder.data)
    builder.data += metadata(bytes(directory))

    fragment_lookup = len(builder.data)
    builder.data += struct.pack("<Q", fragment_lookup + 8)
    builder.data += metadata(struct.pack("<qII", builder.fragment_start, builder.fragment_size, 0))

    lookup_start = len(builder.data)
    builder.data += struct.pack("<Q", inode_start)

    id_lookup_start = len(builder.data)
    builder.data += struct.pack("<Q", id_lookup_start + 8)
    builder.data += metadata(struct.pack("<I", 0))

    superblock = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        c_squashfs.SQUASHFS_MAGIC,
        len(files) + 1,
        1670000000,
        BLOCK_SIZE,
        1,
        c_squashfs.ZLIB_COMPRESSION,
        12,
        0,
        1,
        4,
        0,
        0,
        len(builder.data),
        id_lookup_start,
        c_squashfs.SQUASHFS_INVALID,
        inode_start,
        directory_start,
        fragment_lookup,
        lookup_start,
    )
    builder.data[: len(superblock)] = superblock
    return bytes(builder.data), builder.fragment_offsets


def _assert_random_reads(fs: SquashFS, name: str, expected: bytes, seed: int, align: int) -> None:
    rng = random.Random(seed)
    stream = fs.get(name).open()
    stream.align = align

    # Full read is the reference
    assert stream.read() == expected
    stream.seek(0)

    for _ in range(250):
        offset = rng.randrange(0, len(expected) + BLOCK_SIZE)
        length = rng.choice(
            [-1, 0, 1, 2, 3, 7, BLOCK_SIZE // 4 - 1, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, len(expected)]
        )

        stream.seek(offset)
        result = stream.read(length)

        start = min(offset, len(expected))
        slice_ = expected[start:] if length == -1 else expected[start : start + length]
        assert result == slice_, f"{name} mismatch at offset {offset} length {length}"


@pytest.mark.parametrize("align", [1, 3, BLOCK_SIZE])
def test_squashfs_random_read(align: int) -> None:
    """Random reads must match the full read, regardless of read alignment or crossing boundaries."""
    expected_a = bytes(range(256)) * (BLOCK_SIZE // 256) + b"A-mid-" + MARKER_A
    expected_b = b"short" + MARKER_B
    expected_multi = bytes((i * 7 + 3) & 0xFF for i in range(BLOCK_SIZE * 2 + 333))

    image, fragment_offsets = _build_squashfs(
        [
            ("file-a", expected_a),
            ("file-b", expected_b),
            ("multi", expected_multi),
        ]
    )

    # Both files share the same fragment block
    assert fragment_offsets["file-a"] == 0
    assert fragment_offsets["file-b"] == len(expected_a) - BLOCK_SIZE

    fs = SquashFS(BytesIO(image))
    for index, (name, expected) in enumerate(
        [("file-a", expected_a), ("file-b", expected_b), ("multi", expected_multi)]
    ):
        _assert_random_reads(fs, name, expected, seed=align * 17 + index, align=align)


def test_squashfs_shared_fragment_no_bleed() -> None:
    """Interleaved reads of files sharing a fragment block must never leak data between files."""
    expected_a = bytes(range(256)) * (BLOCK_SIZE // 256) + b"A-mid-" + MARKER_A
    expected_b = b"short" + MARKER_B

    image, _ = _build_squashfs([("file-a", expected_a), ("file-b", expected_b)])
    fs = SquashFS(BytesIO(image))

    stream_a = fs.get("file-a").open()
    stream_b = fs.get("file-b").open()
    stream_a.align = 1
    stream_b.align = 1

    marker_a_start = len(expected_a) - len(MARKER_A)
    for iteration in range(200):
        # Alternate between seeking near the end of file A and reading file B from the start
        offset_a = marker_a_start + (iteration % 3)
        stream_a.seek(offset_a)
        result_a = stream_a.read(len(MARKER_A))
        stream_b.seek(0)
        result_b = stream_b.read(len(expected_b))

        assert result_a == expected_a[offset_a : offset_a + len(MARKER_A)]
        assert result_b == expected_b
        assert MARKER_B not in result_a
        assert MARKER_A not in result_b

        # Reads beyond EOF must not return bytes from the shared fragment block
        stream_a.seek(len(expected_a))
        assert stream_a.read(len(MARKER_B)) == b""
        stream_a.seek(len(expected_a))
        assert stream_a.read(-1) == b""


def test_squashfs_sparse_and_fragment() -> None:
    """Sparse blocks and a trailing fragment must read correctly at any offset."""
    expected = b"S" * BLOCK_SIZE + b"\0" * (BLOCK_SIZE * 2) + b"E" * 17
    image, _ = _build_squashfs([("sparse", expected)])
    fs = SquashFS(BytesIO(image))

    stream = fs.get("sparse").open()
    assert stream.read() == expected

    stream.align = 1
    offsets = [0, 1, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, BLOCK_SIZE * 3 - 2, BLOCK_SIZE * 3, len(expected) - 1]
    for offset in offsets:
        for length in [1, 2, 3, BLOCK_SIZE, BLOCK_SIZE + 1, 2 * BLOCK_SIZE, len(expected)]:
            stream.seek(offset)
            assert stream.read(length) == expected[offset : offset + length]

    # A file that only consists of a fragment
    short = b"only-a-fragment" + MARKER_B
    image, _ = _build_squashfs([("short", short)])
    fs = SquashFS(BytesIO(image))
    stream = fs.get("short").open()
    assert stream.read() == short

    stream.align = 1
    for offset in range(len(short) + 1):
        for length in [1, 2, 3, len(short) - 1, len(short) + 1, -1]:
            stream.seek(offset)
            expected_slice = short[offset:] if length == -1 else short[offset : offset + length]
            assert stream.read(length) == expected_slice
