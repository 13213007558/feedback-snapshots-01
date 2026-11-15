from __future__ import annotations

from io import BytesIO

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import (
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.squashfs import FileStream, SquashFS


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


class _FakeHeader:
    def __init__(self, start_block: int, fragment: int, offset: int, file_size: int):
        self.start_block = start_block
        self.fragment = fragment
        self.offset = offset
        self.file_size = file_size


class _FakeFS:
    """Minimal SquashFS stand-in that serves raw data blocks and decompressed fragment blocks."""

    def __init__(self, blocks: dict[int, tuple[int, bytes]], fragments: dict[int, bytes], block_size: int):
        self.fh = BytesIO()
        self.blocks = blocks
        self.fragments = fragments
        self.block_size = block_size

    def _read_block(self, block: int, length: int) -> tuple[int, bytes]:
        size = length & ~c_squashfs.SQUASHFS_COMPRESSED_BIT_BLOCK
        stored, data = self.blocks[block]
        assert size == stored, (size, stored)
        return block + size, data

    def _read_fragment(self, fragment: int, offset: int, length: int) -> bytes:
        return self.fragments[fragment][offset : offset + length]


class _FakeINode:
    def __init__(self, fs: _FakeFS, block_list: list[tuple[int | None, int]], size: int, header: _FakeHeader):
        self.fs = fs
        self._block_list = block_list
        self.size = size
        self.header = header

    @property
    def block_list(self) -> list[tuple[int | None, int]]:
        return self._block_list

    def open(self) -> FileStream:
        return FileStream(self)


def _fragment_file(
    fragment_data: bytes,
    fragment_offset: int,
    block_data: bytes,
    block_size: int,
    sparse_blocks: set[int] | None = None,
    uncompressed: bool = False,
    fs: _FakeFS | None = None,
    start_block: int = 0x1000,
) -> tuple[_FakeINode, bytes]:
    """Build a fake inode for a file with full blocks followed by a fragment tail."""
    sparse_blocks = sparse_blocks or set()
    num_blocks = len(block_data) // block_size
    blocks: dict[int, tuple[int, bytes]] = {}
    block_list: list[tuple[int | None, int]] = []
    block_start = start_block
    expected = bytearray()

    for index in range(num_blocks):
        chunk = block_data[index * block_size : (index + 1) * block_size]
        if index in sparse_blocks:
            block_list.append((0, 1))
            expected.extend(b"\x00" * block_size)
            continue

        blocks[block_start] = (len(chunk), chunk)
        block_list.append((len(chunk) | (c_squashfs.SQUASHFS_COMPRESSED_BIT_BLOCK if uncompressed else 0), 1))
        expected.extend(chunk)
        block_start += len(chunk)

    tail = block_data[num_blocks * block_size :]
    if tail:
        block_list.append((None, len(tail)))
        expected.extend(fragment_data[fragment_offset : fragment_offset + len(tail)])

    if fs is None:
        fs = _FakeFS(blocks, {0: fragment_data}, block_size)
    else:
        # Share the block and fragment cache with another file
        fs.blocks.update(blocks)
        fs.fragments[0] = fragment_data

    header = _FakeHeader(
        start_block,
        0 if tail else c_squashfs.SQUASHFS_INVALID_FRAG,
        fragment_offset,
        len(expected),
    )
    return _FakeINode(fs, block_list, len(expected), header), bytes(expected)


def _read_offsets(stream: FileStream, content: bytes, offsets: list[int], lengths: list[int]) -> None:
    for offset in offsets:
        for length in lengths:
            stream.seek(offset)
            assert stream.read(length) == content[offset : offset + length], (offset, length)


@pytest.mark.parametrize("block_size", [8, 64, 4096])
def test_squashfs_fragment_random_reads(block_size: int) -> None:
    """Test that seeks and reads into a fragment match a full read for various block sizes."""
    fragment = bytes(range(256)) * 4
    # Two files sharing the decompressed fragment block, each with their own tail.
    first_tail = b"FIRST-TAIL-MARKER!"
    second_tail = b"SECOND-TAIL-MARKER"
    fragment_data = fragment[:block_size] + first_tail + second_tail + fragment[-block_size:]
    first_offset = block_size
    second_offset = block_size + len(first_tail)

    first, first_content = _fragment_file(
        fragment_data, first_offset, bytes([0x41]) * block_size + first_tail, block_size
    )
    second, second_content = _fragment_file(
        fragment_data, second_offset, bytes([0x42]) * block_size + second_tail, block_size
    )

    for inode, content in ((first, first_content), (second, second_content)):
        stream = inode.open()
        assert stream.read() == content

        offsets = sorted(
            {
                0,
                1,
                block_size - 1,
                block_size,
                block_size + 1,
                len(content) - 1,
                len(content),
                len(content) + 1,
            }
        )
        lengths = [0, 1, 2, len(content), block_size, block_size + 1, len(content) * 2]
        _read_offsets(stream, content, offsets, lengths)


def test_squashfs_fragment_small_sequential_chunks() -> None:
    """Test reading a fragment-backed file in the small chunks a firmware reader would use."""
    block_size = 32
    marker = b"<firmware-sensitive-tail>"
    fragment_data = b"\x5a" * block_size + b"<other-file>" + marker + b"\x5a" * block_size
    inode, content = _fragment_file(
        fragment_data, block_size + len(b"<other-file>"), bytes([0x77]) * block_size + marker, block_size
    )

    for chunk_size in (1, 2, 3, 7, block_size - 1, block_size, block_size + 1):
        stream = inode.open()
        result = bytearray()
        while chunk := stream.read(chunk_size):
            result.extend(chunk)
            assert b"<other-file>" not in chunk

        assert bytes(result) == content

        # Seeking back near EOF and reading a large amount must not pick up neighbouring fragment data.
        stream.seek(len(content) - 3)
        assert stream.read(1000) == content[-3:]


def test_squashfs_fragment_shared_interleaved() -> None:
    """Test that two files sharing one fragment cache never return each other's bytes."""
    block_size = 16
    first_marker = b"<marker-one>"
    second_marker = b"<marker-two>"
    fragment_data = (b"\x00" * block_size) + first_marker + b"\xee" * block_size + second_marker
    first, first_content = _fragment_file(
        fragment_data, block_size, bytes([0x11]) * (block_size * 3) + first_marker, block_size
    )
    second, second_content = _fragment_file(
        fragment_data, block_size + len(first_marker), bytes([0x22]) * (block_size * 2) + second_marker, block_size
    )

    first_stream = first.open()
    second_stream = second.open()
    first_pos = second_pos = 0

    for step in range(2000):
        if step % 3 != 1:
            first_pos = (first_pos + 5) % (len(first_content) + 2)
            first_stream.seek(first_pos)
        if step % 4 != 2:
            second_pos = (second_pos + 7) % (len(second_content) + 2)
            second_stream.seek(second_pos)

        first_chunk = first_stream.read(step % 13)
        second_chunk = second_stream.read(step % 11)

        assert first_chunk == first_content[first_pos : first_pos + len(first_chunk)]
        assert second_chunk == second_content[second_pos : second_pos + len(second_chunk)]
        assert second_marker not in first_chunk
        assert first_marker not in second_chunk

        first_pos += len(first_chunk)
        second_pos += len(second_chunk)


@pytest.mark.parametrize(
    "block_size",
    [16, 64, 4096],
)
def test_squashfs_sparse_and_fragment_reads(block_size: int) -> None:
    """Test cross-block reads over sparse blocks into a fragment, including EOF boundaries."""
    marker = b"SPARSE-TAIL"
    fragment_data = b"\xcd" * block_size + marker + b"\xcd" * block_size
    content_blocks = bytes([0x33]) * block_size * 2 + b"\x00" * block_size + bytes([0x44]) * block_size
    inode, content = _fragment_file(fragment_data, block_size, content_blocks + marker, block_size, sparse_blocks={2})

    stream = inode.open()
    assert stream.read() == content

    offsets = [
        0,
        1,
        block_size - 1,
        block_size,
        block_size * 2 - 1,
        block_size * 2,
        block_size * 3 - 1,
        block_size * 3,
        block_size * 4 - 1,
        len(content) - 1,
        len(content),
    ]
    lengths = [0, 1, 3, block_size, block_size * 2, block_size * 3, 10_000]
    _read_offsets(stream, content, offsets, lengths)

    # Requests that start inside a sparse block and cross into the fragment must be zero-filled
    # up to the fragment boundary and then return only this file's fragment bytes.
    stream.seek(block_size * 2 + 1)
    assert stream.read(block_size * 2 - 1 + len(marker)) == (
        (b"\x00" * (block_size - 1)) + bytes([0x44]) * block_size + marker
    )


def test_squashfs_fragment_only_file() -> None:
    """Test a file that consists of only a fragment, including exact EOF reads."""
    block_size = 32
    marker = b"FRAGMENT-ONLY!"
    fragment_data = b"\xff" * block_size + marker + b"\xff" * block_size
    inode, content = _fragment_file(fragment_data, block_size, marker, block_size)
    assert inode.header.fragment != c_squashfs.SQUASHFS_INVALID_FRAG

    stream = inode.open()
    assert stream.read() == content
    assert content == marker

    for offset in range(len(content) + 2):
        for length in range(len(content) + 2):
            stream.seek(offset)
            assert stream.read(length) == content[offset : offset + length]


def test_squashfs_compressed_block_sizes_and_fragment() -> None:
    """Test cross-block reads when stored block sizes differ from the decompressed block size."""
    block_size = 32
    marker = b"<compressed-tail>"
    fragment_data = b"\x33" * block_size + marker + b"\x33" * block_size

    blocks = {
        0x1000: (13, bytes([0x10]) * block_size),
        0x100D: (31, bytes([0x11]) * block_size),
        0x102C: (4, bytes([0x12]) * block_size),
        0x1030: (block_size, bytes([0x13]) * block_size),
    }
    fs = _FakeFS(blocks, {0: fragment_data}, block_size)
    block_list = [(13, 1), (31, 1), (4, 1), (block_size, 1), (None, len(marker))]
    content = b"".join(
        [
            bytes([0x10]) * block_size,
            bytes([0x11]) * block_size,
            bytes([0x12]) * block_size,
            bytes([0x13]) * block_size,
            marker,
        ]
    )
    header = _FakeHeader(0x1000, 0, block_size, len(content))
    inode = _FakeINode(fs, block_list, len(content), header)

    stream = inode.open()
    assert stream.read() == content

    for offset in [
        0,
        1,
        12,
        13,
        block_size - 1,
        block_size,
        2 * block_size,
        3 * block_size,
        len(content) - 1,
        len(content),
    ]:
        for length in (0, 1, 2, block_size, block_size * 2, len(content), 10_000):
            stream.seek(offset)
            assert stream.read(length) == content[offset : offset + length], (offset, length)
            assert stream._read(offset, length) == content[offset : offset + length], (offset, length)

    # Reading the final block directly must be sliced from the start of that block.
    assert stream._read(block_size * 3, block_size) == content[block_size * 3 : block_size * 4]
    assert stream._read(block_size * 4, 100) == marker


def test_squashfs_fixture_fragment_interleaved_reads(gzip_sqfs: BytesIO) -> None:
    """Test that the two real files sharing fragment 0 never leak each other's bytes."""
    sqfs = SquashFS(gzip_sqfs)
    files = [sqfs.get("file-with-xattr"), sqfs.get("small-file")]
    assert {inode.header.fragment for inode in files} == {0}
    assert {inode.header.offset for inode in files} == {0, 9}

    # Both files share the same decompressed fragment block, so interleave raw reads directly to
    # exercise the shared fragment cache without the alignment buffer masking mistakes.
    first_raw = files[0].open()
    second_raw = files[1].open()
    assert first_raw._read(0, 100) == b"hi there\n"
    assert second_raw._read(0, 100) == b"contents\n"
    assert first_raw._read(3, 4) == b"ther"
    assert second_raw._read(3, 4) == b"tent"
    assert first_raw._read(2, 100) == b" there\n"
    assert second_raw._read(2, 100) == b"ntents\n"

    streams = [(inode, inode.open(), inode.open().read()) for inode in files]
    positions = [0, 0]

    for step in range(1000):
        index = step % 2
        inode, stream, content = streams[index]

        if step % 5 != 3:
            positions[index] = (positions[index] + 3) % (len(content) + 2)
            stream.seek(positions[index])

        chunk = stream.read(step % 10)
        assert chunk == content[positions[index] : positions[index] + len(chunk)]

        # Both files are short, so a chunk can never legitimately contain the other file's contents.
        other_content = streams[1 - index][2]
        assert other_content not in chunk

        positions[index] += len(chunk)


def test_squashfs_fragment_run_bounds() -> None:
    """Test that fragment runs are read from the correct offset and bounded by the file size."""
    block_size = 16
    first_marker = b"FIRST-OWN-TAIL"
    second_marker = b"SECOND-OWN-TAIL"
    fragment_data = b"\xaa" * block_size + first_marker + second_marker + b"\xbb" * block_size

    first, first_content = _fragment_file(
        fragment_data, block_size, bytes([0x51]) * block_size + first_marker, block_size
    )
    second, second_content = _fragment_file(
        fragment_data,
        block_size + len(first_marker),
        bytes([0x52]) * block_size + second_marker,
        block_size,
        fs=first.fs,
        start_block=0x2000,
    )
    assert first.fs is second.fs

    first_stream = first.open()
    second_stream = second.open()
    first_fragment = block_size
    second_fragment = block_size

    # Reading at the start of a fragment run must only return the requested number of bytes.
    assert first_stream._read(first_fragment, 3) == first_marker[:3]
    assert second_stream._read(second_fragment, 4) == second_marker[:4]
    assert first_marker not in second_stream._read(second_fragment, len(second_marker))
    assert second_marker not in first_stream._read(first_fragment, len(first_marker))

    # Reading from inside a fragment run must account for the position within the run.
    assert first_stream._read(first_fragment + 2, 5) == first_marker[2:7]
    assert second_stream._read(second_fragment + 1, len(second_marker)) == second_marker[1:] + b""

    # Requests that cross from a full block into the fragment must be sliced consistently.
    assert first_stream._read(first_fragment - 3, 8) == first_content[first_fragment - 3 : first_fragment + 5]
    assert second_stream._read(second_fragment - 2, 10) == second_content[second_fragment - 2 : second_fragment + 8]

    # Requests near or past EOF must never return bytes beyond the file size.
    for stream, content in ((first_stream, first_content), (second_stream, second_content)):
        assert stream._read(len(content) - 2, 100) == content[-2:]
        assert stream._read(len(content), 100) == b""
        assert len(stream._read(0, len(content) + 100)) == len(content)


def test_squashfs_fragment_only_run_bounds() -> None:
    """Test that fragment-only files with a non-zero fragment offset honour the read bounds."""
    block_size = 16
    marker = b"ONLY-THIS-MARKER"
    fragment_data = b"\xcc" * block_size + b"OTHER-MARKER" + marker + b"\xcc" * block_size
    inode, content = _fragment_file(fragment_data, block_size + len(b"OTHER-MARKER"), marker, block_size)

    stream = inode.open()
    assert stream._read(0, len(content)) == content
    assert stream._read(0, 100) == content
    assert stream._read(3, 4) == marker[3:7]
    assert stream._read(len(content) - 2, 100) == marker[-2:]
    assert stream._read(len(content), 100) == b""
    assert b"OTHER-MARKER" not in stream._read(0, 100)
