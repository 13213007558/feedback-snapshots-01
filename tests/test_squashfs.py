from __future__ import annotations

import struct
import zlib
from io import BytesIO

import pytest

from dissect.squashfs import CompressionError, compression
from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import (
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.squashfs import SquashFS

from .conftest import absolute_path


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
METADATA_SIZE = c_squashfs.SQUASHFS_METADATA_SIZE
INVALID_FRAG = c_squashfs.SQUASHFS_INVALID_FRAG
UNCOMPRESSED_DATA_FLAG = c_squashfs.SQUASHFS_COMPRESSED_BIT_BLOCK
UNCOMPRESSED_META_FLAG = c_squashfs.SQUASHFS_COMPRESSED_BIT


def _metadata_block(payload: bytes, compress: bool) -> bytes:
    if compress:
        stored = zlib.compress(payload)
        assert len(stored) <= METADATA_SIZE
        header = len(stored)
    else:
        stored = payload
        assert len(stored) <= METADATA_SIZE
        header = len(stored) | UNCOMPRESSED_META_FLAG
    return struct.pack("<H", header) + stored


def _build_squashfs(
    files: list[tuple[str, bytes]],
    *,
    compress_data: bool,
    compress_meta: bool,
    block_size: int = BLOCK_SIZE,
) -> bytes:
    """Build a minimal SquashFS 4 image with one regular file per entry.

    The image deliberately allows both compressed and uncompressed file data and
    metadata blocks, so the same logical content can be read through either
    representation. No fragment block is used.
    """
    image = bytearray(b"\x00" * len(c_squashfs.squashfs_super_block))
    blocks: dict[str, tuple[int, list[int]]] = {}

    for name, content in files:
        start = len(image)
        entries = []
        for pos in range(0, len(content), block_size):
            chunk = content[pos : pos + block_size]
            if compress_data:
                stored = zlib.compress(chunk)
                entries.append(len(stored))
            else:
                stored = chunk
                entries.append(len(chunk) | UNCOMPRESSED_DATA_FLAG)
            image += stored
        blocks[name] = (start, entries)

    inodes = bytearray(32)
    directory = bytearray(c_squashfs.squashfs_dir_header(count=len(files) - 1, start_block=0, inode_number=2).dumps())
    inode_offsets: dict[str, int] = {}

    for index, (name, content) in enumerate(files):
        inode_offsets[name] = len(inodes)
        start, entries = blocks[name]
        inodes += c_squashfs.squashfs_reg_inode_header(
            inode_type=c_squashfs.SQUASHFS_FILE_TYPE,
            mode=0o644,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=index + 2,
            start_block=start,
            fragment=INVALID_FRAG,
            offset=0,
            file_size=len(content),
        ).dumps()
        for entry in entries:
            inodes += struct.pack("<I", entry)

        encoded_name = name.encode()
        directory += c_squashfs.squashfs_dir_entry(
            offset=inode_offsets[name],
            inode_number=index,
            type=c_squashfs.SQUASHFS_FILE_TYPE,
            size=len(encoded_name) - 1,
        ).dumps()
        directory += encoded_name

    root_inode = c_squashfs.squashfs_dir_inode_header(
        inode_type=c_squashfs.SQUASHFS_DIR_TYPE,
        mode=0o755,
        uid=0,
        guid=0,
        mtime=0,
        inode_number=1,
        start_block=0,
        nlink=2,
        file_size=len(directory) + 3,
        offset=0,
        parent_inode=1,
    ).dumps()
    assert len(root_inode) == 32
    inodes[0:32] = root_inode

    inode_table_start = len(image)
    image += _metadata_block(bytes(inodes), compress_meta)

    directory_table_start = len(image)
    image += _metadata_block(bytes(directory), compress_meta)

    id_metadata_start = len(image)
    image += _metadata_block(struct.pack("<I", 0), compress_meta)

    id_table_start = len(image)
    image += struct.pack("<Q", id_metadata_start)

    superblock = c_squashfs.squashfs_super_block(
        s_magic=c_squashfs.SQUASHFS_MAGIC,
        inodes=len(files) + 1,
        mkfs_time=0,
        block_size=block_size,
        fragments=0,
        compression=c_squashfs.ZLIB_COMPRESSION,
        block_log=block_size.bit_length() - 1,
        flags=0,
        no_ids=1,
        s_major=4,
        s_minor=0,
        root_inode=0,
        bytes_used=len(image),
        id_table_start=id_table_start,
        xattr_id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        fragment_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        lookup_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
    ).dumps()
    image[0 : len(superblock)] = superblock

    return bytes(image)


SQFS_CONTENT = [
    ("alpha", b"A" * BLOCK_SIZE * 2 + b"tail" * 100),
    ("beta", b"hello squashfs\n" * 400),
    ("small", b"contents\n"),
]


@pytest.mark.parametrize("compress_data", [False, True])
@pytest.mark.parametrize("compress_meta", [False, True])
def test_squashfs_compressed_and_uncompressed_blocks(compress_data: bool, compress_meta: bool) -> None:
    """The same logical content must read identically from compressed and stored blocks."""
    image = _build_squashfs(SQFS_CONTENT, compress_data=compress_data, compress_meta=compress_meta)
    sqfs = SquashFS(BytesIO(image))

    assert sorted(sqfs.root.listdir()) == ["alpha", "beta", "small"]

    for name, content in SQFS_CONTENT:
        inode = sqfs.get(name)
        assert inode.is_file()
        assert inode.size == len(content)

        stream = inode.open()
        assert stream.read() == content

        stream.seek(0)
        for offset in (0, 1, BLOCK_SIZE - 1, BLOCK_SIZE, len(content) - 1, len(content)):
            stream.seek(offset)
            assert stream.read() == content[offset:]


def test_squashfs_metadata_and_data_bounds_differ() -> None:
    """Metadata blocks use the fixed 8192-byte bound; file data uses the block size."""
    block_size = METADATA_SIZE * 2
    content = bytes(range(256)) * (METADATA_SIZE // 256)

    image = _build_squashfs(
        [("meta-sized", content)],
        compress_data=False,
        compress_meta=False,
        block_size=block_size,
    )
    sqfs = SquashFS(BytesIO(image))

    # A 8192-byte uncompressed data block is exactly the metadata bound but is
    # still valid as file data because the filesystem block size is larger.
    assert len(content) == METADATA_SIZE
    inode = sqfs.get("meta-sized")
    assert inode.size == METADATA_SIZE
    assert inode.open().read() == content

    # A metadata block is bounded at 8192 bytes regardless of block_size.
    with pytest.raises(CompressionError, match="exceeds 8192"):
        sqfs._compression.decompress(zlib.compress(content + b"X"), METADATA_SIZE)


def test_squashfs_compressed_data_block_exceeding_block_size_is_rejected() -> None:
    """A decompressed data block larger than block_size must fail, not be sliced."""
    payload = b"B" * (BLOCK_SIZE + 1)

    backend = compression.NativeZlib()
    with pytest.raises(CompressionError, match="exceeds"):
        backend.decompress(zlib.compress(payload), BLOCK_SIZE)


@pytest.mark.parametrize(
    "backend",
    [
        compression.NativeZlib(),
        compression.NativeLZMA(),
        compression.NativeXZ(),
        compression.NativeZSTD(),
        compression.AvailableLZO(),
        compression.AvailableLZ4(),
    ],
    ids=["zlib", "lzma", "xz", "zstd", "lzo", "lz4"],
)
def test_compression_block_contract_trailing_stream(backend: compression.Compression) -> None:
    """Every backend rejects a valid block followed by a second compressed stream."""
    if isinstance(backend, (compression.AvailableLZO, compression.AvailableLZ4)):
        # Raw LZO/LZ4 have no frame header; use a real fixture block so the test
        # exercises the same stored representation as a firmware image.
        path = "_data/lzo.sqfs" if isinstance(backend, compression.AvailableLZO) else "_data/lz4.sqfs"
        raw = absolute_path(path).read_bytes()
        sqfs = SquashFS(BytesIO(raw))

        # Extract the first compressed metadata block.
        block_start = sqfs.sb.inode_table_start
        header = struct.unpack_from("<H", raw, block_start)[0]
        size = header & ~UNCOMPRESSED_META_FLAG
        data = raw[block_start + 2 : block_start + 2 + size]
        expected = METADATA_SIZE
    else:
        payload = bytes(range(256)) * 32
        if isinstance(backend, compression.NativeZlib):
            data = zlib.compress(payload)
        elif isinstance(backend, compression.NativeZSTD):
            data = backend._module.compress(payload)
        elif isinstance(backend, compression.NativeLZMA):
            # LZMA compression is not always available/repeatable on every
            # platform, but decompression of the stored LZMA format is.
            data = backend._module.compress(payload, format=backend._module.FORMAT_ALONE)
        else:
            data = backend._module.compress(payload, format=backend._module.FORMAT_XZ)
        expected = len(payload)

    assert backend.decompress(data, expected)

    # A second, identical compressed stream appended to a valid block must be
    # rejected by every backend. A raw LZO/LZ4 block has no end marker, so the
    # adapter relies on the consumed-length/structure checks rather than on the
    # decoder's own EOF signal.
    with pytest.raises(CompressionError):
        backend.decompress(data + data, expected)


def test_squashfs_appended_compressed_stream_is_rejected_by_block_layer() -> None:
    """A valid stored block followed by a second stream must fail during the read.

    The file stream never sees the appended bytes: the error is raised when the
    block is decompressed. This guards against masking the extra input by slicing
    the final result to the file size.
    """
    content = b"payload" * 100
    stored = zlib.compress(content)
    appended = stored + zlib.compress(b"second stream")

    def make_fs(data: bytes) -> SquashFS:
        fs = SquashFS.__new__(SquashFS)
        fs.fh = BytesIO(data)
        fs.block_size = BLOCK_SIZE
        fs._compression = compression.NativeZlib()
        return fs

    # Metadata block layout: 16-bit length header followed by the stored bytes.
    metadata = struct.pack("<H", len(appended)) + appended
    with pytest.raises(CompressionError, match="Trailing data"):
        make_fs(metadata)._read_block(0)

    # Data block layout: the length (including the compressed flag) is passed in.
    with pytest.raises(CompressionError, match="Trailing data"):
        make_fs(appended)._read_block(0, len(appended))
