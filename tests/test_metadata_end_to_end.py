from __future__ import annotations

import zlib
from io import BytesIO

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import MetadataError
from dissect.squashfs.squashfs import SquashFS

COMPRESSED_BIT = c_squashfs.SQUASHFS_COMPRESSED_BIT
SUPERBLOCK_SIZE = len(c_squashfs.squashfs_super_block)
MAX_IMAGE_READS = 64


class RecordingStream(BytesIO):
    """File handle recording every low level read so the physical read count can be asserted."""

    def __init__(self, data: bytes = b""):
        super().__init__(data)
        self.reads: list[tuple[int, int, int]] = []

    @property
    def read_count(self) -> int:
        return len(self.reads)

    def read(self, size: int = -1) -> bytes:
        position = self.tell()
        data = super().read(size)
        self.reads.append((position, size, len(data)))
        return data


def make_frame(payload: bytes, compress: bool = False) -> bytes:
    if compress:
        blob = zlib.compress(payload)
        return len(blob).to_bytes(2, "little") + blob
    return (COMPRESSED_BIT | len(payload)).to_bytes(2, "little") + payload


def split_into_frames(payload: bytes, split_at: int, compress: bool = False) -> bytes:
    return make_frame(payload[:split_at], compress) + make_frame(payload[split_at:], compress)


def make_superblock(*, inode_table_start: int, directory_table_start: int, root_inode: int) -> bytes:
    return c_squashfs.squashfs_super_block(
        s_magic=c_squashfs.SQUASHFS_MAGIC,
        inodes=2,
        mkfs_time=0,
        block_size=4096,
        fragments=0,
        compression=c_squashfs.ZLIB_COMPRESSION,
        block_log=12,
        flags=0,
        no_ids=0,
        s_major=4,
        s_minor=0,
        root_inode=root_inode,
        bytes_used=0,
        id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        xattr_id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        fragment_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        lookup_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
    ).dumps()


def build_inode_payload() -> bytes:
    root = c_squashfs.squashfs_dir_inode_header(
        inode_type=c_squashfs.SQUASHFS_DIR_TYPE,
        mode=0o755,
        uid=0,
        guid=0,
        mtime=0,
        inode_number=1,
        start_block=0,
        nlink=2,
        # 3 bytes squashfs directory overhead + dir header + dir entry + 4 byte name.
        file_size=3 + len(c_squashfs.squashfs_dir_header) + len(c_squashfs.squashfs_dir_entry) + 4,
        offset=0,
        parent_inode=1,
    ).dumps()
    child = c_squashfs.squashfs_reg_inode_header(
        inode_type=c_squashfs.SQUASHFS_FILE_TYPE,
        mode=0o644,
        uid=0,
        guid=0,
        mtime=0,
        inode_number=2,
        start_block=0,
        fragment=c_squashfs.SQUASHFS_INVALID_FRAG,
        offset=0,
        file_size=0,
    ).dumps()
    return root + child


def build_directory_payload() -> bytes:
    header = c_squashfs.squashfs_dir_header(count=0, start_block=0, inode_number=2).dumps()
    entry = c_squashfs.squashfs_dir_entry(
        offset=0,
        inode_number=0,
        type=c_squashfs.SQUASHFS_FILE_TYPE,
        size=3,
    ).dumps()
    return header + entry + b"file"


def build_image(*, inode_split: int, dir_split: int, compress: bool = False) -> RecordingStream:
    inode_frames = split_into_frames(build_inode_payload(), inode_split, compress)
    inode_table_start = SUPERBLOCK_SIZE
    directory_table_start = inode_table_start + len(inode_frames)
    directory_frames = split_into_frames(build_directory_payload(), dir_split, compress)

    image = make_superblock(
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        root_inode=0,
    ) + inode_frames + directory_frames
    return RecordingStream(image)


@pytest.mark.parametrize("compress", [False, True], ids=["raw", "zlib"])
@pytest.mark.parametrize("inode_split", [1, 8, 20, 32])
@pytest.mark.parametrize("dir_split", [1, 7, 12, 20])
def test_cross_frame_inode_and_directory_recovered(compress: bool, inode_split: int, dir_split: int) -> None:
    stream = build_image(inode_split=inode_split, dir_split=dir_split, compress=compress)

    fs = SquashFS(stream)

    assert fs.root.is_dir()
    assert fs.root.inode_number == 1
    entries = list(fs.root.iterdir())
    assert len(entries) == 1
    child = entries[0]
    assert child.name == "file"
    assert child.inode_number == 2
    assert child.is_file()
    # No runaway chain: the complete synthetic image is parsed in a small, fixed number of reads.
    assert stream.read_count <= MAX_IMAGE_READS


def test_cross_frame_directory_header_does_not_fabricate_entry() -> None:
    # Split the directory table so the 12-byte dir header itself straddles a frame, then truncate
    # the second frame. A parser must surface the chain failure rather than assemble a fake header.
    inode_frames = make_frame(build_inode_payload())
    inode_table_start = SUPERBLOCK_SIZE
    directory_table_start = inode_table_start + len(inode_frames)

    directory_payload = build_directory_payload()
    truncated_directory = make_frame(directory_payload[:7])  # header continuation missing
    image = make_superblock(
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        root_inode=0,
    ) + inode_frames + truncated_directory
    stream = RecordingStream(image)

    fs = SquashFS(stream)
    with pytest.raises(MetadataError) as exc_info:
        list(fs.root.iterdir())

    assert exc_info.value.offset >= 0
    assert exc_info.value.block >= directory_table_start
    assert stream.read_count <= MAX_IMAGE_READS


def test_inode_offset_outside_frame_terminates_bounded() -> None:
    # Point the root inode at a logical offset beyond the first frame's decompressed size.
    inode_frames = make_frame(build_inode_payload()[:8])
    inode_table_start = SUPERBLOCK_SIZE
    directory_table_start = inode_table_start + len(inode_frames)
    image = make_superblock(
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        root_inode=0xFFFF,  # block 0, offset 65535
    ) + inode_frames
    stream = RecordingStream(image)

    fs = SquashFS(stream)
    with pytest.raises(MetadataError) as exc_info:
        _ = fs.root.header

    assert exc_info.value.offset == 0xFFFF
    assert stream.read_count <= MAX_IMAGE_READS


def test_empty_metadata_frame_chain_terminates_bounded() -> None:
    # An empty inode frame followed by end of image cannot make progress and must not hang.
    inode_frames = make_frame(b"")
    inode_table_start = SUPERBLOCK_SIZE
    directory_table_start = inode_table_start + len(inode_frames)
    image = make_superblock(
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        root_inode=0,
    ) + inode_frames
    stream = RecordingStream(image)

    fs = SquashFS(stream)
    with pytest.raises(MetadataError):
        _ = fs.root.header

    assert stream.read_count <= MAX_IMAGE_READS
