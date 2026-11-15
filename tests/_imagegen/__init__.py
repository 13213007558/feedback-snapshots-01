"""Minimal, uncompressed SquashFS 4.0 image writer used only by the test-suite.

The shipped parser only requires a subset of the format, so this builder emits
just enough of a valid little-endian SquashFS 4.0 image (uncompressed metadata
and data blocks) to be parsed by :class:`dissect.squashfs.squashfs.SquashFS`.
It deliberately supports both basic and extended inode headers, hard links
(multiple directory entries sharing one inode) and many-entry ID tables.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.squashfs.c_squashfs import c_squashfs

if TYPE_CHECKING:
    from collections.abc import Sequence

SQUASHFS_MAGIC = 0x73717368
SQUASHFS_METADATA_SIZE = 8192
SQUASHFS_INVALID_BLK = -1
SQUASHFS_COMPRESSED_BIT = 1 << 15
SQUASHFS_COMPRESSED_BIT_BLOCK = 1 << 24

SQUASHFS_DIR_TYPE = 1
SQUASHFS_FILE_TYPE = 2
SQUASHFS_SYMLINK_TYPE = 3
SQUASHFS_FIFO_TYPE = 6
SQUASHFS_LDIR_TYPE = 8
SQUASHFS_LREG_TYPE = 9
SQUASHFS_LSYMLINK_TYPE = 10
SQUASHFS_LFIFO_TYPE = 13


class MetadataWriter:
    """Accumulate metadata into 8192-byte blocks with uncompressed headers."""

    def __init__(self) -> None:
        self._chunks: list[bytes] = []
        self._current = bytearray()

    @property
    def block_index(self) -> int:
        return len(self._chunks)

    @property
    def offset(self) -> int:
        return len(self._current)

    def location(self) -> tuple[int, int]:
        return self.block_index, self.offset

    def _ensure(self, size: int) -> None:
        if self._current and len(self._current) + size > SQUASHFS_METADATA_SIZE:
            header = struct.pack("<H", len(self._current) | SQUASHFS_COMPRESSED_BIT)
            self._chunks.append(header + bytes(self._current))
            self._current = bytearray()

    def write(self, data: bytes) -> tuple[int, int]:
        self._ensure(len(data))
        location = self.location()
        self._current.extend(data)
        return location

    def finish(self) -> tuple[bytes, list[int]]:
        if self._current:
            header = struct.pack("<H", len(self._current) | SQUASHFS_COMPRESSED_BIT)
            self._chunks.append(header + bytes(self._current))
            self._current = bytearray()
        blob = bytearray()
        starts: list[int] = []
        for chunk in self._chunks:
            starts.append(len(blob))
            blob.extend(chunk)
        return bytes(blob), starts


@dataclass
class Node:
    name: str
    mode: int
    uid_index: int
    gid_index: int
    node_type: int
    content: bytes | str | None = None
    children: list["Node"] = field(default_factory=list)
    alias_of: "Node | None" = None
    inode_number: int = 0
    inode_block: int = 0
    inode_offset: int = 0
    dir_block: int = 0
    dir_offset: int = 0

    def is_dir(self) -> bool:
        return self.node_type in (SQUASHFS_DIR_TYPE, SQUASHFS_LDIR_TYPE)

    def is_file(self) -> bool:
        return self.node_type in (SQUASHFS_FILE_TYPE, SQUASHFS_LREG_TYPE)

    def is_symlink(self) -> bool:
        return self.node_type in (SQUASHFS_SYMLINK_TYPE, SQUASHFS_LSYMLINK_TYPE)


def _pack_base(node: Node, inode_number: int) -> bytes:
    return struct.pack(
        "<HHHHII",
        node.node_type,
        node.mode,
        node.uid_index,
        node.gid_index,
        0,
        inode_number,
    )


def _content_of(node: Node) -> bytes:
    if node.content is None:
        return b""
    return node.content if isinstance(node.content, bytes) else node.content.encode()


def _inode_header_bytes(
    node: Node,
    root: Node,
    dir_sizes: dict[int, int],
    file_blocks: dict[int, list[int]],
    file_start: dict[int, int],
    data_base: int = 0,
) -> bytes:
    base = _pack_base(node, node.inode_number)

    if node.is_dir():
        if node.node_type == SQUASHFS_LDIR_TYPE:
            return base + struct.pack(
                "<IIIIHHI",
                1 + len(node.children),
                dir_sizes[node.inode_number],
                0,
                root.inode_number,
                0,
                node.dir_offset,
                0xFFFFFFFF,
            )
        return base + struct.pack(
            "<IIHHI",
            0,
            1 + len(node.children),
            dir_sizes[node.inode_number],
            node.dir_offset,
            root.inode_number,
        )

    if node.is_file():
        content = _content_of(node)
        blocks = file_blocks.get(node.inode_number, [])
        trailing = b"".join(struct.pack("<I", size) for size in blocks)
        if node.node_type == SQUASHFS_LREG_TYPE:
            header = base + struct.pack(
                "<qqqIIII",
                data_base + file_start.get(node.inode_number, 0),
                len(content),
                0,
                1,
                0xFFFFFFFF,
                0,
                0xFFFFFFFF,
            )
        else:
            header = base + struct.pack(
                "<IIII",
                data_base + file_start.get(node.inode_number, 0),
                0xFFFFFFFF,
                0,
                len(content),
            )
        return header + trailing

    if node.is_symlink():
        raw = node.content.encode() if isinstance(node.content, str) else b""
        return base + struct.pack("<II", 1, len(raw)) + raw

    return base


def build_squashfs(root: Node, id_table: Sequence[int]) -> bytes:
    """Serialize ``root`` into a complete SquashFS 4.0 image."""
    all_nodes: list[Node] = []

    def assign(node: Node) -> None:
        if node.alias_of is not None:
            # Hard link: reuse the target inode, this entry gets no own inode.
            node.inode_number = node.alias_of.inode_number
        elif node.inode_number == 0:
            node.inode_number = len(all_nodes) + 1
            all_nodes.append(node)
        for child in node.children:
            assign(child)

    assign(root)

    # File content blocks: each <= block size, uncompressed, stored contiguously.
    data_region = bytearray()
    file_blocks: dict[int, list[int]] = {}
    file_start: dict[int, int] = {}
    for node in all_nodes:
        if not node.is_file():
            continue
        sizes = []
        content = _content_of(node)
        for start in range(0, len(content), SQUASHFS_METADATA_SIZE):
            chunk = content[start : start + SQUASHFS_METADATA_SIZE]
            if not sizes:
                file_start[node.inode_number] = len(data_region)
            data_region.extend(chunk)
            # Bit 24 set marks an uncompressed data block.
            sizes.append(len(chunk) | SQUASHFS_COMPRESSED_BIT_BLOCK)
        if content:
            file_blocks[node.inode_number] = sizes

    # Compute every directory's on-disk size up front (includes the 3-byte
    # "." and ".." entries), so inode headers carry a final value during the
    # location pre-pass below.
    dir_sizes: dict[int, int] = {}
    for node in all_nodes:
        if not node.is_dir():
            continue
        body_len = 12  # one squashfs_dir_header
        for child in node.children:
            body_len += 8 + len(child.name.encode())  # dir_entry (8) + name
        dir_sizes[node.inode_number] = body_len + 3

    # First pass: fix every inode's metadata (block, offset). Directory entries
    # point at these locations, so they must be known before the dir table.
    locator = MetadataWriter()
    for node in all_nodes:
        node.inode_block, node.inode_offset = locator.location()
        locator.write(_inode_header_bytes(node, root, dir_sizes, file_blocks, file_start))

    # Directory table.
    dir_writer = MetadataWriter()
    for node in all_nodes:
        if not node.is_dir():
            continue
        node.dir_block, node.dir_offset = dir_writer.location()
        first_inum = node.children[0].inode_number if node.children else node.inode_number
        if node.children:
            first_target = node.children[0].alias_of or node.children[0]
            start_block = first_target.inode_block
        else:
            start_block = node.inode_block
        body = bytearray(struct.pack("<III", max(len(node.children) - 1, -1), start_block, first_inum))
        for child in node.children:
            target = child.alias_of or child
            name = child.name.encode()
            body.extend(
                struct.pack(
                    "<Hhhh",
                    target.inode_offset,
                    child.inode_number - first_inum,
                    target.node_type,
                    len(name) - 1,
                )
            )
            body.extend(name)
        dir_writer.write(bytes(body))

    dir_blob, _dir_starts = dir_writer.finish()

    # Inode table, now that directory offsets are final. The absolute offset of
    # the data region is deterministic: superblock + inode table + dir table.
    inode_writer = MetadataWriter()
    for node in all_nodes:
        node.inode_block, node.inode_offset = inode_writer.location()
        inode_writer.write(_inode_header_bytes(node, root, dir_sizes, file_blocks, file_start))
    inode_blob, _inode_starts = inode_writer.finish()

    data_region_absolute = 96 + len(inode_blob) + len(dir_blob)
    # Rewrite inode headers with the now-known absolute data region offset. The
    # byte layout is identical, so every inode keeps its (block, offset) location.
    final_writer = MetadataWriter()
    for node in all_nodes:
        node.inode_block, node.inode_offset = final_writer.location()
        final_writer.write(
            _inode_header_bytes(node, root, dir_sizes, file_blocks, file_start, data_region_absolute)
        )
    inode_blob, _inode_starts = final_writer.finish()

    # ID table: uint32 entries grouped into 8192-byte metadata blocks.
    id_writer = MetadataWriter()
    for value in id_table:
        id_writer.write(struct.pack("<I", value))
    id_blob, id_block_relative = id_writer.finish()

    image = bytearray(b"\x00" * 96)
    inode_table_start = len(image)
    image.extend(inode_blob)
    directory_table_start = len(image)
    image.extend(dir_blob)
    image.extend(data_region)
    id_table_start = len(image)
    image.extend(id_blob)
    id_pointer_table = len(image)
    for relative in id_block_relative:
        image.extend(struct.pack("<Q", id_table_start + relative))

    root_inode_ref = (root.inode_block << 16) | root.inode_offset
    superblock = c_squashfs.squashfs_super_block(
        s_magic=SQUASHFS_MAGIC,
        inodes=len(all_nodes),
        mkfs_time=0,
        block_size=SQUASHFS_METADATA_SIZE,
        fragments=0,
        compression=1,
        block_log=12,
        flags=0,
        no_ids=len(id_table),
        s_major=4,
        s_minor=0,
        root_inode=root_inode_ref,
        bytes_used=len(image),
        id_table_start=id_pointer_table,
        xattr_id_table_start=SQUASHFS_INVALID_BLK,
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        fragment_table_start=SQUASHFS_INVALID_BLK,
        lookup_table_start=SQUASHFS_INVALID_BLK,
    ).dumps()
    image[0:96] = superblock
    return bytes(image)
