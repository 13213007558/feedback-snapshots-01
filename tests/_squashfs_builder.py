"""Build small deterministic SquashFS 4.0 images for identity and permission tests.

Metadata is written uncompressed so the generated images are easy to inspect.
The builder exercises basic and extended inodes, id-table blocks that span
multiple metadata pages, changed id indexes, bad indexes, hard links, and an
optional truncated id-pointer array.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from io import BytesIO

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.squashfs import SquashFS

SUPERBLOCK_SIZE = len(c_squashfs.squashfs_super_block)
METADATA_SIZE = c_squashfs.SQUASHFS_METADATA_SIZE
INVALID_FRAGMENT = 0xFFFFFFFF
INVALID_XATTR = 0xFFFFFFFF


def metadata_block(data: bytes) -> bytes:
    """Encode one uncompressed metadata block."""
    if not 0 < len(data) <= METADATA_SIZE:
        raise ValueError(f"metadata payload must be 1..{METADATA_SIZE} bytes, got {len(data)}")
    return struct.pack("<H", len(data) | c_squashfs.SQUASHFS_COMPRESSED_BIT) + data


def basic_reg(mode: int, uid: int, gid: int, inode_number: int) -> bytes:
    """Encode a basic regular-file inode header."""
    return struct.pack("<HHHHIIIIII", 2, mode, uid, gid, 0, inode_number, 0, INVALID_FRAGMENT, 0, 0)


def extended_reg(mode: int, uid: int, gid: int, inode_number: int, nlink: int = 1) -> bytes:
    """Encode an extended regular-file inode header."""
    return struct.pack(
        "<HHHHIIqqqIIII",
        9,
        mode,
        uid,
        gid,
        0,
        inode_number,
        0,
        0,
        0,
        nlink,
        INVALID_FRAGMENT,
        0,
        INVALID_XATTR,
    )


def basic_dir(mode: int, uid: int, gid: int, inode_number: int, start_block: int, size: int, offset: int = 0) -> bytes:
    """Encode a basic directory inode header."""
    return struct.pack("<HHHHIIIIHHI", 1, mode, uid, gid, 0, inode_number, start_block, 1, size, offset, inode_number)


def extended_dir(
    mode: int, uid: int, gid: int, inode_number: int, start_block: int, size: int, offset: int = 0
) -> bytes:
    """Encode an extended directory inode header."""
    return struct.pack(
        "<HHHHIIIIIIHHI",
        8,
        mode,
        uid,
        gid,
        0,
        inode_number,
        1,
        size,
        start_block,
        inode_number,
        0,
        offset,
        INVALID_XATTR,
    )


def extended_symlink(mode: int, uid: int, gid: int, inode_number: int, target: bytes = b"target") -> bytes:
    """Encode an extended symlink inode header."""
    return struct.pack("<HHHHIIII", 10, mode, uid, gid, 0, inode_number, 1, len(target)) + target


def directory_data(entries: list[tuple[str, int, int, int, int]]) -> bytes:
    """Encode a single directory header followed by all of its entries.

    Each entry is ``(name, inode_block, inode_offset, inode_type, inode_number)``.
    """
    out = bytearray()
    out += struct.pack("<III", len(entries) - 1, 0, 0)
    for name, _inode_block, inode_offset, inode_type, inode_number in entries:
        encoded = name.encode()
        out += struct.pack("<HhHH", inode_offset, inode_number, inode_type, len(encoded) - 1)
        out += encoded
    return bytes(out)


@dataclass(frozen=True)
class ImageLayout:
    """One generated image plus offsets needed by assertions."""

    image: bytes
    inode_offsets: dict[str, int]
    id_table_start: int
    id_pointer_count: int
    id_metadata_starts: tuple[int, ...]
    id_count: int

    def open(self) -> SquashFS:
        """Parse this image into a SquashFS instance."""
        return SquashFS(BytesIO(self.image))


def build_identity_image(*, truncate_id_pointers: bool = False, id_count: int = 3000) -> ImageLayout:
    """Build a deterministic image exercising the identity-table edge cases.

    Index 0 resolves to numeric uid 1000 even though the inode field says 0.
    Index 2500 lives in the second id-table metadata block.  Index 65535 is
    outside the table.  Numeric root (0) is a valid identity at index 2.
    """
    ids = [1000, 4242, 0] + [5000 + i for i in range(3, id_count)]
    ids[2500] = 7500
    ids[id_count - 1] = 65534

    id_payload = b"".join(struct.pack("<I", value) for value in ids)
    id_chunks = [id_payload[i : i + METADATA_SIZE] for i in range(0, len(id_payload), METADATA_SIZE)]

    # Only hard-a has storage: hard-b is a second directory entry for the same
    # (block, offset) pair, which is how SquashFS represents hard links.
    inode_sizes = {
        "index-vs-uid": 32,
        "cross-page-setgid": 56,
        "bad-index-setuid": 56,
        "root-setuid": 56,
        "world-write": 32,
        "sticky-dir": 32,
        "hard-a": 56,
        "same-index-a": 32,
        "same-index-b": 32,
        "boundary-gid": 56,
        "setuid-symlink": 30,
        "nested": 40,
        "nested-child": 56,
    }
    inode_offsets: dict[str, int] = {}
    offset = 0
    for name, size in inode_sizes.items():
        inode_offsets[name] = offset
        offset += size
    inode_offsets["hard-b"] = inode_offsets["hard-a"]
    root_offset = offset

    inode_numbers = {name: number for number, name in enumerate(inode_sizes, start=2)}
    inode_numbers["hard-b"] = inode_numbers["hard-a"]

    inode_types = {
        "index-vs-uid": 2,
        "cross-page-setgid": 9,
        "bad-index-setuid": 9,
        "root-setuid": 9,
        "world-write": 2,
        "sticky-dir": 1,
        "hard-a": 9,
        "hard-b": 9,
        "same-index-a": 2,
        "same-index-b": 2,
        "boundary-gid": 9,
        "setuid-symlink": 10,
        "nested": 8,
        "nested-child": 9,
    }

    root_names = [name for name in inode_sizes if name != "nested-child"]
    root_names.append("hard-b")
    root_dir = directory_data(
        [(name, 0, inode_offsets[name], inode_types[name], inode_numbers[name]) for name in root_names]
    )
    nested_dir = directory_data([("nested-child", 0, inode_offsets["nested-child"], 9, inode_numbers["nested-child"])])

    inode_parts = [
        basic_reg(0o4755, 0, 0, inode_numbers["index-vs-uid"]),
        # uid index 1 -> numeric uid 4242; gid index 2500 -> numeric gid 7500.
        extended_reg(0o2755, 1, 2500, inode_numbers["cross-page-setgid"]),
        # uid index 65535 is outside the 3000-entry id table.
        extended_reg(0o4755, 0xFFFF, 2, inode_numbers["bad-index-setuid"]),
        extended_reg(0o4755, 2, 2, inode_numbers["root-setuid"]),
        basic_reg(0o666, 1, 1, inode_numbers["world-write"]),
        basic_dir(0o1777, 2, 2, inode_numbers["sticky-dir"], 0, 3),
        # nlink says two paths; hard-a and hard-b both point at this inode.
        extended_reg(0o4755, 1, 1, inode_numbers["hard-a"], nlink=2),
        basic_reg(0o4755, 1, 1, inode_numbers["same-index-a"]),
        basic_reg(0o4755, 1, 1, inode_numbers["same-index-b"]),
        # Index 2047 is the final entry that fits in the first 8192-byte id block.
        extended_reg(0o2755, 0, 2047, inode_numbers["boundary-gid"]),
        # Linux ignores permission bits on symlink inodes.
        extended_symlink(0o4777, 1, 1, inode_numbers["setuid-symlink"]),
        extended_dir(0o2775, 0, 0, inode_numbers["nested"], 0, len(nested_dir) + 3, len(root_dir)),
        extended_reg(0o4755, 2, 2, inode_numbers["nested-child"]),
        basic_dir(0o755, 0, 0, 1, 0, len(root_dir) + 3),
    ]
    inode_data = b"".join(inode_parts)

    inode_block = SUPERBLOCK_SIZE
    inode_table = metadata_block(inode_data)
    directory_block = inode_block + len(inode_table)
    directory_table = metadata_block(root_dir + nested_dir)

    id_metadata_starts = []
    id_metadata = bytearray()
    position = directory_block + len(directory_table)
    for chunk in id_chunks:
        id_metadata_starts.append(position)
        encoded = metadata_block(chunk)
        id_metadata += encoded
        position += len(encoded)

    id_table_start = position
    id_pointers = b"".join(struct.pack("<Q", start) for start in id_metadata_starts)
    total_size = id_table_start + len(id_pointers)

    superblock = struct.pack(
        "<IIIIIHHHHHHQqqqqqqq",
        c_squashfs.SQUASHFS_MAGIC,
        len(inode_sizes),
        0,
        4096,
        0,
        c_squashfs.ZLIB_COMPRESSION,
        12,
        0,
        id_count,
        4,
        0,
        root_offset,
        total_size,
        id_table_start,
        -1,
        inode_block,
        directory_block,
        -1,
        -1,
    )
    image = superblock + inode_table + directory_table + bytes(id_metadata) + id_pointers
    if len(image) != total_size:
        raise AssertionError(f"generated image size {len(image)} != {total_size}")

    if truncate_id_pointers:
        image = image[:id_table_start]

    return ImageLayout(
        image=image,
        inode_offsets={"root": root_offset, **inode_offsets},
        id_table_start=id_table_start,
        id_pointer_count=len(id_metadata_starts),
        id_metadata_starts=tuple(id_metadata_starts),
        id_count=id_count,
    )


def build_cross_block_id_image() -> bytes:
    """Build a tiny image whose id entry starts on one metadata page and ends on the next.

    Real ``mksquashfs`` output normally packs id entries without crossing an
    8192-byte metadata block.  The on-disk format still allows a block chain to
    continue, and the reader must not stall or truncate when an entry starts at
    the last bytes of one block.  This image deliberately shortens the first id
    metadata block by two bytes so id index 2047 crosses the boundary.
    """
    ids = [1000 + index for index in range(2048)]
    ids[2047] = 5555
    payload = b"".join(struct.pack("<I", value) for value in ids)
    chunks = [payload[:8190], payload[8190:]]
    if len(chunks[0]) != 8190 or len(chunks[1]) != 2:
        raise AssertionError("unexpected id payload layout")

    inode_table = metadata_block(basic_dir(0o755, 0, 0, 1, 0, 3))
    inode_block = SUPERBLOCK_SIZE
    directory_block = inode_block + len(inode_table)
    directory_table = metadata_block(b"\x00\x00\x00")

    position = directory_block + len(directory_table)
    starts = []
    id_metadata = bytearray()
    for chunk in chunks:
        starts.append(position)
        encoded = metadata_block(chunk)
        id_metadata += encoded
        position += len(encoded)

    id_table_start = position
    id_pointers = b"".join(struct.pack("<Q", start) for start in starts)
    total_size = id_table_start + len(id_pointers)

    superblock = struct.pack(
        "<IIIIIHHHHHHQqqqqqqq",
        c_squashfs.SQUASHFS_MAGIC,
        1,
        0,
        4096,
        0,
        c_squashfs.ZLIB_COMPRESSION,
        12,
        0,
        len(ids),
        4,
        0,
        0,
        total_size,
        id_table_start,
        -1,
        inode_block,
        directory_block,
        -1,
        -1,
    )
    return superblock + inode_table + directory_table + bytes(id_metadata) + id_pointers
