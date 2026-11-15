from __future__ import annotations

import io
import struct
import zlib
from typing import TYPE_CHECKING

from dissect.util.compression import lzbitmap, lzfse, lzvn
from dissect.util.stream import AlignedStream

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import Error
from dissect.apfs.util import cmp_fext, cmp_fs_extent

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS, INode

_SUPPORTED_DECMPFS_ALGORITHMS = frozenset(
    (
        c_apfs.DECMPFS_ZLIB_ATTR,
        c_apfs.DECMPFS_ZLIB_RSRC,
        c_apfs.DECMPFS_LZVN_ATTR,
        c_apfs.DECMPFS_LZVN_RSRC,
        c_apfs.DECMPFS_PLAIN_ATTR,
        c_apfs.DECMPFS_PLAIN_RSRC,
        c_apfs.DECMPFS_LZFSE_ATTR,
        c_apfs.DECMPFS_LZFSE_RSRC,
        c_apfs.DECMPFS_LZBITMAP_ATTR,
        c_apfs.DECMPFS_LZBITMAP_RSRC,
    )
)


class FileStream(AlignedStream):
    """APFS file data stream.

    Args:
        volume: APFS volume.
        oid: The object ID of the file.
        size: The size of the file in bytes.
    """

    def __init__(self, volume: FS, oid: int, size: int):
        self.volume = volume
        self.oid = oid

        if self.volume.is_sealed:
            self._cursor = Cursor(self.volume.fext_tree)
        else:
            self._cursor = self.volume.cursor()

        super().__init__(size, self.volume.container.block_size)

    def _lookup(self, offset: int) -> tuple[int, int, int, int]:
        if self.volume.is_sealed:
            return self._lookup_sealed(offset)

        return self._lookup_normal(offset)

    def _lookup_normal(self, offset: int) -> tuple[int, int, int, int]:
        self._cursor.reset().search(
            (
                (self.oid, c_apfs.APFS_TYPE.FILE_EXTENT.value),
                offset,
            ),
            cmp=cmp_fs_extent,
        )

        key = c_apfs.j_file_extent_key(self._cursor.key())
        oid = key.hdr.obj_id_and_type & c_apfs.OBJ_ID_MASK
        type = (key.hdr.obj_id_and_type & c_apfs.OBJ_TYPE_MASK) >> c_apfs.OBJ_TYPE_SHIFT

        if oid != self.oid or type != c_apfs.APFS_TYPE.FILE_EXTENT or key.logical_addr > offset:
            raise Error(f"Could not find file extent for {self.oid} at offset {offset}")

        value = c_apfs.j_file_extent_val(self._cursor.value())

        return (
            key.logical_addr,
            value.phys_block_num,
            value.len_and_flags & c_apfs.J_FILE_EXTENT_LEN_MASK,
            value.crypto_id,
        )

    def _lookup_sealed(self, offset: int) -> tuple[int, int, int, int]:
        self._cursor.reset().search((self.oid, offset), cmp=cmp_fext)

        key = c_apfs.fext_tree_key(self._cursor.key())
        if key.private_id != self.oid or key.logical_addr > offset:
            raise Error(f"Could not find file extent for {self.oid} at offset {offset}")

        value = c_apfs.fext_tree_val(self._cursor.value())

        return (
            key.logical_addr,
            value.phys_block_num,
            value.len_and_flags & c_apfs.J_FILE_EXTENT_LEN_MASK,
            0,
        )

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        while length:
            logical_address, physical_address, extent_length, crypto_id = self._lookup(offset)

            offset_in_extent = offset - logical_address
            if offset_in_extent >= extent_length:
                raise Error(
                    f"Offset {offset:#x} is out of bounds for extent ({logical_address:#x}, {extent_length:#x})"
                )

            block_in_extent = offset_in_extent // self.align
            read_length = min(extent_length - offset_in_extent, length)
            block = self.volume.container._read_block(physical_address + block_in_extent, read_length // self.align)

            if self.volume.is_encrypted:
                if not self.volume._cipher:
                    raise Error("Volume is encrypted, unlock it first")

                if self.volume.is_onekey:
                    sector = (crypto_id + block_in_extent) * self.volume.container.sectors_per_block
                    block = self.volume._cipher.decrypt(block, sector)
                else:
                    raise Error("Multi-key encryption is not supported yet")

            result.append(block)
            offset += read_length
            length -= read_length

        return b"".join(result)


class DecmpfsStream(AlignedStream):
    """APFS decompressed file data stream.

    The on-disk layout (block table and declared sizes) is validated while opening and
    reading. Corrupt files are never silently truncated: a mismatch in the block table,
    a compressed payload or the declared logical length raises an :class:`Error`.

    Args:
        inode: The inode of the compressed file.
    """

    def __init__(self, inode: INode):
        self.inode = inode

        if (attr := inode.xattr.get("com.apple.decmpfs")) is None:
            raise Error(f"{inode} is marked as compressed, but has no decmpfs xattr")

        buf = attr.open()
        self._header = c_apfs.decmpfs_header(buf)
        if self._header.magic.to_bytes(4, "big") != c_apfs.DECMPFS_MAGIC:
            raise Error(
                "Invalid decmpfs magic "
                f"(expected {c_apfs.DECMPFS_MAGIC!r}, got {self._header.magic.to_bytes(4, 'big')!r})"
            )

        self._fork = None
        self._entries = []
        self._raw_offsets = []

        if self._header.algorithm & 1 == 0:
            # In resource fork
            if (fork := inode.xattr.get("com.apple.ResourceFork")) is None:
                raise Error(f"{inode} is missing resource fork for decmpfs")

            self._fork = fork.open()
            self._entries = self._parse_fork_entries()
        else:
            # In attribute
            self._data = buf.read()

        self._validate_block_table()
        self._validate_inode_size()

        super().__init__(self._header.uncompressed_size, align=c_apfs.DECMPFS_BLOCK_SIZE)

    def _parse_fork_entries(self) -> list[tuple[int, int]]:
        """Parse the (offset, length) entries describing the compressed blocks in the fork."""
        if self._header.algorithm in (c_apfs.DECMPFS_ZLIB_RSRC, c_apfs.DECMPFS_PLAIN_RSRC):
            # Classic resource fork: a big-endian header points at a data area containing a
            # little-endian table offset, entry count and (offset, length) pairs.
            fork_data_offset, _, _, _ = struct.unpack(">IIII", self._fork.read(16))

            self._fork.seek(fork_data_offset)
            _, entry_count = struct.unpack("<II", self._fork.read(8))
            entries = []
            for _ in range(entry_count):
                offset, length = struct.unpack("<II", self._fork.read(8))
                entries.append((fork_data_offset + 4 + offset, length))
        else:
            # Raw fork: an array of uint32 offsets, one per block plus a trailing end offset.
            expected_offsets = (
                (self._header.uncompressed_size + (c_apfs.DECMPFS_BLOCK_SIZE - 1)) // c_apfs.DECMPFS_BLOCK_SIZE
            ) + 1
            raw = self._fork.read(4 * expected_offsets)
            # A physically truncated table yields a short offset list; _validate_block_table reports
            # the missing blocks instead of silently reading past the end of the table.
            self._raw_offsets = list(struct.unpack(f"<{len(raw) // 4}I", raw))
            entries = [
                (self._raw_offsets[i], self._raw_offsets[i + 1] - self._raw_offsets[i])
                for i in range(len(self._raw_offsets) - 1)
            ]

        return entries

    @property
    def _block_count(self) -> int:
        """The number of compressed blocks required for the declared uncompressed size."""
        return (self._header.uncompressed_size + c_apfs.DECMPFS_BLOCK_SIZE - 1) // c_apfs.DECMPFS_BLOCK_SIZE

    def _validate_block_table(self) -> None:
        """Validate that the block table is consistent with the declared logical length."""
        expected_blocks = self._block_count

        if self._fork is not None:
            fork_size = self._fork.seek(0, io.SEEK_END)
            if len(self._entries) != expected_blocks:
                raise Error(
                    f"Corrupt decmpfs block table: expected {expected_blocks} block entries for "
                    f"{self._header.uncompressed_size} uncompressed bytes, got {len(self._entries)}"
                )

            if self._raw_offsets:
                # Validate the raw offset array directly: entries are derived from consecutive
                # offsets, so a duplicate or reversed offset must be caught before lengths are derived.
                for block in range(1, len(self._raw_offsets)):
                    current = self._raw_offsets[block]
                    previous = self._raw_offsets[block - 1]
                    if current == previous:
                        raise Error(
                            f"Corrupt decmpfs block table: duplicate block offset at block {block} "
                            f"(offset {current:#x})"
                        )
                    if current < previous:
                        raise Error(
                            f"Corrupt decmpfs block table: out-of-order block offset at block {block} "
                            f"(offset {current:#x}, previous offset {previous:#x})"
                        )

            previous_offset = -1
            previous_end = 0
            for block, (offset, length) in enumerate(self._entries):
                if length <= 0:
                    # A non-positive length means two consecutive offsets are equal or reversed.
                    relation = "duplicate" if length == 0 else "out-of-order"
                    raise Error(
                        f"Corrupt decmpfs block table: {relation} block offset at block {block} "
                        f"(offset {offset:#x}, length {length})"
                    )

                if offset <= previous_offset:
                    relation = "duplicate" if offset == previous_offset else "out-of-order"
                    raise Error(
                        f"Corrupt decmpfs block table: {relation} block offset at block {block} "
                        f"(offset {offset:#x}, previous offset {previous_offset:#x})"
                    )

                if offset < previous_end:
                    raise Error(
                        f"Corrupt decmpfs block table: overlapping block offset at block {block} "
                        f"(offset {offset:#x}, previous block ends at {previous_end:#x})"
                    )

                if offset + length > fork_size:
                    raise Error(
                        f"Corrupt decmpfs block table: block {block} (offset {offset:#x}, length {length}) "
                        f"falls outside the resource fork of {fork_size} bytes"
                    )

                previous_offset = offset
                previous_end = offset + length
        else:
            # Inline xattr data holds a single chunk covering the whole uncompressed stream.
            if expected_blocks > 1:
                raise Error(
                    f"Corrupt decmpfs block table: inline xattr cannot store {expected_blocks} blocks "
                    f"for {self._header.uncompressed_size} uncompressed bytes"
                )

    def _validate_inode_size(self) -> None:
        """Validate that the inode size agrees with the decmpfs declared logical length."""
        inode = self.inode.inode
        if (
            inode.internal_flags & c_apfs.INODE.HAS_UNCOMPRESSED_SIZE
            and inode.uncompressed_size != self._header.uncompressed_size
        ):
            raise Error(
                "Corrupt decmpfs logical length: inode reports "
                f"{inode.uncompressed_size} bytes but decmpfs header declares "
                f"{self._header.uncompressed_size} bytes"
            )

    def _decompress_chunk(self, chunk: bytes, block: int) -> bytes:
        """Decompress a single compressed block, validating the payload and its logical length."""
        algorithm = self._header.algorithm

        if algorithm not in _SUPPORTED_DECMPFS_ALGORITHMS:
            raise Error(f"Unsupported decmpfs algorithm {algorithm}")

        if algorithm in (c_apfs.DECMPFS_ZLIB_ATTR, c_apfs.DECMPFS_ZLIB_RSRC) and not (
            chunk[0] == 0x78 or chunk[0] & 0x0F == 0x0F
        ):
            raise Error(f"Invalid zlib chunk: {chunk[0]:#x}")

        try:
            if algorithm in (c_apfs.DECMPFS_ZLIB_ATTR, c_apfs.DECMPFS_ZLIB_RSRC):
                chunk = zlib.decompress(chunk) if chunk[0] == 0x78 and len(chunk) >= 2 else chunk[1:]
            elif algorithm in (c_apfs.DECMPFS_LZVN_ATTR, c_apfs.DECMPFS_LZVN_RSRC):
                chunk = chunk[1:] if chunk[0] == 0x06 else lzvn.decompress(chunk)
            elif algorithm in (c_apfs.DECMPFS_PLAIN_ATTR, c_apfs.DECMPFS_PLAIN_RSRC):
                chunk = chunk[1:]
            elif algorithm in (c_apfs.DECMPFS_LZFSE_ATTR, c_apfs.DECMPFS_LZFSE_RSRC):
                chunk = chunk[1:] if chunk[0] == 0xFF else lzfse.decompress(chunk)
            else:
                chunk = chunk[1:] if chunk[0] & 0x0F == 0x0F else lzbitmap.decompress(chunk)
        except Error:
            raise
        except Exception as e:
            raise Error(f"Corrupt decmpfs compressed payload: failed to decompress block {block}: {e}") from e

        expected_length = min(
            c_apfs.DECMPFS_BLOCK_SIZE,
            self._header.uncompressed_size - block * c_apfs.DECMPFS_BLOCK_SIZE,
        )
        if expected_length < 0 or len(chunk) != expected_length:
            raise Error(
                "Corrupt decmpfs logical length: "
                f"block {block} decompressed to {len(chunk)} bytes, expected {expected_length} bytes "
                f"for a declared size of {self._header.uncompressed_size} bytes"
            )

        return chunk

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        block = offset // self.align
        while length:
            if self._fork is not None:
                if block >= len(self._entries):
                    raise Error(
                        f"Corrupt decmpfs block table: missing entry for block {block} "
                        f"(only {len(self._entries)} entries present)"
                    )

                entry_offset, entry_length = self._entries[block]

                self._fork.seek(entry_offset)
                chunk = self._fork.read(entry_length)
                if len(chunk) != entry_length:
                    raise Error(
                        f"Corrupt decmpfs compressed payload: short read of block {block} "
                        f"(expected {entry_length} bytes, got {len(chunk)})"
                    )
            else:
                chunk = self._data

            result.append(self._decompress_chunk(chunk, block))

            offset += self.align
            length -= min(self.align, length)
            block += 1

        return b"".join(result)
