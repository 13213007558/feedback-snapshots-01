from __future__ import annotations

import struct
import zlib
from typing import TYPE_CHECKING

from dissect.util.compression import lzbitmap, lzfse, lzvn
from dissect.util.stream import AlignedStream

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import (
    DecmpfsBlockTableError,
    DecmpfsLogicalLengthError,
    DecmpfsPayloadError,
    Error,
)
from dissect.apfs.util import cmp_fext, cmp_fs_extent

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS, INode


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

    The compressed layout is validated while parsing so that a corrupt block table,
    payload or declared logical length raises a specific error instead of silently
    returning truncated data.

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

        if self._header.uncompressed_size == 0:
            raise DecmpfsLogicalLengthError("Decmpfs header declares a zero uncompressed size")

        # The inode-reported size and the decmpfs header must describe the same file.
        if (
            c_apfs.INODE.HAS_UNCOMPRESSED_SIZE in inode.internal_flags
            and inode.inode.uncompressed_size != self._header.uncompressed_size
        ):
            raise DecmpfsLogicalLengthError(
                "Inode-reported size "
                f"{inode.inode.uncompressed_size} does not match decmpfs logical length "
                f"{self._header.uncompressed_size}"
            )

        self._fork = None
        self._entries = []
        self._block_count = self._blocks_for_size(self._header.uncompressed_size)

        if self._header.algorithm & 1 == 0:
            # In resource fork
            if (fork := inode.xattr.get("com.apple.ResourceFork")) is None:
                raise Error(f"{inode} is missing resource fork for decmpfs")

            self._fork = fork.open()
            self._parse_fork()
        else:
            # In attribute: the xattr holds a single chunk, so it can only cover one block.
            if self._block_count > 1:
                raise DecmpfsLogicalLengthError(
                    f"Inline decmpfs data cannot span {self._block_count} blocks "
                    f"(logical length {self._header.uncompressed_size} exceeds block size "
                    f"{c_apfs.DECMPFS_BLOCK_SIZE})"
                )
            self._data = buf.read()
            if not self._data:
                raise DecmpfsPayloadError("Inline decmpfs xattr contains no compressed payload")

        super().__init__(self._header.uncompressed_size, align=c_apfs.DECMPFS_BLOCK_SIZE)

    @staticmethod
    def _blocks_for_size(size: int) -> int:
        return (size + (c_apfs.DECMPFS_BLOCK_SIZE - 1)) // c_apfs.DECMPFS_BLOCK_SIZE

    def _parse_fork(self) -> None:
        """Parse and validate the block table stored in the resource fork."""
        if self._header.algorithm in (c_apfs.DECMPFS_ZLIB_RSRC, c_apfs.DECMPFS_PLAIN_RSRC):
            # Classic length table: data_offset, mgmt_offset, data_size, mgmt_size,
            # followed by a table of (offset, length) pairs relative to data_offset + 4.
            self._fork_data_offset, _, _, _ = struct.unpack(">IIII", self._fork.read(16))

            table_offset = self._fork_data_offset
            self._fork.seek(table_offset)
            table_head = self._fork.read(8)
            if len(table_head) != 8:
                raise DecmpfsBlockTableError(
                    f"Resource fork is too small for a block table at offset {table_offset:#x}"
                )
            entry_count = struct.unpack("<II", table_head)[1]
            if entry_count != self._block_count:
                raise DecmpfsBlockTableError(
                    f"Block table describes {entry_count} blocks but the logical length requires "
                    f"{self._block_count} blocks"
                )

            previous_end = self._fork_data_offset + 4
            for index in range(entry_count):
                pair = self._fork.read(8)
                if len(pair) != 8:
                    raise DecmpfsBlockTableError(f"Block table is missing entry {index}")
                offset, length = struct.unpack("<II", pair)
                if length == 0:
                    raise DecmpfsBlockTableError(f"Block table entry {index} has a zero length")
                entry_offset = self._fork_data_offset + 4 + offset
                if entry_offset < previous_end:
                    raise DecmpfsBlockTableError(
                        f"Block table entry {index} at offset {entry_offset:#x} overlaps or precedes "
                        f"the previous block ending at {previous_end:#x}"
                    )
                self._validate_entry(index, entry_offset, length)
                self._entries.append((entry_offset, length))
                previous_end = entry_offset + length
        else:
            # Raw uint32 offset table: one offset per block plus a trailing end offset.
            table_size = (self._block_count + 1) * 4
            if self._fork.size < table_size:
                raise DecmpfsBlockTableError(
                    f"Resource fork of {self._fork.size} bytes cannot hold an offset table of "
                    f"{self._block_count + 1} entries"
                )

            offsets = c_apfs.uint32_t[self._block_count + 1](self._fork)
            for index in range(self._block_count):
                entry_offset = offsets[index]
                length = offsets[index + 1] - entry_offset
                if length <= 0:
                    raise DecmpfsBlockTableError(
                        f"Offset table entry {index} is not strictly increasing "
                        f"(offsets {offsets[index]:#x} -> {offsets[index + 1]:#x})"
                    )
                self._validate_entry(index, entry_offset, length)
                self._entries.append((entry_offset, length))

    def _validate_entry(self, index: int, entry_offset: int, length: int) -> None:
        """Check that a block table entry lies fully inside the resource fork."""
        if entry_offset < 0 or entry_offset + length > self._fork.size:
            raise DecmpfsBlockTableError(
                f"Block table entry {index} ({entry_offset:#x}, {length} bytes) extends beyond the "
                f"resource fork ({self._fork.size} bytes)"
            )

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        algorithm = self._header.algorithm
        block = offset // self.align
        while length:
            if self._fork is not None:
                entry_offset, entry_length = self._entries[block]

                self._fork.seek(entry_offset)
                chunk = self._fork.read(entry_length)
                if len(chunk) != entry_length:
                    raise DecmpfsPayloadError(
                        f"Short read for block {block}: expected {entry_length} compressed bytes, "
                        f"got {len(chunk)}"
                    )
            else:
                chunk = self._data

            expected_length = min(self.align, self._header.uncompressed_size - block * self.align)
            if expected_length <= 0:
                raise DecmpfsLogicalLengthError(
                    f"Block {block} lies outside the declared logical length "
                    f"{self._header.uncompressed_size}"
                )

            chunk = self._decompress_block(algorithm, block, chunk)
            if len(chunk) != expected_length:
                # A normal short final block is expected; any other mismatch means the payload
                # does not reconstruct the logical length and must not be truncated into a result.
                raise DecmpfsPayloadError(
                    f"Decompressed block {block} is {len(chunk)} bytes but the logical length "
                    f"requires {expected_length} bytes"
                )

            result.append(chunk)

            offset += self.align
            length -= min(self.align, length)
            block += 1

        return b"".join(result)

    @staticmethod
    def _decompress_block(algorithm: int, block: int, chunk: bytes) -> bytes:
        if not chunk:
            raise DecmpfsPayloadError(f"Block {block} has an empty compressed payload")

        try:
            if algorithm in (c_apfs.DECMPFS_ZLIB_ATTR, c_apfs.DECMPFS_ZLIB_RSRC):
                if chunk[0] == 0x78 and len(chunk) >= 2:
                    return zlib.decompress(chunk)
                if chunk[0] & 0x0F == 0x0F:
                    return chunk[1:]
                raise DecmpfsPayloadError(f"Invalid zlib chunk marker in block {block}: {chunk[0]:#x}")

            if algorithm in (c_apfs.DECMPFS_LZVN_ATTR, c_apfs.DECMPFS_LZVN_RSRC):
                return chunk[1:] if chunk[0] == 0x06 else lzvn.decompress(chunk)

            if algorithm in (c_apfs.DECMPFS_PLAIN_ATTR, c_apfs.DECMPFS_PLAIN_RSRC):
                return chunk[1:]

            if algorithm in (c_apfs.DECMPFS_LZFSE_ATTR, c_apfs.DECMPFS_LZFSE_RSRC):
                return chunk[1:] if chunk[0] == 0xFF else lzfse.decompress(chunk)

            if algorithm in (c_apfs.DECMPFS_LZBITMAP_ATTR, c_apfs.DECMPFS_LZBITMAP_RSRC):
                return chunk[1:] if chunk[0] & 0x0F == 0x0F else lzbitmap.decompress(chunk)
        except DecmpfsPayloadError:
            raise
        except (ValueError, zlib.error) as e:
            raise DecmpfsPayloadError(f"Failed to decompress block {block} ({algorithm}): {e}") from e

        raise Error(f"Unsupported decmpfs algorithm {algorithm}")
