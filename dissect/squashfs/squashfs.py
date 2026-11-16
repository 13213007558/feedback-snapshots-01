# References:
# - https://dr-emann.github.io/squashfs/
# - Linux kernel

from __future__ import annotations

import stat
import struct
from bisect import bisect_right
from functools import cache, cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.util import ts
from dissect.util.stream import RunlistStream

from dissect.squashfs import compression
from dissect.squashfs.c_squashfs import INODE_STRUCT_MAP, TYPE_MAP, c_squashfs
from dissect.squashfs.capability import analyze_file_capabilities
from dissect.squashfs.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.xattr import (
    XATTR_NAME_MAX,
    XATTR_REF_BLOCK_SHIFT,
    XATTR_REF_OFFSET_MASK,
    XATTR_SIZE_MAX,
    XattrError,
    decode_xattr_entry,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.squashfs.capability import FileCapabilityReport
    from dissect.squashfs.xattr import Xattr


class SquashFS:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        sb = c_squashfs.squashfs_super_block(fh)
        if sb.s_magic != c_squashfs.SQUASHFS_MAGIC:
            if sb.s_magic == c_squashfs.SQUASHFS_MAGIC_SWAP:
                raise NotImplementedError("Unsupported squashfs pre-4.0 big-endian filesystem")

            raise ValueError("Invalid squashfs superblock")

        # Only support squashfs 4.x for now
        if sb.s_major != 4:
            raise NotImplementedError("Unsupported squashfs version")

        self.sb = sb
        self.mkfs_time = ts.from_unix(self.sb.mkfs_time)
        self.block_size = self.sb.block_size
        self.block_log = self.sb.block_log
        self.flags = self.sb.flags
        self.major = self.sb.s_major
        self.minor = self.sb.s_minor
        self.size = self.sb.bytes_used

        self._read_block = lru_cache(1024)(self._read_block)
        self._lookup_id = lru_cache(1024)(self._lookup_id)
        self._lookup_inode = lru_cache(1024)(self._lookup_inode)
        self._lookup_fragment = lru_cache(1024)(self._lookup_fragment)
        self._lookup_xattr_id = lru_cache(1024)(self._lookup_xattr_id)

        self._compression_options = None
        if (self.sb.flags >> c_squashfs.SQUASHFS_COMP_OPT) & 1:
            self._compression_options = self._read_block(len(self.sb))[1]

        self._compression = compression.initialize(self.sb.compression, self._compression_options)

        self.id_table = self._read_table(self.sb.id_table_start, self.sb.no_ids, 4)
        self.lookup_table = self._read_table(self.sb.lookup_table_start, self.sb.inodes, 8)
        self.fragment_table = self._read_table(
            self.sb.fragment_table_start, self.sb.fragments, len(c_squashfs.squashfs_fragment_entry)
        )
        self._init_xattr_table()

        self.root = self.inode(self.sb.root_inode >> 16, self.sb.root_inode & 0xFFFF, name="/")

    def inode(
        self,
        block: int,
        offset: int,
        name: str | None = None,
        type: int | None = None,
        inode_number: int | None = None,
        parent: INode | None = None,
    ) -> INode:
        # squashfs inode numbers consist of a block number and offset in that block
        return INode(self, block, offset, name, type, inode_number, parent)

    def get(self, path: str | int, node: INode | None = None) -> INode:
        if isinstance(path, int):
            return self.inode(path >> 16, path & 0xFFFF)

        node = node or self.root

        parts = path.split("/")

        for part_num, part in enumerate(parts):
            if not part:
                continue

            if part == ".":
                continue

            if part == "..":
                node = node.parent or node
                continue

            while node.is_symlink() and part_num < len(parts):
                node = node.link_inode

            for entry in node.iterdir():
                if entry.name == part:
                    node = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return node

    def _read_table(self, offset: int, count: int, entry_size: int) -> list[int]:
        if not count or offset == c_squashfs.SQUASHFS_INVALID_BLK:
            return []

        num_bytes = count * entry_size
        num_blocks = (num_bytes + c_squashfs.SQUASHFS_METADATA_SIZE - 1) // c_squashfs.SQUASHFS_METADATA_SIZE

        self.fh.seek(offset)
        return c_squashfs.uint64[num_blocks](self.fh)

    def _init_xattr_table(self) -> None:
        """Read the xattr ID table index, if the filesystem has one."""
        self.xattr_table = None
        self.xattr_table_start = 0
        self.xattr_ids = 0
        self.xattr_id_table = []

        if self.sb.xattr_id_table_start == c_squashfs.SQUASHFS_INVALID_BLK:
            return

        table_header_size = len(c_squashfs.squashfs_xattr_table)

        if self.sb.xattr_id_table_start < 0 or self.sb.xattr_id_table_start + table_header_size > self.size:
            raise XattrError(f"xattr ID table offset out of bounds: {self.sb.xattr_id_table_start}")

        self.fh.seek(self.sb.xattr_id_table_start)
        table = c_squashfs.squashfs_xattr_table(self.fh)

        if not table.xattr_ids:
            return

        if table.xattr_table_start < 0 or table.xattr_table_start >= self.size:
            raise XattrError(f"xattr table offset out of bounds: {table.xattr_table_start}")

        num_bytes = table.xattr_ids * len(c_squashfs.squashfs_xattr_id)
        num_blocks = (num_bytes + c_squashfs.SQUASHFS_METADATA_SIZE - 1) // c_squashfs.SQUASHFS_METADATA_SIZE

        index_start = self.sb.xattr_id_table_start + len(c_squashfs.squashfs_xattr_table)
        if index_start + num_blocks * 8 > self.size:
            raise XattrError("xattr ID table index exceeds filesystem size")

        self.fh.seek(index_start)
        self.xattr_table = table
        self.xattr_table_start = table.xattr_table_start
        self.xattr_ids = table.xattr_ids
        self.xattr_id_table = list(c_squashfs.uint64[num_blocks](self.fh))

        for block in self.xattr_id_table:
            if block < 0 or block >= self.size:
                raise XattrError(f"xattr ID table block out of bounds: {block:#x}")

    def _xattr_ref(self, block: int, offset: int) -> int:
        """Encode an absolute metadata position as a SquashFS xattr reference."""
        return ((block - self.xattr_table_start) << XATTR_REF_BLOCK_SHIFT) | offset

    def _xattr_block(self, ref: int) -> tuple[int, int]:
        """Resolve an xattr reference to an absolute metadata block and offset."""
        block = self.xattr_table_start + (ref >> XATTR_REF_BLOCK_SHIFT)
        offset = ref & XATTR_REF_OFFSET_MASK

        if block < 0 or block >= self.size:
            raise XattrError(f"xattr reference out of bounds: {ref:#x}")

        return block, offset

    def _lookup_xattr_id(self, index: int) -> tuple[int, int, int]:
        """Look up an xattr ID.

        Args:
            index: Index into the xattr ID table.

        Returns:
            A tuple of ``(xattr_ref, count, size)``.

        Raises:
            IndexError: If ``index`` is out of bounds.
            XattrError: If the xattr ID table entry cannot be read.
        """
        if index < 0 or index >= self.xattr_ids:
            raise IndexError(f"xattr ID out of bounds (0, {self.xattr_ids}): {index}")

        entry_offset = index * len(c_squashfs.squashfs_xattr_id)
        block, offset = divmod(entry_offset, c_squashfs.SQUASHFS_METADATA_SIZE)

        if block >= len(self.xattr_id_table):
            raise XattrError(f"xattr ID table entry out of bounds: {index}")

        _, _, data = self._read_metadata_exact(
            self.xattr_id_table[block],
            offset,
            len(c_squashfs.squashfs_xattr_id),
        )
        return struct.unpack("<QII", data)

    def xattr(self, xattr_id: int) -> list[Xattr]:
        """Alias for :meth:`xattrs`."""
        return self.xattrs(xattr_id)

    def xattrs(self, xattr_id: int) -> list[Xattr]:
        """Read all extended attributes for an xattr ID.

        The xattr ID identifies a list of attribute records in the shared xattr metadata
        table. Values can either be stored inline or in the shared out-of-line value area.
        In both cases the complete value is resolved and retained together with its origin.

        Args:
            xattr_id: The xattr ID from an inode header.

        Returns:
            The decoded attributes, in on-disk order.

        Raises:
            XattrError: If the xattr record or its value is malformed or out of bounds.
        """
        xattr_ref, count, size = self._lookup_xattr_id(xattr_id)

        if count == 0:
            return []

        if size == 0 or count > size:
            raise XattrError(f"invalid xattr record count {count} for size {size}")

        block, offset = self._xattr_block(xattr_ref)
        result = []

        for _ in range(count):
            entry_ref = self._xattr_ref(block, offset)
            block, offset, data = self._read_metadata_exact(
                block,
                offset,
                len(c_squashfs.squashfs_xattr_entry),
            )
            entry = c_squashfs.squashfs_xattr_entry(data)

            if entry.size > XATTR_NAME_MAX:
                raise XattrError(f"xattr name too long: {entry.size}")

            block, offset, name = self._read_metadata_exact(block, offset, entry.size)

            value_header_ref = self._xattr_ref(block, offset)
            block, offset, data = self._read_metadata_exact(
                block,
                offset,
                len(c_squashfs.squashfs_xattr_val),
            )
            value_header = c_squashfs.squashfs_xattr_val(data)

            if entry.type & c_squashfs.SQUASHFS_XATTR_VALUE_OOL:
                block, offset, data = self._read_metadata_exact(block, offset, 8)
                ool_ref = struct.unpack("<Q", data)[0]

                ool_block, ool_offset = self._xattr_block(ool_ref)
                ool_block, ool_offset, data = self._read_metadata_exact(
                    ool_block,
                    ool_offset,
                    len(c_squashfs.squashfs_xattr_val),
                )
                shared_header = c_squashfs.squashfs_xattr_val(data)
                value_size = shared_header.vsize
                value_ref = self._xattr_ref(ool_block, ool_offset)

                if value_size > XATTR_SIZE_MAX:
                    raise XattrError(f"xattr value too large: {value_size}")

                _, _, value = self._read_metadata_exact(ool_block, ool_offset, value_size)
            else:
                value_size = value_header.vsize
                ool_ref = None
                value_ref = value_header_ref

                if value_size > XATTR_SIZE_MAX:
                    raise XattrError(f"xattr value too large: {value_size}")

                block, offset, value = self._read_metadata_exact(block, offset, value_size)

            result.append(
                decode_xattr_entry(
                    entry.type,
                    name,
                    value,
                    xattr_id=xattr_id,
                    entry_ref=entry_ref,
                    value_ref=value_ref,
                    ool_ref=ool_ref,
                )
            )

        return result

    def _read_metadata_exact(self, block: int, offset: int, length: int) -> tuple[int, int, bytes]:
        """Read metadata and return the position directly after the requested bytes."""
        if length == 0:
            return block, offset, b""

        result = []
        remaining = length
        while remaining:
            next_block, data = self._read_block(block)

            if offset > len(data):
                raise XattrError(f"metadata offset {offset} outside block {block:#x} of size {len(data)}")

            available = len(data) - offset
            if available <= remaining:
                result.append(data[offset:])
                remaining -= available
                block = next_block
                offset = 0
            else:
                result.append(data[offset : offset + remaining])
                offset += remaining
                remaining = 0

        data = b"".join(result)
        if len(data) != length:
            raise XattrError(f"truncated metadata read at block {block:#x} offset {offset}: {length} bytes expected")

        return block, offset, data

    def _read_metadata(self, block: int, offset: int, length: int) -> tuple[int, int, bytes]:
        result = []
        while length:
            next_block, data = self._read_block(block)
            remaining = len(data) - offset

            if remaining <= length:
                result.append(data[offset:])
                length -= remaining
                block = next_block
                offset = 0
            else:
                result.append(data[offset : offset + length])
                offset += length
                break

        return block, offset, b"".join(result)

    def _read_block(self, block: int, length: int | None = None) -> tuple[int, bytes]:
        if length is not None:
            # Data block
            compressed = length & c_squashfs.SQUASHFS_COMPRESSED_BIT_BLOCK == 0
            length = length & ~c_squashfs.SQUASHFS_COMPRESSED_BIT_BLOCK
        else:
            # Metadata block
            self.fh.seek(block)
            length = c_squashfs.uint16(self.fh)

            compressed = length & c_squashfs.SQUASHFS_COMPRESSED_BIT == 0
            length = length & ~c_squashfs.SQUASHFS_COMPRESSED_BIT
            block += 2

        self.fh.seek(block)
        data = self.fh.read(length)

        if not compressed:
            return block + length, data

        if self._compression is None:
            raise RuntimeError(f"Tried to read compressed block {block} but no compression initialized")

        return block + length, self._compression.decompress(data, self.block_size)

    def _read_fragment(self, fragment: int, offset: int, length: int) -> bytes:
        entry = self._lookup_fragment(fragment)
        _, data = self._read_block(entry.start_block, entry.size)
        return data[offset : offset + length]

    def _lookup_id(self, id: int) -> int:
        block, offset = divmod(id * 4, c_squashfs.SQUASHFS_METADATA_SIZE)
        _, _, data = self._read_metadata(self.id_table[block], offset, 4)
        return struct.unpack("<I", data)[0]

    def _lookup_inode(self, inode_number: int) -> INode:
        if inode_number <= 0 or inode_number > self.sb.inodes:
            raise IndexError(f"inode number out of bounds (1, {self.sb.inodes}): {inode_number}")
        block, offset = divmod((inode_number - 1) * 8, c_squashfs.SQUASHFS_METADATA_SIZE)
        _, _, data = self._read_metadata(self.lookup_table[block], offset, 8)
        return self.get(struct.unpack("<Q", data)[0])

    def _lookup_fragment(self, fragment: int) -> c_squashfs.squashfs_fragment_entry:
        fragment_offset = fragment * len(c_squashfs.squashfs_fragment_entry)
        block, offset = divmod(fragment_offset, c_squashfs.SQUASHFS_METADATA_SIZE)

        _, _, data = self._read_metadata(self.fragment_table[block], offset, len(c_squashfs.squashfs_fragment_entry))
        return c_squashfs.squashfs_fragment_entry(data)

    def iter_inodes(self) -> Iterator[INode]:
        for inum in range(1, self.sb.inodes + 1):
            yield self._lookup_inode(inum)

    def iter_file_capabilities(
        self,
        namespace_rootid: int | None = None,
        *,
        rootid: int | None = None,
    ) -> Iterator[tuple[INode, FileCapabilityReport]]:
        """Iterate over all files that have a ``security.capability`` attribute.

        The tree is walked from the root. Each entry is visited once, and no file
        contents are read or executed.

        Args:
            namespace_rootid: Root UID of the target user namespace, as seen from the
                initial user namespace.
            rootid: Alias for ``namespace_rootid``.

        Yields:
            Pairs of ``(inode, report)``.
        """
        if rootid is not None:
            if namespace_rootid is not None and namespace_rootid != rootid:
                raise ValueError("conflicting namespace_rootid and rootid arguments")
            namespace_rootid = rootid

        seen: set[tuple[int, int]] = set()
        stack = [self.root]

        while stack:
            node = stack.pop()
            position = (node.block, node.offset)

            if position in seen:
                continue
            seen.add(position)

            if node.is_dir():
                stack.extend(reversed(list(node.iterdir())))
                continue

            report = node.file_capabilities(namespace_rootid=namespace_rootid)
            if report is not None:
                yield node, report


class INode:
    def __init__(
        self,
        fs: SquashFS,
        block: int,
        offset: int,
        name: str | None = None,
        type: int | None = None,
        inode_number: int | None = None,
        parent: INode | None = None,
    ):
        self.fs = fs
        self.block = block
        self.offset = offset
        self.name = name
        self._type = type
        self._inode_number = inode_number
        self.parent = parent

        self.listdir = cache(self.listdir)

    def __repr__(self) -> str:
        return f"<inode {self.inode_number} ({self.block}, {self.offset})>"

    def _metadata(
        self,
    ) -> tuple[
        c_squashfs.squashfs_base_inode_header
        | c_squashfs.squashfs_dir_inode_header
        | c_squashfs.squashfs_reg_inode_header
        | c_squashfs.squashfs_symlink_inode_header
        | c_squashfs.squashfs_dev_inode_header
        | c_squashfs.squashfs_ldir_inode_header
        | c_squashfs.squashfs_lreg_inode_header
        | c_squashfs.squashfs_ldev_inode_header
        | c_squashfs.squashfs_lipc_inode_header,
        int,
        int,
    ]:
        base_struct = c_squashfs.squashfs_base_inode_header

        block = self.fs.sb.inode_table_start + self.block
        data_block, data_offset, data = self.fs._read_metadata(block, self.offset, len(base_struct))

        header = base_struct(data)
        actual_struct = INODE_STRUCT_MAP.get(header.inode_type)

        if len(actual_struct) != len(base_struct):
            data_block, data_offset, data = self.fs._read_metadata(block, self.offset, len(actual_struct))

        if actual_struct != base_struct:
            header = actual_struct(data)

        self.header = header
        self.data_block = data_block
        self.data_offset = data_offset

        return header, data_block, data_offset

    @cached_property
    def header(
        self,
    ) -> (
        c_squashfs.squashfs_base_inode_header
        | c_squashfs.squashfs_dir_inode_header
        | c_squashfs.squashfs_reg_inode_header
        | c_squashfs.squashfs_symlink_inode_header
        | c_squashfs.squashfs_dev_inode_header
        | c_squashfs.squashfs_ldir_inode_header
        | c_squashfs.squashfs_lreg_inode_header
        | c_squashfs.squashfs_ldev_inode_header
        | c_squashfs.squashfs_lipc_inode_header
    ):
        header, _, _ = self._metadata()
        return header

    @cached_property
    def data_block(self) -> int:
        _, data_block, _ = self._metadata()
        return data_block

    @cached_property
    def data_offset(self) -> int:
        _, _, data_offset = self._metadata()
        return data_offset

    @property
    def inode_number(self) -> int:
        return self._inode_number or self.header.inode_number

    @property
    def type(self) -> int:
        return TYPE_MAP[self._type or self.header.inode_type]

    @property
    def mode(self) -> int:
        return self.header.mode | self.type

    @property
    def uid(self) -> int:
        return self.fs._lookup_id(self.header.uid)

    @property
    def guid(self) -> int:
        return self.fs._lookup_id(self.header.guid)

    @property
    def gid(self) -> int:
        return self.guid

    @property
    def mtime(self) -> datetime:
        return ts.from_unix(self.header.mtime)

    @property
    def size(self) -> int | None:
        if self.is_dir() or self.is_file():
            return self.header.file_size
        if self.is_symlink():
            return self.header.symlink_size
        return None

    @property
    def xattr_id(self) -> int | None:
        """The xattr ID for this inode, or ``None`` if it has no extended attributes."""
        if self.header.inode_type == c_squashfs.SQUASHFS_LSYMLINK_TYPE:
            # The long symlink inode has no xattr field in its header struct: it follows
            # the symlink target in the metadata stream.
            block, offset, _ = self.fs._read_metadata(
                self.data_block,
                self.data_offset,
                self.header.symlink_size,
            )
            _, _, data = self.fs._read_metadata(block, offset, 4)
            xattr = struct.unpack("<I", data)[0]
        else:
            xattr = getattr(self.header, "xattr", c_squashfs.SQUASHFS_INVALID_XATTR)

        if xattr == c_squashfs.SQUASHFS_INVALID_XATTR:
            return None
        return xattr

    @cached_property
    def xattrs(self) -> list[Xattr]:
        """All extended attributes of this inode."""
        if self.xattr_id is None:
            return []
        return self.fs.xattrs(self.xattr_id)

    def getxattr(self, name: str) -> Xattr | None:
        """Return a single extended attribute by its full name, if present."""
        return self.get_xattr(name)

    def get_xattr(self, name: str) -> Xattr | None:
        """Return a single extended attribute by its full name, if present."""
        for xattr in self.xattrs:
            if xattr.name == name:
                return xattr
        return None

    def file_capabilities(
        self,
        namespace_rootid: int | None = None,
        *,
        rootid: int | None = None,
    ) -> FileCapabilityReport | None:
        """Read and analyse the ``security.capability`` attribute of this inode.

        Args:
            namespace_rootid: Root UID of the user namespace in which the stored
                declaration should be evaluated, as seen from the initial user namespace.
                This is supplied by the caller; the identity of the analysis host is never
                used. If omitted, the declaration is reported but no effectiveness
                conclusion is made.
            rootid: Alias for ``namespace_rootid``.

        Returns:
            A capability report, or ``None`` if the inode has no ``security.capability``.
        """
        return analyze_file_capabilities(self.xattrs, namespace_rootid=namespace_rootid, rootid=rootid)

    def capabilities(
        self,
        namespace_rootid: int | None = None,
        *,
        rootid: int | None = None,
    ) -> FileCapabilityReport | None:
        """Alias for :meth:`file_capabilities`."""
        return self.file_capabilities(namespace_rootid=namespace_rootid, rootid=rootid)

    def security_capability(
        self,
        namespace_rootid: int | None = None,
        *,
        rootid: int | None = None,
    ) -> FileCapabilityReport | None:
        """Alias for :meth:`file_capabilities`."""
        return self.file_capabilities(namespace_rootid=namespace_rootid, rootid=rootid)

    def caps(
        self,
        namespace_rootid: int | None = None,
        *,
        rootid: int | None = None,
    ) -> FileCapabilityReport | None:
        """Alias for :meth:`file_capabilities`."""
        return self.file_capabilities(namespace_rootid=namespace_rootid, rootid=rootid)

    def is_dir(self) -> bool:
        return self.type == stat.S_IFDIR

    def is_file(self) -> bool:
        return self.type == stat.S_IFREG

    def is_symlink(self) -> bool:
        return self.type == stat.S_IFLNK

    def is_block_device(self) -> bool:
        return self.type == stat.S_IFBLK

    def is_character_device(self) -> bool:
        return self.type == stat.S_IFCHR

    def is_device(self) -> bool:
        return self.is_block_device() or self.is_character_device()

    def is_fifo(self) -> bool:
        return self.type == stat.S_IFIFO

    def is_socket(self) -> bool:
        return self.type == stat.S_IFSOCK

    def is_ipc(self) -> bool:
        return self.is_fifo() or self.is_socket()

    @cached_property
    def link(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(f"{self!r} is not a symlink")

        _, _, data = self.fs._read_metadata(
            self.data_block,
            self.data_offset,
            self.header.symlink_size,
        )
        return data.decode(errors="surrogateescape")

    @cached_property
    def link_inode(self) -> INode:
        link = self.link
        relnode = None if link.startswith("/") else self.parent
        return self.fs.get(self.link, relnode)

    def listdir(self) -> dict[str, INode]:
        return {inode.name: inode for inode in self.iterdir()}

    def iterdir(self) -> Iterator[INode]:
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        if self.size == 3:
            return

        start = self.fs.sb.directory_table_start + self.header.start_block
        offset = self.header.offset

        bytes_read = 0
        while bytes_read < self.size - 3:
            start, offset, data = self.fs._read_metadata(start, offset, len(c_squashfs.squashfs_dir_header))
            dir_header = c_squashfs.squashfs_dir_header(data)
            bytes_read += len(data)

            for _ in range(dir_header.count + 1):
                start, offset, data = self.fs._read_metadata(start, offset, len(c_squashfs.squashfs_dir_entry))
                dir_entry = c_squashfs.squashfs_dir_entry(data)
                bytes_read += len(data)

                start, offset, data = self.fs._read_metadata(start, offset, dir_entry.size + 1)
                bytes_read += len(data)

                yield self.fs.inode(
                    dir_header.start_block,
                    dir_entry.offset,
                    data.decode(errors="surrogateescape"),
                    dir_entry.type,
                    dir_header.inode_number + dir_entry.inode_number,
                    parent=self,
                )

    @cached_property
    def block_list(self) -> list[tuple[int | None, int]]:
        fragment = self.header.fragment
        file_size = self.header.file_size
        if fragment == c_squashfs.SQUASHFS_INVALID_FRAG:
            frag_bytes = 0
            blocks = (file_size + self.fs.block_size - 1) >> self.fs.block_log
        else:
            blocks, frag_bytes = divmod(file_size, self.fs.block_size)

        if blocks:
            _, _, data = self.fs._read_metadata(
                self.data_block,
                self.data_offset,
                blocks * 4,
            )
            block_list = [(block, 1) for block in c_squashfs.uint32[blocks](data)]
        else:
            block_list = []

        if frag_bytes:
            block_list.append((None, frag_bytes))

        return block_list

    def open(self) -> FileStream:
        if not self.is_file():
            raise NotAFileError(f"{self!r} is not a file")

        return FileStream(self)


class FileStream(RunlistStream):
    def __init__(self, inode: INode):
        super().__init__(inode.fs.fh, inode.block_list, inode.size, inode.fs.block_size)
        self.inode = inode
        self.fs = inode.fs
        self.start_block = inode.header.start_block
        self.fragment = inode.header.fragment
        self.fragment_offset = inode.header.offset

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        block_offset = offset // self.block_size

        run_idx = bisect_right(self._runlist_offsets, block_offset)
        runlist_len = len(self.runlist)
        size = self.size

        start_block = self.start_block + sum(
            v & ~c_squashfs.SQUASHFS_COMPRESSED_BIT_BLOCK for v, _ in self.runlist[:run_idx]
        )

        while length > 0:
            if run_idx >= runlist_len:
                # We somehow requested more data than we have runs for
                break

            run_block_size, run_block_count = self.runlist[run_idx]

            # For squashfs we use 0 to indicate a sparse block and None to indicate a fragment
            if run_block_size is None:
                result.append(self.fs._read_fragment(self.fragment, self.fragment_offset, run_block_count))
                offset += run_block_count
                length -= run_block_count
            else:
                run_pos = offset - run_idx * self.block_size
                run_remaining = self.block_size - run_pos

                # Sometimes the self.size is way larger than what we actually have runs for?
                # Stop reading if we reach a negative run_remaining
                if run_remaining < 0:
                    break

                read_count = min(size - offset, min(run_remaining, length))

                # Sparse run
                if run_block_size == 0:
                    result.append(b"\x00" * read_count)
                else:
                    start_block, data = self.fs._read_block(start_block, run_block_size)
                    result.append(data[:read_count])

                offset += read_count
                length -= read_count
                run_idx += 1

        return b"".join(result)
