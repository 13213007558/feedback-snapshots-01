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
from dissect.squashfs.c_squashfs import INODE_STRUCT_MAP, c_squashfs
from dissect.squashfs.consistency import (
    LOOKUP_AVAILABLE,
    LOOKUP_CORRUPT,
    LOOKUP_UNAVAILABLE,
    ConsistencyError,
    ConsistencyIssue,
    DirectoryEntryEvidence,
    DirectoryRecord,
    InodeConsistencyEntry,
    InodeConsistencyReport,
    InodeHeaderEvidence,
    LookupEntryEvidence,
    LookupTableStatus,
    finalize_lookup_status,
    stat_type,
    type_name,
)
from dissect.squashfs.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime


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

        self._compression_options = None
        if (self.sb.flags >> c_squashfs.SQUASHFS_COMP_OPT) & 1:
            self._compression_options = self._read_block(len(self.sb))[1]

        self._compression = compression.initialize(self.sb.compression, self._compression_options)

        self.id_table = self._read_table(self.sb.id_table_start, self.sb.no_ids, 4)
        self.lookup_table = self._read_table(self.sb.lookup_table_start, self.sb.inodes, 8)
        self.fragment_table = self._read_table(
            self.sb.fragment_table_start, self.sb.fragments, len(c_squashfs.squashfs_fragment_entry)
        )

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
            node = self.inode(path >> 16, path & 0xFFFF)
            node.inode_record = path
            return node

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

    def _read_metadata(self, block: int, offset: int, length: int) -> tuple[int, int, bytes]:
        if length < 0:
            raise ValueError(f"Negative metadata length: {length}")
        if offset < 0:
            raise ValueError(f"Negative metadata offset: {offset}")

        result = []
        while length:
            next_block, data = self._read_block(block)
            if not data:
                raise ValueError(f"Empty metadata block at {block}")
            if offset > len(data):
                raise ValueError(f"Metadata offset {offset} outside block {block} (length {len(data)})")

            remaining = len(data) - offset
            if remaining <= length:
                result.append(data[offset:])
                length -= remaining
                if length and next_block <= block:
                    raise ValueError(f"Metadata chain does not advance from block {block}")
                block = next_block
                offset = 0
            else:
                result.append(data[offset : offset + length])
                offset += length
                length = 0

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
        if len(data) != length:
            raise EOFError(f"Short read at {block}: expected {length} bytes, got {len(data)}")

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

    def _read_inode_header(
        self, block: int, offset: int
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
        block = self.sb.inode_table_start + block
        base_struct = c_squashfs.squashfs_base_inode_header
        data_block, data_offset, data = self._read_metadata(block, offset, len(base_struct))

        header = base_struct(data)
        actual_struct = INODE_STRUCT_MAP.get(header.inode_type)
        if actual_struct is None:
            raise ValueError(f"Unknown inode type {header.inode_type} at {block}:{offset}")

        if len(actual_struct) != len(base_struct):
            data_block, data_offset, data = self._read_metadata(block, offset, len(actual_struct))

        if actual_struct != base_struct:
            header = actual_struct(data)

        return header, data_block, data_offset

    def _lookup_inode_ref(self, inode_number: int) -> tuple[int, int, int]:
        if inode_number <= 0 or inode_number > self.sb.inodes:
            raise IndexError(f"inode number out of bounds (1, {self.sb.inodes}): {inode_number}")

        block, offset = divmod((inode_number - 1) * 8, c_squashfs.SQUASHFS_METADATA_SIZE)
        if block >= len(self.lookup_table):
            raise IndexError(f"inode lookup table has no block {block} for inode {inode_number}")

        lookup_block = self.lookup_table[block]
        if self._is_invalid_table_block(lookup_block):
            raise ValueError(f"invalid inode lookup block {lookup_block} for inode {inode_number}")

        _, data = self._read_block(lookup_block)
        if offset + 8 > len(data):
            raise ValueError(
                f"inode lookup entry {inode_number} at {lookup_block}:{offset} is outside its metadata block"
            )

        reference = struct.unpack("<Q", data[offset : offset + 8])[0]
        return reference, reference >> 16, reference & 0xFFFF

    def _lookup_inode(self, inode_number: int) -> INode:
        reference, _, _ = self._lookup_inode_ref(inode_number)
        return self.get(reference)

    def _lookup_fragment(self, fragment: int) -> c_squashfs.squashfs_fragment_entry:
        fragment_offset = fragment * len(c_squashfs.squashfs_fragment_entry)
        block, offset = divmod(fragment_offset, c_squashfs.SQUASHFS_METADATA_SIZE)

        _, _, data = self._read_metadata(self.fragment_table[block], offset, len(c_squashfs.squashfs_fragment_entry))
        return c_squashfs.squashfs_fragment_entry(data)

    def iter_inodes(self) -> Iterator[INode]:
        for inum in range(1, self.sb.inodes + 1):
            yield self._lookup_inode(inum)

    @staticmethod
    def _is_invalid_table_block(block: int) -> bool:
        # Table entries are read as unsigned 64-bit values, so the signed -1 invalid marker
        # appears as 0xFFFFFFFFFFFFFFFF. Treat all signed-negative values as invalid.
        return block < 0 or block >= 1 << 63

    def _lookup_table_status(self) -> LookupTableStatus:
        table_start = int(self.sb.lookup_table_start)
        exported = bool(int(self.sb.flags) & (1 << c_squashfs.SQUASHFS_EXPORT))
        declared = exported and table_start > 0 and not self._is_invalid_table_block(table_start)
        present = declared and bool(self.lookup_table)

        if not declared:
            return LookupTableStatus(
                declared=False,
                present=False,
                available=False,
                status=LOOKUP_UNAVAILABLE,
                table_start=table_start,
                entry_count=0,
                error="superblock does not publish an inode lookup table",
            )

        if not present:
            return LookupTableStatus(
                declared=True,
                present=False,
                available=False,
                status=LOOKUP_CORRUPT,
                table_start=table_start,
                entry_count=0,
                error="inode lookup table is declared but its block list is empty or unreadable",
            )

        invalid_blocks = [block for block in self.lookup_table if self._is_invalid_table_block(block)]
        if invalid_blocks:
            return LookupTableStatus(
                declared=True,
                present=True,
                available=False,
                status=LOOKUP_CORRUPT,
                table_start=table_start,
                entry_count=self.sb.inodes,
                error=f"inode lookup table contains {len(invalid_blocks)} invalid metadata block pointer(s)",
            )

        return LookupTableStatus(
            declared=True,
            present=True,
            available=True,
            status=LOOKUP_AVAILABLE,
            table_start=table_start,
            entry_count=self.sb.inodes,
        )

    def _inode_header_evidence(self, block: int, offset: int) -> InodeHeaderEvidence:
        address = self.sb.inode_table_start + block
        try:
            header, _, _ = self._read_inode_header(block, offset)
        except Exception as e:
            return InodeHeaderEvidence(
                block=block,
                offset=offset,
                address=address,
                error=f"{type(e).__name__}: {e}",
            )

        return InodeHeaderEvidence(
            block=block,
            offset=offset,
            address=address,
            inode_number=int(header.inode_number),
            inode_type=int(header.inode_type),
            inode_stat_type=stat_type(int(header.inode_type)),
        )

    def _lookup_evidence(self, status: LookupTableStatus, inode_number: int) -> LookupEntryEvidence:
        if not status.available:
            return LookupEntryEvidence(
                available=status.status != LOOKUP_UNAVAILABLE,
                inode_number=inode_number,
                error=status.error or "inode lookup table unavailable",
            )

        try:
            reference, block, offset = self._lookup_inode_ref(inode_number)
        except Exception as e:
            return LookupEntryEvidence(
                available=True,
                inode_number=inode_number,
                error=f"{type(e).__name__}: {e}",
            )

        header = self._inode_header_evidence(reference >> 16, reference & 0xFFFF)
        if header.error is not None:
            entry_error = header.error
        elif header.inode_number != inode_number:
            entry_error = f"lookup entry for inode {inode_number} points to inode header {header.inode_number}"
        else:
            entry_error = None

        return LookupEntryEvidence(
            available=True,
            inode_number=inode_number,
            reference=reference,
            block=block,
            offset=offset,
            address=self.sb.inode_table_start + block,
            header=header,
            error=entry_error,
        )

    def lookup_table_status(self) -> LookupTableStatus:
        """Return the availability and health state of the inode lookup table.

        A missing table is a valid two-way-comparison mode. A table that is declared or
        populated but whose entries cannot be read is reported as corrupt.
        """
        return self._lookup_table_status()

    def lookup_inode_entry(self, inode_number: int) -> LookupEntryEvidence:
        """Return the raw lookup evidence for a specific inode number.

        This never falls back to directory traversal: an unreadable table or entry is reported
        on the returned evidence object.
        """
        return self._lookup_evidence(self._lookup_table_status(), inode_number)

    def check_consistency(self, start: INode | None = None, max_depth: int | None = None) -> InodeConsistencyReport:
        """Cross-check directory entries, inode headers and the inode lookup table.

        Args:
            start: Directory to start from. Defaults to the root inode.
            max_depth: Optional maximum directory depth. ``None`` means unlimited, while ``0``
                checks only entries in ``start`` itself.

        Returns:
            A report containing one entry per directory entry, including raw directory,
            inode-header and lookup-table evidence, any discrepancies, and explicit
            lookup-table health.
        """
        start = start or self.root
        status = self._lookup_table_status()
        report = InodeConsistencyReport(lookup=status)

        root_evidence = self._inode_header_evidence(start.block, start.offset)
        report.root = root_evidence
        if root_evidence.error is not None:
            report.errors.append(
                ConsistencyError(
                    path=start.name or "/",
                    source="inode_header",
                    message=root_evidence.error,
                    record_address=root_evidence.address,
                )
            )

        if not start.is_dir():
            report.lookup = finalize_lookup_status(status, report.entries)
            return report

        records: list[tuple[str, DirectoryRecord]] = []
        self._collect_directory_records(start, records, report.errors, max_depth)

        seen_inodes: dict[tuple[int, int], list[str]] = {}
        for path, record in records:
            key = (record.inode_block, record.inode_offset)
            seen_inodes.setdefault(key, []).append(path)

        for path, record in records:
            shared = len(seen_inodes[(record.inode_block, record.inode_offset)]) > 1
            report.entries.append(self._check_record(path, record, status, shared_inode=shared))

        report.lookup = finalize_lookup_status(status, report.entries)
        return report

    def _collect_directory_records(
        self,
        directory: INode,
        records: list[tuple[str, DirectoryRecord]],
        errors: list[ConsistencyError],
        remaining_depth: int | None,
        seen_directories: set[tuple[int, int]] | None = None,
        path: str = "",
    ) -> None:
        if remaining_depth is not None and remaining_depth < 0:
            return

        seen_directories = seen_directories or set()
        key = (directory.block, directory.offset)
        if key in seen_directories:
            return
        seen_directories.add(key)

        try:
            dir_records = list(directory._iterdir_records())
        except Exception as e:
            errors.append(
                ConsistencyError(
                    path=path or "/",
                    source="directory",
                    message=f"{type(e).__name__}: {e}",
                    record_address=self.sb.directory_table_start + directory.header.start_block,
                )
            )
            return

        child_directories = []
        for record in dir_records:
            child_path = f"{path}/{record.name}" if path else f"/{record.name}"
            records.append((child_path, record))

            header = self._inode_header_evidence(record.inode_block, record.inode_offset)
            if header.error is None and stat_type(header.inode_type) == stat.S_IFDIR:
                node = self.inode(
                    record.inode_block,
                    record.inode_offset,
                    record.name,
                    record.declared_type,
                    record.declared_inode_number,
                    parent=directory,
                )
                node.directory_record = record
                child_directories.append((child_path, node))

        if remaining_depth == 0:
            return

        for child_path, child in child_directories:
            self._collect_directory_records(
                child,
                records,
                errors,
                None if remaining_depth is None else remaining_depth - 1,
                seen_directories,
                child_path,
            )

    def _check_record(
        self,
        path: str,
        record: DirectoryRecord,
        status: LookupTableStatus,
        shared_inode: bool,
    ) -> InodeConsistencyEntry:
        directory = DirectoryEntryEvidence(
            name=record.name,
            dir_header_inode_number=int(record.header.inode_number),
            inode_number_delta=record.inode_number_delta,
            declared_inode_number=record.declared_inode_number,
            declared_type=record.declared_type,
            declared_stat_type=stat_type(record.declared_type),
            inode_block=record.inode_block,
            inode_offset=record.inode_offset,
            inode_record_address=record.inode_record_address,
            directory_header_block=record.directory_header_block,
            directory_header_offset=record.directory_header_offset,
            directory_entry_block=record.directory_entry_block,
            directory_entry_offset=record.directory_entry_offset,
        )

        inode = self._inode_header_evidence(record.inode_block, record.inode_offset)
        lookup = self._lookup_evidence(status, record.declared_inode_number)
        issues: list[ConsistencyIssue] = []

        if inode.error is not None:
            issues.append(
                ConsistencyIssue(
                    code="inode_header_unreadable",
                    message=(
                        f"cannot read inode header at {record.inode_record_address}:{record.inode_offset}: "
                        f"{inode.error}"
                    ),
                    source="inode_header",
                )
            )
            inode_number_match = None
            type_match = None
            raw_type_match = None
        else:
            inode_number_match = record.declared_inode_number == inode.inode_number
            declared_stat_type = stat_type(record.declared_type)
            raw_type_match = record.declared_type == inode.inode_type
            type_match = declared_stat_type == inode.inode_stat_type

            if not inode_number_match:
                issues.append(
                    ConsistencyIssue(
                        code="inode_number_mismatch",
                        message=(
                            f"directory declares inode {record.declared_inode_number} "
                            f"(header base {record.header.inode_number} + delta {record.inode_number_delta}), "
                            f"but inode header reports {inode.inode_number}"
                        ),
                        source="directory/inode_header",
                    )
                )

            if not type_match:
                issues.append(
                    ConsistencyIssue(
                        code="type_mismatch",
                        message=(
                            f"directory declares type {record.declared_type} "
                            f"({type_name(record.declared_type)}), "
                            f"but inode header reports {inode.inode_type} ({inode.type_name})"
                        ),
                        source="directory/inode_header",
                    )
                )

        if not lookup.available:
            lookup_match = None
        elif status.status == LOOKUP_CORRUPT and lookup.reference is None:
            lookup_match = None
            issues.append(
                ConsistencyIssue(
                    code="lookup_table_invalid",
                    message=f"inode lookup table is not usable: {lookup.error}",
                    source="lookup_table",
                )
            )
        elif lookup.error is not None:
            lookup_match = None
            issues.append(
                ConsistencyIssue(
                    code="lookup_entry_invalid",
                    message=f"inode lookup entry {record.declared_inode_number} is not usable: {lookup.error}",
                    source="lookup_table",
                )
            )
        else:
            lookup_match = True

            if (lookup.block, lookup.offset) != (record.inode_block, record.inode_offset):
                lookup_match = False
                issues.append(
                    ConsistencyIssue(
                        code="lookup_address_mismatch",
                        message=(
                            f"lookup entry {record.declared_inode_number} references "
                            f"{lookup.block}:{lookup.offset} (address {lookup.address}), "
                            f"but directory declares {record.inode_block}:{record.inode_offset} "
                            f"(address {record.inode_record_address})"
                        ),
                        source="directory/lookup_table",
                    )
                )

            if (
                lookup.header is not None
                and inode.error is None
                and (
                    lookup.header.inode_number != inode.inode_number
                    or lookup.header.inode_stat_type != inode.inode_stat_type
                )
            ):
                lookup_match = False
                issues.append(
                    ConsistencyIssue(
                        code="lookup_header_mismatch",
                        message=(
                            f"lookup entry {record.declared_inode_number} points to inode header "
                            f"{lookup.header.inode_number} ({type_name(lookup.header.inode_type)}), "
                            f"but directory address reads inode header "
                            f"{inode.inode_number} ({inode.type_name})"
                        ),
                        source="inode_header/lookup_table",
                    )
                )

        return InodeConsistencyEntry(
            path=path,
            directory=directory,
            inode=inode,
            lookup=lookup,
            inode_number_match=inode_number_match,
            type_match=type_match,
            lookup_match=lookup_match,
            raw_type_match=raw_type_match,
            issues=tuple(issues),
            shared_inode=shared_inode,
        )


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

        # Raw directory-declared values. These are retained for forensic comparison, but are not
        # authoritative for the inode's real type or number (those come from the inode header).
        self.directory_type = type
        self.directory_inode_number = inode_number
        self.directory_record = None
        self.inode_record = None

        self.listdir = cache(self.listdir)

    def __repr__(self) -> str:
        return f"<inode {self.inode_number} ({self.block}, {self.offset})>"

    @cached_property
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
        return self.fs._read_inode_header(self.block, self.offset)

    @property
    def declared_type(self) -> int | None:
        """The type declared by the directory entry that produced this inode, if any."""
        return self.directory_type

    @property
    def declared_inode_number(self) -> int | None:
        """The inode number declared by the directory entry that produced this inode, if any."""
        return self.directory_inode_number

    @property
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
        return self._metadata[0]

    @cached_property
    def data_block(self) -> int:
        _, data_block, _ = self._metadata
        return data_block

    @cached_property
    def data_offset(self) -> int:
        _, _, data_offset = self._metadata
        return data_offset

    @property
    def inode_number(self) -> int:
        """The inode number from the inode header, which is authoritative once the record is read."""
        return self.header.inode_number

    @property
    def type(self) -> int:
        """The POSIX file type from the inode header, not the directory entry declaration."""
        value = stat_type(self.header.inode_type)
        if value is None:
            raise ValueError(f"Unknown inode type: {self.header.inode_type}")
        return value

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

    def _iterdir_records(self) -> Iterator[DirectoryRecord]:
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        if self.size == 3:
            return

        start = self.fs.sb.directory_table_start + self.header.start_block
        offset = self.header.offset

        bytes_read = 0
        while bytes_read < self.size - 3:
            header_block = start
            header_offset = offset
            start, offset, data = self.fs._read_metadata(start, offset, len(c_squashfs.squashfs_dir_header))
            dir_header = c_squashfs.squashfs_dir_header(data)
            bytes_read += len(data)

            for _ in range(dir_header.count + 1):
                entry_block = start
                entry_offset = offset
                start, offset, data = self.fs._read_metadata(start, offset, len(c_squashfs.squashfs_dir_entry))
                dir_entry = c_squashfs.squashfs_dir_entry(data)
                bytes_read += len(data)

                start, offset, data = self.fs._read_metadata(start, offset, dir_entry.size + 1)
                bytes_read += len(data)

                yield DirectoryRecord(
                    name=data.decode(errors="surrogateescape"),
                    header=dir_header,
                    entry=dir_entry,
                    directory_header_block=header_block,
                    directory_header_offset=header_offset,
                    directory_entry_block=entry_block,
                    directory_entry_offset=entry_offset,
                    inode_table_start=self.fs.sb.inode_table_start,
                )

    def iterdir(self) -> Iterator[INode]:
        for record in self._iterdir_records():
            node = self.fs.inode(
                record.inode_block,
                record.inode_offset,
                record.name,
                record.declared_type,
                record.declared_inode_number,
                parent=self,
            )
            node.directory_record = record
            yield node

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
