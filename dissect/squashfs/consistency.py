from __future__ import annotations

import stat
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from dissect.squashfs.c_squashfs import TYPE_MAP, c_squashfs

if TYPE_CHECKING:
    from collections.abc import Iterator


DIRECTORY_TRUST = (
    "Directory declaration: records only what the directory entry claims. The inode number delta is "
    "signed and the inode address is relative to the inode table, but neither is proof of the inode "
    "record that actually exists at that address."
)
INODE_HEADER_TRUST = (
    "Inode header: bytes read from the directory-declared inode address. This is the primary inode "
    "record, but it is only authoritative after the address has been corroborated by another source."
)
LOOKUP_TRUST = (
    "Inode lookup table: the export index maps inode numbers to inode addresses independently of "
    "directory entries. It is only usable while the superblock declares/publishes it and every "
    "consulted entry is readable; a broken entry cannot be treated as agreement."
)

LOOKUP_UNAVAILABLE = "unavailable"
LOOKUP_AVAILABLE = "available"
LOOKUP_CORRUPT = "corrupt"

_TYPE_NAMES = {
    c_squashfs.SQUASHFS_DIR_TYPE: "dir",
    c_squashfs.SQUASHFS_FILE_TYPE: "file",
    c_squashfs.SQUASHFS_SYMLINK_TYPE: "symlink",
    c_squashfs.SQUASHFS_BLKDEV_TYPE: "block-device",
    c_squashfs.SQUASHFS_CHRDEV_TYPE: "character-device",
    c_squashfs.SQUASHFS_FIFO_TYPE: "fifo",
    c_squashfs.SQUASHFS_SOCKET_TYPE: "socket",
    c_squashfs.SQUASHFS_LDIR_TYPE: "long-dir",
    c_squashfs.SQUASHFS_LREG_TYPE: "long-file",
    c_squashfs.SQUASHFS_LSYMLINK_TYPE: "long-symlink",
    c_squashfs.SQUASHFS_LBLKDEV_TYPE: "long-block-device",
    c_squashfs.SQUASHFS_LCHRDEV_TYPE: "long-character-device",
    c_squashfs.SQUASHFS_LFIFO_TYPE: "long-fifo",
    c_squashfs.SQUASHFS_LSOCKET_TYPE: "long-socket",
}

_STAT_TYPE_NAMES = {
    stat.S_IFDIR: "directory",
    stat.S_IFREG: "regular-file",
    stat.S_IFLNK: "symlink",
    stat.S_IFBLK: "block-device",
    stat.S_IFCHR: "character-device",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
}


def stat_type(type_id: int | None) -> int | None:
    """Return the POSIX file type for a SquashFS type identifier, if known."""
    if type_id is None or type_id < 0 or type_id >= len(TYPE_MAP):
        return None
    return TYPE_MAP[type_id]


def type_name(type_id: int | None) -> str | None:
    """Return a human-readable name for a raw SquashFS type identifier."""
    if type_id is None:
        return None
    return _TYPE_NAMES.get(type_id, f"unknown-{type_id}")


def stat_type_name(value: int | None) -> str | None:
    """Return a human-readable name for a POSIX file type."""
    if value is None:
        return None
    return _STAT_TYPE_NAMES.get(value, f"unknown-{value:#x}")


@dataclass(frozen=True)
class DirectoryRecord:
    """The raw on-disk directory entry and the inode address it declares."""

    name: str
    header: Any
    entry: Any
    directory_header_block: int
    directory_header_offset: int
    directory_entry_block: int
    directory_entry_offset: int
    inode_table_start: int

    @property
    def inode_number_delta(self) -> int:
        """The signed inode number delta stored in the directory entry."""
        return int(self.entry.inode_number)

    @property
    def declared_inode_number(self) -> int:
        """The inode number obtained from the directory header base plus the signed delta."""
        return int(self.header.inode_number) + self.inode_number_delta

    @property
    def declared_type(self) -> int:
        """The raw SquashFS type identifier stored in the directory entry."""
        return int(self.entry.type)

    @property
    def inode_block(self) -> int:
        """The inode table block declared by the directory header (relative to the inode table)."""
        return int(self.header.start_block)

    @property
    def inode_offset(self) -> int:
        """The inode table offset declared by the directory entry."""
        return int(self.entry.offset)

    @property
    def inode_record_address(self) -> int:
        """The absolute metadata block address for the declared inode record."""
        return self.inode_table_start + self.inode_block


@dataclass(frozen=True)
class ConsistencyIssue:
    """A single discrepancy or unreadable evidence source in a consistency report."""

    code: str
    message: str
    source: str

    def __str__(self) -> str:
        return f"{self.source}: {self.message}"


@dataclass(frozen=True)
class DirectoryEntryEvidence:
    """Raw values from a directory entry, including the signed inode-number delta."""

    name: str
    dir_header_inode_number: int
    inode_number_delta: int
    declared_inode_number: int
    declared_type: int
    declared_stat_type: int | None
    inode_block: int
    inode_offset: int
    inode_record_address: int
    directory_header_block: int
    directory_header_offset: int
    directory_entry_block: int
    directory_entry_offset: int
    trust: str = DIRECTORY_TRUST

    @property
    def inode_number(self) -> int:
        """Alias for :attr:`declared_inode_number`."""
        return self.declared_inode_number

    @property
    def type(self) -> int:
        """Alias for :attr:`declared_type`."""
        return self.declared_type

    @property
    def stat_type(self) -> int | None:
        """Alias for :attr:`declared_stat_type`."""
        return self.declared_stat_type

    @property
    def record_address(self) -> int:
        """Alias for :attr:`inode_record_address`."""
        return self.inode_record_address

    @property
    def type_name(self) -> str | None:
        return type_name(self.declared_type)

    @property
    def stat_type_name(self) -> str | None:
        return stat_type_name(self.declared_stat_type)


@dataclass(frozen=True)
class InodeHeaderEvidence:
    """Raw values from the inode header at a particular inode-table address."""

    block: int
    offset: int
    address: int
    inode_number: int | None = None
    inode_type: int | None = None
    inode_stat_type: int | None = None
    error: str | None = None
    trust: str = INODE_HEADER_TRUST

    @property
    def type(self) -> int | None:
        """Alias for :attr:`inode_type`."""
        return self.inode_type

    @property
    def stat_type(self) -> int | None:
        """Alias for :attr:`inode_stat_type`."""
        return self.inode_stat_type

    @property
    def type_name(self) -> str | None:
        return type_name(self.inode_type)

    @property
    def stat_type_name(self) -> str | None:
        return stat_type_name(self.inode_stat_type)

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class LookupEntryEvidence:
    """Raw values from an inode lookup table entry and the header it points to."""

    available: bool
    inode_number: int
    reference: int | None = None
    block: int | None = None
    offset: int | None = None
    address: int | None = None
    header: InodeHeaderEvidence | None = None
    error: str | None = None
    trust: str = LOOKUP_TRUST

    @property
    def present(self) -> bool:
        """Whether the lookup evidence could be consulted at all."""
        return self.available

    @property
    def ok(self) -> bool:
        return self.available and self.error is None

    @property
    def inode_type(self) -> int | None:
        return None if self.header is None else self.header.inode_type

    @property
    def stat_type(self) -> int | None:
        return None if self.header is None else self.header.inode_stat_type

    @property
    def type_name(self) -> str | None:
        return None if self.header is None else self.header.type_name


@dataclass(frozen=True)
class InodeConsistencyEntry:
    """Cross-checked evidence for one directory entry."""

    path: str
    directory: DirectoryEntryEvidence
    inode: InodeHeaderEvidence
    lookup: LookupEntryEvidence
    inode_number_match: bool | None
    type_match: bool | None
    lookup_match: bool | None
    raw_type_match: bool | None = None
    issues: tuple[ConsistencyIssue, ...] = ()
    shared_inode: bool = False

    @property
    def name(self) -> str:
        return self.directory.name

    @property
    def hard_link(self) -> bool:
        """Whether another directory entry references the same inode record."""
        return self.shared_inode

    @property
    def is_consistent(self) -> bool:
        return not self.issues

    @property
    def trust_boundaries(self) -> dict[str, str]:
        return {
            "directory": self.directory.trust,
            "inode_header": self.inode.trust,
            "lookup_table": self.lookup.trust,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "directory": {
                "dir_header_inode_number": self.directory.dir_header_inode_number,
                "inode_number_delta": self.directory.inode_number_delta,
                "declared_inode_number": self.directory.declared_inode_number,
                "type": self.directory.declared_type,
                "type_name": self.directory.type_name,
                "stat_type": self.directory.declared_stat_type,
                "stat_type_name": self.directory.stat_type_name,
                "inode_block": self.directory.inode_block,
                "inode_offset": self.directory.inode_offset,
                "inode_record_address": self.directory.inode_record_address,
                "directory_header_block": self.directory.directory_header_block,
                "directory_header_offset": self.directory.directory_header_offset,
                "directory_entry_block": self.directory.directory_entry_block,
                "directory_entry_offset": self.directory.directory_entry_offset,
                "trust": self.directory.trust,
            },
            "inode_header": {
                "block": self.inode.block,
                "offset": self.inode.offset,
                "address": self.inode.address,
                "inode_number": self.inode.inode_number,
                "type": self.inode.inode_type,
                "type_name": self.inode.type_name,
                "stat_type": self.inode.inode_stat_type,
                "stat_type_name": self.inode.stat_type_name,
                "error": self.inode.error,
                "trust": self.inode.trust,
            },
            "lookup_table": {
                "available": self.lookup.available,
                "inode_number": self.lookup.inode_number,
                "reference": self.lookup.reference,
                "block": self.lookup.block,
                "offset": self.lookup.offset,
                "address": self.lookup.address,
                "inode_number_from_header": None if self.lookup.header is None else self.lookup.header.inode_number,
                "type": self.lookup.inode_type,
                "type_name": self.lookup.type_name,
                "stat_type": self.lookup.stat_type,
                "error": self.lookup.error,
                "trust": self.lookup.trust,
            },
            "inode_number_match": self.inode_number_match,
            "type_match": self.type_match,
            "raw_type_match": self.raw_type_match,
            "lookup_match": self.lookup_match,
            "shared_inode": self.shared_inode,
            "issues": [issue.__dict__ for issue in self.issues],
            "trust_boundaries": self.trust_boundaries,
        }


@dataclass(frozen=True)
class LookupTableStatus:
    """Availability and structural health of the superblock's inode lookup table."""

    declared: bool
    present: bool
    available: bool
    status: str
    table_start: int
    entry_count: int
    error: str | None = None
    trust: str = LOOKUP_TRUST

    @property
    def ok(self) -> bool:
        return self.status != LOOKUP_CORRUPT

    @property
    def complete(self) -> bool:
        return self.available


@dataclass(frozen=True)
class ConsistencyError:
    """A directory or table-level failure that prevented a complete comparison."""

    path: str
    source: str
    message: str
    record_address: int | None = None

    def __str__(self) -> str:
        return f"{self.source} at {self.path}: {self.message}"


@dataclass
class InodeConsistencyReport:
    """Read-only cross-check of directory entries, inode headers and the lookup table."""

    entries: list[InodeConsistencyEntry] = field(default_factory=list)
    lookup: LookupTableStatus | None = None
    errors: list[ConsistencyError] = field(default_factory=list)
    root: InodeHeaderEvidence | None = None

    def __iter__(self) -> Iterator[InodeConsistencyEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    @property
    def lookup_available(self) -> bool:
        return bool(self.lookup and self.lookup.available)

    @property
    def lookup_errors(self) -> list[LookupEntryEvidence]:
        """Lookup entries that could not be read or parsed."""
        return [entry.lookup for entry in self.entries if entry.lookup.error is not None]

    @property
    def conflicts(self) -> list[InodeConsistencyEntry]:
        return [entry for entry in self.entries if not entry.is_consistent]

    @property
    def issues(self) -> list[ConsistencyIssue]:
        return [issue for entry in self.entries for issue in entry.issues]

    @property
    def shared_inodes(self) -> dict[tuple[int, int], list[str]]:
        """Inode records referenced by more than one directory path."""
        result: dict[tuple[int, int], list[str]] = {}
        for entry in self.entries:
            if entry.shared_inode:
                result.setdefault((entry.directory.inode_block, entry.directory.inode_offset), []).append(entry.path)
        return result

    @property
    def is_consistent(self) -> bool:
        """Whether every available source agrees and no lookup entry is corrupt."""
        if self.errors:
            return False
        if self.lookup is not None and self.lookup.status == LOOKUP_CORRUPT:
            return False
        return all(entry.is_consistent for entry in self.entries)

    ok = is_consistent

    @property
    def trust_boundaries(self) -> dict[str, str]:
        return {
            "directory": DIRECTORY_TRUST,
            "inode_header": INODE_HEADER_TRUST,
            "lookup_table": LOOKUP_TRUST,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_consistent": self.is_consistent,
            "lookup": None
            if self.lookup is None
            else {
                "declared": self.lookup.declared,
                "present": self.lookup.present,
                "available": self.lookup.available,
                "status": self.lookup.status,
                "table_start": self.lookup.table_start,
                "entry_count": self.lookup.entry_count,
                "error": self.lookup.error,
                "trust": self.lookup.trust,
            },
            "root": None
            if self.root is None
            else {
                "block": self.root.block,
                "offset": self.root.offset,
                "address": self.root.address,
                "inode_number": self.root.inode_number,
                "type": self.root.inode_type,
                "type_name": self.root.type_name,
                "stat_type": self.root.inode_stat_type,
                "error": self.root.error,
                "trust": self.root.trust,
            },
            "entries": [entry.to_dict() for entry in self.entries],
            "errors": [error.__dict__ for error in self.errors],
            "trust_boundaries": self.trust_boundaries,
        }


def finalize_lookup_status(status: LookupTableStatus, entries: list[InodeConsistencyEntry]) -> LookupTableStatus:
    """Mark the lookup table corrupt when any consulted entry could not be read."""
    if status.status == LOOKUP_CORRUPT or not status.available:
        return status

    if any(entry.lookup.error is not None for entry in entries):
        return replace(status, status=LOOKUP_CORRUPT, error="one or more inode lookup entries could not be read")

    return status
