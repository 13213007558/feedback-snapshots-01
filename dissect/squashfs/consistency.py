# References:
# - https://dr-emann.github.io/squashfs/
# - Linux kernel

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.squashfs.c_squashfs import TYPE_MAP, c_squashfs

if TYPE_CHECKING:
    from dissect.squashfs.squashfs import INode, SquashFS

# Issue kinds. They are strings so callers can log or serialize them without
# importing the report classes.
TYPE_MISMATCH = "type_mismatch"
INODE_NUMBER_MISMATCH = "inode_number_mismatch"
INVALID_DIRECTORY_TYPE = "invalid_directory_type"
INODE_NUMBER_OUT_OF_RANGE = "inode_number_out_of_range"
INODE_HEADER_ERROR = "inode_header_error"
INVALID_INODE_TYPE = "invalid_inode_type"
LOOKUP_ENTRY_MISSING = "lookup_entry_missing"
LOOKUP_ENTRY_CORRUPT = "lookup_entry_corrupt"
LOOKUP_ADDRESS_MISMATCH = "lookup_address_mismatch"
DIRECTORY_READ_ERROR = "directory_read_error"

LOOKUP_ABSENT = "absent"
LOOKUP_OK = "ok"
LOOKUP_CORRUPT = "corrupt"

DIRECTORY_TRUST_BOUNDARY = (
    "advisory: a directory entry carries a type and a signed inode number delta, "
    "but it does not define the inode; it is compared with the inode header"
)
INODE_TRUST_BOUNDARY = (
    "authoritative when readable: the inode header at the recorded inode address "
    "defines the inode identity and type; an unreadable header is unknown, not a pass"
)
LOOKUP_TRUST_BOUNDARY = (
    "independent identity map: an inode lookup entry is usable only when its pointer "
    "resolves inside the inode table and the pointed-to inode header agrees with the index"
)
LOOKUP_ABSENT_BOUNDARY = (
    "not present: no inode lookup table is available, so only the directory entry and "
    "the actual inode header can be compared"
)


def stat_type_for_inode_type(inode_type: int | None) -> int | None:
    """Return the POSIX file type for a SquashFS inode type.

    Basic and extended inode types that describe the same kind of file map to the
    same POSIX type, so a directory entry using ``SQUASHFS_FILE_TYPE`` does not
    conflict with an actual ``SQUASHFS_LREG_TYPE`` inode header.
    """
    if inode_type is None or inode_type <= 0 or inode_type >= len(TYPE_MAP):
        return None
    return TYPE_MAP[inode_type]


@dataclass(frozen=True)
class DirectoryClaim:
    """The identity and type declared by one raw directory entry."""

    inode_number: int
    inode_type: int
    inode_number_base: int
    inode_number_delta: int
    inode_block: int
    inode_offset: int
    record_block: int
    record_offset: int
    header_record_block: int | None = None
    header_record_offset: int | None = None
    inode_table_start: int | None = None

    @property
    def stat_type(self) -> int | None:
        return stat_type_for_inode_type(self.inode_type)

    @property
    def inode_record_address(self) -> tuple[int, int]:
        """The inode record address, relative to the inode table start."""
        return (self.inode_block, self.inode_offset)

    @property
    def absolute_inode_record_address(self) -> tuple[int, int] | None:
        """The absolute inode record address, if the filesystem base was recorded."""
        if self.inode_table_start is None:
            return None
        return (self.inode_table_start + self.inode_block, self.inode_offset)

    @property
    def directory_record_address(self) -> tuple[int, int]:
        """The physical metadata block and offset of the directory entry record."""
        return (self.record_block, self.record_offset)

    @property
    def directory_header_record_address(self) -> tuple[int, int] | None:
        """The physical metadata block and offset of the enclosing directory header."""
        if self.header_record_block is None or self.header_record_offset is None:
            return None
        return (self.header_record_block, self.header_record_offset)

    @property
    def trusted(self) -> bool:
        return False

    @property
    def trust_boundary(self) -> str:
        return DIRECTORY_TRUST_BOUNDARY


@dataclass(frozen=True)
class InodeHeaderClaim:
    """The identity and type read from the actual inode header."""

    inode_number: int | None
    inode_type: int | None
    inode_block: int
    inode_offset: int
    absolute_block: int
    error: str | None = None

    @property
    def stat_type(self) -> int | None:
        return stat_type_for_inode_type(self.inode_type)

    @property
    def address(self) -> tuple[int, int]:
        return (self.inode_block, self.inode_offset)

    @property
    def trusted(self) -> bool:
        return self.error is None and self.stat_type is not None

    @property
    def trust_boundary(self) -> str:
        return INODE_TRUST_BOUNDARY


@dataclass(frozen=True)
class LookupClaim:
    """The identity pointer for an inode number in the lookup/export table."""

    available: bool
    inode_number: int | None
    raw: int | None = None
    inode_block: int | None = None
    inode_offset: int | None = None
    matches: bool | None = None
    error: str | None = None

    @property
    def address(self) -> tuple[int, int] | None:
        if self.inode_block is None or self.inode_offset is None:
            return None
        return (self.inode_block, self.inode_offset)

    @property
    def trusted(self) -> bool:
        return self.available and self.error is None and self.matches is not False

    @property
    def trust_boundary(self) -> str:
        return LOOKUP_TRUST_BOUNDARY if self.available else LOOKUP_ABSENT_BOUNDARY


@dataclass(frozen=True)
class ConsistencyIssue:
    """One discrepancy or unreadable evidence source found during the check."""

    kind: str
    message: str
    path: str | None = None
    inode_number: int | None = None
    source: str | None = None


@dataclass(frozen=True)
class DirectoryEntryEvidence:
    """The three evidence sources for one directory entry."""

    path: str
    name: str
    directory: DirectoryClaim
    inode_header: InodeHeaderClaim
    lookup: LookupClaim
    issues: tuple[ConsistencyIssue, ...] = ()

    @property
    def consistent(self) -> bool:
        return not self.issues


@dataclass(frozen=True)
class LookupEntryEvidence:
    """The decoded evidence for one inode lookup table entry."""

    inode_number: int
    raw: int | None
    inode_block: int | None
    inode_offset: int | None
    absolute_block: int | None
    target_inode_number: int | None = None
    target_inode_type: int | None = None
    error: str | None = None
    issues: tuple[ConsistencyIssue, ...] = ()

    @property
    def address(self) -> tuple[int, int] | None:
        if self.inode_block is None or self.inode_offset is None:
            return None
        return (self.inode_block, self.inode_offset)

    @property
    def consistent(self) -> bool:
        return not self.issues


@dataclass
class LookupTableEvidence:
    """The state of the inode lookup/export table.

    ``status`` is one of :data:`LOOKUP_ABSENT`, :data:`LOOKUP_OK` or
    :data:`LOOKUP_CORRUPT`. A corrupt entry is deliberately reported as corrupt;
    callers must not treat it as if the table were absent and fall back to a
    two-way comparison that passes.
    """

    available: bool
    start: int
    inode_count: int
    status: str
    entries: list[LookupEntryEvidence] = field(default_factory=list)
    issues: list[ConsistencyIssue] = field(default_factory=list)

    @property
    def checked(self) -> bool:
        return self.available

    @property
    def trusted(self) -> bool:
        return self.available and self.status == LOOKUP_OK

    @property
    def trust_boundary(self) -> str:
        return LOOKUP_TRUST_BOUNDARY if self.available else LOOKUP_ABSENT_BOUNDARY


@dataclass
class ConsistencyReport:
    """Result of a read-only cross-check of directory, inode and lookup evidence."""

    entries: list[DirectoryEntryEvidence] = field(default_factory=list)
    lookup_table: LookupTableEvidence | None = None
    issues: list[ConsistencyIssue] = field(default_factory=list)
    root_error: str | None = None

    @property
    def consistent(self) -> bool:
        if self.root_error is not None:
            return False
        if self.lookup_table is not None and self.lookup_table.status == LOOKUP_CORRUPT:
            return False
        return not self.issues

    @property
    def ok(self) -> bool:
        """Alias for :attr:`consistent`."""
        return self.consistent

    @property
    def lookup_table_present(self) -> bool:
        return self.lookup_table is not None and self.lookup_table.available

    @property
    def shared_inodes(self) -> dict[tuple[int, int], list[str]]:
        """Paths grouped by their authoritative inode record address.

        Multiple paths for one address are hard links, not conflicts.
        """
        groups: dict[tuple[int, int], list[str]] = {}
        for entry in self.entries:
            if entry.inode_header.error is None:
                groups.setdefault(entry.inode_header.address, []).append(entry.path)
        return {address: paths for address, paths in groups.items() if len(paths) > 1}

    @property
    def all_issues(self) -> list[ConsistencyIssue]:
        """All issues, including table-level lookup table issues."""
        return list(self.issues)

    def issues_of_kind(self, kind: str) -> list[ConsistencyIssue]:
        return [issue for issue in self.all_issues if issue.kind == kind]

    def for_path(self, path: str) -> DirectoryEntryEvidence | None:
        for entry in self.entries:
            if entry.path == path:
                return entry
        return None

    def as_dict(self) -> dict:
        """Return a JSON-serializable representation of the report."""
        return {
            "consistent": self.consistent,
            "root_error": self.root_error,
            "lookup_table": None
            if self.lookup_table is None
            else {
                "available": self.lookup_table.available,
                "start": self.lookup_table.start,
                "inode_count": self.lookup_table.inode_count,
                "status": self.lookup_table.status,
                "trusted": self.lookup_table.trusted,
                "trust_boundary": self.lookup_table.trust_boundary,
                "entries": [
                    {
                        "inode_number": entry.inode_number,
                        "raw": entry.raw,
                        "address": _json_address(entry.address),
                        "absolute_block": entry.absolute_block,
                        "target_inode_number": entry.target_inode_number,
                        "target_inode_type": entry.target_inode_type,
                        "error": entry.error,
                    }
                    for entry in self.lookup_table.entries
                ],
                "issues": [_issue_dict(issue) for issue in self.lookup_table.issues],
            },
            "shared_inodes": [
                {"inode_record_address": list(address), "paths": paths} for address, paths in self.shared_inodes.items()
            ],
            "entries": [
                {
                    "path": entry.path,
                    "name": entry.name,
                    "consistent": entry.consistent,
                    "directory": {
                        "inode_number": entry.directory.inode_number,
                        "inode_type": entry.directory.inode_type,
                        "inode_number_base": entry.directory.inode_number_base,
                        "inode_number_delta": entry.directory.inode_number_delta,
                        "inode_record_address": list(entry.directory.inode_record_address),
                        "absolute_inode_record_address": _json_address(entry.directory.absolute_inode_record_address),
                        "directory_record_address": list(entry.directory.directory_record_address),
                        "directory_header_record_address": _json_address(
                            entry.directory.directory_header_record_address
                        ),
                        "trusted": entry.directory.trusted,
                        "trust_boundary": entry.directory.trust_boundary,
                    },
                    "inode_header": {
                        "inode_number": entry.inode_header.inode_number,
                        "inode_type": entry.inode_header.inode_type,
                        "address": _json_address(entry.inode_header.address),
                        "absolute_block": entry.inode_header.absolute_block,
                        "error": entry.inode_header.error,
                        "trusted": entry.inode_header.trusted,
                        "trust_boundary": entry.inode_header.trust_boundary,
                    },
                    "lookup": {
                        "available": entry.lookup.available,
                        "inode_number": entry.lookup.inode_number,
                        "raw": entry.lookup.raw,
                        "address": _json_address(entry.lookup.address),
                        "matches": entry.lookup.matches,
                        "error": entry.lookup.error,
                        "trusted": entry.lookup.trusted,
                        "trust_boundary": entry.lookup.trust_boundary,
                    },
                    "issues": [_issue_dict(issue) for issue in entry.issues],
                }
                for entry in self.entries
            ],
            "issues": [_issue_dict(issue) for issue in self.issues],
        }

    def describe(self) -> str:
        """Return a human-readable report that retains every source's raw values."""
        lines = []
        lookup = self.lookup_table
        status = "FAILED" if not self.consistent else "OK"
        lines.append(f"consistency: {status} ({len(self.entries)} directory entries, {len(self.all_issues)} issues)")
        if self.root_error is not None:
            lines.append(f"root: ERROR: {self.root_error}")

        if lookup is None:
            lines.append("lookup table: not inspected")
        else:
            state = lookup.status
            lines.append(
                f"lookup table: {state} at {lookup.start} "
                f"({len(lookup.entries)} entries, inode count {lookup.inode_count})"
            )
            lines.append(f"  trust_boundary: {lookup.trust_boundary}")
            lines.extend(f"  issue {issue.kind}: {issue.message}" for issue in lookup.issues)

        for address, paths in self.shared_inodes.items():
            lines.append(f"shared inode {address}: hardlinks {paths}")

        for entry in self.entries:
            lines.append(f"{entry.path or '/'}: {'OK' if entry.consistent else 'CONFLICT'}")
            claim = entry.directory
            lines.append(
                f"  directory: inode_number={claim.inode_number} "
                f"(base={claim.inode_number_base} delta={claim.inode_number_delta:+d}) "
                f"type={claim.inode_type} stat_type={_format_stat_type(claim.stat_type)} "
                f"inode_record_address={claim.inode_record_address} "
                f"absolute_inode_record_address={claim.absolute_inode_record_address} "
                f"directory_record_address={claim.directory_record_address} "
                f"trusted={claim.trusted}"
            )
            lines.append(f"    trust_boundary: {claim.trust_boundary}")
            header = entry.inode_header
            lines.append(
                f"  inode_header: inode_number={header.inode_number} type={header.inode_type} "
                f"stat_type={_format_stat_type(header.stat_type)} address={header.address} "
                f"absolute_block={header.absolute_block} trusted={header.trusted}"
                f"{f' error={header.error}' if header.error else ''}"
            )
            lines.append(f"    trust_boundary: {header.trust_boundary}")
            lookup_claim = entry.lookup
            lines.append(
                f"  lookup: available={lookup_claim.available} inode_number={lookup_claim.inode_number} "
                f"raw={lookup_claim.raw} address={lookup_claim.address} matches={lookup_claim.matches} "
                f"trusted={lookup_claim.trusted}"
                f"{f' error={lookup_claim.error}' if lookup_claim.error else ''}"
            )
            lines.append(f"    trust_boundary: {lookup_claim.trust_boundary}")
            lines.extend(f"  issue {issue.kind}: {issue.message}" for issue in entry.issues)

        return "\n".join(lines)

    def __str__(self) -> str:
        return self.describe()


def check_consistency(fs: SquashFS, root: INode | None = None) -> ConsistencyReport:
    """Cross-check directory entries, actual inode headers and the lookup table.

    The tree is traversed read-only from ``root`` (the filesystem root by
    default). Directory declarations, the inode header at the record address and,
    when available, the independent inode lookup table are all retained as
    separate evidence. Shared inode addresses are valid hard links and are not
    reported as conflicts.
    """
    lookup_table = _check_lookup_table(fs)
    lookup_by_number = {entry.inode_number: entry for entry in lookup_table.entries}

    report = ConsistencyReport(lookup_table=lookup_table)
    report.issues.extend(lookup_table.issues)

    root = root or fs.root
    visited: set[tuple[int, int]] = set()

    def walk(node: INode) -> None:
        address = (node.block, node.offset)
        if address in visited:
            return
        visited.add(address)

        try:
            children = list(node.iterdir())
        except Exception as exc:
            report.issues.append(
                ConsistencyIssue(
                    kind=DIRECTORY_READ_ERROR,
                    message=f"unable to read directory entries: {type(exc).__name__}: {exc}",
                    path=node.path,
                    inode_number=_safe_inode_number(node),
                    source="directory",
                )
            )
            return

        for child in children:
            entry = _check_directory_entry(fs, child, lookup_table, lookup_by_number)
            report.entries.append(entry)
            report.issues.extend(entry.issues)

            if entry.inode_header.error is None and entry.inode_header.stat_type == 0o040000:
                walk(child)

    try:
        if not root.is_dir():
            report.root_error = f"{root.path} is not a directory according to its inode header"
            return report
    except Exception as exc:
        report.root_error = f"unable to read root inode header: {type(exc).__name__}: {exc}"
        return report

    walk(root)
    return report


def _check_directory_entry(
    fs: SquashFS,
    node: INode,
    lookup_table: LookupTableEvidence,
    lookup_by_number: dict[int, LookupEntryEvidence],
) -> DirectoryEntryEvidence:
    claim = node.directory_entry
    if claim is None:
        # INode objects created directly do not carry a raw directory claim.
        claim = DirectoryClaim(
            inode_number=node.declared_inode_number if node.declared_inode_number is not None else 0,
            inode_type=node.declared_type if node.declared_type is not None else 0,
            inode_number_base=0,
            inode_number_delta=0,
            inode_block=node.block,
            inode_offset=node.offset,
            record_block=0,
            record_offset=0,
        )

    issues: list[ConsistencyIssue] = []
    absolute_block = fs.sb.inode_table_start + claim.inode_block
    header_error = _inode_address_error(fs, claim.inode_block, claim.inode_offset)
    inode_number = None
    inode_type = None

    if header_error is None:
        try:
            header = _read_inode_base_header(fs, claim.inode_block, claim.inode_offset)
            inode_number = header.inode_number
            inode_type = header.inode_type
        except Exception as exc:
            header_error = f"{type(exc).__name__}: {exc}"

    inode_header = InodeHeaderClaim(
        inode_number=inode_number,
        inode_type=inode_type,
        inode_block=claim.inode_block,
        inode_offset=claim.inode_offset,
        absolute_block=absolute_block,
        error=header_error,
    )

    if header_error is not None:
        issues.append(
            ConsistencyIssue(
                kind=INODE_HEADER_ERROR,
                message=f"unable to read inode header at ({claim.inode_block}, {claim.inode_offset}): {header_error}",
                path=node.path,
                inode_number=claim.inode_number,
                source="inode_header",
            )
        )
    else:
        issues.extend(_compare_declarations(fs, node.path, claim, inode_header))

    lookup = _lookup_claim(fs, node.path, claim, lookup_table, lookup_by_number, issues)
    return DirectoryEntryEvidence(
        path=node.path,
        name=node.name or "",
        directory=claim,
        inode_header=inode_header,
        lookup=lookup,
        issues=tuple(issues),
    )


def _compare_declarations(
    fs: SquashFS,
    path: str,
    claim: DirectoryClaim,
    inode_header: InodeHeaderClaim,
) -> list[ConsistencyIssue]:
    issues: list[ConsistencyIssue] = []

    declared_stat = claim.stat_type
    actual_stat = inode_header.stat_type

    # Directory and inode types are compared as POSIX kinds so that basic and
    # extended inode types (e.g. FILE_TYPE vs LREG_TYPE) do not produce false conflicts.
    if declared_stat is None:
        issues.append(
            ConsistencyIssue(
                kind=INVALID_DIRECTORY_TYPE,
                message=f"directory entry has unknown type {claim.inode_type}",
                path=path,
                inode_number=claim.inode_number,
                source="directory",
            )
        )
    elif actual_stat is None:
        issues.append(
            ConsistencyIssue(
                kind=INVALID_INODE_TYPE,
                message=f"inode header has unknown type {inode_header.inode_type}",
                path=path,
                inode_number=inode_header.inode_number,
                source="inode_header",
            )
        )
    elif declared_stat != actual_stat:
        issues.append(
            ConsistencyIssue(
                kind=TYPE_MISMATCH,
                message=(
                    f"directory entry declares type {claim.inode_type} ({_type_name(declared_stat)}), "
                    f"but inode header has type {inode_header.inode_type} ({_type_name(actual_stat)})"
                ),
                path=path,
                inode_number=claim.inode_number,
                source="directory/inode_header",
            )
        )

    if claim.inode_number != inode_header.inode_number:
        issues.append(
            ConsistencyIssue(
                kind=INODE_NUMBER_MISMATCH,
                message=(
                    f"directory entry declares inode number {claim.inode_number} "
                    f"(base {claim.inode_number_base} + delta {claim.inode_number_delta}), "
                    f"but inode header has inode number {inode_header.inode_number}"
                ),
                path=path,
                inode_number=claim.inode_number,
                source="directory/inode_header",
            )
        )

    for source, number in (("directory", claim.inode_number), ("inode_header", inode_header.inode_number)):
        if number is None or not (1 <= number <= fs.sb.inodes):
            issues.append(
                ConsistencyIssue(
                    kind=INODE_NUMBER_OUT_OF_RANGE,
                    message=f"inode number {number!r} is outside the declared range 1..{fs.sb.inodes}",
                    path=path,
                    inode_number=number,
                    source=source,
                )
            )

    return issues


def _lookup_claim(
    fs: SquashFS,
    path: str,
    claim: DirectoryClaim,
    lookup_table: LookupTableEvidence,
    lookup_by_number: dict[int, LookupEntryEvidence],
    issues: list[ConsistencyIssue],
) -> LookupClaim:
    if not lookup_table.available:
        return LookupClaim(available=False, inode_number=claim.inode_number)

    lookup_entry = lookup_by_number.get(claim.inode_number)
    if lookup_entry is None:
        issues.append(
            ConsistencyIssue(
                kind=LOOKUP_ENTRY_MISSING,
                message=f"lookup table has no entry for inode number {claim.inode_number}",
                path=path,
                inode_number=claim.inode_number,
                source="lookup_table",
            )
        )
        return LookupClaim(available=True, inode_number=claim.inode_number, error="entry missing")

    matches = None
    if lookup_entry.error is None:
        matches = lookup_entry.address == claim.inode_record_address
        if not matches:
            issues.append(
                ConsistencyIssue(
                    kind=LOOKUP_ADDRESS_MISMATCH,
                    message=(
                        f"lookup table entry {claim.inode_number} points to "
                        f"({lookup_entry.inode_block}, {lookup_entry.inode_offset}), but the directory entry "
                        f"refers to ({claim.inode_block}, {claim.inode_offset})"
                    ),
                    path=path,
                    inode_number=claim.inode_number,
                    source="lookup_table/directory",
                )
            )
    else:
        issues.append(
            ConsistencyIssue(
                kind=LOOKUP_ENTRY_CORRUPT,
                message=(
                    f"lookup table entry {claim.inode_number} could not be validated for this path: "
                    f"{lookup_entry.error}"
                ),
                path=path,
                inode_number=claim.inode_number,
                source="lookup_table",
            )
        )

    return LookupClaim(
        available=True,
        inode_number=claim.inode_number,
        raw=lookup_entry.raw,
        inode_block=lookup_entry.inode_block,
        inode_offset=lookup_entry.inode_offset,
        matches=matches,
        error=lookup_entry.error,
    )


def _check_lookup_table(fs: SquashFS) -> LookupTableEvidence:
    start = fs.sb.lookup_table_start
    available = start != c_squashfs.SQUASHFS_INVALID_BLK

    if not available:
        return LookupTableEvidence(
            available=False,
            start=start,
            inode_count=fs.sb.inodes,
            status=LOOKUP_ABSENT,
        )

    table = LookupTableEvidence(
        available=True,
        start=start,
        inode_count=fs.sb.inodes,
        status=LOOKUP_OK,
    )

    for inode_number in range(1, fs.sb.inodes + 1):
        entry, entry_issues = _check_lookup_entry(fs, inode_number)
        table.entries.append(entry)
        table.issues.extend(entry_issues)

    if table.issues:
        table.status = LOOKUP_CORRUPT

    return table


def _read_lookup_pointer(fs: SquashFS, inode_number: int) -> tuple[int, int, int]:
    """Read the raw pointer for one lookup entry."""
    block_index, offset = divmod((inode_number - 1) * 8, c_squashfs.SQUASHFS_METADATA_SIZE)
    if block_index >= len(fs.lookup_table):
        raise IndexError(f"lookup table index block {block_index} is outside the table")

    table_block = fs.lookup_table[block_index]
    if not (0 <= table_block < fs.sb.bytes_used):
        raise ValueError(f"lookup table metadata block {table_block} is outside the image")

    data = _read_metadata_bounded(fs, table_block, offset, 8)
    if len(data) != 8:
        raise ValueError(f"lookup table entry is truncated ({len(data)} bytes)")
    raw = struct.unpack("<Q", data)[0]

    if raw == c_squashfs.SQUASHFS_INVALID or raw >> 48:
        raise ValueError(f"invalid inode reference 0x{raw:x}")

    return raw, raw >> 16, raw & 0xFFFF


def _validate_lookup_pointer(fs: SquashFS, inode_number: int, inode_block: int, inode_offset: int) -> None:
    """Validate that a lookup pointer resolves to the inode header for ``inode_number``."""
    address_error = _inode_address_error(fs, inode_block, inode_offset)
    if address_error is not None:
        raise ValueError(address_error)

    header = _read_inode_base_header(fs, inode_block, inode_offset)
    if header.inode_number != inode_number:
        raise ValueError(
            f"lookup table entry {inode_number} points to inode header {header.inode_number} "
            f"at ({inode_block}, {inode_offset})"
        )
    if stat_type_for_inode_type(header.inode_type) is None:
        raise ValueError(f"inode header at ({inode_block}, {inode_offset}) has unknown type {header.inode_type}")


def _check_lookup_entry(fs: SquashFS, inode_number: int) -> tuple[LookupEntryEvidence, list[ConsistencyIssue]]:
    raw = None
    inode_block = None
    inode_offset = None
    target_inode_number = None
    target_inode_type = None
    error = None

    try:
        raw, inode_block, inode_offset = _read_lookup_pointer(fs, inode_number)
        _validate_lookup_pointer(fs, inode_number, inode_block, inode_offset)
        header = _read_inode_base_header(fs, inode_block, inode_offset)
        target_inode_number = header.inode_number
        target_inode_type = header.inode_type
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    issues = []
    if error is not None:
        issues.append(
            ConsistencyIssue(
                kind=LOOKUP_ENTRY_CORRUPT,
                message=f"lookup table entry {inode_number} is corrupt: {error}",
                inode_number=inode_number,
                source="lookup_table",
            )
        )

    entry = LookupEntryEvidence(
        inode_number=inode_number,
        raw=raw,
        inode_block=inode_block,
        inode_offset=inode_offset,
        absolute_block=None if inode_block is None else fs.sb.inode_table_start + inode_block,
        target_inode_number=target_inode_number,
        target_inode_type=target_inode_type,
        error=error,
        issues=tuple(issues),
    )
    return entry, issues


def _read_metadata_bounded(fs: SquashFS, block: int, offset: int, length: int) -> bytes:
    """Read metadata with an explicit block budget so a malformed chain cannot loop."""
    result = []
    budget = 4096

    while length and budget:
        budget -= 1
        next_block, data = fs._read_block(block)
        if offset > len(data):
            raise ValueError(f"offset {offset} is outside metadata block {block} ({len(data)} bytes)")

        remaining = len(data) - offset
        if remaining <= 0:
            raise ValueError(f"metadata block {block} made no progress at offset {offset}")

        if remaining <= length:
            result.append(data[offset:])
            length -= remaining
            block = next_block
            offset = 0
        else:
            result.append(data[offset : offset + length])
            length = 0

    if length:
        raise ValueError("metadata chain exceeded the read budget")

    return b"".join(result)


def _read_inode_base_header(fs: SquashFS, inode_block: int, inode_offset: int) -> c_squashfs.squashfs_base_inode_header:
    """Read the common part of the inode header at a table-relative address."""
    absolute_block = fs.sb.inode_table_start + inode_block
    data = _read_metadata_bounded(fs, absolute_block, inode_offset, len(c_squashfs.squashfs_base_inode_header))
    if len(data) != len(c_squashfs.squashfs_base_inode_header):
        raise ValueError(f"inode header at ({inode_block}, {inode_offset}) is truncated")
    return c_squashfs.squashfs_base_inode_header(data)


def _inode_address_error(fs: SquashFS, inode_block: int, inode_offset: int) -> str | None:
    if inode_block < 0:
        return f"inode block {inode_block} is negative"
    if not (0 <= inode_offset < c_squashfs.SQUASHFS_METADATA_SIZE):
        return f"inode offset {inode_offset} is outside a metadata block"

    absolute_block = fs.sb.inode_table_start + inode_block
    end = fs.sb.directory_table_start
    if end <= fs.sb.inode_table_start:
        end = fs.sb.bytes_used

    if not (fs.sb.inode_table_start <= absolute_block < end):
        return (
            f"inode record address ({absolute_block}, {inode_offset}) is outside the inode table "
            f"[{fs.sb.inode_table_start}, {end})"
        )
    if absolute_block >= fs.sb.bytes_used:
        return f"inode record address ({absolute_block}, {inode_offset}) is outside the image"

    try:
        _, data = fs._read_block(absolute_block)
    except Exception as exc:
        return f"unable to read inode metadata block {absolute_block}: {type(exc).__name__}: {exc}"

    if inode_offset >= len(data):
        return (
            f"inode offset {inode_offset} is outside the decompressed metadata block "
            f"at {absolute_block} ({len(data)} bytes)"
        )

    return None


def _json_address(address: tuple[int, int] | None) -> list[int] | None:
    return None if address is None else list(address)


def _issue_dict(issue: ConsistencyIssue) -> dict:
    return {
        "kind": issue.kind,
        "message": issue.message,
        "path": issue.path,
        "inode_number": issue.inode_number,
        "source": issue.source,
    }


def _safe_inode_number(node: INode) -> int | None:
    try:
        return node.inode_number
    except Exception:
        return None


def _format_stat_type(stat_type: int | None) -> str:
    return "unknown" if stat_type is None else f"0o{stat_type:o}"


def _type_name(stat_type: int | None) -> str:
    names = {
        0o040000: "directory",
        0o100000: "regular file",
        0o120000: "symlink",
        0o060000: "block device",
        0o020000: "character device",
        0o010000: "fifo",
        0o140000: "socket",
    }
    return names.get(stat_type, "unknown")
