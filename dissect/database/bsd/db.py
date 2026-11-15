from __future__ import annotations

from dataclasses import dataclass, replace
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.exception import CorruptRecordError

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


DBT = tuple[
    c_db.HOFFPAGE | c_db.HKEYDATA | c_db.HEAPHDR | c_db.BKEYDATA | c_db.BOVERFLOW | c_db.BINTERNAL | c_db.RINTERNAL,
    bytes,
]
"""An internal page entry structure + data (loosely related to Data-Base Thang)."""

HASH_PAGE_TYPES = (c_db.P_HASH_UNSORTED, c_db.P_HASH)
BTREE_LEAF_PAGE_TYPES = (c_db.P_LBTREE, c_db.P_LDUP, c_db.P_LRECNO)
BTREE_INTERNAL_PAGE_TYPES = (c_db.P_IBTREE, c_db.P_IRECNO)


@dataclass(frozen=True)
class Location:
    """The physical origin of a key or value.

    Args:
        pgno: Page number containing the entry.
        slot: Zero-based index into the page its lookup array.
        page_type: Berkeley DB page type the entry was read from.
    """

    pgno: int
    slot: int
    page_type: int | None = None


@dataclass(frozen=True)
class RecordIssue:
    """A structural problem encountered while reading a record.

    The ``pgno`` and ``slot`` always identify the record entry that owns the
    problem. For overflow problems ``overflow_pgno`` identifies the page in the
    overflow chain that caused the problem.

    Args:
        kind: Short, stable identifier for the kind of problem.
        pgno: Page number of the record entry the problem belongs to.
        slot: Slot index of the record entry the problem belongs to.
        field: Which part of the record is affected: ``key``, ``value`` or ``record``.
        message: Human readable explanation.
        overflow_pgno: Overflow page involved in the problem, if any.
        expected: Expected length, if applicable.
        actual: Actually available length, if applicable.
    """

    kind: str
    pgno: int = 0
    slot: int | None = None
    field: str = "record"
    message: str = ""
    overflow_pgno: int | None = None
    expected: int | None = None
    actual: int | None = None

    @property
    def page(self) -> int:
        """Alias for :attr:`pgno`."""
        return self.pgno

    @property
    def index(self) -> int | None:
        """Alias for :attr:`slot`."""
        return self.slot

    def __str__(self) -> str:
        location = f"pgno={self.pgno}"
        if self.slot is not None:
            location += f" slot={self.slot}"
        message = f"{self.kind} at {location} ({self.field})"
        if self.overflow_pgno is not None:
            message += f" overflow_pgno={self.overflow_pgno}"
        if self.expected is not None or self.actual is not None:
            message += f" expected={self.expected} actual={self.actual}"
        if self.message:
            message += f": {self.message}"
        return message


@dataclass(frozen=True)
class Slot:
    """A single parsed page entry, including whether it could be read completely.

    Args:
        pgno: Page number containing the entry.
        index: Slot index in the page.
        type: Raw entry type byte, if it could be read.
        entry: Parsed cstruct entry, if its header could be read.
        data: Entry data. For corrupt entries this is the proven prefix only.
        complete: Whether the entry (including overflow data) was read completely.
        deleted: Whether the Berkeley DB delete flag is set on the entry.
        issues: Problems encountered while reading this entry.
        pages: Overflow pages that contributed to :attr:`data`.
        overflow_pgno: First overflow page declared by the entry, if any.
        overflow_size: Total overflow length declared by the entry, if any.
        page_type: Berkeley DB page type this slot was read from.
    """

    pgno: int
    index: int
    type: int | None
    entry: object | None
    data: bytes
    complete: bool
    deleted: bool = False
    issues: tuple[RecordIssue, ...] = ()
    pages: tuple[int, ...] = ()
    overflow_pgno: int | None = None
    overflow_size: int | None = None
    page_type: int | None = None

    @property
    def location(self) -> Location:
        """Physical location of this slot."""
        return Location(self.pgno, self.index, self.page_type)


@dataclass(frozen=True)
class OverflowResult:
    """The result of reading an overflow item.

    Args:
        data: Bytes that could be proven to belong to the item.
        pages: Overflow pages that contributed to :attr:`data`.
        complete: Whether exactly ``expected`` bytes were read.
        expected: Requested length from the entry's overflow descriptor.
        issues: Problems encountered while following the overflow chain.
    """

    data: bytes
    pages: tuple[int, ...]
    complete: bool
    expected: int
    issues: tuple[RecordIssue, ...] = ()


@dataclass(frozen=True)
class Record:
    """A key/value record with its physical origin and completeness.

    In recovery mode incomplete records are yielded with :attr:`value` containing
    only the bytes that could be proven to belong to that record. Bytes from a
    neighbouring slot, page or record are never used to fill the gap.

    Args:
        key: Record key, or the record number for RECNO databases.
        value: Record value. For incomplete records this is the proven prefix.
        key_location: Physical origin of the key.
        value_location: Physical origin of the value.
        complete: Whether key and value were both read completely.
        issues: Problems encountered while reading this record.
    """

    key: bytes | int
    value: bytes
    key_location: Location | None = None
    value_location: Location | None = None
    complete: bool = True
    issues: tuple[RecordIssue, ...] = ()

    @property
    def data(self) -> bytes:
        """Alias for :attr:`value`, matching the historic ``records`` tuple."""
        return self.value

    @property
    def incomplete(self) -> bool:
        """Whether this record is an incomplete recovery candidate."""
        return not self.complete

    @property
    def pgno(self) -> int | None:
        """Page number of the key entry."""
        return self.key_location.pgno if self.key_location else None

    @property
    def slot(self) -> int | None:
        """Slot index of the key entry."""
        return self.key_location.slot if self.key_location else None

    @property
    def key_page(self) -> int | None:
        """Page number of the key entry."""
        return self.key_location.pgno if self.key_location else None

    @property
    def key_slot(self) -> int | None:
        """Slot index of the key entry."""
        return self.key_location.slot if self.key_location else None

    @property
    def value_page(self) -> int | None:
        """Page number of the value entry."""
        return self.value_location.pgno if self.value_location else None

    @property
    def value_slot(self) -> int | None:
        """Slot index of the value entry."""
        return self.value_location.slot if self.value_location else None

    def __iter__(self) -> Iterator[bytes | int]:
        """Allow unpacking as ``key, value``."""
        yield self.key
        yield self.value


@dataclass(frozen=True)
class RecordReport:
    """A forensic report of a record walk.

    Args:
        records: All yielded records, including incomplete candidates.
        issues: All structural issues encountered, deduplicated.
    """

    records: tuple[Record, ...]
    issues: tuple[RecordIssue, ...]

    @property
    def complete(self) -> tuple[Record, ...]:
        """Only records that were read completely."""
        return tuple(record for record in self.records if record.complete)

    @property
    def incomplete(self) -> tuple[Record, ...]:
        """Only incomplete recovery candidates."""
        return tuple(record for record in self.records if not record.complete)


class DB:
    """Berkeley DB.

    Args:
        fh: File-like object containing the Berkeley DB data. The file is only
            ever read from; it is never modified.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)

        meta = c_db.DBMETA(self.fh)
        self.fh.seek(0)

        if meta.magic == c_db.DB_BTREEMAGIC and meta.type == c_db.P_BTREEMETA:
            self.meta = c_db.BTMETA(self.fh)
        elif meta.magic == c_db.DB_HASHMAGIC and meta.type == c_db.P_HASHMETA:
            self.meta = c_db.HMETA(self.fh)
        else:
            raise NotImplementedError(f"Unsupported DB type: {meta.magic:#x} {meta.type}")

        self.page_size = self.meta.dbmeta.pagesize

        page_overhead = len(c_db.PAGE)
        if self.meta.dbmeta.flags & c_db.DB_AM_ENCRYPT:
            page_overhead += len(c_db.PG_CRYPTO)
        elif self.meta.dbmeta.flags & c_db.DB_AM_CHKSUM:
            page_overhead += len(c_db.PG_CHKSUM)
        self._page_overhead = page_overhead

        self.fh.seek(0, 2)
        self.file_size = self.fh.tell()
        self.fh.seek(0)

        self._last_issues: tuple[RecordIssue, ...] = ()

        self.page = lru_cache(128)(self.page)

    @property
    def is_btree(self) -> bool:
        """Return whether the database of a ``DB_BTREE`` type."""
        return self.meta.dbmeta.magic == c_db.DB_BTREEMAGIC

    @property
    def is_recno(self) -> bool:
        """Return whether the database is a ``DB_RECNO`` type."""
        return self.is_btree and (self.meta.dbmeta.flags & c_db.BTM_RECNO) != 0

    @property
    def is_hash(self) -> bool:
        """Return whether the database is a ``DB_HASH`` type."""
        return self.meta.dbmeta.magic == c_db.DB_HASHMAGIC

    @property
    def page_count(self) -> int:
        """Number of pages that have at least a readable page header in the file."""
        if not self.page_size:
            return 0
        return (self.file_size + self.page_size - 1) // self.page_size

    def has_page(self, pgno: int) -> bool:
        """Whether ``pgno`` starts inside the file.

        A trailing page that is shorter than ``page_size`` is still considered
        present: its readable prefix is evidence and any missing bytes are
        reported as a truncated page.
        """
        if pgno < 0 or not self.page_size:
            return False
        return pgno * self.page_size < self.file_size

    @property
    def issues(self) -> tuple[RecordIssue, ...]:
        """Issues collected by the last completed record iteration."""
        return self._last_issues

    def page(self, pgno: int) -> Page:
        """Get a single page by page number.

        Args:
            pgno: Page number to retrieve.
        """
        return Page(self, pgno)

    def records(self, recover: bool = False) -> Iterator[tuple[bytes | int, bytes] | Record]:
        """Iterate over records in the database.

        By default only completely readable ``(key, value)`` pairs are yielded.
        Corrupt records are isolated and do not consume or borrow bytes from a
        neighbouring entry. With ``recover=True`` every candidate is yielded as
        a :class:`Record`, including incomplete ones whose :attr:`Record.value`
        holds only the bytes that could be proven to belong to that record.

        Args:
            recover: Yield incomplete recovery candidates as :class:`Record` objects.
        """
        for record in self.iter_records(recover=recover):
            if recover:
                yield record
            elif record.complete:
                yield record.key, record.value

    def iter_records(
        self,
        recover: bool = False,
        issues: list[RecordIssue] | None = None,
    ) -> Iterator[Record]:
        """Iterate over records with their physical origin.

        Args:
            recover: Yield incomplete recovery candidates instead of skipping them.
            issues: Optional list to append all encountered issues to.
        """
        collected: list[RecordIssue] = [] if issues is None else issues
        self._last_issues = ()
        reported = 0

        if self.is_btree and not self.is_recno:
            source = self._iter_btree_records(recover, collected)
        elif self.is_hash:
            source = self._iter_hash_records(recover, collected)
        elif self.is_recno:
            source = self._iter_recno_records(recover, collected)
        else:
            raise NotImplementedError("Unsupported DB type")

        for record in source:
            if len(collected) != reported:
                reported = len(collected)
                self._last_issues = _unique_issues(collected)
            yield record

        if len(collected) != reported:
            self._last_issues = _unique_issues(collected)

    def record_report(self, recover: bool = True) -> RecordReport:
        """Walk all records and return a report including incomplete candidates.

        Args:
            recover: Include incomplete recovery candidates in the report.
        """
        issues: list[RecordIssue] = []
        records = tuple(self.iter_records(recover=recover, issues=issues))
        return RecordReport(records=records, issues=_unique_issues(issues))

    def read_overflow(
        self,
        pgno: int,
        size: int,
        *,
        record_pgno: int = 0,
        record_slot: int | None = None,
        field: str = "value",
    ) -> OverflowResult:
        """Read an overflow item without ever borrowing bytes from another item.

        The walk stops at the declared ``size``, at ``PGNO_INVALID`` or at the
        first structural problem. Only bytes from pages that were proven to be
        part of this overflow chain are returned.

        Args:
            pgno: First overflow page.
            size: Total item length from the entry's overflow descriptor.
            record_pgno: Page number of the owning record entry, for diagnostics.
            record_slot: Slot index of the owning record entry, for diagnostics.
            field: Which part of the record owns the overflow item.
        """
        issues: list[RecordIssue] = []
        pages: list[int] = []
        chunks: list[bytes] = []
        remaining = max(0, size)
        current = pgno
        last_page: int | None = None
        seen: set[int] = set()

        def add_issue(
            kind: str,
            message: str,
            overflow_pgno: int | None = None,
            expected: int | None = None,
            actual: int | None = None,
        ) -> None:
            issues.append(
                RecordIssue(
                    kind=kind,
                    pgno=record_pgno,
                    slot=record_slot,
                    field=field,
                    message=message,
                    overflow_pgno=overflow_pgno,
                    expected=expected,
                    actual=actual,
                )
            )

        if remaining == 0:
            return OverflowResult(b"", (), True, size)

        if current == c_db.PGNO_INVALID:
            add_issue("overflow-missing", "overflow descriptor has no page", current, remaining, 0)
            return OverflowResult(b"", (), False, size, tuple(issues))

        while remaining > 0:
            if current == c_db.PGNO_INVALID:
                add_issue(
                    "overflow-chain-truncated",
                    "overflow chain ended before the declared length",
                    last_page if last_page is not None else current,
                    size,
                    size - remaining,
                )
                break

            if current in seen:
                add_issue("overflow-cycle", "overflow chain contains a cycle", current, size, size - remaining)
                break
            seen.add(current)

            if not self.has_page(current):
                add_issue(
                    "overflow-page-out-of-range",
                    "overflow page lies outside the file",
                    current,
                    size,
                    size - remaining,
                )
                break

            page = self.page(current)
            try:
                header = page.header
            except CorruptRecordError as e:
                issues.append(e.issue)
                break

            if header.type != c_db.P_OVERFLOW:
                add_issue(
                    "overflow-page-type",
                    f"expected overflow page, got type {header.type}",
                    current,
                    size,
                    size - remaining,
                )
                break

            if header.pgno != current:
                add_issue(
                    "overflow-page-number-mismatch",
                    f"page header claims pgno {header.pgno}",
                    current,
                    size,
                    size - remaining,
                )

            available = min(header.hf_offset, len(page.data))
            if header.hf_offset > len(page.data):
                add_issue(
                    "overflow-page-truncated",
                    "overflow page is shorter than its declared data length",
                    current,
                    header.hf_offset,
                    len(page.data),
                )
            if available <= 0:
                add_issue("overflow-page-empty", "overflow page has no data", current, remaining, 0)
                break

            read_size = min(remaining, available)
            chunks.append(bytes(page.data[:read_size]))
            pages.append(current)
            last_page = current
            remaining -= read_size

            if remaining <= 0:
                break

            current = header.next_pgno

        data = b"".join(chunks)
        complete = remaining == 0 and len(data) == size and not issues
        return OverflowResult(data, tuple(pages), complete, size, _unique_issues(issues))

    def _iter_btree_records(self, recover: bool, issues: list[RecordIssue]) -> Iterator[Record]:
        yield from self._walk_btree_records(self.meta.root, recover, issues, set())

    def _walk_btree_records(
        self,
        pgno: int,
        recover: bool,
        issues: list[RecordIssue],
        visited: set[int],
    ) -> Iterator[Record]:
        if pgno in visited:
            issues.append(RecordIssue("btree-cycle", pgno, None, "record", "btree page is referenced more than once"))
            return
        if not self.has_page(pgno):
            issues.append(RecordIssue("invalid-child-page", pgno, None, "record", "child page lies outside the file"))
            return
        visited.add(pgno)

        page = self.page(pgno)
        try:
            page_type = page.header.type
        except CorruptRecordError as e:
            issues.append(e.issue)
            return

        if page_type in BTREE_INTERNAL_PAGE_TYPES:
            for index in range(len(page.lookup)):
                slot = page.read_entry(index, field="record")
                if slot.issues:
                    issues.extend(slot.issues)
                if slot.entry is None:
                    continue

                child = getattr(slot.entry, "pgno", None)
                if child in (None, c_db.PGNO_INVALID) or not self.has_page(child):
                    issues.append(
                        RecordIssue(
                            "invalid-child-page",
                            page.pgno,
                            index,
                            "record",
                            f"invalid child page number {child}",
                            expected=1,
                            actual=child,
                        )
                    )
                    continue
                yield from self._walk_btree_records(child, recover, issues, visited)
        elif page_type == c_db.P_LBTREE:
            yield from self._records_from_page(page, recover, issues)
        elif page_type == c_db.P_LDUP:
            issues.append(
                RecordIssue(
                    "unsupported-duplicate-page",
                    page.pgno,
                    None,
                    "record",
                    "off-page duplicate leaf is not implemented",
                )
            )
        else:
            issues.append(
                RecordIssue(
                    "unexpected-page-type",
                    page.pgno,
                    None,
                    "record",
                    f"unexpected btree page type {page_type}",
                )
            )

    def _iter_hash_records(self, recover: bool, issues: list[RecordIssue]) -> Iterator[Record]:
        seen: set[int] = set()

        max_bucket = self.meta.max_bucket
        if max_bucket >= self.page_count:
            issues.append(
                RecordIssue(
                    "invalid-bucket-count",
                    0,
                    None,
                    "record",
                    "metadata declares more hash buckets than the file has pages",
                    expected=max(0, self.page_count - 1),
                    actual=max_bucket,
                )
            )
            max_bucket = max(0, self.page_count - 1)

        for bucket in range(max_bucket + 1):
            try:
                pgno = BUCKET_TO_PAGE(self, bucket)
            except (IndexError, TypeError) as e:
                issues.append(RecordIssue("invalid-bucket", bucket, None, "record", f"cannot map bucket: {e}"))
                continue

            if pgno == c_db.PGNO_INVALID:
                continue

            chain_seen: set[int] = set()
            while pgno != c_db.PGNO_INVALID:
                if pgno in chain_seen:
                    issues.append(
                        RecordIssue(
                            "hash-chain-cycle",
                            pgno,
                            None,
                            "record",
                            f"hash bucket {bucket} chain contains a cycle",
                        )
                    )
                    break
                if pgno in seen:
                    issues.append(
                        RecordIssue(
                            "hash-chain-duplicate",
                            pgno,
                            None,
                            "record",
                            f"page already reached by another hash bucket (bucket {bucket})",
                        )
                    )
                    break
                chain_seen.add(pgno)
                seen.add(pgno)

                if not self.has_page(pgno):
                    issues.append(
                        RecordIssue(
                            "hash-page-out-of-range",
                            pgno,
                            None,
                            "record",
                            f"hash bucket {bucket} points outside the file",
                        )
                    )
                    break

                page = self.page(pgno)
                try:
                    page_type = page.header.type
                except CorruptRecordError as e:
                    issues.append(e.issue)
                    break

                if page_type not in HASH_PAGE_TYPES:
                    issues.append(
                        RecordIssue(
                            "unexpected-page-type",
                            page.pgno,
                            None,
                            "record",
                            f"hash bucket {bucket} points at page type {page_type}",
                        )
                    )
                    break

                yield from self._records_from_page(page, recover, issues)
                pgno = page.header.next_pgno

    def _iter_recno_records(self, recover: bool, issues: list[RecordIssue]) -> Iterator[Record]:
        recno = 0
        for slot in self._walk_recno_slots(self.meta.root, issues, set()):
            recno += 1
            if slot.deleted:
                continue
            if not slot.complete:
                issues.extend(slot.issues)
                if recover:
                    yield Record(
                        recno,
                        slot.data,
                        slot.location,
                        slot.location,
                        False,
                        slot.issues,
                    )
                continue
            yield Record(recno, slot.data, slot.location, slot.location)

    def _walk_recno_slots(
        self,
        pgno: int,
        issues: list[RecordIssue],
        visited: set[int],
    ) -> Iterator[Slot]:
        if pgno in visited:
            issues.append(RecordIssue("btree-cycle", pgno, None, "record", "recno page is referenced more than once"))
            return
        if not self.has_page(pgno):
            issues.append(RecordIssue("invalid-child-page", pgno, None, "record", "child page lies outside the file"))
            return
        visited.add(pgno)

        page = self.page(pgno)
        try:
            page_type = page.header.type
        except CorruptRecordError as e:
            issues.append(e.issue)
            return

        if page_type in (c_db.P_IRECNO, c_db.P_IBTREE):
            for index in range(len(page.lookup)):
                slot = page.read_entry(index, field="record")
                if slot.issues:
                    issues.extend(slot.issues)
                child = getattr(slot.entry, "pgno", None) if slot.entry is not None else None
                if child in (None, c_db.PGNO_INVALID) or not self.has_page(child):
                    issues.append(
                        RecordIssue(
                            "invalid-child-page",
                            page.pgno,
                            index,
                            "record",
                            f"invalid child page number {child}",
                        )
                    )
                    continue
                yield from self._walk_recno_slots(child, issues, visited)
        elif page_type == c_db.P_LRECNO:
            for index in range(len(page.lookup)):
                slot = page.read_entry(index, field="record")
                if slot.issues:
                    issues.extend(slot.issues)
                yield slot
        else:
            issues.append(
                RecordIssue(
                    "unexpected-page-type",
                    page.pgno,
                    None,
                    "record",
                    f"unexpected recno page type {page_type}",
                )
            )

    def _records_from_page(
        self,
        page: Page,
        recover: bool,
        issues: list[RecordIssue],
    ) -> Iterator[Record]:
        count = len(page.lookup)
        page_issues = page.page_issues
        if page_issues:
            issues.extend(page_issues)

        for index in range(0, count, 2):
            key_slot = page.read_entry(index, field="key")

            if index + 1 >= count:
                record_issue = RecordIssue(
                    "orphan-key",
                    page.pgno,
                    index,
                    "key",
                    "key slot has no paired value slot on this page",
                )
                candidate_issues = _unique_issues((*key_slot.issues, record_issue))
                issues.extend(candidate_issues)
                if recover:
                    yield Record(
                        key_slot.data,
                        b"",
                        key_slot.location,
                        None,
                        False,
                        candidate_issues,
                    )
                continue

            value_slot = page.read_entry(index + 1, field="value")

            if key_slot.deleted or value_slot.deleted:
                if key_slot.deleted != value_slot.deleted:
                    record_issue = RecordIssue(
                        "inconsistent-delete-flag",
                        page.pgno,
                        index + (1 if value_slot.deleted else 0),
                        "value" if value_slot.deleted else "key",
                        "only one half of the key/value pair is marked deleted",
                    )
                    candidate_issues = _unique_issues((*key_slot.issues, *value_slot.issues, record_issue))
                    issues.extend(candidate_issues)
                    if recover:
                        yield Record(
                            key_slot.data,
                            value_slot.data,
                            key_slot.location,
                            value_slot.location,
                            False,
                            candidate_issues,
                        )
                continue

            record_issues = _unique_issues((*key_slot.issues, *value_slot.issues))
            complete = key_slot.complete and value_slot.complete
            if record_issues:
                issues.extend(record_issues)

            if complete or recover:
                yield Record(
                    key_slot.data,
                    value_slot.data,
                    key_slot.location,
                    value_slot.location,
                    complete,
                    record_issues,
                )

    def _iter_db(self) -> Iterator[DBT]:
        if self.is_btree:
            yield from self._iter_btree()
        elif self.is_hash:
            yield from self._iter_hash()
        else:
            raise NotImplementedError("Unsupported DB type")

    def _iter_btree(self) -> Iterator[DBT]:
        yield from self._walk_btree(self.meta.root, set())

    def _walk_btree(self, pgno: int, visited: set[int] | None = None) -> Iterator[DBT]:
        visited = set() if visited is None else visited
        if pgno in visited or not self.has_page(pgno):
            return
        visited.add(pgno)

        page = self.page(pgno)
        try:
            page_type = page.header.type
        except CorruptRecordError:
            return

        if page_type in BTREE_INTERNAL_PAGE_TYPES:
            for index in range(len(page.lookup)):
                slot = page.read_entry(index)
                child = getattr(slot.entry, "pgno", None) if slot.entry is not None else None
                if child is None:
                    continue
                yield from self._walk_btree(child, visited)
        elif page_type in BTREE_LEAF_PAGE_TYPES:
            for index in range(len(page.lookup)):
                slot = page.read_entry(index)
                if slot.entry is not None:
                    yield slot.entry, slot.data

    def _iter_hash(self) -> Iterator[DBT]:
        max_bucket = min(self.meta.max_bucket, max(0, self.page_count - 1))
        for i in range(max_bucket + 1):
            try:
                pgno = BUCKET_TO_PAGE(self, i)
            except (IndexError, TypeError):
                continue
            yield from self._walk_hash(pgno, set())

    def _walk_hash(self, pgno: int, visited: set[int] | None = None) -> Iterator[DBT]:
        visited = set() if visited is None else visited
        while pgno not in (c_db.PGNO_INVALID, None) and pgno not in visited and self.has_page(pgno):
            visited.add(pgno)
            page = self.page(pgno)
            try:
                page_type = page.header.type
            except CorruptRecordError:
                return

            for index in range(len(page.lookup)):
                slot = page.read_entry(index)
                if slot.entry is not None:
                    yield slot.entry, slot.data

            if page_type not in HASH_PAGE_TYPES:
                return
            pgno = page.header.next_pgno


class Page:
    """A single page in a Berkeley DB.

    Args:
        db: The parent ``DB`` instance.
        pgno: The page number to load.
    """

    def __init__(self, db: DB, pgno: int):
        self.db = db
        self.pgno = pgno
        self.offset = pgno * self.db.page_size

    @cached_property
    def raw(self) -> bytes:
        """Raw page data."""
        self.db.fh.seek(self.offset)
        return self.db.fh.read(self.db.page_size)

    @cached_property
    def data(self) -> memoryview:
        """Page data, excluding any overhead (headers)."""
        return memoryview(self.raw)[self.db._page_overhead :]

    @cached_property
    def header(self) -> c_db.PAGE:
        """Page header."""
        if len(self.raw) < len(c_db.PAGE):
            raise CorruptRecordError(
                RecordIssue("truncated-page", self.pgno, None, "record", "page header is truncated")
            )
        return c_db.PAGE(self.raw)

    @property
    def type(self) -> int:
        """Page type."""
        return self.header.type

    @cached_property
    def _lookup(self) -> tuple[list[int], tuple[RecordIssue, ...]]:
        issues: list[RecordIssue] = []
        try:
            header = self.header
        except CorruptRecordError as e:
            return [], (e.issue,)

        if header.type not in (
            c_db.P_LBTREE,
            c_db.P_IBTREE,
            c_db.P_LRECNO,
            c_db.P_IRECNO,
            c_db.P_HASH,
            c_db.P_HASH_UNSORTED,
            c_db.P_LDUP,
        ):
            return [], ()

        count = header.entries
        max_count = max(0, (self.db.page_size - self.db._page_overhead) // 2)
        if count > max_count:
            issues.append(
                RecordIssue(
                    "invalid-entry-count",
                    self.pgno,
                    None,
                    "record",
                    "entry count exceeds page capacity",
                    expected=max_count,
                    actual=count,
                )
            )
            count = max_count

        available = len(self.data) // 2
        if count > available:
            issues.append(
                RecordIssue(
                    "truncated-page",
                    self.pgno,
                    None,
                    "record",
                    "page is shorter than its entry count requires",
                    expected=count,
                    actual=available,
                )
            )
            count = available

        if count <= 0:
            return [], tuple(issues)

        return list(c_db.uint16[count](self.data)), tuple(issues)

    @property
    def lookup(self) -> list[int]:
        """List of offsets to entries in the page."""
        return self._lookup[0]

    @property
    def page_issues(self) -> tuple[RecordIssue, ...]:
        """Structural issues with the page itself."""
        return self._lookup[1]

    @property
    def entry_count(self) -> int:
        """Number of readable slots in the page."""
        return len(self.lookup)

    def read_entry(self, index: int, field: str = "value") -> Slot:
        """Read a single entry without ever crossing its slot boundary.

        Corrupt entries are returned as incomplete :class:`Slot` objects with
        only the bytes that could be proven to belong to that slot.

        Args:
            index: Index of the entry to retrieve.
            field: Which part of the record the entry represents, for diagnostics.
        """
        slot = self._read_entry(index, field)
        if slot.page_type is not None:
            return slot
        try:
            page_type = self.header.type
        except CorruptRecordError:
            return slot
        return replace(slot, page_type=page_type)

    def _read_entry(self, index: int, field: str = "value") -> Slot:
        issues: list[RecordIssue] = []
        offsets, lookup_issues = self._lookup
        issues.extend(lookup_issues)

        if index < 0 or index >= len(offsets):
            issues.append(
                RecordIssue(
                    "slot-out-of-range",
                    self.pgno,
                    index,
                    field,
                    "entry slot does not exist in the page lookup array",
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        try:
            header = self.header
        except CorruptRecordError as e:
            issues.append(e.issue)
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        offset = offsets[index]
        upper = self.db.page_size if index == 0 else offsets[index - 1]
        raw_length = len(self.raw)
        clamped = upper > raw_length
        if clamped:
            upper = raw_length
            issues.append(
                RecordIssue(
                    "truncated-page",
                    self.pgno,
                    index,
                    field,
                    "page data ends before the slot's upper bound",
                    expected=self.db.page_size,
                    actual=raw_length,
                )
            )

        min_offset = self.db._page_overhead + len(offsets) * 2
        if offset < self.db._page_overhead or offset < min_offset or offset >= self.db.page_size:
            issues.append(
                RecordIssue(
                    "invalid-slot-offset",
                    self.pgno,
                    index,
                    field,
                    "slot offset points outside the item area",
                    expected=min_offset,
                    actual=offset,
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        if offset > upper:
            issues.append(
                RecordIssue(
                    "invalid-slot-bound",
                    self.pgno,
                    index,
                    field,
                    "slot starts after its upper bound",
                    expected=upper,
                    actual=offset,
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        if header.hf_offset and offset < header.hf_offset:
            issues.append(
                RecordIssue(
                    "invalid-slot-offset",
                    self.pgno,
                    index,
                    field,
                    "slot offset points into the free area",
                    expected=header.hf_offset,
                    actual=offset,
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        buf = self.raw[offset:upper]

        if header.type in HASH_PAGE_TYPES:
            return replace(self._read_hash_slot(index, buf, field, issues, clamped), page_type=header.type)
        if header.type in (c_db.P_LBTREE, c_db.P_LDUP, c_db.P_LRECNO):
            return replace(self._read_btree_slot(index, buf, field, issues, clamped), page_type=header.type)
        if header.type == c_db.P_IBTREE:
            return replace(self._read_btree_internal_slot(index, buf, field, issues), page_type=header.type)
        if header.type == c_db.P_IRECNO:
            return replace(self._read_recno_internal_slot(index, buf, field, issues), page_type=header.type)

        issues.append(
            RecordIssue(
                "unexpected-page-type",
                self.pgno,
                index,
                field,
                f"page type {header.type} does not contain readable entries",
            )
        )
        return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

    def _read_hash_slot(
        self,
        index: int,
        buf: bytes,
        field: str,
        issues: list[RecordIssue],
        clamped: bool = False,
    ) -> Slot:
        if not buf:
            issues.append(RecordIssue("truncated-entry-header", self.pgno, index, field, "hash entry has no type byte"))
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        type_byte = buf[0]
        entry_type = type_byte & ~c_db.B_DELETE
        deleted = bool(type_byte & c_db.B_DELETE)

        if entry_type == c_db.H_OFFPAGE:
            if len(buf) < len(c_db.HOFFPAGE):
                issues.append(
                    RecordIssue(
                        "truncated-entry-header",
                        self.pgno,
                        index,
                        field,
                        "off-page hash entry is truncated",
                        expected=len(c_db.HOFFPAGE),
                        actual=len(buf),
                    )
                )
                return Slot(self.pgno, index, type_byte, None, b"", False, deleted, tuple(issues))

            entry = c_db.HOFFPAGE(buf)
            overflow = self.db.read_overflow(
                entry.pgno,
                entry.tlen,
                record_pgno=self.pgno,
                record_slot=index,
                field=field,
            )
            issues.extend(overflow.issues)
            return Slot(
                self.pgno,
                index,
                type_byte,
                entry,
                overflow.data,
                overflow.complete,
                deleted,
                tuple(issues),
                overflow.pages,
                entry.pgno,
                entry.tlen,
            )

        if entry_type == c_db.H_OFFDUP:
            if len(buf) < len(c_db.HOFFDUP):
                issues.append(
                    RecordIssue(
                        "truncated-entry-header",
                        self.pgno,
                        index,
                        field,
                        "off-page duplicate hash entry is truncated",
                    )
                )
                return Slot(self.pgno, index, type_byte, None, b"", False, deleted, tuple(issues))
            entry = c_db.HOFFDUP(buf)
            issues.append(
                RecordIssue(
                    "unsupported-duplicate",
                    self.pgno,
                    index,
                    field,
                    "off-page hash duplicates are not implemented",
                    overflow_pgno=entry.pgno,
                )
            )
            return Slot(
                self.pgno,
                index,
                type_byte,
                entry,
                b"",
                False,
                deleted,
                tuple(issues),
                (),
                entry.pgno,
                None,
            )

        if entry_type in (c_db.H_KEYDATA, c_db.H_DUPLICATE):
            entry = c_db.HKEYDATA(buf)
            data = buf[len(c_db.HKEYDATA) :]
            return Slot(
                self.pgno,
                index,
                type_byte,
                entry,
                bytes(data),
                not clamped,
                deleted,
                tuple(issues),
            )

        issues.append(
            RecordIssue(
                "unknown-entry-type",
                self.pgno,
                index,
                field,
                f"unknown hash entry type {entry_type}",
            )
        )
        return Slot(self.pgno, index, type_byte, None, b"", False, deleted, tuple(issues))

    def _read_btree_slot(
        self,
        index: int,
        buf: bytes,
        field: str,
        issues: list[RecordIssue],
        clamped: bool = False,
    ) -> Slot:
        if len(buf) < len(c_db.BKEYDATA):
            issues.append(
                RecordIssue(
                    "truncated-entry-header",
                    self.pgno,
                    index,
                    field,
                    "btree entry header is truncated",
                    expected=len(c_db.BKEYDATA),
                    actual=len(buf),
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        entry_type_byte = buf[2]
        entry_type = entry_type_byte & ~c_db.B_DELETE
        deleted = bool(entry_type_byte & c_db.B_DELETE)
        declared_length = int.from_bytes(buf[0:2], "little")

        if entry_type in (c_db.B_OVERFLOW, c_db.B_DUPLICATE):
            if len(buf) < len(c_db.BOVERFLOW):
                issues.append(
                    RecordIssue(
                        "truncated-entry-header",
                        self.pgno,
                        index,
                        field,
                        "off-page btree entry is truncated",
                        expected=len(c_db.BOVERFLOW),
                        actual=len(buf),
                    )
                )
                return Slot(self.pgno, index, entry_type_byte, None, b"", False, deleted, tuple(issues))

            entry = c_db.BOVERFLOW(buf)
            overflow = self.db.read_overflow(
                entry.pgno,
                entry.tlen,
                record_pgno=self.pgno,
                record_slot=index,
                field=field,
            )
            issues.extend(overflow.issues)
            return Slot(
                self.pgno,
                index,
                entry_type_byte,
                entry,
                overflow.data,
                overflow.complete,
                deleted,
                tuple(issues),
                overflow.pages,
                entry.pgno,
                entry.tlen,
            )

        entry = c_db.BKEYDATA(buf)
        available = max(0, len(buf) - len(c_db.BKEYDATA))
        data_length = min(declared_length, available)
        data = bytes(buf[len(c_db.BKEYDATA) : len(c_db.BKEYDATA) + data_length])
        complete = declared_length <= available and not clamped
        if declared_length > available:
            issues.append(
                RecordIssue(
                    "truncated-entry",
                    self.pgno,
                    index,
                    field,
                    "declared entry length extends past its slot",
                    expected=declared_length,
                    actual=available,
                )
            )

        return Slot(
            self.pgno,
            index,
            entry_type_byte,
            entry,
            data,
            complete,
            deleted,
            tuple(issues),
        )

    def _read_btree_internal_slot(
        self,
        index: int,
        buf: bytes,
        field: str,
        issues: list[RecordIssue],
    ) -> Slot:
        if len(buf) < len(c_db.BINTERNAL):
            issues.append(
                RecordIssue(
                    "truncated-entry-header",
                    self.pgno,
                    index,
                    field,
                    "btree internal entry header is truncated",
                    expected=len(c_db.BINTERNAL),
                    actual=len(buf),
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        entry = c_db.BINTERNAL(buf)
        available = max(0, len(buf) - len(c_db.BINTERNAL))
        data_length = min(entry.len, available)
        data = bytes(buf[len(c_db.BINTERNAL) : len(c_db.BINTERNAL) + data_length])
        complete = entry.len <= available
        if entry.len > available:
            issues.append(
                RecordIssue(
                    "truncated-entry",
                    self.pgno,
                    index,
                    field,
                    "declared internal key length extends past its slot",
                    expected=entry.len,
                    actual=available,
                )
            )

        return Slot(
            self.pgno,
            index,
            entry.type,
            entry,
            data,
            complete,
            bool(entry.type & c_db.B_DELETE),
            tuple(issues),
        )

    def _read_recno_internal_slot(
        self,
        index: int,
        buf: bytes,
        field: str,
        issues: list[RecordIssue],
    ) -> Slot:
        if len(buf) < len(c_db.RINTERNAL):
            issues.append(
                RecordIssue(
                    "truncated-entry-header",
                    self.pgno,
                    index,
                    field,
                    "recno internal entry header is truncated",
                    expected=len(c_db.RINTERNAL),
                    actual=len(buf),
                )
            )
            return Slot(self.pgno, index, None, None, b"", False, issues=tuple(issues))

        return Slot(self.pgno, index, None, c_db.RINTERNAL(buf), b"", True)

    def entry(self, index: int) -> DBT:
        """Get a single entry by index. Type depends on page type.

        Also returns the associated data (DBT, Data-Base Thang, or key/data buffer) if applicable.

        Raises:
            CorruptRecordError: If the entry cannot be read completely.

        References:
            - ``__db_ret``

        Args:
            index: Index of the entry to retrieve.
        """
        if index < 0 or index >= len(self.lookup):
            raise IndexError("Index out of range")

        slot = self.read_entry(index)
        if not slot.complete:
            issue = (
                slot.issues[0]
                if slot.issues
                else RecordIssue("incomplete-entry", self.pgno, index, "value", "entry could not be read completely")
            )
            raise CorruptRecordError(issue, slot.data, slot.pages)
        return slot.entry, slot.data

    def entries(self) -> Iterator[DBT]:
        """Iterate over all entries in the page.

        Raises:
            TypeError: If the page type has no iterable entries.
            CorruptRecordError: If an entry cannot be read completely.
        """
        if not self.header.entries:
            raise TypeError("Page doesn't have iterable entries")

        for idx in range(self.entry_count):
            yield self.entry(idx)


def _unique_issues(issues: Sequence[RecordIssue]) -> tuple[RecordIssue, ...]:
    return tuple(dict.fromkeys(issues))


def overflow_data(db: DB, pgno: int, size: int, *, strict: bool = True) -> bytes:
    """Get off-page data.

    The returned bytes always belong to the requested overflow item. If the
    chain is truncated, broken or contains a non-overflow page, only the proven
    prefix is returned. In strict mode an incomplete item raises
    :class:`CorruptRecordError` carrying that prefix.

    References:
        - ``__db_goff``

    Args:
        db: The parent ``DB`` instance.
        pgno: The starting page number of the overflow data.
        size: The total size of the overflow data to read.
        strict: Raise on an incomplete item instead of returning its proven prefix.
    """
    result = db.read_overflow(pgno, size)
    if strict and not result.complete:
        issue = next(
            (issue for issue in result.issues if issue.kind != "overflow-page-number-mismatch"),
            None,
        ) or RecordIssue("incomplete-overflow", pgno, None, "value", "overflow item could not be read completely")
        raise CorruptRecordError(issue, result.data, result.pages)
    return result.data


def _db_log2(num: int) -> int:
    i = 0
    limit = 1
    while limit < num:
        i += 1
        limit = limit << 1

    return i


def BS_TO_PAGE(bucket: int, spares: list[int]) -> int:
    return bucket + spares[_db_log2(bucket + 1)]


def BUCKET_TO_PAGE(db: DB, bucket: int) -> int:
    return BS_TO_PAGE(bucket, db.meta.spares)
