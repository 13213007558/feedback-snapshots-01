from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.exception import InvalidEntryError, InvalidPageError, OverflowChainError

if TYPE_CHECKING:
    from collections.abc import Iterator


DBT = tuple[
    c_db.HOFFPAGE | c_db.HKEYDATA | c_db.HEAPHDR | c_db.BKEYDATA | c_db.BOVERFLOW | c_db.BINTERNAL | c_db.RINTERNAL,
    bytes,
]
"""An internal page entry structure + data (loosely related to Data-Base Thang)."""


@dataclass
class Record:
    """A record candidate from a Berkeley DB.

    Incomplete records are only reported in recovery mode. Their ``key`` or
    ``data`` may be ``None`` or contain partial data, but only ever bytes that
    belong to the record itself, never bytes of neighbouring records.

    Attributes:
        key: The record key, or ``None`` if it could not be recovered.
        data: The record data, or ``None`` if it could not be recovered.
        complete: Whether the record was recovered completely.
        pgno: Page number the record was found on.
        slot: Slot (entry index) of the record's key item on the page.
        errors: Human readable reasons why the record is incomplete.
    """

    key: bytes | int | None
    data: bytes | None
    complete: bool
    pgno: int | None = None
    slot: int | None = None
    errors: list[str] = field(default_factory=list)


class DB:
    """Berkeley DB.

    Args:
        fh: File-like object containing the Berkeley DB data. Only read from, never written to.
        recover: Recover as much as possible from corrupted databases instead of raising on the first error.
    """

    def __init__(self, fh: BinaryIO, recover: bool = False):
        self.fh = fh
        self.recover = recover
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

    def page(self, pgno: int) -> Page:
        """Get a single page by page number.

        Args:
            pgno: Page number to retrieve.
        """
        return Page(self, pgno)

    def records(self) -> Iterator[tuple[bytes | int, bytes]]:
        """Iterate over all complete records in the database.

        In strict mode the first corrupted record raises an ``InvalidEntryError`` that locates the
        record by page and slot. In recovery mode corrupted records are skipped instead; use
        ``iter_records`` to also inspect the incomplete candidates.
        """
        for record in self.iter_records():
            if not record.complete:
                if self.recover:
                    continue
                raise InvalidEntryError(record.pgno, record.slot, "; ".join(record.errors))
            yield record.key, record.data

    def iter_records(self) -> Iterator[Record]:
        """Iterate over all record candidates in the database, including incomplete ones.

        Key/value pairs are formed per page, so a missing or corrupted item can never
        shift the pairing of subsequent records.
        """
        for page in self._iter_pages():
            yield from self._page_records(page)

    def _iter_pages(self) -> Iterator[Page]:
        """Iterate over all leaf pages that hold records."""
        if self.is_btree:
            yield from self._walk_btree(self.meta.root, set())
        elif self.is_hash:
            for i in range(self.meta.max_bucket + 1):
                yield from self._walk_hash(BUCKET_TO_PAGE(self, i), set())
        else:
            raise NotImplementedError("Unsupported DB type")

    def _check_page(self, page: Page, types: tuple[int, ...]) -> bool:
        """Check that a page is readable and of an expected type.

        Raises an ``InvalidPageError`` in strict mode, returns ``False`` in recovery mode.
        """
        try:
            ptype = page.header.type
            entries = page.header.entries
            if ptype not in types:
                raise InvalidPageError(page.pgno, f"unexpected page type {ptype}")
            if entries * 2 > self.page_size - self._page_overhead:
                raise InvalidPageError(page.pgno, f"implausible entry count {entries}")
        except InvalidPageError:
            if self.recover:
                return False
            raise
        except Exception as e:
            if self.recover:
                return False
            raise InvalidPageError(page.pgno, _reason(e)) from e
        return True

    def _walk_btree(self, pgno: int, visited: set[int]) -> Iterator[Page]:
        if pgno in visited:
            return
        visited.add(pgno)

        page = self.page(pgno)
        if not self._check_page(page, (c_db.P_IBTREE, c_db.P_IRECNO, c_db.P_LBTREE, c_db.P_LRECNO)):
            return

        if page.header.type in (c_db.P_IBTREE, c_db.P_IRECNO):
            # Internal page
            try:
                children = [entry.pgno for entry, _ in page.entries()]
            except Exception as e:
                if self.recover:
                    return
                raise InvalidPageError(pgno, _reason(e)) from e
            for child in children:
                yield from self._walk_btree(child, visited)
        else:
            # Leaf page
            yield page

    def _walk_hash(self, pgno: int, visited: set[int]) -> Iterator[Page]:
        # Hash buckets can be chained over multiple pages with next_pgno
        while pgno != c_db.PGNO_INVALID and pgno not in visited:
            visited.add(pgno)

            page = self.page(pgno)
            if not self._check_page(page, (c_db.P_HASH, c_db.P_HASH_UNSORTED)):
                return
            yield page

            pgno = page.header.next_pgno

    def _page_records(self, page: Page) -> Iterator[Record]:
        """Build records from the entries of a single leaf page.

        Entries are paired by their slot index, so corrupted entries only affect their own pair.
        """
        count = page.header.entries

        if self.is_recno:
            recno = 0
            for idx in range(count):
                recno += 1
                entry, error = _read_entry(page, idx)
                if error is not None:
                    yield Record(recno, None, False, page.pgno, idx, [_reason(error)])
                    continue
                dbt, data = entry
                if dbt.type & c_db.B_DELETE:
                    continue
                yield Record(recno, bytes(data), True, page.pgno, idx)
            return

        # Hash and Btree leaf pages store key/data in pairs: slot 2n is the key of slot 2n+1's data
        idx = 0
        while idx + 1 < count:
            key, key_error = _entry_value(page, idx)
            data, data_error = _entry_value(page, idx + 1)
            errors = [error for error in (key_error, data_error) if error is not None]
            yield Record(key, data, not errors, page.pgno, idx, errors)
            idx += 2

        if idx < count:
            # Odd number of entries: a dangling item without its partner
            key, key_error = _entry_value(page, idx)
            errors = ["unpaired item (odd entry count)"]
            if key_error is not None:
                errors.append(key_error)
            yield Record(key, None, False, page.pgno, idx, errors)


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
        """Raw page data. May be shorter than the page size if the file is truncated."""
        self.db.fh.seek(self.offset)
        return self.db.fh.read(self.db.page_size)

    @cached_property
    def data(self) -> memoryview:
        """Page data, excluding any overhead (headers)."""
        return memoryview(self.raw)[self.db._page_overhead :]

    @cached_property
    def header(self) -> c_db.PAGE:
        """Page header."""
        return c_db.PAGE(self.raw)

    @property
    def type(self) -> int:
        """Page type."""
        return self.header.type

    @cached_property
    def lookup(self) -> list[int]:
        """List of offsets to entries in the page."""
        if self.type in (
            c_db.P_LBTREE,
            c_db.P_IBTREE,
            c_db.P_LRECNO,
            c_db.P_IRECNO,
            c_db.P_HASH,
            c_db.P_HASH_UNSORTED,
        ):
            return c_db.uint16[self.header.entries](self.data)
        return []

    def entry(self, index: int) -> DBT:
        """Get a single entry by index. Type depends on page type.

        Also returns the associated data (DBT, Data-Base Thang, or key/data buffer) if applicable.

        Raises an ``InvalidEntryError`` locating the entry by page and slot if it cannot be parsed.

        References:
            - ``__db_ret``

        Args:
            index: Index of the entry to retrieve.
        """
        if index >= len(self.lookup):
            raise IndexError("Index out of range")

        try:
            return self._entry(index)
        except (InvalidEntryError, OverflowChainError):
            raise
        except Exception as e:
            raise InvalidEntryError(self.pgno, index, _reason(e)) from e

    def _entry(self, index: int) -> DBT:
        offset = self.lookup[index]
        if offset >= len(self.raw):
            raise InvalidEntryError(
                self.pgno, index, f"item offset {offset} out of bounds (page has {len(self.raw)} bytes)"
            )

        buf = memoryview(self.raw)[offset:]
        # These are the types that can be DBTs
        if self.header.type in (c_db.P_HASH_UNSORTED, c_db.P_HASH):
            if buf[0] == c_db.H_OFFPAGE:
                entry = c_db.HOFFPAGE(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            next_offset = self.db.page_size if index == 0 else self.lookup[index - 1]
            data_length = (next_offset - offset) - len(c_db.HKEYDATA)
            if data_length < 0:
                raise InvalidEntryError(self.pgno, index, f"negative item length {data_length}")
            self._check_bounds(index, offset, len(c_db.HKEYDATA) + data_length)

            return c_db.HKEYDATA(buf), buf[len(c_db.HKEYDATA) : len(c_db.HKEYDATA) + data_length]

        if self.header.type == c_db.P_HEAP:
            entry = c_db.HEAPHDR(buf)
            if entry.flags & (c_db.HEAP_RECSPLIT | c_db.HEAP_RECFIRST):
                raise NotImplementedError("Heap split records not implemented")
            self._check_bounds(index, offset, len(c_db.HEAPHDR) + entry.size)
            return entry, buf[len(c_db.HEAPHDR) : len(c_db.HEAPHDR) + entry.size]

        if self.header.type in (c_db.P_LBTREE, c_db.P_LDUP, c_db.P_LRECNO):
            entry = c_db.BKEYDATA(buf)
            if entry.type == c_db.B_OVERFLOW:
                entry = c_db.BOVERFLOW(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            self._check_bounds(index, offset, len(c_db.BKEYDATA) + entry.len)
            return entry, buf[len(c_db.BKEYDATA) : len(c_db.BKEYDATA) + entry.len]

        # These are more internal types, but we still want to parse them
        if self.header.type == c_db.P_IBTREE:
            entry = c_db.BINTERNAL(buf)
            self._check_bounds(index, offset, len(c_db.BINTERNAL) + entry.len)
            return entry, buf[len(c_db.BINTERNAL) : len(c_db.BINTERNAL) + entry.len]

        if self.header.type == c_db.P_IRECNO:
            return c_db.RINTERNAL(buf), b""

        raise NotImplementedError(f"Page type not implemented: {self.header.type}")

    def _check_bounds(self, index: int, offset: int, size: int) -> None:
        """Validate that an item of ``size`` bytes at ``offset`` fits in the available page data."""
        if offset + size > len(self.raw):
            raise InvalidEntryError(
                self.pgno,
                index,
                f"item of {size} bytes at offset {offset} exceeds available page data ({len(self.raw)} bytes)",
            )

    def entries(self) -> Iterator[DBT]:
        """Iterate over all entries in the page."""
        if not self.header.entries:
            raise TypeError("Page doesn't have iterable entries")

        for idx in range(self.header.entries):
            yield self.entry(idx)


def _reason(error: Exception) -> str:
    """Human readable reason for an error, falling back to the exception type name."""
    return str(error) or type(error).__name__


def _read_entry(page: Page, index: int) -> tuple[DBT | None, Exception | None]:
    """Read a single entry, capturing any error instead of raising it."""
    try:
        return page.entry(index), None
    except Exception as e:
        return None, e


def _entry_value(page: Page, index: int) -> tuple[bytes | None, str | None]:
    """Read a single entry and return its data, or partial overflow data if the chain broke."""
    entry, error = _read_entry(page, index)
    if error is None:
        _, data = entry
        return bytes(data), None
    partial = getattr(error, "partial", None)
    return (bytes(partial) if partial else None), _reason(error)


def overflow_data(db: DB, pgno: int, size: int) -> bytes:
    """Get off-page data.

    Raises an ``OverflowChainError`` if the chain is broken (truncated file, unexpected page type,
    premature end of chain or a cycle). The error carries the partial data read from the chain
    itself; the data is never padded with bytes from other items.

    References:
        - ``__db_goff``

    Args:
        db: The parent ``DB`` instance.
        pgno: The starting page number of the overflow data.
        size: The total size of the overflow data to read.
    """
    start_pgno = pgno
    total_size = size
    result = []
    visited = set()

    def broken(message: str) -> OverflowChainError:
        return OverflowChainError(start_pgno, message, partial=b"".join(result))

    while size > 0:
        if pgno == c_db.PGNO_INVALID:
            raise broken(f"chain ended after {total_size - size} of {total_size} bytes")
        if pgno in visited:
            raise broken(f"cycle detected at page {pgno}")
        visited.add(pgno)

        try:
            page = db.page(pgno)
            ptype = page.header.type
            available = len(page.data)
            hf_offset = page.header.hf_offset
            next_pgno = page.header.next_pgno
        except Exception as e:
            raise broken(f"page {pgno} unreadable: {_reason(e)}") from e

        if ptype != c_db.P_OVERFLOW:
            raise broken(f"expected overflow page, got type {ptype} (pgno={pgno})")

        if hf_offset > available:
            # The page claims to hold more data than is actually present (truncated file)
            read_size = min(size, available)
            result.append(page.data[:read_size])
            raise broken(f"page {pgno} holds {available} of {hf_offset} announced bytes")

        read_size = min(size, hf_offset)
        result.append(page.data[:read_size])
        size -= read_size

        pgno = next_pgno

    return b"".join(result)


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
