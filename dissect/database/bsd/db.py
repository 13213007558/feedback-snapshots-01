from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.bsd.c_db import c_db

if TYPE_CHECKING:
    from collections.abc import Iterator


DBT = tuple[
    c_db.HOFFPAGE | c_db.HKEYDATA | c_db.HEAPHDR | c_db.BKEYDATA | c_db.BOVERFLOW | c_db.BINTERNAL | c_db.RINTERNAL,
    bytes,
]
"""An internal page entry structure + data (loosely related to Data-Base Thang)."""


@dataclass(frozen=True)
class RecnoLeaf:
    """A physical leaf page, or an unavailable subtree, in a ``DB_RECNO`` tree.

    Attributes:
        pgno: Page number of the leaf page or of the unavailable subtree root.
        base: Record number of the first slot in this leaf.
        nrecs: Number of record numbers this leaf spans, as declared by its parent.
        entries: Number of physical slots on the page, or ``None`` if the page is unreadable.
        error: Reason the page could not be read, if any.
    """

    pgno: int
    base: int
    nrecs: int
    entries: int | None = None
    error: str | None = None

    @property
    def end(self) -> int:
        """Record number of the last slot in this leaf."""
        return self.base + self.nrecs - 1


@dataclass(frozen=True)
class RecnoAnomaly:
    """A structural inconsistency found while restoring ``DB_RECNO`` record numbers.

    Attributes:
        kind: One of ``unreadable_page``, ``cycle``, ``short_leaf``, ``long_leaf``,
            ``subtree_count_mismatch`` or ``unexpected_page_type``.
        pgno: Page number the anomaly was found on.
        parent_pgno: Page number of the parent page, if any.
        base: Record number the page should start at.
        declared: Record count declared by the parent.
        actual: Record count actually present.
        detail: Human readable details.
    """

    kind: str
    pgno: int
    parent_pgno: int | None = None
    base: int | None = None
    declared: int | None = None
    actual: int | None = None
    detail: str = ""


@dataclass(frozen=True)
class RecnoEntry:
    """A single physical slot in a ``DB_RECNO`` tree.

    Record numbers are derived from the slot position in its leaf, offset by the record counts of
    preceding subtrees. They are never derived from how many live records were yielded before, so
    deleted slots and unavailable pages leave stable holes in the numbering.

    Attributes:
        recno: The record number of this slot, including deleted slots.
        data: The record data, or ``None`` for deleted, missing or unreadable slots.
        pgno: Page number of the leaf page holding the slot.
        slot: Slot index within the leaf page.
        deleted: Whether the slot has the ``B_DELETE`` flag set.
        error: Reason the slot data could not be read, if any.
        page_error: Whether the error is caused by the whole page being unavailable.
        residual: Bytes still present in a deleted slot, according to its declared length. These
            bytes are never reported as a live record.
        raw_type: The raw type byte of the slot, including the delete flag.
    """

    recno: int
    data: bytes | None
    pgno: int
    slot: int
    deleted: bool = False
    error: str | None = None
    page_error: bool = False
    residual: bytes = b""
    raw_type: int | None = None

    @property
    def live(self) -> bool:
        """Return whether this slot contains a live record with readable data."""
        return not self.deleted and self.error is None and self.data is not None


@dataclass(frozen=True)
class RecnoGap:
    """A contiguous range of record numbers without a live record.

    Attributes:
        start: First record number in the range (inclusive).
        end: Last record number in the range (inclusive).
        pgno: Page number the range belongs to, or ``None`` if unknown.
        reason: Why the range has no live record: ``deleted``, ``missing``, ``unreadable_slot``
            or ``unreadable_page``.
    """

    start: int
    end: int
    pgno: int | None = None
    reason: str = "deleted"


class DB:
    """Berkeley DB.

    Args:
        fh: File-like object containing the Berkeley DB data.
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
        """Iterate over all live records in the database.

        For ``DB_RECNO`` databases the key is the physical record number, so numbered holes caused
        by deleted slots, unreadable slots or unreadable pages are preserved. Use
        :meth:`recno_entries` to inspect those holes and :meth:`recno_gaps` for their ranges.
        """
        if self.is_recno:
            for entry in self.recno_entries():
                if entry.live:
                    assert entry.data is not None
                    yield entry.recno, entry.data
            return

        it = self._iter_db()

        if self.is_btree or self.is_hash:
            # Hash and Btree are stored in pairs
            while entry := next(it, None):
                _, key = entry
                _, data = next(it)
                yield bytes(key), bytes(data)

    def recno_entries(self) -> Iterator[RecnoEntry]:
        """Iterate over every physical slot in a ``DB_RECNO`` tree, including deleted slots.

        Record numbers come from the slot position in its leaf plus the subtree record counts
        stored in the parent ``RINTERNAL`` entries. Deleted slots keep their number but are
        reported with ``deleted=True`` and without data; bytes still present in such a slot are
        only exposed as ``residual`` and are never promoted to a live record.
        """
        if not self.is_recno:
            raise TypeError("Not a DB_RECNO database")

        for leaf in self.recno_leaves():
            if leaf.error is not None:
                for slot in range(leaf.nrecs):
                    yield RecnoEntry(leaf.base + slot, None, leaf.pgno, slot, error=leaf.error, page_error=True)
                continue

            page = self.page(leaf.pgno)
            lookup = _recno_lookup(page)
            for slot in range(leaf.nrecs):
                yield self._recno_entry(page, leaf, slot, lookup)

    def recno_leaves(self) -> Iterator[RecnoLeaf]:
        """Iterate over the leaf pages of a ``DB_RECNO`` tree in record number order.

        Each leaf carries the record number of its first slot (``base``) and the record count
        declared by its parent (``nrecs``). Subtrees that cannot be read still consume their
        declared range, so record numbers after them do not shift.
        """
        if not self.is_recno:
            raise TypeError("Not a DB_RECNO database")

        anomalies: list[RecnoAnomaly] = []
        yield from self._recno_walk(self.meta.root, 1, None, None, set(), anomalies)

    def recno_gaps(self) -> Iterator[RecnoGap]:
        """Iterate over contiguous ranges of record numbers without a live record.

        A gap can be caused by deleted slots, missing slots or unreadable subtrees. Gaps never
        cross a page boundary and carry the page number and reason for that page, so a hole can
        be explained from the page layout. Bounds are derived from the same structural record
        numbering as :meth:`recno_entries`.
        """
        if not self.is_recno:
            raise TypeError("Not a DB_RECNO database")

        for leaf in self.recno_leaves():
            if leaf.error is not None:
                if leaf.nrecs:
                    yield RecnoGap(leaf.base, leaf.end, leaf.pgno, "unreadable_page")
                continue

            page = self.page(leaf.pgno)
            lookup = _recno_lookup(page)
            start = None
            start_reason = None
            previous = None

            for slot in range(leaf.nrecs):
                entry = self._recno_entry(page, leaf, slot, lookup)
                if entry.live:
                    if start is not None:
                        yield RecnoGap(start, previous, leaf.pgno, start_reason)
                        start = None
                    continue

                if lookup is None:
                    reason = "unreadable_slot"
                elif slot >= len(lookup):
                    reason = "missing"
                elif entry.page_error:
                    reason = "unreadable_page"
                elif entry.deleted:
                    reason = "deleted"
                elif entry.error is not None:
                    reason = "unreadable_slot"
                else:
                    reason = "missing"

                if start is not None and reason != start_reason:
                    yield RecnoGap(start, previous, leaf.pgno, start_reason)
                    start = entry.recno
                    start_reason = reason
                elif start is None:
                    start = entry.recno
                    start_reason = reason
                previous = entry.recno

            if start is not None:
                yield RecnoGap(start, previous, leaf.pgno, start_reason)

    def recno_anomalies(self) -> Iterator[RecnoAnomaly]:
        """Iterate over structural inconsistencies found while walking a ``DB_RECNO`` tree.

        The entry and gap iterators silently keep numbering stable around such problems; this
        iterator explains them, for example when a leaf holds fewer slots than its parent declares.
        """
        if not self.is_recno:
            raise TypeError("Not a DB_RECNO database")

        anomalies: list[RecnoAnomaly] = []
        for _ in self._recno_walk(self.meta.root, 1, None, None, set(), anomalies):
            pass
        yield from anomalies

    def _recno_walk(
        self,
        pgno: int,
        base: int,
        nrecs: int | None,
        parent_pgno: int | None,
        visited: set[int],
        anomalies: list[RecnoAnomaly],
    ) -> Iterator[RecnoLeaf]:
        if pgno in visited:
            anomalies.append(
                RecnoAnomaly("cycle", pgno, parent_pgno, base, nrecs, detail="page referenced more than once")
            )
            if nrecs:
                yield RecnoLeaf(pgno, base, nrecs, None, "page referenced more than once")
            return
        visited.add(pgno)

        try:
            page = self.page(pgno)
            page_type = page.header.type
            entries = page.header.entries
        except Exception as e:
            reason = _reason(e)
            anomalies.append(RecnoAnomaly("unreadable_page", pgno, parent_pgno, base, nrecs, detail=reason))
            if nrecs is not None:
                yield RecnoLeaf(pgno, base, nrecs, None, reason)
            return

        if page_type == c_db.P_IRECNO:
            try:
                children = [(entry.pgno, entry.nrecs) for entry, _ in page.entries()]
            except Exception as e:
                reason = _reason(e)
                anomalies.append(RecnoAnomaly("unreadable_page", pgno, parent_pgno, base, nrecs, detail=reason))
                if nrecs is not None:
                    yield RecnoLeaf(pgno, base, nrecs, None, reason)
                return

            child_base = base
            for child_pgno, child_nrecs in children:
                yield from self._recno_walk(child_pgno, child_base, child_nrecs, pgno, visited, anomalies)
                child_base += child_nrecs

            if nrecs is not None and child_base - base != nrecs:
                anomalies.append(
                    RecnoAnomaly("subtree_count_mismatch", pgno, parent_pgno, base, nrecs, child_base - base)
                )
            return

        if page_type == c_db.P_LRECNO:
            if nrecs is not None and entries != nrecs:
                kind = "short_leaf" if entries < nrecs else "long_leaf"
                anomalies.append(RecnoAnomaly(kind, pgno, parent_pgno, base, nrecs, entries))
                yield RecnoLeaf(pgno, base, nrecs, entries)
            else:
                yield RecnoLeaf(pgno, base, entries, entries)
            return

        anomalies.append(
            RecnoAnomaly(
                "unexpected_page_type",
                pgno,
                parent_pgno,
                base,
                nrecs,
                detail=f"expected P_IRECNO or P_LRECNO, got {page_type}",
            )
        )
        if nrecs is not None:
            yield RecnoLeaf(pgno, base, nrecs, None, f"unexpected page type {page_type}")

    def _recno_entry(self, page: Page, leaf: RecnoLeaf, slot: int, lookup: list[int] | None) -> RecnoEntry:
        recno = leaf.base + slot
        if lookup is None:
            return RecnoEntry(recno, None, leaf.pgno, slot, error="slot lookup table unreadable")
        if slot >= len(lookup):
            return RecnoEntry(recno, None, leaf.pgno, slot)

        offset = lookup[slot]
        buf = memoryview(page.raw)[offset:]
        if len(buf) < len(c_db.BKEYDATA):
            return RecnoEntry(recno, None, leaf.pgno, slot, error="slot header out of bounds")

        entry = c_db.BKEYDATA(buf)
        deleted = bool(entry.type & c_db.B_DELETE)
        if entry.type & ~c_db.B_DELETE == c_db.B_OVERFLOW:
            if deleted:
                return RecnoEntry(recno, None, leaf.pgno, slot, True, raw_type=entry.type)
            try:
                overflow = c_db.BOVERFLOW(buf)
                data = overflow_data(self, overflow.pgno, overflow.tlen)
            except Exception as e:
                return RecnoEntry(recno, None, leaf.pgno, slot, False, _reason(e), raw_type=entry.type)
            return RecnoEntry(recno, data, leaf.pgno, slot, False, raw_type=entry.type)

        data = bytes(buf[len(c_db.BKEYDATA) : len(c_db.BKEYDATA) + entry.len])
        if len(data) != entry.len:
            return RecnoEntry(recno, None, leaf.pgno, slot, deleted, "slot data out of bounds", raw_type=entry.type)

        if deleted:
            return RecnoEntry(recno, None, leaf.pgno, slot, True, residual=data, raw_type=entry.type)

        return RecnoEntry(recno, data, leaf.pgno, slot, False, raw_type=entry.type)

    def _iter_db(self) -> Iterator[DBT]:
        if self.is_btree:
            yield from self._iter_btree()
        elif self.is_hash:
            yield from self._iter_hash()
        else:
            raise NotImplementedError("Unsupported DB type")

    def _iter_btree(self) -> Iterator[DBT]:
        yield from self._walk_btree(self.meta.root)

    def _walk_btree(self, pgno: int) -> Iterator[DBT]:
        page = self.page(pgno)
        if page.header.type in (c_db.P_IBTREE, c_db.P_IRECNO):
            # Internal page
            for entry, _ in page.entries():
                yield from self._walk_btree(entry.pgno)
        elif page.header.type in (c_db.P_LBTREE, c_db.P_LRECNO):
            # Leaf page
            yield from page.entries()

    def _iter_hash(self) -> Iterator[DBT]:
        for i in range(self.meta.max_bucket + 1):
            pgno = BUCKET_TO_PAGE(self, i)
            yield from self._walk_hash(pgno)

    def _walk_hash(self, pgno: int) -> Iterator[DBT]:
        page = self.page(pgno)
        yield from page.entries()

        if page.header.next_pgno:
            yield from self._walk_hash(page.header.next_pgno)


def _recno_lookup(page: Page) -> list[int] | None:
    """Read a leaf page's slot offset table, or ``None`` if the page is too short to hold it."""
    try:
        return page.lookup
    except Exception:
        return None


def _reason(error: Exception) -> str:
    """Human readable reason for an error, falling back to the exception type name."""
    return str(error) or type(error).__name__


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
        return c_db.PAGE(self.raw)

    @property
    def type(self) -> int:
        """Page type."""
        return self.header.type

    @cached_property
    def lookup(self) -> list[int]:
        """List of offsets to entries in the page."""
        if self.type in (c_db.P_LBTREE, c_db.P_IBTREE, c_db.P_LRECNO, c_db.P_IRECNO, c_db.P_HASH):
            return c_db.uint16[self.header.entries](self.data)
        return []

    def entry(self, index: int) -> DBT:
        """Get a single entry by index. Type depends on page type.

        Also returns the associated data (DBT, Data-Base Thang, or key/data buffer) if applicable.

        References:
            - ``__db_ret``

        Args:
            index: Index of the entry to retrieve.
        """
        if index >= len(self.lookup):
            raise IndexError("Index out of range")

        buf = memoryview(self.raw)[self.lookup[index] :]
        # These are the types that can be DBTs
        if self.header.type in (c_db.P_HASH_UNSORTED, c_db.P_HASH):
            if buf[0] == c_db.H_OFFPAGE:
                entry = c_db.HOFFPAGE(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            next_offset = self.db.page_size if index == 0 else self.lookup[index - 1]
            data_length = (next_offset - self.lookup[index]) - len(c_db.HKEYDATA)

            return c_db.HKEYDATA(buf), buf[len(c_db.HKEYDATA) : len(c_db.HKEYDATA) + data_length]

        if self.header.type == c_db.P_HEAP:
            entry = c_db.HEAPHDR(buf)
            if entry.flags & (c_db.HEAP_RECSPLIT | c_db.HEAP_RECFIRST):
                raise NotImplementedError("Heap split records not implemented")
            return entry, buf[len(c_db.HEAPHDR) : len(c_db.HEAPHDR) + entry.size]

        if self.header.type in (c_db.P_LBTREE, c_db.P_LDUP, c_db.P_LRECNO):
            entry = c_db.BKEYDATA(buf)
            if entry.type == c_db.B_OVERFLOW:
                entry = c_db.BOVERFLOW(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            return entry, buf[len(c_db.BKEYDATA) : len(c_db.BKEYDATA) + entry.len]

        # These are more internal types, but we still want to parse them
        if self.header.type == c_db.P_IBTREE:
            entry = c_db.BINTERNAL(buf)
            return entry, buf[len(c_db.BINTERNAL) : len(c_db.BINTERNAL) + entry.len]

        if self.header.type == c_db.P_IRECNO:
            return c_db.RINTERNAL(buf), b""

        raise NotImplementedError(f"Page type not implemented: {self.header.type}")

    def entries(self) -> Iterator[DBT]:
        """Iterate over all entries in the page."""
        if not self.header.entries:
            return

        for idx in range(self.header.entries):
            yield self.entry(idx)


def overflow_data(db: DB, pgno: int, size: int) -> bytes:
    """Get off-page data.

    References:
        - ``__db_goff``

    Args:
        db: The parent ``DB`` instance.
        pgno: The starting page number of the overflow data.
        size: The total size of the overflow data to read.
    """
    result = []
    while size > 0 and pgno != c_db.PGNO_INVALID:
        page = db.page(pgno)
        if page.type != c_db.P_OVERFLOW:
            raise ValueError(f"Expected overflow page, got {page.type} (pgno={pgno})")

        read_size = min(size, page.header.hf_offset)
        result.append(page.data[:read_size])
        size -= read_size

        pgno = page.header.next_pgno

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
