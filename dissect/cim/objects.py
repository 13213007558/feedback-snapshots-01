from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.cim.c_cim import DATA_PAGE_SIZE, UNMAPPED_PAGE_VALUE, c_cim
from dissect.cim.exceptions import (
    DuplicateRecordIdError,
    InvalidObjectError,
    MissingObjectDataError,
    ObjectDataError,
    ObjectLengthError,
    RecordNotFoundError,
    ShortReadError,
    UnmappedPageError,
)

if TYPE_CHECKING:
    from dissect.cim.cim import CIM
    from dissect.cim.index import Key
    from dissect.cim.mappings import Mapping

# Upper bound on how many further logical pages are inspected when reporting missing pages.
MAX_MISSING_PAGE_SCAN = 0x10000


class Objects:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.store = Store(cim, fh, mapping)

    def get(self, key: Key) -> BytesIO:
        """Reassemble the object referenced by ``key``.

        The object starts at the TOC entry identified by the record id in ``key`` and occupies
        ``key.data_length`` bytes. Only the remainder of the start page and the logical pages
        that follow it contribute bytes. Continuation pages are resolved through the logical
        page mapping, never through physical adjacency.

        A page alone determines how many bytes it may contribute: the start page contributes at
        most up to its end, so bytes belonging to another page or object are never used to pad
        the declared length.

        Raises:
            ValueError: If ``key`` is not a data reference.
            ObjectLengthError: If the TOC size and index-declared length disagree.
            DuplicateRecordIdError: If the start page TOC has multiple entries for the record id.
            RecordNotFoundError: If the start page TOC has no entry for the record id.
            MissingObjectDataError: If a required logical page is unmapped or outside the mapping.
            ShortReadError: If the input does not contain all required bytes.
        """
        if not key.is_data_reference:
            raise ValueError(f"Key is not a data reference: {key}")

        start_page = key.data_page
        data_len = key.data_length

        if data_len < 0:
            raise InvalidObjectError(f"Invalid object length {data_len} for {key}")

        try:
            page = self.store.page(start_page)
        except UnmappedPageError as e:
            raise MissingObjectDataError(start_page, start_page, [start_page], "start page is unmapped") from e
        except ShortReadError:
            raise
        except ObjectDataError as e:
            raise InvalidObjectError(f"Invalid TOC on logical page {start_page}: {e}") from e

        entry = page.entry_for(key.data_id)

        if entry.size != data_len:
            raise ObjectLengthError(key.data_id, start_page, entry.size, data_len)

        if data_len == 0:
            return BytesIO()

        if entry.offset >= DATA_PAGE_SIZE:
            raise InvalidObjectError(
                f"TOC offset {entry.offset} for record id {key.data_id} on logical page "
                f"{start_page} is outside the data page"
            )

        end_page = object_end_page(start_page, entry.offset, data_len)

        # The start page can only contribute bytes up to its end. Anything beyond that lives on
        # the following logical pages and must be read through the mapping.
        first_length = min(data_len, DATA_PAGE_SIZE - entry.offset)
        first_end = entry.offset + first_length

        if len(page.buf) < first_end:
            raise ShortReadError(start_page, first_end, len(page.buf), start_page, end_page)

        chunks = [page.buf[entry.offset : first_end]]
        remaining = data_len - first_length
        current_page = start_page + 1

        while remaining > 0:
            try:
                page_number = self.store.page_number(current_page)
            except UnmappedPageError as e:
                missing = self.store.missing_pages(current_page, end_page)
                raise MissingObjectDataError(start_page, end_page, missing) from e

            page_buf = self.store.physical_page(page_number)
            need = min(remaining, DATA_PAGE_SIZE)

            if len(page_buf) < need:
                raise ShortReadError(current_page, need, len(page_buf), start_page, end_page)

            chunks.append(page_buf[:need])
            remaining -= need
            current_page += 1

        data = b"".join(chunks)
        if len(data) != data_len:
            raise ObjectDataError(f"Reassembled {len(data)} bytes, expected {data_len} bytes")

        return BytesIO(data)


class Store:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.cim = cim
        self.fh = fh
        self.map = mapping

    def page_number(self, logical_num: int) -> int:
        """Resolve a logical page number to a physical page number."""
        try:
            entry = self.map.get_entry(logical_num)
        except (IndexError, UnmappedPageError) as e:
            raise UnmappedPageError(logical_num) from e

        page_number = entry.page_number

        if page_number == UNMAPPED_PAGE_VALUE or not entry.is_mapped:
            raise UnmappedPageError(logical_num)

        return page_number

    def page(self, logical_num: int) -> DataPage:
        page_number = self.page_number(logical_num)
        buf = self.physical_page(page_number)
        return DataPage(self, BytesIO(buf), logical_num, page_number)

    def logical_page(self, logical_num: int) -> bytes:
        """Read a logical page through the page mapping."""
        return self.physical_page(self.page_number(logical_num))

    def physical_page(self, page_number: int) -> bytes:
        if page_number == UNMAPPED_PAGE_VALUE:
            raise UnmappedPageError(page_number)

        self.fh.seek(DATA_PAGE_SIZE * page_number)
        return self.fh.read(DATA_PAGE_SIZE)

    def missing_pages(self, first_missing: int, end_page: int) -> list[int]:
        """Return the unmapped logical pages in the inclusive range ``first_missing..end_page``.

        The scan is bounded so a hostile declared length can not turn an error path into an
        unbounded mapping walk. The first missing page is always reported. Pages outside the
        mapping are treated as missing.
        """
        if end_page < first_missing:
            return [first_missing]

        scan_end = min(end_page, first_missing + MAX_MISSING_PAGE_SCAN)
        entry_count = getattr(self.map.mapping, "mapping_entry_count", None)
        missing = [first_missing]

        for logical_num in range(first_missing + 1, scan_end + 1):
            if entry_count is not None and logical_num >= entry_count:
                missing.append(logical_num)
                continue

            try:
                self.page_number(logical_num)
            except UnmappedPageError:
                missing.append(logical_num)

        return missing


class DataPage:
    def __init__(self, store: Store, fh: BinaryIO, logical_num: int, page_number: int):
        self.store = store
        self.fh = fh
        self.logical_num = logical_num
        self.page_number = page_number

        self.buf = fh.getvalue() if isinstance(fh, BytesIO) else _read_all(fh)
        self.toc = TOC(BytesIO(self.buf), page=logical_num)

    def entry_for(self, record_id: int) -> c_cim.toc_entry:
        """Return the single TOC entry for ``record_id``."""
        matches = [self.toc[i] for i in range(self.toc.count) if self.toc[i].record_id == record_id]

        if len(matches) > 1:
            raise DuplicateRecordIdError(record_id, self.logical_num, len(matches))

        if not matches:
            raise RecordNotFoundError(record_id, self.logical_num)

        return matches[0]

    def data(self, key: Key) -> bytes:
        """Return the bytes for ``key`` that are present on this page only."""
        entry = self.entry_for(key.data_id)
        target_size = key.data_length

        if entry.size != target_size:
            raise ObjectLengthError(key.data_id, self.logical_num, entry.size, target_size)

        if entry.offset > len(self.buf):
            raise InvalidObjectError(
                f"TOC offset {entry.offset} for record id {key.data_id} on logical page "
                f"{self.logical_num} is outside the data page"
            )

        end = min(entry.offset + entry.size, len(self.buf))
        return self.buf[entry.offset : end]

    def objects(self) -> None:
        pass


class TOC:
    def __init__(self, fh: BinaryIO, page: int | None = None):
        self.fh = fh
        self.page = page
        self.entries = []

        buf = fh.getvalue() if isinstance(fh, BytesIO) else _read_all(fh)
        size = len(buf)
        pos = 0

        while True:
            if pos + 0x10 > size:
                if size < DATA_PAGE_SIZE:
                    raise ShortReadError(page if page is not None else 0, pos + 0x10, size)

                location = f" on logical page {page}" if page is not None else ""
                raise InvalidObjectError(f"No TOC terminator{location}")

            entry = c_cim.toc_entry(BytesIO(buf[pos : pos + 0x10]))
            pos += 0x10

            if entry.record_id == 0 and entry.offset == 0 and entry.size == 0 and entry.crc == 0:
                break

            self.entries.append(entry)

        self.count = len(self.entries)

    def __getitem__(self, k: int) -> c_cim.toc_entry:
        return self.entries[k]


def _read_all(fh: BinaryIO) -> bytes:
    pos = fh.tell()
    fh.seek(0)
    try:
        return fh.read()
    finally:
        fh.seek(pos)


def object_end_page(start_page: int, offset: int, data_len: int) -> int:
    """Return the last logical page that can contain bytes of an object."""
    if data_len <= 0 or offset >= DATA_PAGE_SIZE:
        return start_page

    first_available = DATA_PAGE_SIZE - offset
    if data_len <= first_available:
        return start_page

    remaining = data_len - first_available
    return start_page + (remaining + DATA_PAGE_SIZE - 1) // DATA_PAGE_SIZE
