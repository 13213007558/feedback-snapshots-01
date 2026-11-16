from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.cim.c_cim import DATA_PAGE_SIZE, c_cim
from dissect.cim.exceptions import Error

if TYPE_CHECKING:
    from dissect.cim.cim import CIM
    from dissect.cim.index import Key
    from dissect.cim.mappings import Mapping


class Objects:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.store = Store(cim, fh, mapping)

    def get(self, key: Key) -> BytesIO:
        if not key.is_data_reference:
            raise ValueError(f"Key is not a data reference: {key}")

        return self.get_record(key.data_page, key.data_id, key.data_length)

    def get_record(self, data_page: int, record_id: int, data_length: int) -> BytesIO:
        """Read a record by its physical location, without requiring an index reference.

        Args:
            data_page: Logical data page number the record starts on.
            record_id: The record identifier from the data page TOC.
            data_length: The expected length of the record. Records that span pages are stitched together.
        """
        page = self.store.page(data_page)

        buf = page.data_by_id(record_id, data_length)
        cur_len = len(buf)

        if cur_len == data_length:
            return BytesIO(buf)

        read_list = [buf]
        cur_page = data_page + 1
        while cur_len < data_length:
            next_buf = self.store.logical_page(cur_page)
            if cur_len + len(next_buf) > data_length:
                # Last page containing partial data
                chunk_size = data_length - cur_len
                read_list.append(next_buf[:chunk_size])
                cur_len += chunk_size
            else:
                # Entire page is data
                read_list.append(next_buf)
                cur_len += len(next_buf)

            cur_page += 1

        return BytesIO(b"".join(read_list))


class Store:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.cim = cim
        self.fh = fh
        self.map = mapping

    def page(self, logical_num: int) -> DataPage:
        page_number = self.map.get_entry(logical_num).page_number
        buf = self.physical_page(page_number)
        return DataPage(self, BytesIO(buf), logical_num, page_number)

    def logical_page(self, logical_num: int) -> bytes:
        return self.physical_page(self.map.get_entry(logical_num).page_number)

    def physical_page(self, page_number: int) -> bytes:
        self.fh.seek(DATA_PAGE_SIZE * page_number)
        return self.fh.read(DATA_PAGE_SIZE)


class DataPage:
    def __init__(self, store: Store, fh: BinaryIO, logical_num: int, page_number: int):
        self.store = store
        self.fh = fh
        self.logical_num = logical_num
        self.page_number = page_number

        self.toc = TOC(fh)

    def data(self, key: Key) -> bytes:
        return self.data_by_id(key.data_id, key.data_length)

    def data_by_id(self, record_id: int, data_length: int) -> bytes:
        target_id = record_id
        target_size = data_length

        for i in range(self.toc.count):
            entry = self.toc[i]
            if entry.record_id == target_id:
                if entry.size < target_size:
                    raise Error(f"Entry size is smaller than target size: {entry.size} < {target_size}")

                if entry.size > DATA_PAGE_SIZE - entry.offset:
                    pass

                self.fh.seek(entry.offset)
                return self.fh.read(entry.size)

        raise IndexError

    def objects(self) -> None:
        pass


class TOC:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.entries = []

        while True:
            e = c_cim.toc_entry(self.fh)
            if e.record_id == 0 and e.offset == 0 and e.size == 0 and e.crc == 0:
                break
            self.entries.append(e)

        self.count = len(self.entries)

    def __getitem__(self, k: int) -> c_cim.toc_entry:
        return self.entries[k]
