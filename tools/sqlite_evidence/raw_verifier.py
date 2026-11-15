"""Independent, stdlib-only ground-truth reader for the SQLite file format.

This deliberately does NOT import dissect.database. It walks the b-tree and
WAL at the byte level so that the diagnostic can prove, against an independent
implementation, exactly which fields exist in a record's bytes versus which
are reconstructed by the parser from the schema's DEFAULT clause.

Only the subset needed for the evidence is implemented (table b-trees, the
record format, WAL frame/commit iteration).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

LEAF_TABLE = 0x0D
INTERIOR_TABLE = 0x05


def _varint(buf: bytes, off: int) -> tuple[int, int]:
    value = 0
    for i in range(9):
        byte = buf[off + i]
        if i == 8:
            return value | byte, off + 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, off + i + 1
    raise ValueError("varint too long")


def _serial_value(buf: bytes, off: int, serial: int) -> tuple[object, int]:
    if serial == 0:
        return None, off
    if serial == 8:
        return 0, off
    if serial == 9:
        return 1, off
    int_sizes = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}
    if serial in int_sizes:
        n = int_sizes[serial]
        raw = buf[off : off + n]
        return int.from_bytes(raw, "big", signed=True), off + n
    if serial == 7:
        return struct.unpack(">d", buf[off : off + 8])[0], off + 8
    if serial >= 12:
        n = (serial - 12) // 2
        chunk = buf[off : off + n]
        return (chunk.decode("utf-8") if serial % 2 else chunk), off + n
    raise ValueError(f"reserved serial type {serial}")


@dataclass
class RawRecord:
    rowid: int
    serial_types: list[int]
    values: list[object]
    page: int
    cell_offset: int
    source: str  # "main" | "wal-commit#n"

    @property
    def physical_field_count(self) -> int:
        return len(self.serial_types)


def _parse_table_page(page: bytes, page_num: int, source: str) -> list[RawRecord]:
    flag = page[0]
    if flag == INTERIOR_TABLE:
        # Right-most pointer then cell pointers; recurse into children.
        right = struct.unpack(">I", page[8:12])[0]
        n = struct.unpack(">H", page[3:5])[0]
        ptrs = [struct.unpack(">H", page[12 + 2 * i : 14 + 2 * i])[0] for i in range(n)]
        children = [struct.unpack(">I", page[p : p + 4])[0] for p in ptrs] + [right]
        return [child for cnum in children for child in _open_and_parse(cnum, source)]
    if flag != LEAF_TABLE:
        return []
    n = struct.unpack(">H", page[3:5])[0]
    ptrs = [struct.unpack(">H", page[8 + 2 * i : 10 + 2 * i])[0] for i in range(n)]
    records: list[RawRecord] = []
    for ptr in ptrs:
        payload_len, p = _varint(page, ptr)
        rowid, p = _varint(page, p)
        header_start = p
        header_len, hp = _varint(page, p)
        header_end = header_start + header_len
        serials: list[int] = []
        while hp < header_end:
            serial, hp = _varint(page, hp)
            serials.append(serial)
        body = header_end
        values: list[object] = []
        for serial in serials:
            val, body = _serial_value(page, body, serial)
            values.append(val)
        records.append(RawRecord(rowid, serials, values, page_num, ptr, source))
    return records


# Page source registry injected by the driver so interior pages recurse into
# the same (possibly WAL-overlaid) page set.
_PAGE_PROVIDER: dict[str, object] = {}


def _open_and_parse(page_num: int, source: str) -> list[RawRecord]:
    page = _PAGE_PROVIDER["get_page"](page_num)
    return _parse_table_page(page, page_num, source)


def parse_table_rootpage(rootpage: int, get_page, source: str) -> list[RawRecord]:
    _PAGE_PROVIDER["get_page"] = get_page
    return _open_and_parse(rootpage, source)


# ----------------------------- WAL handling -----------------------------


@dataclass
class WalFrame:
    page_number: int
    page_count: int
    salt1: int
    salt2: int
    data: bytes


@dataclass
class WalCommit:
    index: int
    frames: list[WalFrame] = field(default_factory=list)

    @property
    def salt(self) -> tuple[int, int]:
        first = self.frames[0]
        return first.salt1, first.salt2


def read_wal_commits(wal_path: Path, page_size: int) -> tuple[dict, list[WalCommit]]:
    blob = wal_path.read_bytes()
    magic = struct.unpack(">I", blob[0:4])[0]
    endian = "<" if magic == 0x377F0682 else ">"
    wal_page_size = struct.unpack(endian + "I", blob[8:12])[0]
    if wal_page_size == 1:
        wal_page_size = 65536
    header = blob[:32]
    h_salt1, h_salt2 = struct.unpack(endian + "II", blob[16:24])
    frame_hdr = 24
    stride = frame_hdr + wal_page_size
    commits: list[WalCommit] = []
    current: list[WalFrame] = []
    idx = 0
    pos = 32
    while pos + stride <= len(blob):
        pn, pc, s1, s2 = struct.unpack(endian + "IIII", blob[pos : pos + 16])
        data = blob[pos + frame_hdr : pos + frame_hdr + wal_page_size]
        frame = WalFrame(pn, pc, s1, s2, data)
        current.append(frame)
        if pc > 0:
            commits.append(WalCommit(idx, current))
            idx += 1
            current = []
        pos += stride
    info = {
        "salt": (h_salt1, h_salt2),
        "page_size": wal_page_size or page_size,
        "header": header,
    }
    return info, commits
