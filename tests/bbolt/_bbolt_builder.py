from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

BUCKET_FLAG = 0x01
BRANCH_FLAG = 0x01
LEAF_FLAG = 0x02
META_FLAG = 0x04
FREELIST_FLAG = 0x10
MAGIC = 0xED0CDAED
VERSION = 2

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def fnv1a_64(data: bytes) -> int:
    """Calculate the bbolt meta checksum (FNV-1a)."""
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return value


def leaf_page(pgid: int, items: list[tuple[int, bytes, bytes]], page_size: int) -> bytes:
    """Build a leaf page, padded to *page_size*."""
    page = bytearray(page_size)
    page[:16] = struct.pack("<QHHI", pgid, LEAF_FLAG, len(items), 0)

    data_start = 16 + 16 * len(items)
    data = bytearray()
    for i, (flags, key, value) in enumerate(items):
        element_offset = 16 + i * 16
        pos = data_start + len(data) - element_offset
        page[element_offset : element_offset + 16] = struct.pack("<IIII", flags, pos, len(key), len(value))
        data += key + value

    if data_start + len(data) > page_size:
        raise ValueError("Leaf page contents do not fit in a page")
    page[data_start : data_start + len(data)] = data
    return bytes(page)


def inline_page(items: list[tuple[int, bytes, bytes]]) -> bytes:
    """Build an inline page (header + elements + data)."""
    header = struct.pack("<QHHI", 0, LEAF_FLAG, len(items), 0)
    elements = bytearray()
    data = bytearray()
    data_start = 16 + 16 * len(items)

    for i, (flags, key, value) in enumerate(items):
        element_offset = 16 + i * 16
        pos = data_start + len(data) - element_offset
        elements += struct.pack("<IIII", flags, pos, len(key), len(value))
        data += key + value

    return bytes(header + elements + data)


def freelist_page(pgid: int, page_size: int) -> bytes:
    page = bytearray(page_size)
    page[:16] = struct.pack("<QHHI", pgid, FREELIST_FLAG, 0, 0)
    return bytes(page)


def meta_page(
    index: int,
    page_size: int,
    *,
    root: int = 3,
    high_water: int = 6,
    txid: int = 1,
    freelist: int = 2,
    corrupt: str | None = None,
) -> bytes:
    """Build a meta page for *index*.

    ``corrupt`` can be ``"checksum"``, ``"page_size"``, ``"root"``, ``"high_water"``
    or ``"magic"``. Except for ``"checksum"`` and ``"magic"`` the checksum is
    recalculated, so the page looks internally consistent to a checksum-only
    reader.
    """
    meta = bytearray(page_size)
    meta[:16] = struct.pack("<QHHI", index, META_FLAG, 0, 0)
    meta[16:32] = struct.pack("<IIII", MAGIC, VERSION, page_size, 0)
    meta[32:48] = struct.pack("<QQ", root, 0)
    meta[48:72] = struct.pack("<QQQ", freelist, high_water, txid)

    if corrupt == "page_size":
        struct.pack_into("<I", meta, 24, page_size * 2)
    elif corrupt == "root":
        struct.pack_into("<Q", meta, 32, high_water + 100)
    elif corrupt == "high_water":
        struct.pack_into("<Q", meta, 56, root)
    elif corrupt == "magic":
        struct.pack_into("<I", meta, 16, MAGIC ^ 1)

    checksum = fnv1a_64(bytes(meta[16:72]))
    if corrupt == "checksum":
        checksum ^= 0xFFFFFFFFFFFFFFFF
    meta[72:80] = struct.pack("<Q", checksum)
    return bytes(meta)


def write_pages(path: Path, pages: dict[int, bytes], page_size: int) -> Path:
    path.write_bytes(b"".join(pages.get(index, bytes(page_size)) for index in range(max(pages) + 1)))
    return path
