from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

BUCKET_FLAG = 0x01
LEAF_FLAG = 0x02
META_FLAG = 0x04
FREELIST_FLAG = 0x10
MAGIC = 0xED0CDAED
VERSION = 2
PAGE_SIZE = 4096

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


def fnv1a_64(data: bytes) -> int:
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return value


def bucket_value(root: int, sequence: int = 0, inline_page: bytes | None = None) -> bytes:
    """Build a leaf value for a sub-bucket, optionally with inline page contents."""
    value = struct.pack("<QQ", root, sequence)
    if inline_page is not None:
        if root != 0:
            raise ValueError("Only buckets without a root page can be inline")
        value += inline_page
    return value


def inline_page(items: list[tuple[int, bytes, bytes]]) -> bytes:
    """Build an inline page (header + elements + data) without a page header padding."""
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


def leaf_page(pgid: int, items: list[tuple[int, bytes, bytes]]) -> bytes:
    """Build a full leaf page, padded to PAGE_SIZE."""
    page = bytearray(PAGE_SIZE)
    page[:16] = struct.pack("<QHHI", pgid, LEAF_FLAG, len(items), 0)

    data_start = 16 + 16 * len(items)
    data = bytearray()
    for i, (flags, key, value) in enumerate(items):
        element_offset = 16 + i * 16
        pos = data_start + len(data) - element_offset
        page[element_offset : element_offset + 16] = struct.pack("<IIII", flags, pos, len(key), len(value))
        data += key + value

    if data_start + len(data) > PAGE_SIZE:
        raise ValueError("Leaf page contents do not fit in a page")
    page[data_start : data_start + len(data)] = data
    return bytes(page)


def meta_page(page_id: int, root: int, sequence: int, pages: int, txid: int) -> bytes:
    meta = bytearray(80)
    meta[:16] = struct.pack("<QHHI", page_id, META_FLAG, 0, 0)
    meta[16:32] = struct.pack("<IIII", MAGIC, VERSION, PAGE_SIZE, 0)
    meta[32:48] = struct.pack("<QQ", root, sequence)
    meta[48:72] = struct.pack("<QQQ", 2, pages, txid)
    meta[72:80] = struct.pack("<Q", fnv1a_64(bytes(meta[:72])))
    return bytes(meta) + bytes(PAGE_SIZE - len(meta))


def freelist_page(pgid: int) -> bytes:
    page = bytearray(PAGE_SIZE)
    page[:16] = struct.pack("<QHHI", pgid, FREELIST_FLAG, 0, 0)
    return bytes(page)


def write_database(path: Path, root_page: bytes, root_pgid: int, extra_pages: list[bytes]) -> Path:
    """Write a minimal but structurally valid bbolt database."""
    total = 3 + 1 + len(extra_pages)
    pages = [meta_page(0, root_pgid, 0, total, 1), meta_page(1, root_pgid, 0, total, 2), freelist_page(2), root_page]
    pages.extend(extra_pages)
    path.write_bytes(b"".join(pages))
    return path
