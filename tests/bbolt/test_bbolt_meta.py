from __future__ import annotations

import io
import struct

import pytest

from dissect.database.bbolt import Bbolt

PAGE_SIZE = 0x200
MAGIC = 0xED0CDAED
PGID_NO_FREELIST = 0xFFFFFFFFFFFFFFFF

FLAG_META = 0x04
FLAG_LEAF = 0x02


def fnv1a64(data: bytes) -> int:
    h = 14695981039346656037
    for byte in data:
        h = ((h ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def meta_page(
    index: int,
    txid: int,
    root: int,
    high_water: int,
    page_size: int = PAGE_SIZE,
    *,
    corrupt_checksum: bool = False,
) -> bytes:
    """Build a minimal bbolt meta page."""
    header = struct.pack("<QHHI", index, FLAG_META, 0, 0)
    body = struct.pack("<IIII", MAGIC, 2, page_size, 0)
    body += struct.pack("<QQ", root, 0)  # root bucket: root pgid + sequence
    body += struct.pack("<QQQ", PGID_NO_FREELIST, high_water, txid)
    checksum = fnv1a64(body)
    if corrupt_checksum:
        checksum ^= 0xFFFFFFFFFFFFFFFF
    return (header + body + struct.pack("<Q", checksum)).ljust(page_size, b"\x00")


def leaf_page(pgid: int, entries: list[tuple[bytes, bytes]], page_size: int = PAGE_SIZE) -> bytes:
    """Build a minimal bbolt leaf page with the given key/value pairs."""
    header = struct.pack("<QHHI", pgid, FLAG_LEAF, len(entries), 0)
    elements = []
    data = b""
    base = 16 + 16 * len(entries)
    for i, (key, value) in enumerate(entries):
        # leafPageElement.pos is relative to the offset of the element itself
        pos = base + len(data) - (16 + i * 16)
        elements.append(struct.pack("<IIII", 0, pos, len(key), len(value)))
        data += key + value
    return (header + b"".join(elements) + data).ljust(page_size, b"\x00")


def build_db(meta0: bytes, meta1: bytes, pages: dict[int, bytes], page_size: int = PAGE_SIZE) -> io.BytesIO:
    """Assemble a small bbolt image from two meta pages and a mapping of pgid to page."""
    size = (max(pages) + 1) * page_size
    buf = bytearray(size)
    buf[0:page_size] = meta0
    buf[page_size : 2 * page_size] = meta1
    for pgid, page in pages.items():
        buf[pgid * page_size : (pgid + 1) * page_size] = page
    return io.BytesIO(bytes(buf))


def old_new_db(meta1_corrupt: bool = False) -> io.BytesIO:
    """Database where meta0 (txid 1) is the old view and meta1 (txid 2) the new view."""
    return build_db(
        meta_page(0, txid=1, root=2, high_water=4),
        meta_page(1, txid=2, root=3, high_water=4, corrupt_checksum=meta1_corrupt),
        {
            2: leaf_page(2, [(b"name", b"old-view")]),
            3: leaf_page(3, [(b"name", b"new-view")]),
        },
    )


def test_selects_newest_valid_meta() -> None:
    """Both meta pages valid: the newer transaction view must be selected."""
    db = Bbolt(old_new_db())

    assert db.txid == 2
    assert db.keys() == ["name"]
    assert db.get("name") == "new-view"

    old, new = db.meta_candidates
    assert old.valid and not old.selected
    assert "older txid 1 < 2" in old.reason
    assert new.valid and new.selected
    assert "highest valid txid 2" in new.reason


def test_falls_back_to_old_meta_when_new_is_corrupt() -> None:
    """A corrupt newer meta page must fall back to the provably valid older snapshot."""
    db = Bbolt(old_new_db(meta1_corrupt=True))

    assert db.txid == 1
    assert db.get("name") == "old-view"

    old, new = db.meta_candidates
    assert old.valid and old.selected
    assert not new.valid and not new.selected
    assert "checksum mismatch" in new.reason
    assert "newer but cannot be proven valid" in new.reason


def test_selects_second_meta_when_first_is_corrupt() -> None:
    """A corrupt first meta page must not prevent using the valid second one."""
    db = Bbolt(
        build_db(
            meta_page(0, txid=1, root=2, high_water=4, corrupt_checksum=True),
            meta_page(1, txid=2, root=3, high_water=4),
            {
                2: leaf_page(2, [(b"name", b"old-view")]),
                3: leaf_page(3, [(b"name", b"new-view")]),
            },
        )
    )

    assert db.txid == 2
    assert db.get("name") == "new-view"

    old, new = db.meta_candidates
    assert not old.valid and "checksum mismatch" in old.reason
    assert new.valid and new.selected


def test_raises_when_both_metas_are_unusable() -> None:
    """No provably valid meta page: refuse to open and report both rejection reasons."""
    db = build_db(
        meta_page(0, txid=1, root=2, high_water=4, corrupt_checksum=True),
        meta_page(1, txid=2, root=3, high_water=4, corrupt_checksum=True),
        {
            2: leaf_page(2, [(b"name", b"old-view")]),
            3: leaf_page(3, [(b"name", b"new-view")]),
        },
    )

    with pytest.raises(ValueError, match="No valid bbolt meta page found") as excinfo:
        Bbolt(db)

    assert "meta0: checksum mismatch" in str(excinfo.value)
    assert "meta1: checksum mismatch" in str(excinfo.value)


def test_conflicting_valid_metas_are_not_mixed() -> None:
    """Both meta pages valid but with conflicting page sizes: a single consistent view must be used."""
    meta0 = meta_page(0, txid=1, root=2, high_water=8, page_size=0x200)
    meta1 = meta_page(1, txid=2, root=3, high_water=4, page_size=0x400)

    buf = bytearray(0x1000)
    buf[0:0x200] = meta0  # meta0 view: page size 0x200, root at page 2
    buf[0x200:0x600] = meta1  # meta1 view: page size 0x400, root at page 3 (offset 0xC00)
    buf[0xC00:0x1000] = leaf_page(3, [(b"name", b"new-view")], page_size=0x400)

    db = Bbolt(io.BytesIO(bytes(buf)))

    # Only the newer meta's page size, root and high-water mark may be used
    assert db.txid == 2
    assert db.page_size == 0x400
    assert db.get("name") == "new-view"

    old, new = db.meta_candidates
    assert old.valid and not old.selected
    assert "conflicting page size" in old.reason
    assert "views were not mixed" in old.reason
    assert new.selected
    assert "page size conflict" in new.reason
