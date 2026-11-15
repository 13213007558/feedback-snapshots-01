from __future__ import annotations

import gzip
import hashlib
import io
import struct
from unittest.mock import Mock

import pytest

from dissect.archive.vbk.c_vbk import c_vbk
from dissect.archive.vbk.vbk import (
    META_ITEM_CACHE_BUDGET,
    PAGE_CACHE_BUDGET,
    PAGE_SIZE,
    VBK,
    MetaBlob,
    MetaTableDescriptor,
    MetaVector,
    MetaVector2,
    VBKError,
    _Cache,
)
from tests._util import CountingIO, absolute_path


def test_vbk_version_9() -> None:
    """Test VBK parsing for version 9 files."""
    with gzip.open(absolute_path("_data/vbk/test9.vbk.gz")) as fh:
        vbk = VBK(fh)

        assert vbk.format_version == 9
        assert vbk.is_v7()
        assert isinstance(vbk.block_store, MetaVector)

        assert vbk.root.is_dir()
        assert not vbk.root.is_file()
        assert list(vbk.get("/").listdir().keys()) == [
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)"  # noqa: E501
        ]

        entry = vbk.get(
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)"  # noqa: E501
        )
        assert entry.is_dir()
        assert not vbk.root.is_file()
        assert list(entry.listdir().keys()) == [
            "DEV__dev_nvme1n1",
            "summary.xml",
        ]

        entry = vbk.get("DEV__dev_nvme1n1", entry)
        assert not entry.is_dir()
        assert entry.is_file()
        assert entry.is_internal_file()
        assert not entry.properties
        assert entry.size == 0x400000

        with entry.open() as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
            assert digest == "337350cac29d2ed34c23ce9fc675950badf85fd2b694791abe6999d36f0dc1b3"


def test_vbk_version_13() -> None:
    """Test VBK parsing for version 13 files."""
    with gzip.open(absolute_path("_data/vbk/test13.vbk.gz")) as fh:
        vbk = VBK(fh)

        assert vbk.format_version == 13
        assert vbk.is_v7()
        assert isinstance(vbk.block_store, MetaVector2)
        assert list(vbk.get("/").listdir().keys()) == [
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)"
        ]

        entry = vbk.get("6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)")
        assert entry.is_dir()
        assert not entry.is_file()
        assert list(entry.listdir().keys()) == [
            "digest_47d9f323-442b-433d-bd4f-1ecb3fa97351",
            "8b14f74c-360d-4d7a-98f7-7f4c5e737eb7",
            "GuestMembers.xml",
            "BackupComponents.xml",
            "summary.xml",
        ]

        entry = vbk.get(
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/8b14f74c-360d-4d7a-98f7-7f4c5e737eb7"  # noqa: E501
        )
        assert not entry.is_dir()
        assert entry.is_file()
        assert entry.is_internal_file()
        assert "DefinedBlocksMask" in entry.properties
        assert len(entry.properties["DefinedBlocksMask"]) == 35
        assert entry.size == 0x314200

        with entry.open() as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
            assert digest == "e9ed281cf9c2fe1745e4eb9c926c1a64bd47569c48be511c5fdf6fd5793e5a77"


def test_metavector2_lookup() -> None:
    """Test that the lookup logic in MetaVector2 works as expected."""
    raw_blob = []
    entry = 0
    num_pages = 11
    for i in range(num_pages):
        if i == 0:
            # root page
            header = struct.pack("<qq", i + 1, 0)
        elif i % 3 == 1:
            # "first" page
            header = struct.pack(
                "<qqqq",
                i + 1 if i + 1 < num_pages else -1,
                i,
                i + 1 if i + 1 < num_pages else -1,
                i + 2 if i + 2 < num_pages else -1,
            )
        else:
            # "middle" pages
            header = struct.pack("<q", i + 1 if i + 1 < num_pages else -1)

        num_entries = (PAGE_SIZE // 8) - (len(header) // 8)
        data = struct.pack(f"<{num_entries}q", *range(entry, entry + num_entries))
        raw_blob.append(header + data)
        entry += num_entries

    mock_blob = b"".join(raw_blob)

    mock_slot = Mock()
    mock_slot.page = lambda page: mock_blob[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]
    mock_vbk = Mock(format_version=13)
    mock_vbk.page = mock_slot.page
    mock_vbk.get_meta_blob = lambda page: MetaBlob(mock_slot, page)
    vec = MetaVector2(mock_vbk, MetaTableDescriptor, 0, 4096)
    assert isinstance(vec, MetaVector2)

    for i in range(entry):
        assert vec._lookup_page(i) == i


def _open_counting(name: str) -> tuple[VBK, CountingIO]:
    with gzip.open(absolute_path(f"_data/vbk/{name}.vbk.gz")) as fh:
        raw = fh.read()
    io = CountingIO(raw)
    return VBK(io), io


def _files(vbk: VBK) -> list[tuple[str, object]]:
    files = []

    def walk(item, prefix: str = "") -> None:
        for child in item.iterdir():
            path = f"{prefix}/{child.name}"
            if child.is_dir():
                walk(child, path)
            else:
                files.append((path, child))

    walk(vbk.root)
    return files


def _sha256(item) -> str:
    with item.open() as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def test_repeated_small_queries_reuse_metadata_reads() -> None:
    # Listing the same directory repeatedly must not re-read any metadata, and repeated
    # opens of a small internal file must re-read only the file's own data block: its page
    # table, block descriptors and properties are already in the instance caches.
    vbk, io = _open_counting("test13")
    base = f"/{next(iter(vbk.get('/').listdir()))}"

    vbk.get("/").listdir()
    io.reset()
    for _ in range(50):
        assert list(vbk.get("/").listdir()) == [base[1:]]
    assert io.reads == 0
    assert io.bytes == 0

    small = f"{base}/digest_47d9f323-442b-433d-bd4f-1ecb3fa97351"
    with vbk.get(small).open() as fh:
        expected = hashlib.sha256(fh.read()).hexdigest()

    io.reset()
    for _ in range(20):
        with vbk.get(small).open() as fh:
            assert hashlib.sha256(fh.read()).hexdigest() == expected
    # One data read per open, with no metadata traffic (a cold open read eight pages).
    assert io.reads == 20
    assert io.bytes == 20 * 536


def test_instances_do_not_share_or_serve_from_each_other() -> None:
    # Interleave two instances of the same file. Each must serve its own cached metadata and
    # must agree with the other on content, i.e. neither one's cache changes the answer.
    first, first_io = _open_counting("test13")
    second, second_io = _open_counting("test13")

    subdir = f"/{next(iter(first.get('/').listdir()))}"
    names = list(first.get(subdir).listdir())

    first.get(subdir).listdir()
    second.get(subdir).listdir()
    first_io.reset()
    second_io.reset()
    for _ in range(10):
        assert list(first.get(subdir).listdir()) == names
        assert list(second.get(subdir).listdir()) == names

    assert first_io.reads == 0
    assert second_io.reads == 0
    assert first._pages.hits > 0
    assert second._pages.hits > 0

    # Each instance's caches are distinct objects and their contents agree on the file.
    assert first._pages is not second._pages
    assert _sha256(first.get(f"{subdir}/{names[0]}")) == _sha256(second.get(f"{subdir}/{names[0]}"))
    assert first.active_slot.offset == second.active_slot.offset


def test_caches_are_bounded_in_bytes() -> None:
    vbk, _ = _open_counting("test13")

    # Touch every file and every property dictionary, then read one large file fully. Even
    # after a full pass the retained metadata must stay within the published budgets.
    for _, item in _files(vbk):
        _ = item.properties
        with item.open() as fh:
            fh.read(vbk.block_size * 2)

    assert vbk._pages.nbytes <= vbk._pages.budget
    assert vbk._meta_items.nbytes <= vbk._meta_items.budget
    assert vbk._properties.nbytes <= vbk._properties.budget

    # A single entry larger than the budget is still returned, but the cache retains at most
    # one such oversized entry rather than growing with every read.
    assert vbk._pages.nbytes <= vbk._pages.budget + PAGE_SIZE

    # The budgets are fixed, not derived from archive size or vector counts.
    assert vbk._pages.budget == PAGE_CACHE_BUDGET
    assert vbk._meta_items.budget == META_ITEM_CACHE_BUDGET


def test_closing_releases_evidence_handles_and_caches() -> None:
    # Closing one of several concurrently open archives must drop that archive's metadata
    # caches and, once no external references remain, let the instance and its evidence
    # handle be collected even while another archive is still open.
    import gc
    import weakref

    first, first_io = _open_counting("test9")
    second, _ = _open_counting("test13")
    first.get("/").listdir()
    second.get("/").listdir()

    first_pages = weakref.ref(first._pages)
    first_ref = weakref.ref(first)
    first_handle = weakref.ref(first_io)

    first.close()
    assert len(first._pages) == 0
    assert len(first._meta_items) == 0
    assert len(first._properties) == 0

    # Parent/child references (item -> vbk, bank -> vbk) form a cycle by design, so the
    # instance is reclaimed by the cyclic collector rather than by refcounting alone.
    # The file handle is owned by the caller, so the test drops its own reference too.
    del first, first_io
    gc.collect()
    assert first_ref() is None
    assert first_pages() is None
    assert first_handle() is None

    # The other instance still works after the first one is gone.
    assert len(second.get("/").listdir()) == 1


def test_bank_headers_are_only_read_when_used() -> None:
    # Opening a VBK used to read a full 4 KiB bank header for every bank in both slots.
    # Selection needs only the descriptors, so no header page is read while opening or while
    # walking the directory, and none is retained for a bank that was never used.
    vbk, io = _open_counting("test13")
    assert not any(slot._bank_cache for slot in (vbk.slot1, vbk.slot2))

    io.reset()
    vbk.get("/").listdir()
    assert not any(bank._header is not None for slot in (vbk.slot1, vbk.slot2) for bank in slot._bank_cache.values())

    # A data read constructs the bank it reads from; its header stays lazy until asked for.
    item = _files(vbk)[0][1]
    with item.open() as fh:
        fh.read(PAGE_SIZE)
    bank = vbk.active_slot._bank_cache[0]
    assert bank._header is None
    assert bank.header.PageCount >= 1


def _raw(name: str) -> bytearray:
    with gzip.open(absolute_path(f"_data/vbk/{name}.vbk.gz")) as fh:
        return bytearray(fh.read())


def test_default_verification_still_selects_the_valid_slot() -> None:
    # A corrupt first slot must fail its CRC and lose to the intact second slot; this is the
    # property the cache changes must not weaken. Version lives at slot offset + 8.
    raw = _raw("test13")
    intact = VBK(io.BytesIO(bytes(raw)))
    assert intact.active_slot is intact.slot1

    corrupt = raw[:]
    corrupt[intact.slot1.offset + 8] ^= 0xFF

    vbk = VBK(io.BytesIO(bytes(corrupt)))
    assert vbk.active_slot is vbk.slot2
    assert list(vbk.get("/").listdir()) == list(intact.get("/").listdir())


def test_verification_can_be_disabled_but_is_on_by_default() -> None:
    raw = _raw("test13")
    intact = VBK(io.BytesIO(bytes(raw)))
    corrupt = raw[:]
    corrupt[intact.slot1.offset + 8] ^= 0xFF
    corrupt[intact.slot2.offset + 8] ^= 0xFF

    with pytest.raises(VBKError):
        VBK(io.BytesIO(bytes(corrupt)))

    # With verification off both slots are candidates again, so the archive still opens.
    vbk = VBK(io.BytesIO(bytes(corrupt)), verify=False)
    assert vbk.active_slot in (vbk.slot1, vbk.slot2)


def test_invalid_bank_grain_is_still_rejected() -> None:
    # MaxBanks is bounded by the slot format; the check runs in the slot constructor before
    # any cache exists, so a malformed slot cannot be masked by lazy bank loading.
    raw = _raw("test13")
    grain_offset = PAGE_SIZE + len(c_vbk.SnapshotSlotHeader) + len(c_vbk.SnapshotDescriptor)
    raw[grain_offset : grain_offset + 4] = (0x7F01).to_bytes(4, "little")

    with pytest.raises(VBKError, match="MaxBanks"):
        VBK(io.BytesIO(bytes(raw)), verify=False)


def test_metavector2_does_not_retain_the_whole_table() -> None:
    # Finding which page holds entry N means following the table's next-page chain, which
    # reads each table page once. What must not happen is joining the table into one bytes
    # object and holding a memoryview over the whole index for the vector's lifetime -- that
    # is what the old constructor did for every archive, however small the query.
    num_pages = 200
    raw_blob = []
    entry = 0
    for i in range(num_pages):
        if i == 0:
            header = struct.pack("<qq", i + 1, 0)
        elif i % 3 == 1:
            header = struct.pack(
                "<qqqq",
                i + 1 if i + 1 < num_pages else -1,
                i,
                i + 1 if i + 1 < num_pages else -1,
                i + 2 if i + 2 < num_pages else -1,
            )
        else:
            header = struct.pack("<q", i + 1 if i + 1 < num_pages else -1)

        num_entries = (PAGE_SIZE // 8) - (len(header) // 8)
        raw_blob.append(header + struct.pack(f"<{num_entries}q", *range(entry, entry + num_entries)))
        entry += num_entries

    blob = b"".join(raw_blob)
    page_reads = []

    class FakeVBK:
        format_version = 13

        def __init__(self):
            self._pages = _Cache(PAGE_SIZE * 4, len)

        def page(self, page: int) -> bytes:
            page_reads.append(page)
            return blob[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]

        def get_meta_blob(self, page: int):
            return MetaBlob(self, page)

    vbk = FakeVBK()
    vec = MetaVector2(vbk, MetaTableDescriptor, 0, 4096)

    # Building the vector reads nothing: the page list and table are resolved on demand.
    assert vec._table_pages is None
    assert page_reads == []
    assert not hasattr(vec, "_table")

    # One lookup walks the page chain (all pages, as the format requires) but only touches
    # each table page once, and retained table content is capped by the page cache budget.
    assert vec._lookup_page(0) == 0
    walked = len(page_reads)
    assert walked == num_pages + 1  # the chain plus the one lookup into page 0
    assert len(vbk._pages) <= 4
    assert vbk._pages.nbytes <= vbk._pages.budget

    # The page list is now known, so another lookup of a page already cached is free and one
    # of an evicted page re-reads at most a single table page.
    page_reads.clear()
    vec._lookup_page(0)
    assert page_reads == []

    page_reads.clear()
    vec._lookup_page(5)
    assert len(page_reads) <= 1
    assert vbk._pages.nbytes <= vbk._pages.budget
