from __future__ import annotations

import gc
import gzip
import hashlib
import io
import struct
import weakref

from dissect.archive.vbk.vbk import (
    PAGE_SIZE,
    VBK,
    MetaBlob,
    MetaTableDescriptor,
    MetaVector,
    MetaVector2,
    _LRUCache,
)
from tests._util import absolute_path


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

    class _FakeSlot:
        def __init__(self, vbk: "_FakeVBK") -> None:
            self.vbk = vbk

        def page(self, page: int) -> memoryview:
            return memoryview(mock_blob[page * PAGE_SIZE : (page + 1) * PAGE_SIZE])

    class _FakeVBK:
        format_version = 13

        def __init__(self) -> None:
            self._page_cache = _LRUCache(256, PAGE_SIZE)

        def page(self, page: int) -> memoryview:
            cache = self._page_cache
            try:
                return cache.get(page)
            except KeyError:
                value = _FakeSlot(self).page(page)
                cache.put(page, value)
                return value

        def get_meta_blob(self, page: int) -> MetaBlob:
            return MetaBlob(_FakeSlot(self), page)

    mock_vbk = _FakeVBK()
    vec = MetaVector2(mock_vbk, MetaTableDescriptor, 0, 4096)
    assert isinstance(vec, MetaVector2)

    for i in range(entry):
        assert vec._lookup_page(i) == i


class _CountingHandle(io.BytesIO):
    """File handle that records actual read operations and the distinct pages touched."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_calls = 0
        self.pages_read = set()

    def read(self, n: int = -1) -> bytes:
        pos = self.tell()
        data = super().read(n)
        self.read_calls += 1
        first = pos // PAGE_SIZE
        last = (pos + len(data) - 1) // PAGE_SIZE
        self.pages_read.update(range(first, last + 1))
        return data


def _load_bytes(name: str) -> bytes:
    with gzip.open(absolute_path(f"_data/vbk/{name}")) as fh:
        return fh.read()


def _first_internal_file(vbk: VBK):
    for subfolder in vbk.root.iterdir():
        for item in subfolder.iterdir():
            if item.is_internal_file():
                return item
    raise AssertionError("no internal file found")


def test_page_cache_is_bounded() -> None:
    """The per-instance page cache never exceeds its configured page/byte upper bound."""
    fh = _CountingHandle(_load_bytes("test13.vbk.gz"))
    vbk = VBK(fh, page_cache_size=8)

    for idx in range(vbk.block_store.count):
        vbk.block_store.get(idx)
    for subfolder in vbk.root.iterdir():
        for item in subfolder.iterdir():
            _ = item.properties
            if item.is_internal_file():
                with item.open() as stream:
                    stream.read()

    stats = vbk.cache_stats()
    assert stats.currsize <= 8
    assert stats.retained_bytes == stats.currsize * PAGE_SIZE
    assert stats.retained_bytes <= 8 * PAGE_SIZE


def test_repeated_small_query_is_served_from_cache() -> None:
    """Re-reading a small file reuses cached pages instead of issuing new page reads."""
    fh = _CountingHandle(_load_bytes("test13.vbk.gz"))
    vbk = VBK(fh, page_cache_size=32)
    item = _first_internal_file(vbk)

    with item.open() as stream:
        first = stream.read(1024)
    pages_after_first = set(fh.pages_read)
    misses_after_first = vbk.cache_stats().misses

    for _ in range(3):
        with item.open() as stream:
            assert stream.read(1024) == first

    # No new distinct pages and no new misses: the repeated queries hit cached pages.
    assert fh.pages_read == pages_after_first
    assert vbk.cache_stats().misses == misses_after_first
    assert vbk.cache_stats().hits > 0


def test_interleaved_instances_are_isolated_and_consistent() -> None:
    """Two VBK instances of the same bytes keep independent bounded caches and equal content."""
    raw = _load_bytes("test9.vbk.gz")
    vbk_a = VBK(io.BytesIO(raw), page_cache_size=16)
    vbk_b = VBK(io.BytesIO(raw), page_cache_size=16)

    assert vbk_a._page_cache is not vbk_b._page_cache

    item_a = _first_internal_file(vbk_a)
    item_b = _first_internal_file(vbk_b)

    with item_a.open() as stream_a, item_b.open() as stream_b:
        # Interleave access across the two instances.
        chunk_a = stream_a.read(2048)
        chunk_b = stream_b.read(2048)
        assert chunk_a == chunk_b
        assert stream_a.read(2048) == stream_b.read(2048)

    stats_a = vbk_a.cache_stats()
    stats_b = vbk_b.cache_stats()
    assert stats_a.currsize <= 16 and stats_b.currsize <= 16
    assert stats_a.retained_bytes <= 16 * PAGE_SIZE
    assert stats_b.retained_bytes <= 16 * PAGE_SIZE

    # A third instance of the unchanged source produces identical content.
    vbk_c = VBK(io.BytesIO(raw), page_cache_size=16)
    with _first_internal_file(vbk_c).open() as stream_c:
        assert stream_c.read(2048) == chunk_a


def test_releasing_vbk_drops_cache_and_handle() -> None:
    """No global cache keeps page buffers or the file handle alive after the VBK is released."""
    raw = _load_bytes("test13.vbk.gz")

    def open_and_read():
        fh = io.BytesIO(raw)
        vbk = VBK(fh, page_cache_size=16)
        with _first_internal_file(vbk).open() as stream:
            stream.read()
        return weakref.ref(vbk), weakref.ref(fh)

    vbk_ref, fh_ref = open_and_read()
    gc.collect()

    assert vbk_ref() is None
    assert fh_ref() is None


def test_clear_cache_drops_retained_pages() -> None:
    """clear_cache empties the retained footprint while the instance stays usable."""
    fh = _CountingHandle(_load_bytes("test13.vbk.gz"))
    vbk = VBK(fh, page_cache_size=32)
    item = _first_internal_file(vbk)
    with item.open() as stream:
        stream.read(1024)

    assert vbk.cache_stats().currsize > 0
    vbk.clear_cache()
    stats = vbk.cache_stats()
    assert stats.currsize == 0
    assert stats.retained_bytes == 0
    assert stats.hits == 0 and stats.misses == 0

    # The instance remains functional and repopulates the cache.
    with item.open() as stream:
        stream.read(1024)
    assert vbk.cache_stats().currsize > 0


def test_lru_cache_evicts_oldest() -> None:
    """The internal LRU honours its bound and tracks retained bytes."""
    cache = _LRUCache(2, PAGE_SIZE)
    cache.put(0, b"a" * PAGE_SIZE)
    cache.put(1, b"b" * PAGE_SIZE)
    assert cache.get(0) == b"a" * PAGE_SIZE
    cache.put(2, b"c" * PAGE_SIZE)  # evicts key 1 (least recently used)

    stats = cache.stats()
    assert stats.currsize == 2
    assert stats.retained_bytes == 2 * PAGE_SIZE
    assert stats.hits == 1

    try:
        cache.get(1)
    except KeyError:
        pass
    else:
        raise AssertionError("key 1 should have been evicted")

    evicted_stats = cache.stats()
    assert evicted_stats.misses == 1
    assert evicted_stats.retained_bytes == 2 * PAGE_SIZE

