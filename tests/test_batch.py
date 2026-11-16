from __future__ import annotations

import gzip
from pathlib import Path
from typing import BinaryIO

import pytest

from dissect.cim import CIM
from dissect.cim.exceptions import Error


class CountingIO:
    """Wraps a binary file and counts physical read() calls (page accesses)."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.reads = 0

    def seek(self, *args) -> int:
        return self.fh.seek(*args)

    def tell(self) -> int:
        return self.fh.tell()

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        return self.fh.read(size)

    def __getattr__(self, attr: str):
        return getattr(self.fh, attr)


DATA = Path(__file__).parent / "_data"


def _open_gz(name: str) -> BinaryIO:
    return gzip.open(DATA / name, "rb")


def _build_counting() -> tuple[CIM, CountingIO, CountingIO]:
    index = CountingIO(_open_gz("INDEX.BTR.gz"))
    objects = CountingIO(_open_gz("OBJECTS.DATA.gz"))
    mappings = [_open_gz(f"MAPPING{i}.MAP.gz") for i in range(1, 4)]
    repo = CIM(index, objects, mappings)
    return repo, index, objects


def _initialized(instance) -> dict[str, str]:
    return {name: str(prop.value) for name, prop in instance.properties.items() if prop.state.is_initialized}


def test_query_many_preserves_order_and_independence(index_bin, objects_bin, mappings_bin) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    paths = [
        "//./root/CIMV2:Win32_ShadowContext.Name=AppRollback",
        "//./root/CIMV2:Win32_ShadowContext.Name=Backup",
        "//./root/CIMV2:Win32_ShadowContext.Name=AppRollback",  # duplicate reference
        "//./root/CIMV2:Win32_ShadowContext",
        "//./root/CIMV2",
    ]

    results = repo.query_many(paths)

    assert [result.path for result in results] == paths
    assert all(result.ok for result in results)
    assert [type(result.value).__name__ for result in results] == [
        "Instance",
        "Instance",
        "Instance",
        "Class",
        "Namespace",
    ]
    # Duplicate references share the parsed fact but keep independent result objects.
    assert results[0].value.class_instance is results[2].value.class_instance
    assert results[0].value is not results[2].value


def test_query_many_matches_single_query_content(index_bin, objects_bin, mappings_bin) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    paths = [
        "//./root/CIMV2:Win32_ShadowContext.Name=AppRollback",
        "//./root/CIMV2:Win32_ShadowContext.Name=Backup",
        "//./root/CIMV2:Win32_ShadowContext.Name=NASRollback",
    ]

    for result, path in zip(repo.query_many(paths), paths, strict=True):
        assert result.ok
        assert _initialized(result.value) == _initialized(repo.query(path))


def test_query_many_isolates_failures(index_bin, objects_bin, mappings_bin) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    good = "//./root/CIMV2:__NAMESPACE.Name=power"
    missing = "//./root/CIMV2:Win32_ShadowContext.Name='__does_not_exist__'"

    results = repo.query_many([good, missing, good])

    assert results[0].ok and results[2].ok
    assert not results[1].ok
    assert isinstance(results[1].error, IndexError)
    # The bad reference does not touch the successful results.
    assert _initialized(results[0].value) == _initialized(results[2].value)


def test_query_many_corrupt_class_is_contained() -> None:
    repo, _, _ = _build_counting()
    poisoned = ["//./root/CIMV2:Win32_ShadowContext.Name=AppRollback"]
    healthy = ["//./root/CIMV2:__NAMESPACE.Name=power", "//./root/CIMV2"]

    original = repo.get_class_definition

    def poisoned_get(q):
        class_definition = original(q)
        if class_definition.class_name == "Win32_ShadowContext":
            raise Error("corrupt class definition")
        return class_definition

    repo.get_class_definition = poisoned_get
    results = repo.query_many([*poisoned, *healthy])

    assert not results[0].ok and isinstance(results[0].error, Error)
    assert all(result.ok for result in results[1:])

    clean, _, _ = _build_counting()
    assert _initialized(results[1].value) == _initialized(clean.query(healthy[0]))


def test_query_many_shares_layout_and_pages() -> None:
    paths = [
        "//./root/CIMV2:Win32_ShadowContext.Name=AppRollback",
        "//./root/CIMV2:Win32_ShadowContext.Name=Backup",
        "//./root/CIMV2:Win32_ShadowContext.Name=AppRollback",
        "//./root/CIMV2:Win32_ShadowContext.Name=All",
    ]

    # One-by-one with the read-only caches cleared between items, mirroring the
    # pre-batch behaviour where every reference rescanned and re-parsed.
    single_repo, single_index, single_objects = _build_counting()
    single_index_base = single_index.reads
    single_objects_base = single_objects.reads
    for path in paths:
        single_repo._class_definition_cache.clear()
        single_repo._derivation_cache.clear()
        single_repo.index._lookup.cache_clear()
        single_repo.index.store.page.cache_clear()
        single_repo.objects.store.page.cache_clear()
        single_repo.objects.store.physical_page.cache_clear()
        single_repo.query(path)
    single_index_reads = single_index.reads - single_index_base
    single_objects_reads = single_objects.reads - single_objects_base

    # A single batched pass over the same input.
    batch_repo, batch_index, batch_objects = _build_counting()
    batch_index_base = batch_index.reads
    batch_objects_base = batch_objects.reads
    batch_results = batch_repo.query_many(paths)
    batch_index_reads = batch_index.reads - batch_index_base
    batch_objects_reads = batch_objects.reads - batch_objects_base

    assert all(result.ok for result in batch_results)
    # The batch must reduce real page accesses rather than only CPU work.
    assert batch_index_reads < single_index_reads
    assert batch_objects_reads < single_objects_reads
    # The shared layout is resolved once for the whole batch.
    assert len(batch_repo._derivation_cache) == 1


def test_query_many_does_not_expand_unrelated_layouts() -> None:
    from dissect.cim.cim import Class

    repo, _, _ = _build_counting()
    original = Class.derivation.fget
    computed: list[str] = []

    def spy(self):
        computed.append(self.name)
        return original(self)

    Class.derivation = property(spy)
    try:
        results = repo.query_many(
            [
                "//./root/CIMV2:Win32_ShadowContext.Name=AppRollback",
                "//./root/CIMV2:Win32_ShadowContext.Name=Backup",
            ]
        )
    finally:
        Class.derivation = property(original)

    assert all(result.ok for result in results)
    assert set(computed) == {"Win32_ShadowContext"}


def test_mapping_views_are_isolated() -> None:
    first, _, _ = _build_counting()
    second, _, _ = _build_counting()

    assert first._class_definition_cache is not second._class_definition_cache
    assert first._derivation_cache is not second._derivation_cache
    assert first.index is not second.index
    assert first.objects is not second.objects

    first.namespace("root\\CIMV2").class_("Win32_ShadowContext").derivation
    assert first._derivation_cache
    assert not second._derivation_cache
    assert not second._class_definition_cache


def test_instance_accepts_textual_key(index_bin, objects_bin, mappings_bin) -> None:
    repo = CIM(index_bin, objects_bin, mappings_bin)
    cls = repo.namespace("root\\CIMV2").class_("Win32_ShadowContext")
    instance = next(iter(cls.instances))

    assert cls.instance(str(instance.key)).key == instance.key


@pytest.mark.parametrize(
    "key",
    [
        {"Name": "Beep"},
        {"A": 1, "B": 2},
    ],
)
def test_instance_key_is_hashable(key) -> None:
    from dissect.cim.classes import InstanceKey

    instance_key = InstanceKey(key)
    assert hash(instance_key) == id(instance_key)
    assert {instance_key: "present"}[instance_key] == "present"
