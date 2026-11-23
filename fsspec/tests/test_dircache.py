import pickle
import time

import pytest

from fsspec.dircache import DirCache


def test_dircache_evicts_oldest_when_capacity_exceeded():
    dc = DirCache(max_paths=2)
    dc["a"] = 1
    dc["b"] = 2

    dc["c"] = 3

    assert "a" not in dc
    assert dc["b"] == 2
    assert dc["c"] == 3
    assert len(dc) == 2


def test_dircache_read_promotes_key_to_most_recent():
    dc = DirCache(max_paths=2)
    dc["a"] = 1
    dc["b"] = 2

    _ = dc["a"]
    dc["c"] = 3

    assert "b" not in dc
    assert dc["a"] == 1
    assert dc["c"] == 3


@pytest.mark.parametrize("max_paths", [-1, 0, None])
def test_dircache_unlimited_paths_retains_all_items(max_paths):
    dc = DirCache(max_paths=max_paths)
    for i in range(10):
        dc[f"k{i}"] = i

    assert len(dc) == 10
    assert dc["k0"] == 0
    assert dc["k9"] == 9
    assert len(list(dc)) == 10


@pytest.mark.parametrize("operation", ["get", "contains", "iter"])
def test_dircache_expired_entry(operation):
    dc = DirCache(listings_expiry_time=0.05)
    dc["a"] = 100
    dc["b"] = 200
    time.sleep(0.08)

    # Use a fresh cache for each operation: checking expiry can evict entries.
    if operation == "get":
        with pytest.raises(KeyError):
            dc["a"]
    elif operation == "contains":
        assert "a" not in dc
    else:
        assert list(dc) == []
        assert len(dc) == 0


def test_dircache_missing_key_not_in_cache_with_expiry():
    dc = DirCache(listings_expiry_time=10)

    is_present = "missing" in dc

    assert is_present is False


def test_dircache_disabled():
    dc = DirCache(use_listings_cache=False)
    dc["a"] = 1
    assert "a" not in dc
    assert len(dc) == 0
    assert list(dc) == []
    with pytest.raises(KeyError):
        dc["a"]


def test_dircache_del_removes_entry():
    dc = DirCache(listings_expiry_time=60, max_paths=10)
    dc["a"] = 1

    del dc["a"]

    assert "a" not in dc
    assert len(dc) == 0


def test_dircache_clear_removes_all_entries():
    dc = DirCache(listings_expiry_time=60, max_paths=10)
    dc["a"] = 1
    dc["b"] = 2

    dc.clear()

    assert len(dc) == 0
    assert "a" not in dc
    assert "b" not in dc


def test_dircache_pickle_roundtrip():
    dc = DirCache(use_listings_cache=True, listings_expiry_time=10, max_paths=5)

    dc2 = pickle.loads(pickle.dumps(dc))

    assert dc2.use_listings_cache is True
    assert dc2.listings_expiry_time == 10
    assert dc2.max_paths == 5


def test_dircache_fields_are_projected_on_write_and_read():
    dc = DirCache(fields=("name", "type"))

    source = [
        {"name": "a", "type": "file", "size": 3, "etag": "secret"},
        {"name": "b", "type": "directory", "size": 0},
    ]
    dc["root"] = source

    # The caller's full record is not referenced by the cache.
    source[0]["etag"] = "changed"
    assert dc["root"] == [
        {"name": "a", "type": "file"},
        {"name": "b", "type": "directory"},
    ]
    assert dc._cache["root"] == dc["root"]


def test_dircache_fields_returned_records_are_copies():
    dc = DirCache(fields=("name", "size"))
    dc["root"] = [{"name": "a", "size": 1}]

    returned = dc["root"]
    returned[0]["size"] = 99
    returned[0]["etag"] = "smuggled"

    assert dc["root"] == [{"name": "a", "size": 1}]
    assert dc._cache["root"] == [{"name": "a", "size": 1}]


def test_dircache_fields_change_narrows_existing_entries():
    dc = DirCache(fields=("name", "size", "etag"))
    dc["root"] = [{"name": "a", "size": 1, "etag": "old"}]

    dc.fields = ("name",)

    assert dc["root"] == [{"name": "a"}]
    assert dc._cache["root"] == [{"name": "a"}]


def test_dircache_fields_require_name():
    with pytest.raises(ValueError):
        DirCache(fields=("size",))
    with pytest.raises(ValueError):
        DirCache(fields=())
    with pytest.raises(TypeError):
        DirCache(fields="name")


def test_dircache_fields_pickle_roundtrip():
    dc = DirCache(fields=("name", "type"))
    dc["root"] = [{"name": "a", "type": "file", "size": 1}]

    dc2 = pickle.loads(pickle.dumps(dc))

    assert dc2.fields == ("name", "type")
    dc2["root"] = [{"name": "a", "type": "file", "size": 1}]
    assert dc2["root"] == [{"name": "a", "type": "file"}]


def test_dircache_fields_project_pair_entries():
    dc = DirCache(fields=("name", "type"))
    dc["root"] = [("a", {"name": "a", "type": "file", "size": 3})]

    assert dc["root"] == [("a", {"name": "a", "type": "file"})]
    assert dc._cache["root"] == [("a", {"name": "a", "type": "file"})]
