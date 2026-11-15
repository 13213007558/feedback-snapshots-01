from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest

from dissect.database.bbolt import Bbolt, InvalidDatabase, select_meta
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

from tests.bbolt._bbolt_builder import (
    BRANCH_FLAG,
    BUCKET_FLAG,
    fnv1a_64,
    leaf_page,
    meta_page,
    write_pages,
)

PAGE_SIZE = 1024


def _bucket(value_root: int, pgid: int = 3) -> bytes:
    return leaf_page(pgid, [(BUCKET_FLAG, b"data", struct.pack("<QQ", value_root, 0))], PAGE_SIZE)


def _value_page(value: bytes, pgid: int) -> bytes:
    return leaf_page(pgid, [(0, b"key", value)], PAGE_SIZE)


def _database(
    path: Path,
    *,
    old_value: bytes = b"old",
    new_value: bytes = b"new",
    old: dict | None = None,
    new: dict | None = None,
) -> Path:
    old_meta = {"root": 3, "high_water": 5, "txid": 10, **(old or {})}
    new_meta = {"root": 3, "high_water": 5, "txid": 11, **(new or {})}
    pages = {
        0: meta_page(0, PAGE_SIZE, **old_meta),
        1: meta_page(1, PAGE_SIZE, **new_meta),
        2: bytes(PAGE_SIZE),
        3: _bucket(4),
        4: _value_page(new_value, 4),
    }
    return write_pages(path, pages, PAGE_SIZE)


def test_selects_newest_valid_snapshot(tmp_path: Path) -> None:
    path = _database(tmp_path / "db")
    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "selected"
    assert selection.selected_index == 1
    assert selection.txid == 11
    assert selection.page_size == PAGE_SIZE
    assert selection.other is not None
    assert selection.other.txid == 10
    assert "older transaction" in selection.explain()

    db = Bbolt(path)
    assert db.meta_index == 1
    assert db.txid == 11
    assert db.get("data key") == "new"


def test_old_first_new_second_prefers_new(tmp_path: Path) -> None:
    """Both metas are valid; the second (newer) one provides the data view."""
    path = _database(tmp_path / "db")
    db = Bbolt(path)

    assert db.txid == 11
    assert db.get("data key") == "new"
    assert db.meta_selection.selected_index == 1
    assert db.meta_selection.candidates[0].valid
    assert "older transaction" in db.explain_selection()


def test_falls_back_to_old_when_new_root_is_outside_view(tmp_path: Path) -> None:
    """The newer meta has a valid checksum, but its root page is outside the file."""
    path = _database(tmp_path / "db", new={"root": 20})
    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "selected"
    assert selection.selected_index == 0
    assert selection.txid == 10
    assert not selection.candidates[1].valid
    assert any("outside" in problem for problem in selection.candidates[1].problems)
    assert "not selected" in selection.explain()

    db = Bbolt(path)
    assert db.txid == 10
    assert db.get("data key") == "new"


def test_fall_back_when_new_page_checksum_is_damaged(tmp_path: Path) -> None:
    path = _database(tmp_path / "db", new={"corrupt": "checksum"})
    db = Bbolt(path)

    assert db.txid == 10
    assert db.get("data key") == "new"
    assert db.meta_selection.status == "selected"
    assert "checksum mismatch" in db.meta_selection.candidates[1].problems[0]


def test_new_page_size_mismatch_is_rejected(tmp_path: Path) -> None:
    path = _database(tmp_path / "db", new={"corrupt": "page_size"})
    db = Bbolt(path)

    assert db.txid == 10
    assert db.page_size == PAGE_SIZE
    assert "page size" in db.meta_selection.candidates[1].problems[0]


def test_old_view_fallback_reads_only_old_pages(tmp_path: Path) -> None:
    """A valid newer meta whose *graph* is damaged must not contaminate the fallback."""
    # meta[0] (txid 10) -> bucket page 3 -> value page 5 -> "old"
    # meta[1] (txid 11) -> bucket page 6 -> value page 7 -> "new"
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=8, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=6, high_water=8, txid=11, freelist=2),
        2: bytes(PAGE_SIZE),
        3: _bucket(5),
        4: bytes(PAGE_SIZE),
        5: _value_page(b"old", 5),
        6: _bucket(7, pgid=6),
        7: _value_page(b"new", 7),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    db = Bbolt(path)
    assert db.txid == 11
    assert db.get("data key") == "new"

    # Damage page 6's header id so the newer snapshot's graph is inconsistent.
    data = bytearray(path.read_bytes())
    struct.pack_into("<Q", data, 6 * PAGE_SIZE, 99)
    path.write_bytes(bytes(data))

    db = Bbolt(path)
    assert db.txid == 10
    assert db.get("data key") == "old"
    assert db.meta_selection.status == "selected"
    assert "header id" in db.meta_selection.candidates[1].problems[0]


def test_conflicting_valid_views_are_not_combined(tmp_path: Path) -> None:
    """Two valid metas at the same txid but with different roots cannot be reconciled."""
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=6, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=4, high_water=6, txid=10, freelist=2),
        2: bytes(PAGE_SIZE),
        3: _value_page(b"one", 3),
        4: _value_page(b"two", 4),
        5: bytes(PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "conflict"
    assert selection.selected is None
    assert "conflicting transaction views" in selection.explain()

    with pytest.raises(InvalidDatabase, match="conflicting transaction views"):
        Bbolt(path)


def test_both_metas_unusable(tmp_path: Path) -> None:
    path = _database(tmp_path / "db", old={"corrupt": "checksum"}, new={"corrupt": "checksum"})

    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "unavailable"
    assert selection.selected is None
    assert all(not candidate.valid for candidate in selection.candidates)

    with pytest.raises(InvalidDatabase, match="both meta candidates are unusable"):
        Bbolt(path)


def test_missing_second_meta_is_unavailable(tmp_path: Path) -> None:
    path = tmp_path / "db"
    path.write_bytes(meta_page(0, PAGE_SIZE, root=3, high_water=4, txid=1))

    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "unavailable"
    assert selection.candidates[1].present is False


def test_high_water_mark_bounds_the_view(tmp_path: Path) -> None:
    """A root page at the high water mark cannot be part of the candidate's own view."""
    path = _database(tmp_path / "db", new={"corrupt": "high_water"})
    db = Bbolt(path)

    assert db.meta_index == 0
    assert db.txid == 10


def test_checksum_is_fnv1a_over_meta_fields() -> None:
    raw = meta_page(0, PAGE_SIZE, root=3, high_water=5, txid=10)
    stored = struct.unpack_from("<Q", raw, 72)[0]
    assert stored == fnv1a_64(raw[16:72])


def test_real_sample_selects_newest_verified() -> None:
    path = absolute_path("_data/bbolt/metadata.db")
    db = Bbolt(path)

    assert db.meta_index == 1
    assert db.txid == 25
    assert db.meta_selection.candidates[0].valid
    assert db.meta_selection.candidates[1].valid
    assert "stale snapshot" in db.explain_selection()


def _branch_page(pgid: int, children: list[tuple[bytes, int]]) -> bytes:
    """Build a branch page pointing at *children* (first key, page id)."""
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<QHHI", page, 0, pgid, BRANCH_FLAG, len(children), 0)
    data_start = 16 + 16 * len(children)
    data = bytearray()
    for i, (key, child) in enumerate(children):
        element_offset = 16 + i * 16
        pos = data_start + len(data) - element_offset
        struct.pack_into("<IIQ", page, element_offset, pos, len(key), child)
        data += key
    page[data_start : data_start + len(data)] = data
    assert data_start + len(data) <= PAGE_SIZE
    return bytes(page)


def test_branch_pages_are_bound_to_the_view(tmp_path: Path) -> None:
    """A branch element pointing above the high water mark rejects the candidate."""
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=6, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=3, high_water=6, txid=11, freelist=2),
        2: bytes(PAGE_SIZE),
        3: _branch_page(3, [(b"key", 4)]),
        4: _value_page(b"value", 4),
        5: bytes(PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    db = Bbolt(path)
    assert db.get("key") == "value"

    # Point the branch at page 5, which is at the high water mark (outside the view).
    data = bytearray(path.read_bytes())
    struct.pack_into("<Q", data, 3 * PAGE_SIZE + 16 + 8, 5)
    path.write_bytes(bytes(data))

    with pytest.raises(InvalidDatabase):
        Bbolt(path)


def test_new_snapshot_with_overflow_past_high_water_is_rejected(tmp_path: Path) -> None:
    """An overflow that crosses the newer candidate's pgid must reject only that candidate."""
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=6, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=4, high_water=6, txid=11, freelist=2),
        2: bytes(PAGE_SIZE),
        3: _value_page(b"old", 3),
        4: _value_page(b"new", 4),
        5: bytes(PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    data = bytearray(path.read_bytes())
    # The newer root page (page 4) claims overflow pages that cross pgid=6.
    struct.pack_into("<I", data, 4 * PAGE_SIZE + 12, 4)
    path.write_bytes(bytes(data))

    db = Bbolt(path)
    assert db.txid == 10
    assert db.get("key") == "old"
    assert db.meta_selection.candidates[1].problems
    assert any("high water" in problem for problem in db.meta_selection.candidates[1].problems)


def test_first_meta_missing_falls_back_to_second(tmp_path: Path) -> None:
    path = _database(tmp_path / "db")
    data = bytearray(path.read_bytes())
    data[:PAGE_SIZE] = bytes(PAGE_SIZE)
    path.write_bytes(bytes(data))

    db = Bbolt(path)
    assert db.meta_index == 1
    assert db.txid == 11
    assert db.meta_selection.candidates[0].present
    assert db.meta_selection.candidates[0].problems


def test_second_meta_corrupt_checksum_falls_back_to_first(tmp_path: Path) -> None:
    path = _database(tmp_path / "db", new={"corrupt": "checksum"})
    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.selected_index == 0
    assert selection.status == "selected"
    assert selection.other is not None
    assert not selection.other.valid
    explanation = selection.explain()
    assert "meta[1]" in explanation
    assert "checksum mismatch" in explanation


def test_selection_is_serialisable(tmp_path: Path) -> None:
    path = _database(tmp_path / "db")
    with path.open("rb") as fh:
        selection = select_meta(fh)

    payload = selection.as_dict()
    assert payload["status"] == "selected"
    assert payload["selected_index"] == 1
    assert len(payload["candidates"]) == 2
    assert payload["candidates"][0]["valid"] is True
    assert payload["candidates"][1]["checksum_verified"] is True


def test_fallback_reason_identifies_damaged_newer_meta(tmp_path: Path) -> None:
    path = _database(tmp_path / "db", new={"corrupt": "checksum"})
    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "selected"
    assert selection.selected_index == 0
    assert "newer meta[1]" in selection.reason
    assert "falling back" in selection.reason
    assert "failed integrity validation" in selection.reason


def test_select_meta_accepts_path(tmp_path: Path) -> None:
    path = _database(tmp_path / "db")
    selection = select_meta(path)
    assert selection.status == "selected"
    assert selection.selected_index == 1


def test_callers_interface_is_exposed(tmp_path: Path) -> None:
    path = _database(tmp_path / "db")
    db = Bbolt(path)

    assert db.meta_selection.status == "selected"
    assert db.meta_selection.selected_index == 1
    assert "selected meta[1]" in db.explain_selection()
    assert "older transaction" in db.explain_selection()
    assert db.meta_selection.as_dict()["selected_index"] == 1


def test_select_meta_preserves_file_position(tmp_path: Path) -> None:
    path = _database(tmp_path / "db")
    with path.open("rb") as fh:
        fh.seek(123)
        select_meta(fh)
        assert fh.tell() == 123


def test_different_views_with_different_txids_use_newest(tmp_path: Path) -> None:
    """A valid newer transaction with a different root wins over an older one."""
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=6, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=4, high_water=6, txid=11, freelist=2),
        2: bytes(PAGE_SIZE),
        3: _value_page(b"old", 3),
        4: _value_page(b"new", 4),
        5: bytes(PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    db = Bbolt(path)
    assert db.meta_index == 1
    assert db.get("key") == "new"


def test_identical_view_uses_lower_index(tmp_path: Path) -> None:
    """Two valid candidates describing the same view are deterministic."""
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=5, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=3, high_water=5, txid=10, freelist=2),
        2: bytes(PAGE_SIZE),
        3: _value_page(b"same", 3),
        4: bytes(PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    db = Bbolt(path)
    assert db.meta_index == 0
    assert db.get("key") == "same"
    assert "same transaction view" in db.meta_selection.reason


def test_invalid_database_is_a_value_error(tmp_path: Path) -> None:
    path = _database(tmp_path / "db", old={"corrupt": "checksum"}, new={"corrupt": "checksum"})
    with pytest.raises(ValueError, match="both meta candidates are unusable"):
        Bbolt(path)


def test_conflicting_freelist_at_same_txid_is_not_combined(tmp_path: Path) -> None:
    """Same root and txid but different freelist pointers are still conflicting views."""
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=5, txid=10, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=3, high_water=5, txid=10, freelist=4),
        2: bytes(PAGE_SIZE),
        3: _value_page(b"same", 3),
        4: bytes(PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    with path.open("rb") as fh:
        selection = select_meta(fh)

    assert selection.status == "conflict"
    assert selection.selected is None
    assert "conflicting transaction views" in selection.reason


def test_inline_bucket_with_sequence_is_read_correctly(tmp_path: Path) -> None:
    """An inline bucket is identified by a zero root, not by zeroed sequence bytes."""
    from tests.bbolt._bbolt_builder import inline_page

    value = struct.pack("<QQ", 0, 7) + inline_page([(0, b"a", b"1"), (0, b"b", b"2")])
    pages = {
        0: meta_page(0, PAGE_SIZE, root=3, high_water=4, txid=1, freelist=2),
        1: meta_page(1, PAGE_SIZE, root=3, high_water=4, txid=2, freelist=2),
        2: bytes(PAGE_SIZE),
        3: leaf_page(3, [(BUCKET_FLAG, b"inner", value)], PAGE_SIZE),
    }
    path = tmp_path / "db"
    write_pages(path, pages, PAGE_SIZE)

    db = Bbolt(path)
    assert db.keys("inner") == ["a", "b"]
    assert db.get("inner a") == "1"
