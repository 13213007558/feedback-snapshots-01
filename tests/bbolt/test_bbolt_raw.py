from __future__ import annotations

from pathlib import Path

from dissect.database.bbolt import Bbolt
from dissect.database.bbolt.bbolt import Page
from dissect.database.bbolt.c_bbolt import c_bbolt
from tests.bbolt._bbolt_builder import (
    BUCKET_FLAG,
    bucket_value,
    inline_page,
    leaf_page,
    write_database,
)

KEY_PLAIN = b"cfg"
KEY_HIGH = b"cfg\xff"
KEY_HIGHER = b"cfg\x80"
VALUE_PLAIN = b""
VALUE_HIGH = b"high-\xff"
VALUE_HIGHER = b"higher-\x80"
TEXT_HIGH = KEY_HIGH.decode("utf-8", "surrogateescape")
TEXT_HIGHER = KEY_HIGHER.decode("utf-8", "surrogateescape")

INNER = (b"root", b"level\x80", b"inner")


def _database(path: Path) -> Path:
    """Build a database with nested inline buckets and one regular bucket."""
    innermost = inline_page(
        [
            (0, KEY_PLAIN, VALUE_PLAIN),
            (0, KEY_HIGHER, VALUE_HIGHER),
            (0, KEY_HIGH, VALUE_HIGH),
            (BUCKET_FLAG, b"with space", bucket_value(0, inline_page=inline_page([(0, b"a b", b"space")]))),
        ]
    )
    middle = inline_page([(BUCKET_FLAG, b"inner", bucket_value(0, inline_page=innermost))])
    outer = inline_page([(BUCKET_FLAG, b"level\x80", bucket_value(0, inline_page=middle))])

    root = leaf_page(
        3,
        [
            (BUCKET_FLAG, b"root", bucket_value(0, inline_page=outer)),
            (BUCKET_FLAG, b"regular", bucket_value(4)),
            (0, b"plain", b"top-level"),
        ],
    )
    regular = leaf_page(4, [(0, b"present", b"regular-value"), (0, b"empty", b"")])

    return write_database(path, root, 3, [regular])


def test_raw_entry_exact_bytes(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    entries = db.entries(*INNER)
    assert entries is not None
    assert [entry.key for entry in entries] == [KEY_PLAIN, KEY_HIGHER, KEY_HIGH, b"with space"]

    assert db.get_raw(*INNER, KEY_PLAIN) == b""
    assert db.get_raw(*INNER, KEY_HIGHER) == VALUE_HIGHER
    assert db.get_raw(*INNER, KEY_HIGH) == VALUE_HIGH

    assert db.entry(*INNER, KEY_PLAIN).value == b""
    assert db.entry(*INNER, b"cfg\x00") is None
    assert db.entry(b"root", b"level", b"inner") is None


def test_raw_entry_distinguishes_bucket_and_missing(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    bucket = db.entry(*INNER, b"with space")
    assert bucket is not None
    assert bucket.is_bucket
    assert bucket.value is None
    assert db.get_raw(*INNER, b"with space") is None
    assert db.entry(*INNER, b"missing") is None
    assert db.entries(b"missing") is None
    assert db.keys_raw(*INNER, KEY_PLAIN) is None


def test_raw_entry_provenance_inline(tmp_path: Path) -> None:
    path = _database(tmp_path / "inline.db")
    db = Bbolt(path)
    raw = path.read_bytes()

    expected = {
        KEY_PLAIN: VALUE_PLAIN,
        KEY_HIGHER: VALUE_HIGHER,
        KEY_HIGH: VALUE_HIGH,
    }

    sources = set()
    for key, value in expected.items():
        entry = db.entry(*INNER, key)
        assert entry is not None
        assert entry.key == key
        assert entry.value == value
        assert entry.inline
        assert entry.pgid == 0
        assert entry.inline_offset == entry.offset
        assert entry.element_offset is not None
        assert entry.value_offset is not None
        assert entry.offset < entry.element_offset < entry.value_offset

        # Each key comes from its own element inside the same inline page.
        sources.add((entry.offset, entry.element_offset, entry.value_offset))
        # Inline pages carry no page id, but the physical container page is kept.
        assert entry.container_pgid == 3
        assert entry.offset == entry.inline_offset
        assert raw[entry.element_offset : entry.element_offset + 16]
        assert entry.value_size == len(value)
        assert raw[entry.value_offset : entry.value_offset + entry.value_size] == value

    assert len(sources) == 3

    # The reported offset must be the start of a parseable inline leaf page.
    entry = db.entry(*INNER, KEY_HIGH)
    page = Page(db, 0, entry.offset, inline=True)
    assert int(page.flags) == int(c_bbolt.PageFlag.Leaf)
    assert page.count == 4
    assert raw[entry.offset : entry.offset + 8] == (0).to_bytes(8, "little")

    # An empty value is a hit with zero-length bytes, not a miss.
    assert db.entry(*INNER, KEY_PLAIN).value == b""
    assert db.entry(*INNER, KEY_PLAIN).value_size == 0
    assert db.entry(*INNER, b"cfg\xff\xff") is None
    assert db.get_raw(*INNER, KEY_PLAIN) == b""
    assert db.get_raw(*INNER, b"cfg\xff\xff") is None

    bucket = db.entry(*INNER, b"with space")
    assert bucket is not None
    assert bucket.is_bucket
    assert bucket.bucket_inline
    assert bucket.root is None
    assert bucket.bucket_offset is not None
    assert raw[bucket.value_offset : bucket.value_offset + 16] == (0).to_bytes(16, "little")
    assert bucket.bucket_offset == bucket.value_offset + 16
    assert bucket.value_size > 16

    # The outer inline page is itself nested inside the enclosing inline page.
    enclosing = db.entry(b"root", b"level\x80")
    assert enclosing.offset < bucket.offset
    assert enclosing.value_offset < bucket.offset < bucket.value_offset + bucket.value_size
    assert bucket.value_offset + bucket.value_size <= enclosing.value_offset + enclosing.value_size


def test_raw_entry_provenance_page(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    entry = db.entry(b"regular", b"present")
    assert entry is not None
    assert not entry.inline
    assert entry.pgid == 4
    assert entry.container_pgid == 4
    assert entry.offset == 4 * db.page_size
    assert entry.value == b"regular-value"
    assert entry.inline_offset is None

    assert db.entry(b"regular", b"empty").value == b""
    assert db.get_raw(b"regular", b"empty") == b""
    assert db.get_raw(b"regular", b"missing") is None

    bucket = db.entry(b"regular")
    assert bucket.is_bucket
    assert bucket.bucket_inline is False
    assert bucket.root == 4

    assert db.entry().is_bucket
    assert db.entry().root == db.root.pgid


def test_text_interface_keeps_distinct_keys(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    keys = db.keys_raw(*INNER)
    assert keys is not None
    assert keys == [KEY_PLAIN, KEY_HIGHER, KEY_HIGH, b"with space"]

    # Invalid UTF-8 and its replacement character stay distinct, so decoding
    # cannot merge different keys into one display name.
    texts = db.keys("root level\udc80 inner", sep=" ")
    assert texts == [key.decode("utf-8", "surrogateescape") for key in keys]
    assert len(set(texts)) == len(texts)
    assert "\ufffd" not in texts[1]
    assert TEXT_HIGH != TEXT_HIGHER

    # Replacement decoding would collapse both invalid keys into one name,
    # which is exactly why key identity must stay byte-based.
    replacement = {key.decode("utf-8", "replace") for key in keys}
    assert len(replacement) < len(keys)

    # Round-trip each raw key through its display text.
    for entry in db.entries(*INNER):
        assert db.entry(*INNER, entry.key_text).key == entry.key

    # The legacy text interface can address the non-UTF-8 bucket losslessly.
    assert db.get("root level\udc80 inner cfg\udc80", sep=" ", decode=False) == VALUE_HIGHER
    assert db.get("root level\udc80 inner cfg\udc80", sep=" ", decode=False) == VALUE_HIGHER


def test_space_in_bucket_name_is_not_a_separator(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    entry = db.entry(*INNER, b"with space", b"a b")
    assert entry is not None
    assert entry.key == b"a b"
    assert entry.value == b"space"
    assert db.get_raw(*INNER, b"with space", b"a b") == b"space"
    # No separator interpretation means the whole multi-word name is one key.
    assert db.entry(*INNER, b"with") is None


def test_inline_page_header_parses(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    bucket = db.entry(*INNER, b"with space")
    page = Page(db, 0, bucket.bucket_offset, inline=True)
    assert page.page.size == c_bbolt.Page.size
    assert page.count == 1
    assert page.inode(0).key_raw == b"a b"
    assert page.inode(0).flags == 0


def test_empty_bucket_is_not_missing(tmp_path: Path) -> None:
    # An empty bucket exists, but has no entries and no value.
    root = leaf_page(3, [(BUCKET_FLAG, b"empty-bucket", bucket_value(0))])
    path = write_database(tmp_path / "empty.db", root, 3, [])
    empty = Bbolt(path)

    entry = empty.entry(b"empty-bucket")
    assert entry is not None
    assert entry.is_bucket
    assert entry.value is None
    assert entry.bucket_inline is False
    assert entry.root is None
    assert entry.bucket_offset is None

    assert empty.entries(b"empty-bucket") == []
    assert empty.keys_raw(b"empty-bucket") == []
    assert empty.get_raw(b"empty-bucket") is None
    assert empty.entry(b"empty-bucket", b"anything") is None
    assert empty.entry(b"does-not-exist") is None
    assert empty.entries(b"does-not-exist") is None


def test_real_evidence_empty_values_and_inline_positions() -> None:
    """Check empty values and shared-page inline origins in a real containerd database."""
    db = Bbolt(Path(__file__).parents[1] / "_data/bbolt/meta.db")

    container = (b"v1", b"moby", b"containers", b"5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181")
    for key in (b"sandboxid", b"snapshotKey", b"snapshotter"):
        entry = db.entry(*container, key)
        assert entry is not None
        assert entry.value == b""
        assert entry.value_size == 0
        assert db.get_raw(*container, key) == b""
        assert db.get([*container, key]) == ""

    assert db.entry(*container, b"not-a-key") is None
    # The legacy path interface used to return None for the empty value too.
    assert db.get("v1 moby containers 5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181 sandboxid") == ""

    overlay = (b"v1", b"moby", b"snapshots", b"overlayfs")
    inline_offsets = {}
    for snap in db.entries(*overlay):
        assert snap.is_bucket
        name = db.entry(*overlay, snap.key, b"name")
        if name is not None and name.inline:
            inline_offsets[snap.key] = name.inline_offset
            assert name.container_pgid == snap.container_pgid
            assert name.container_pgid not in (None, 0)

    # Several inline buckets live in the same physical page; only the inline
    # offsets tell them apart.
    assert len(inline_offsets) >= 2
    assert len(set(inline_offsets.values())) == len(inline_offsets)
    assert len({name.container_pgid for name in db.entries(*overlay) if name.is_bucket}) >= 1


def test_legacy_and_raw_interfaces_agree(tmp_path: Path) -> None:
    db = Bbolt(_database(tmp_path / "inline.db"))

    assert db.keys("regular") == ["present", "empty"]
    assert db.get("regular present") == "regular-value"
    assert db.get("regular present", decode=False) == b"regular-value"
    assert db.get("plain") == "top-level"
    assert db.get("regular empty") == ""
    assert db.get("regular missing") is None
    assert db.get("regular") is None
