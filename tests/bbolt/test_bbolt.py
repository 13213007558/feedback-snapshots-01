from __future__ import annotations

import struct
from io import BytesIO

from dissect.database.bbolt import Bbolt, BoltDB, EntryType
from tests._util import absolute_path

container_id = "5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181"

PAGE_SIZE = 4096
LEAF_PAGE_FLAG = 0x02
BUCKET_LEAF_FLAG = 0x01


def _leaf_page(pgid: int, entries: list[tuple[bytes, int, bytes]]) -> bytes:
    """Build a leaf page with the given (key, flags, value) entries."""
    elements = b""
    data = b""
    data_start = 16 + 16 * len(entries)
    for i, (key, flags, value) in enumerate(entries):
        pos = data_start + len(data) - (16 + i * 16)
        elements += struct.pack("<IIII", flags, pos, len(key), len(value))
        data += key + value
    return struct.pack("<QHHI", pgid, LEAF_PAGE_FLAG, len(entries), 0) + elements + data


def _inline_bucket(entries: list[tuple[bytes, int, bytes]]) -> bytes:
    """Build an inline bucket value: a zeroed InBucket header followed by a leaf page."""
    return b"\x00" * 16 + _leaf_page(0, entries)


def _nested_inline_db() -> bytes:
    """Build a bbolt database with two nested inline buckets.

    The innermost bucket holds three keys that look alike when displayed but
    differ in bytes: ``key``, ``key `` (trailing space, empty value) and
    ``key\\xff`` (non UTF-8).
    """
    inner = _inline_bucket(
        [
            (b"key", 0, b"first"),
            (b"key ", 0, b""),
            (b"key\xff", 0, b"third"),
        ]
    )
    outer = _inline_bucket([(b"bucket two", BUCKET_LEAF_FLAG, inner)])
    root = _leaf_page(2, [(b"bucket one", BUCKET_LEAF_FLAG, outer)])

    meta = (
        struct.pack("<QHHI", 0, 0x04, 0, 0)  # page header (meta)
        + struct.pack("<IIII", 0xED0CDAED, 2, PAGE_SIZE, 0)  # magic, version, pageSize, flags
        + struct.pack("<QQ", 2, 0)  # root bucket
        + struct.pack("<QQQQ", 3, 3, 2, 0)  # freelist, pgid, txid, checksum
    )
    return meta.ljust(PAGE_SIZE, b"\x00") + bytes(PAGE_SIZE) + root.ljust(PAGE_SIZE, b"\x00")


def test_bbolt_meta_db() -> None:
    """Test if we can parse a containerd meta.db file. Created on amd64 Debian 13.6.0 with Docker 29.7.2."""
    path = absolute_path("_data/bbolt/meta.db")
    db = Bbolt(path)

    assert db.version == 2
    assert db.page_size == 4096

    assert db.keys() == ["v1"]
    assert db.keys("v1") == ["moby", "version"]
    assert db.get("v1 version") == "\x08"
    assert db.keys("v1 moby") == [
        "containers",
        "content",
        "images",
        "leases",
        "snapshots",
    ]

    assert db.keys("v1\\moby", sep="\\") == [
        "containers",
        "content",
        "images",
        "leases",
        "snapshots",
    ]

    assert db.keys(f"v1 moby snapshots overlayfs {container_id}") == [
        "createdat",
        "name",
        "parent",
        "updatedat",
    ]

    name = db.get(f"v1 moby snapshots overlayfs {container_id} name")
    assert name == f"moby/18/{container_id}"

    assert db.keys("v1 moby containers") == [container_id]

    assert db.keys(f"v1 moby containers {container_id}") == [
        "createdat",
        "image",
        "labels",
        "runtime",
        "sandboxid",
        "snapshotKey",
        "snapshotter",
        "spec",
        "updatedat",
    ]
    assert db.keys(f"v1 moby containers {container_id} labels") == ["com.docker/engine.bundle.path"]
    assert (
        db.get(f"v1 moby containers {container_id} labels com.docker/engine.bundle.path")
        == f"/var/run/docker/containerd/{container_id}"
    )


def test_bbolt_metadata_db() -> None:
    """Test if we can parse a containerd metadata.db file. Created on amd64 Debian 13.6.0 with Docker 29.7.2."""
    path = absolute_path("_data/bbolt/metadata.db")
    db = BoltDB(path)

    assert db.keys() == ["v1"]
    assert db.keys("v1") == ["parents", "snapshots"]
    assert db.keys("v1 snapshots") == [
        "moby/10/36cd9d816e2c23639eee0d4cb933d76ddc482761dd07cddb64a3f9f83c7fbb3f-init",
        "moby/11/36cd9d816e2c23639eee0d4cb933d76ddc482761dd07cddb64a3f9f83c7fbb3f",
        "moby/13/sha256:b577adbc0b589bb7c1d3be98cc4b703e8228ab4413156754445e8b20a001c5d3",
        "moby/15/sha256:82198e809c0011c54f98a18f72fcb1db9d563c8835cff6d37126dbb030a8302c",
        f"moby/17/{container_id}-init",
        f"moby/18/{container_id}",
        "moby/2/sha256:897b3f2a7c1bc2f3d02432f7892fe31c6272c521ad4d70257df624504a3238b4",
        "moby/4/13553351c913076aa74e1ef76519aa82127cf85121413eb5fe5002731d97556c-init",
        "moby/5/13553351c913076aa74e1ef76519aa82127cf85121413eb5fe5002731d97556c",
        "moby/7/abf09ccc5e9d25015bd042a3139f9ecd387c711f81ff5fde20093515b9825a5b-init",
        "moby/8/abf09ccc5e9d25015bd042a3139f9ecd387c711f81ff5fde20093515b9825a5b",
    ]

    assert db.keys(f"v1 snapshots moby/18/{container_id}") == [
        "createdat",
        "id",
        "kind",
        "parent",
        "updatedat",
    ]

    id = db.get(f"v1 snapshots moby/18/{container_id} id", decode=False)
    assert id == b"\x0b"

    assert db.get(
        f"v1 snapshots moby/18/{container_id} createdat",
        decode=False,
    ) == bytes.fromhex("010000000ee2221c201f08a2f6ffff")


def test_bbolt_raw_key_lookup_nested_inline_buckets() -> None:
    """Test raw key sequence lookups in nested inline buckets.

    Keys that look alike when displayed (``key``, ``key `` and ``key\\xff``)
    must be addressable unambiguously, and an empty value must be
    distinguishable from a missing key.
    """
    db = Bbolt(BytesIO(_nested_inline_db()))
    bucket_path = [b"bucket one", b"bucket two"]

    # The root of the database is a regular page
    root = db.lookup([])
    assert root.type is EntryType.BUCKET
    assert root.pgid == 2
    assert db.keys_raw() == [b"bucket one"]

    # Both nested buckets are inline: page number 0, actual file offset preserved
    outer = db.lookup([b"bucket one"])
    assert outer.type is EntryType.BUCKET
    assert outer.pgid == 0
    inner = db.lookup(bucket_path)
    assert inner.type is EntryType.BUCKET
    assert inner.pgid == 0
    assert inner.offset != outer.offset

    # The recorded offsets point at actual leaf page headers
    for entry in (outer, inner):
        db.fh.seek(entry.offset + 8)
        assert struct.unpack("<H", db.fh.read(2))[0] == LEAF_PAGE_FLAG

    # Retrieve each of the three look-alike keys with exact content and source
    first = db.lookup([*bucket_path, b"key"])
    assert first.type is EntryType.VALUE
    assert first.value == b"first"

    empty = db.lookup([*bucket_path, b"key "])
    assert empty.type is EntryType.VALUE
    assert empty.value == b""
    assert empty.found

    non_utf8 = db.lookup([*bucket_path, b"key\xff"])
    assert non_utf8.type is EntryType.VALUE
    assert non_utf8.value == b"third"

    # All three live in the same inline bucket page
    assert first.pgid == empty.pgid == non_utf8.pgid == 0
    assert first.offset == empty.offset == non_utf8.offset == inner.offset

    # An empty value is distinguishable from a missing key
    missing = db.lookup([*bucket_path, b"key\x00"])
    assert missing.type is EntryType.NOT_FOUND
    assert not missing.found
    assert missing.value is None
    assert empty.value is not None and empty.value != missing.value

    # Raw key listing keeps the exact bytes of every key
    assert db.keys_raw(bucket_path) == [b"key", b"key ", b"key\xff"]
    assert db.keys_raw([*bucket_path, b"key"]) is None
    assert db.keys_raw([b"bucket one", b"no such bucket"]) is None

    # Convenience raw getter: empty bytes for empty values, None when missing
    assert db.get_raw([*bucket_path, b"key"]) == b"first"
    assert db.get_raw([*bucket_path, b"key "]) == b""
    assert db.get_raw([*bucket_path, b"key\xff"]) == b"third"
    assert db.get_raw([*bucket_path, b"key\x00"]) is None
    assert db.get_raw(bucket_path) is None
