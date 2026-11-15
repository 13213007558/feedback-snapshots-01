from __future__ import annotations

import gzip
import struct

import pytest

from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.btree import BTree
from dissect.apfs.objects.omap import ObjectMap
from dissect.apfs.util import cmp_omap
from tests.conftest import absolute_path

BLOCK_SIZE = 4096
INFO_SIZE = len(c_apfs.btree_info)


class FakeContainer:
    """Minimal container that serves pre-built blocks by address."""

    sectors_per_block = BLOCK_SIZE // 512

    def __init__(self, blocks: dict[int, bytes]):
        self.blocks = blocks

    def _read_block(self, address: int, count: int = 1) -> bytes:
        return self.blocks[address]


def _key(oid: int, xid: int) -> bytes:
    return struct.pack("<QQ", oid, xid)


def _value(paddr: int, flags: int = 0, size: int = BLOCK_SIZE) -> bytes:
    value = c_apfs.omap_val()
    value.ov_flags = flags
    value.ov_size = size
    value.ov_paddr = paddr
    return bytes(value)


def _node(entries: list[tuple[bytes, bytes]], flags: c_apfs.BTNODE, level: int = 0) -> bytes:
    """Build a fixed-size key/value B-tree node."""
    block = bytearray(BLOCK_SIZE)
    nkeys = len(entries)

    header = c_apfs.btree_node_phys()
    header.btn_flags = flags
    header.btn_level = level
    header.btn_nkeys = nkeys
    header.btn_table_space.off = 0
    header.btn_table_space.len = len(c_apfs.kvoff) * nkeys
    block[: len(bytes(header))] = bytes(header)

    toc_offset = len(bytes(header))
    key_offset = toc_offset + len(c_apfs.kvoff) * nkeys
    value_base = BLOCK_SIZE - (INFO_SIZE if flags & c_apfs.BTNODE_ROOT else 0)

    for i, (key, value) in enumerate(entries):
        struct.pack_into("<HH", block, toc_offset + len(c_apfs.kvoff) * i, len(key) * i, len(value) * (i + 1))
        block[key_offset + len(key) * i : key_offset + len(key) * (i + 1)] = key
        block[value_base - len(value) * (i + 1) : value_base - len(value) * i] = value

    if flags & c_apfs.BTNODE_ROOT:
        info = c_apfs.btree_info()
        info.bt_fixed.bt_flags = c_apfs.BTREE.PHYSICAL | c_apfs.BTREE.SEQUENTIAL_INSERT
        info.bt_fixed.bt_node_size = BLOCK_SIZE
        info.bt_fixed.bt_key_size = 16
        info.bt_fixed.bt_val_size = 16
        block[-INFO_SIZE:] = bytes(info)

    return bytes(block)


def _child(address: int) -> bytes:
    return struct.pack("<Q", address) + bytes(8)


def build_omap() -> tuple[ObjectMap, FakeContainer]:
    """Build an object map with three versions of one object and an adjacent object at a leaf boundary.

    Leaf 0 holds the create (xid 10), update (xid 20) and delete (xid 30) versions of object 100.
    Leaf 1 starts with object 200 at xid 15, so object 200 is the first key of a leaf and the direct
    B-tree neighbour of object 100.
    """
    leaf_size = 96
    leaf_100 = _node(
        [
            (_key(100, 10), _value(1100)),
            (_key(100, 20), _value(1200)),
            (_key(100, 30), _value(0, c_apfs.OMAP_VAL_DELETED)),
        ],
        c_apfs.BTNODE.LEAF | c_apfs.BTNODE.FIXED_KV_SIZE,
    )
    leaf_200 = _node(
        [
            (_key(200, 15), _value(2150)),
            (_key(250, 5), _value(2500, c_apfs.OMAP_VAL_ENCRYPTED)),
            (_key(300, 40), _value(3000, c_apfs.OMAP_VAL_NOHEADER)),
        ],
        c_apfs.BTNODE.LEAF | c_apfs.BTNODE.FIXED_KV_SIZE,
    )
    root = _node(
        [
            (_key(100, 10), _child(leaf_size)),
            (_key(200, 15), _child(leaf_size + 1)),
        ],
        c_apfs.BTNODE.ROOT | c_apfs.BTNODE.FIXED_KV_SIZE,
        level=1,
    )

    container = FakeContainer({leaf_size: leaf_100, leaf_size + 1: leaf_200})
    omap = ObjectMap(container, 0, block=bytes(BLOCK_SIZE))
    omap.__dict__["btree"] = BTree(container, 0, block=root)
    return omap, container


@pytest.mark.parametrize(
    ("oid", "xid", "expected_xid", "expected_paddr", "deleted"),
    [
        (100, 10, 10, 1100, False),
        (100, 15, 10, 1100, False),
        (100, 20, 20, 1200, False),
        (100, 25, 20, 1200, False),
        (100, 30, 30, 0, True),
        (100, 35, 30, 0, True),
        (200, 15, 15, 2150, False),
        (200, 100, 15, 2150, False),
    ],
)
def test_omap_visible_version(
    oid: int, xid: int, expected_xid: int, expected_paddr: int, deleted: bool
) -> None:
    """A transaction sees the newest version at or before its xid, never a later one."""
    omap, _ = build_omap()

    entry = omap.lookup_entry(oid, xid)
    assert entry.oid == oid
    assert entry.xid == expected_xid
    assert entry.paddr == expected_paddr
    assert entry.is_deleted is deleted
    assert entry.is_visible is not deleted

    if deleted:
        with pytest.raises(KeyError, match="deleted"):
            omap.lookup(oid, xid)
    else:
        assert omap.lookup(oid, xid) == expected_paddr


@pytest.mark.parametrize(
    ("oid", "xid"),
    [
        (100, 0),
        (100, 9),
        (200, 0),
        (200, 10),
        (150, 100),
        (1000, 100),
    ],
)
def test_omap_does_not_use_adjacent_oid(oid: int, xid: int) -> None:
    """A missing object must not fall back to a neighbouring object's predecessor entry."""
    omap, _ = build_omap()

    with pytest.raises(KeyError):
        omap.lookup_entry(oid, xid)

    with pytest.raises(KeyError):
        omap.lookup(oid, xid)


def test_omap_deleted_blocks_older_versions() -> None:
    """A deletion hides older versions, while the older view itself still resolves."""
    omap, _ = build_omap()

    # The delete tombstone is the visible entry at and after its transaction.
    assert omap.lookup_entry(100, 30).is_deleted
    assert omap.lookup_entry(100, 31).is_deleted
    with pytest.raises(KeyError):
        omap.lookup(100, 30)

    # An earlier view is unaffected by the later queries.
    assert omap.lookup(100, 20) == 1200
    assert omap.lookup(100, 19) == 1100
    assert omap.lookup(100, 10) == 1100

    # A view before creation has nothing to return.
    with pytest.raises(KeyError):
        omap.lookup(100, 9)


def test_omap_without_xid_returns_newest_version() -> None:
    """Omitting the xid keeps the optional-argument convention and means "newest known version"."""
    omap, _ = build_omap()

    assert omap.lookup(200) == 2150
    assert omap.lookup_entry(200).xid == 15

    # The newest version of object 100 is its deletion, which cannot be resolved to an address.
    assert omap.lookup_entry(100).is_deleted
    with pytest.raises(KeyError):
        omap.lookup(100)

    with pytest.raises(KeyError):
        omap.lookup(150)


def test_omap_flags_are_not_ignored() -> None:
    """Deleted, encrypted and headerless entries are distinguishable and affect address lookup."""
    omap, _ = build_omap()

    encrypted = omap.lookup_entry(250, 5)
    assert encrypted.is_encrypted
    assert encrypted.is_visible
    assert omap.lookup(250, 5) == 2500

    # A headerless object still has a physical address; the flag only says how to interpret the block.
    noheader = omap.lookup_entry(300, 40)
    assert noheader.is_noheader
    assert noheader.is_visible
    assert omap.lookup(300, 40) == 3000


def test_omap_cache_distinguishes_query_conditions() -> None:
    """Cached lookups are keyed by both oid and xid, so views cannot contaminate each other."""
    omap, _ = build_omap()

    assert omap.lookup(100, 10) == 1100
    assert omap.lookup(100, 20) == 1200
    assert omap.lookup(100, 10) == 1100
    assert omap.lookup(100, 20) == 1200

    with pytest.raises(KeyError):
        omap.lookup(100, 30)

    # Re-querying earlier views after a later (deleted) query still returns their own address.
    assert omap.lookup(100, 20) == 1200
    assert omap.lookup(100, 10) == 1100

    assert omap.lookup.cache_info().currsize == 2


def test_btree_search_does_not_wrap_at_leaf_boundary() -> None:
    """A key below the first key of the selected leaf fails instead of wrapping to the previous leaf."""
    omap, _ = build_omap()

    # Object 200 lives in the second leaf; a query before its first version must not find object 100's last entry.
    with pytest.raises(KeyError):
        omap.lookup_entry(200, 10)

    # A key that sorts before the entire tree must not index negatively into the root's last child.
    with pytest.raises(KeyError):
        omap.btree.search_item((0, 0), cmp=cmp_omap)


def test_omap_real_image_no_xid_stays_within_object() -> None:
    """On a real OMAP, the no-xid lookup returns the newest version of the requested object, not a neighbour's."""
    with gzip.open(absolute_path("_data/snapshot.bin.gz"), "rb") as fh:
        volume = APFS(fh).volumes[0]
        omap = volume.omap

        for oid in (1028, 1030, 1445):
            entry = omap.lookup_entry(oid)
            assert entry.oid == oid
            assert omap.lookup(oid) == entry.paddr

            explicit = omap.lookup_entry(oid, volume.xid)
            assert explicit.oid == oid
            assert explicit.xid <= volume.xid

        with pytest.raises(KeyError):
            omap.lookup(0xFFFF_FFFF_FFFF)
