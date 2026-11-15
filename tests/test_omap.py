from __future__ import annotations

import struct

import pytest

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.omap import ObjectMap

BLOCK_SIZE = 4096
BTREE_NODE_PHYS_SIZE = len(c_apfs.btree_node_phys)
BTREE_INFO_SIZE = len(c_apfs.btree_info)

# Object with three generations: created, updated and deleted
OID = 0x1000
XID_CREATE = 10
XID_UPDATE = 20
XID_DELETE = 30
PADDR_CREATE = 0xA00
PADDR_UPDATE = 0xB00
PADDR_STALE = 0xC00  # old physical block referenced by the deletion marker

# Neighbouring object, placed as the first key of the next leaf node
OID_BOUNDARY = OID + 1
PADDR_BOUNDARY = 0xD00

ADDR_OMAP = 10
ADDR_ROOT = 100
ADDR_LEAF = 200
ADDR_LEAF_BOUNDARY = 300


def _omap_key(oid: int, xid: int) -> bytes:
    return struct.pack("<QQ", oid, xid)


def _omap_val(flags: int, paddr: int) -> bytes:
    return struct.pack("<IIQ", flags, BLOCK_SIZE, paddr)


def _child_ref(address: int) -> bytes:
    return struct.pack("<Q", address) + b"\x00" * 8


def _btree_node(*, root: bool, leaf: bool, level: int, keys: list[bytes], values: list[bytes]) -> bytes:
    """Build a fixed-kv-size B-tree node block with the given keys and values."""
    nkeys = len(keys)
    toc_size = 4 * nkeys  # kvoff entries
    key_area = BTREE_NODE_PHYS_SIZE + toc_size
    value_end = BLOCK_SIZE - (BTREE_INFO_SIZE if root else 0)

    block = bytearray(BLOCK_SIZE)
    struct.pack_into("<I", block, 24, c_apfs.OBJECT_TYPE_BTREE_NODE)

    flags = c_apfs.BTNODE_FIXED_KV_SIZE
    if root:
        flags |= c_apfs.BTNODE_ROOT
    if leaf:
        flags |= c_apfs.BTNODE_LEAF
    struct.pack_into("<HHIHH", block, 32, flags, level, nkeys, 0, toc_size)

    for idx, (key, value) in enumerate(zip(keys, values, strict=True)):
        assert len(key) == len(value) == 16
        struct.pack_into("<HH", block, BTREE_NODE_PHYS_SIZE + 4 * idx, 16 * idx, 16 * (idx + 1))
        block[key_area + 16 * idx : key_area + 16 * (idx + 1)] = key
        block[value_end - 16 * (idx + 1) : value_end - 16 * idx] = value

    if root:
        struct.pack_into(
            "<IIIIIIQQ",
            block,
            BLOCK_SIZE - BTREE_INFO_SIZE,
            c_apfs.BTREE_PHYSICAL | c_apfs.BTREE_SEQUENTIAL_INSERT,
            BLOCK_SIZE,
            16,  # bt_key_size
            16,  # bt_val_size
            16,  # bt_longest_key
            16,  # bt_longest_val
            nkeys,  # bt_key_count
            3,  # bt_node_count
        )

    return bytes(block)


def _omap_block(tree_oid: int) -> bytes:
    block = bytearray(BLOCK_SIZE)
    struct.pack_into("<I", block, 24, c_apfs.OBJECT_TYPE_OMAP)
    struct.pack_into("<Q", block, 48, tree_oid)  # om_tree_oid
    return bytes(block)


class _Container:
    """Minimal container stub that serves blocks from memory."""

    block_size = BLOCK_SIZE

    def __init__(self, blocks: dict[int, bytes]):
        self.blocks = blocks

    def _read_block(self, address: int, count: int = 1) -> bytes:
        return self.blocks[address]


@pytest.fixture
def omap() -> ObjectMap:
    leaf = _btree_node(
        root=False,
        leaf=True,
        level=0,
        keys=[_omap_key(OID, XID_CREATE), _omap_key(OID, XID_UPDATE), _omap_key(OID, XID_DELETE)],
        values=[
            _omap_val(0, PADDR_CREATE),
            _omap_val(0, PADDR_UPDATE),
            _omap_val(c_apfs.OMAP_VAL_DELETED, PADDR_STALE),
        ],
    )
    leaf_boundary = _btree_node(
        root=False,
        leaf=True,
        level=0,
        keys=[_omap_key(OID_BOUNDARY, XID_CREATE)],
        values=[_omap_val(c_apfs.OMAP_VAL_NOHEADER, PADDR_BOUNDARY)],
    )
    root = _btree_node(
        root=True,
        leaf=False,
        level=1,
        keys=[_omap_key(OID, XID_CREATE), _omap_key(OID_BOUNDARY, XID_CREATE)],
        values=[_child_ref(ADDR_LEAF), _child_ref(ADDR_LEAF_BOUNDARY)],
    )
    container = _Container(
        {
            ADDR_OMAP: _omap_block(ADDR_ROOT),
            ADDR_ROOT: root,
            ADDR_LEAF: leaf,
            ADDR_LEAF_BOUNDARY: leaf_boundary,
        }
    )
    return ObjectMap(container, ADDR_OMAP)


def test_omap_lookup_generations(omap: ObjectMap) -> None:
    """Each transaction sees the version committed in or before it, never a newer one."""
    assert omap.lookup(OID, XID_CREATE) == PADDR_CREATE
    assert omap.lookup(OID, XID_CREATE + 5) == PADDR_CREATE
    assert omap.lookup(OID, XID_UPDATE) == PADDR_UPDATE
    assert omap.lookup(OID, XID_UPDATE + 5) == PADDR_UPDATE


def test_omap_lookup_before_create(omap: ObjectMap) -> None:
    """An object is not visible before its first version, not even via a neighbour's record."""
    with pytest.raises(KeyError):
        omap.lookup(OID, XID_CREATE - 1)


def test_omap_lookup_deleted(omap: ObjectMap) -> None:
    """A deletion marker blocks falling back to older versions."""
    with pytest.raises(KeyError):
        omap.lookup(OID, XID_DELETE)
    with pytest.raises(KeyError):
        omap.lookup(OID, XID_DELETE + 5)


def test_omap_lookup_latest_without_xid(omap: ObjectMap) -> None:
    """Omitting the xid queries the most recent version of the object."""
    # The most recent version of OID is the deletion marker
    with pytest.raises(KeyError):
        omap.lookup(OID)
    # The most recent version of the neighbouring object is live
    assert omap.lookup(OID_BOUNDARY) == PADDR_BOUNDARY


def test_omap_lookup_unknown_oid(omap: ObjectMap) -> None:
    """An unknown OID must not resolve to the predecessor record of an adjacent OID."""
    with pytest.raises(KeyError):
        omap.lookup(OID_BOUNDARY + 1, XID_CREATE)
    with pytest.raises(KeyError):
        omap.lookup(OID - 1, XID_CREATE)


def test_omap_lookup_value_flags(omap: ObjectMap) -> None:
    """OMAP value flags are exposed to callers instead of being parsed and ignored."""
    value = omap.lookup_value(OID, XID_UPDATE)
    assert value.ov_flags == 0
    assert value.ov_paddr == PADDR_UPDATE

    deleted = omap.lookup_value(OID, XID_DELETE)
    assert deleted.ov_flags & c_apfs.OMAP_VAL_DELETED

    noheader = omap.lookup_value(OID_BOUNDARY, XID_CREATE)
    assert noheader.ov_flags & c_apfs.OMAP_VAL_NOHEADER
    # OMAP_VAL_NOHEADER does not affect address resolution
    assert omap.lookup(OID_BOUNDARY, XID_CREATE) == PADDR_BOUNDARY


def test_omap_lookup_cache_per_query(omap: ObjectMap) -> None:
    """Cached results are kept per (oid, xid); a later query must not pollute earlier views."""
    with pytest.raises(KeyError):
        omap.lookup(OID, XID_DELETE)
    with pytest.raises(KeyError):
        omap.lookup(OID)

    assert omap.lookup(OID, XID_UPDATE) == PADDR_UPDATE
    assert omap.lookup(OID, XID_CREATE) == PADDR_CREATE
    assert omap.lookup(OID_BOUNDARY, XID_CREATE) == PADDR_BOUNDARY
