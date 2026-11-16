from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import InvalidBTreeNode
from dissect.apfs.objects import BTree, BTreeNode
from dissect.apfs.util import fletcher64

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

NODE_SIZE = 4096
HEADER_SIZE = len(c_apfs.btree_node_phys)
INFO_SIZE = len(c_apfs.btree_info)

BTREE_TYPE = int(c_apfs.OBJECT_TYPE_BTREE) | int(c_apfs.OBJ_PHYSICAL)
BTNODE_TYPE = int(c_apfs.OBJECT_TYPE_BTREE_NODE) | int(c_apfs.OBJ_PHYSICAL)
FSTREE_SUBTYPE = int(c_apfs.OBJECT_TYPE.FSTREE)

BTNODE_ROOT = int(c_apfs.BTNODE.ROOT)
BTNODE_LEAF = int(c_apfs.BTNODE.LEAF)
BTNODE_FIXED_KV_SIZE = int(c_apfs.BTNODE.FIXED_KV_SIZE)
BTREE_PHYSICAL = int(c_apfs.BTREE.PHYSICAL)

ROOT_ADDRESS = 12
LEAF_ADDRESSES = (10, 11)


class FakeContainer:
    """Serve synthetic B-tree blocks by address."""

    def __init__(self, blocks: dict[int, bytes]):
        self.blocks = blocks
        self.block_size = NODE_SIZE

    @property
    def sectors_per_block(self) -> int:
        return self.block_size // 512

    def _read_block(self, address: int, count: int = 1) -> bytes:
        return self.blocks[address][: count * self.block_size]


@dataclass
class NodeSpec:
    entries: list[tuple[bytes, bytes]]
    level: int
    is_root: bool = False
    fixed: bool = False
    key_size: int = 0
    val_size: int = 0
    is_leaf: bool = True
    table_len: int | None = None
    free_len: int | None = None


@dataclass
class Tree:
    blocks: dict[int, bytes]
    root: int
    leaves: list[tuple[int, list[tuple[bytes, bytes]]]] = field(default_factory=list)

    @property
    def entries(self) -> list[tuple[bytes, bytes]]:
        return [entry for _, leaf_entries in self.leaves for entry in leaf_entries]


def _write_node(address: int, spec: NodeSpec) -> bytes:
    block = bytearray(NODE_SIZE)
    nkeys = len(spec.entries)
    entry_size = len(c_apfs.kvoff) if spec.fixed else len(c_apfs.kvloc)
    table_len = nkeys * entry_size if spec.table_len is None else spec.table_len
    data_end = NODE_SIZE - (INFO_SIZE if spec.is_root else 0)
    key_area = HEADER_SIZE + table_len

    key_offsets = []
    key_cursor = 0
    for key, _ in spec.entries:
        key_offsets.append(key_cursor)
        key_cursor += len(key)

    value_offsets = []
    value_cursor = 0
    for _, value in reversed(spec.entries):
        value_cursor += len(value)
        value_offsets.append(value_cursor)
    value_offsets.reverse()

    free_len = data_end - (key_area + key_cursor) - value_cursor if spec.free_len is None else spec.free_len
    flags = BTNODE_ROOT if spec.is_root else 0
    flags |= BTNODE_LEAF if spec.is_leaf else 0
    flags |= BTNODE_FIXED_KV_SIZE if spec.fixed else 0

    node = c_apfs.btree_node_phys()
    node.btn_o.o_oid = address
    node.btn_o.o_xid = 1
    node.btn_o.o_type = BTREE_TYPE if spec.is_root else BTNODE_TYPE
    node.btn_o.o_subtype = FSTREE_SUBTYPE
    node.btn_flags = flags
    node.btn_level = spec.level
    node.btn_nkeys = nkeys
    node.btn_table_space.off = 0
    node.btn_table_space.len = table_len
    node.btn_free_space.off = key_cursor
    node.btn_free_space.len = free_len
    node.btn_key_free_list.off = 0xFFFF
    node.btn_key_free_list.len = 0
    node.btn_val_free_list.off = 0xFFFF
    node.btn_val_free_list.len = 0
    block[:HEADER_SIZE] = bytes(node)

    for idx, (key, value) in enumerate(spec.entries):
        key_start = key_area + key_offsets[idx]
        block[key_start : key_start + len(key)] = key

        value_start = data_end - value_offsets[idx]
        block[value_start : value_start + len(value)] = value

        toc_offset = HEADER_SIZE + idx * entry_size
        if spec.fixed:
            block[toc_offset : toc_offset + 4] = struct.pack("<HH", key_offsets[idx], value_offsets[idx])
        else:
            block[toc_offset : toc_offset + 8] = struct.pack(
                "<HHHH", key_offsets[idx], len(key), value_offsets[idx], len(value)
            )

    if spec.is_root:
        info = c_apfs.btree_info()
        info.bt_fixed.bt_flags = BTREE_PHYSICAL
        info.bt_fixed.bt_node_size = NODE_SIZE
        info.bt_fixed.bt_key_size = spec.key_size
        info.bt_fixed.bt_val_size = spec.val_size
        info.bt_longest_key = max((len(key) for key, _ in spec.entries), default=0)
        info.bt_longest_val = max((len(value) for _, value in spec.entries), default=0)
        info.bt_key_count = nkeys
        info.bt_node_count = 1
        block[-INFO_SIZE:] = bytes(info)

    block[0:8] = fletcher64(bytes(block[8:])).to_bytes(8, "little")
    return bytes(block)


def _variable_key(index: int) -> bytes:
    return struct.pack(">I", index)


def _variable_value(index: int) -> bytes:
    return f"value-{index:02d}".encode()


def _fixed_key(index: int) -> bytes:
    return struct.pack(">Q", index)


def _fixed_value(index: int) -> bytes:
    return struct.pack(">Q", index) + b"-sixteen-byte-v"


def _tree(*, fixed: bool) -> Tree:
    key_fn = _fixed_key if fixed else _variable_key
    value_fn = _fixed_value if fixed else _variable_value
    key_size = len(_fixed_key(0)) if fixed else 0
    val_size = len(_fixed_value(0)) if fixed else 0

    leaves = []
    for address, first in zip(LEAF_ADDRESSES, (0, 4), strict=True):
        entries = [(key_fn(i), value_fn(i)) for i in range(first, first + 4)]
        leaves.append((address, entries))

    blocks = {}
    for address, entries in leaves:
        blocks[address] = _write_node(
            address, NodeSpec(entries, level=0, fixed=fixed, key_size=key_size, val_size=val_size)
        )

    root_entries = [(entries[0][0], struct.pack("<Q", address)) for address, entries in leaves]
    blocks[ROOT_ADDRESS] = _write_node(
        ROOT_ADDRESS,
        NodeSpec(
            root_entries,
            level=1,
            is_root=True,
            fixed=fixed,
            key_size=key_size,
            val_size=val_size,
            is_leaf=False,
        ),
    )

    return Tree(blocks=blocks, root=ROOT_ADDRESS, leaves=leaves)


def _header(block: bytearray) -> c_apfs.btree_node_phys:
    return c_apfs.btree_node_phys(bytes(block))


def _edit_header(block: bytearray, edit: Callable[[c_apfs.btree_node_phys], None]) -> None:
    node = _header(block)
    edit(node)
    block[:HEADER_SIZE] = bytes(node)


def _edit_info(block: bytearray, edit: Callable[[c_apfs.btree_info], None]) -> None:
    info = c_apfs.btree_info(bytes(block[-INFO_SIZE:]))
    edit(info)
    block[-INFO_SIZE:] = bytes(info)


def _toc_entry(block: bytearray, idx: int) -> c_apfs.kvoff | c_apfs.kvloc:
    node = _header(block)
    fixed = bool(node.btn_flags & BTNODE_FIXED_KV_SIZE)
    cls = c_apfs.kvoff if fixed else c_apfs.kvloc
    entry_size = len(cls)
    offset = HEADER_SIZE + node.btn_table_space.off + idx * entry_size
    return cls(bytes(block[offset : offset + entry_size]))


def _edit_toc(block: bytearray, idx: int, edit: Callable[[c_apfs.kvoff | c_apfs.kvloc], None]) -> None:
    node = _header(block)
    fixed = bool(node.btn_flags & BTNODE_FIXED_KV_SIZE)
    cls = c_apfs.kvoff if fixed else c_apfs.kvloc
    entry_size = len(cls)
    offset = HEADER_SIZE + node.btn_table_space.off + idx * entry_size
    entry = cls(bytes(block[offset : offset + entry_size]))
    edit(entry)
    block[offset : offset + entry_size] = bytes(entry)


def _mutate(tree: Tree, address: int, edit: Callable[[bytearray], None]) -> None:
    block = bytearray(tree.blocks[address])
    edit(block)
    block[0:8] = fletcher64(bytes(block[8:])).to_bytes(8, "little")
    tree.blocks[address] = bytes(block)


def _assert_checksum_only_accepts(tree: Tree, address: int) -> None:
    block = tree.blocks[address]
    assert BTreeNode(FakeContainer(tree.blocks), address, block=block).is_valid()


def _search(tree: Tree, key: bytes) -> bytes:
    return BTree(FakeContainer(tree.blocks), tree.root).search(key, exact=True)


def _walk(tree: Tree) -> Iterator[tuple[bytes, bytes]]:
    return Cursor(BTree(FakeContainer(tree.blocks), tree.root)).walk()


@pytest.mark.parametrize("fixed", [False, True], ids=["variable-kv", "fixed-kv"])
def test_valid_multilevel_tree_search_and_walk(fixed: bool) -> None:
    """A valid multi-level tree returns complete keys and values through search and walk."""
    tree = _tree(fixed=fixed)
    entries = tree.entries

    for address in [tree.root, *LEAF_ADDRESSES]:
        _assert_checksum_only_accepts(tree, address)

    for key, value in entries:
        assert _search(tree, key) == value

    walked = list(_walk(tree))
    assert walked == entries
    assert [key for key, _ in walked] == sorted(key for key, _ in walked)


def _malformed_cases() -> list[tuple[str, bool, int, Callable[[bytearray], None], str]]:
    """Build cases where a checksum-correct node violates its internal layout."""

    def variable_toc_too_short(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node.btn_table_space, "len", node.btn_table_space.len - 1))

    def fixed_toc_too_short(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node.btn_table_space, "len", node.btn_table_space.len - 1))

    def variable_toc_past_data(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node.btn_table_space, "len", NODE_SIZE))

    def variable_key_past_node(block: bytearray) -> None:
        _edit_toc(block, 0, lambda entry: setattr(entry.k, "off", NODE_SIZE))

    def fixed_key_past_node(block: bytearray) -> None:
        _edit_toc(block, 0, lambda entry: setattr(entry, "k", NODE_SIZE))

    def variable_empty_key(block: bytearray) -> None:
        _edit_toc(block, 0, lambda entry: setattr(entry.k, "len", 0))

    def variable_key_overlaps_key(block: bytearray) -> None:
        _edit_toc(block, 1, lambda entry: setattr(entry.k, "off", 0))

    def fixed_key_overlaps_key(block: bytearray) -> None:
        _edit_toc(block, 1, lambda entry: setattr(entry, "k", 0))

    def variable_value_overlaps_value(block: bytearray) -> None:
        first_offset = _toc_entry(block, 0).v.off
        _edit_toc(block, 1, lambda entry: setattr(entry.v, "off", first_offset))

    def fixed_value_overlaps_value(block: bytearray) -> None:
        first_offset = _toc_entry(block, 0).v
        _edit_toc(block, 1, lambda entry: setattr(entry, "v", first_offset))

    def variable_key_overlaps_value(block: bytearray) -> None:
        # Move the first key over the last value. The key must not leave the node, but it may still collide
        # with the value area.
        node = _header(block)
        key_start = HEADER_SIZE + node.btn_table_space.len
        first_value_offset = _toc_entry(block, 0).v.off
        first_value_start = NODE_SIZE - first_value_offset
        _edit_toc(
            block,
            0,
            lambda entry: (
                setattr(entry.k, "off", first_value_start - key_start),
                setattr(entry.k, "len", 16),
            ),
        )

    def variable_root_value_in_trailer(block: bytearray) -> None:
        _edit_toc(block, 0, lambda entry: setattr(entry.v, "off", 0))

    def fixed_root_value_in_trailer(block: bytearray) -> None:
        _edit_toc(block, 0, lambda entry: setattr(entry, "v", 0))

    def variable_root_key_in_trailer(block: bytearray) -> None:
        _edit_toc(block, 0, lambda entry: setattr(entry.k, "len", NODE_SIZE))

    def root_node_size_too_small(block: bytearray) -> None:
        _edit_info(block, lambda info: setattr(info.bt_fixed, "bt_node_size", HEADER_SIZE))

    def root_node_size_past_block(block: bytearray) -> None:
        _edit_info(block, lambda info: setattr(info.bt_fixed, "bt_node_size", NODE_SIZE * 2))

    return [
        (
            "variable-toc-too-short",
            False,
            10,
            variable_toc_too_short,
            r"node 0xa .*btn_table_space\.len 0x1f is too small for 4 TOC entries of 0x8 bytes",
        ),
        (
            "fixed-toc-too-short",
            True,
            10,
            fixed_toc_too_short,
            r"node 0xa .*btn_table_space\.len 0xf is too small for 4 TOC entries of 0x4 bytes",
        ),
        (
            "variable-toc-past-data",
            False,
            10,
            variable_toc_past_data,
            r"node 0xa .*TOC at \[0x38,0x1038\) extends past data end 0x1000",
        ),
        (
            "variable-key-past-node",
            False,
            10,
            variable_key_past_node,
            r"node 0xa .*TOC entry 0: key range \[0x1058,0x105c\) extends past data end 0x1000",
        ),
        (
            "fixed-key-past-node",
            True,
            10,
            fixed_key_past_node,
            r"node 0xa .*TOC entry 0: key range \[0x1048,0x1050\) extends past data end 0x1000",
        ),
        (
            "variable-empty-key",
            False,
            10,
            variable_empty_key,
            r"node 0xa .*TOC entry 0: key has zero length",
        ),
        (
            "variable-key-overlaps-key",
            False,
            10,
            variable_key_overlaps_key,
            r"node 0xa .*key 0 range .* overlaps key 1 range",
        ),
        (
            "fixed-key-overlaps-key",
            True,
            10,
            fixed_key_overlaps_key,
            r"node 0xa .*key 0 range .* overlaps key 1 range",
        ),
        (
            "variable-value-overlaps-value",
            False,
            10,
            variable_value_overlaps_value,
            r"node 0xa .*value 0 range .* overlaps value 1 range",
        ),
        (
            "fixed-value-overlaps-value",
            True,
            10,
            fixed_value_overlaps_value,
            r"node 0xa .*value 0 range .* overlaps value 1 range",
        ),
        (
            "variable-key-overlaps-value",
            False,
            10,
            variable_key_overlaps_value,
            r"node 0xa .*key 0 range .* overlaps value 0 range",
        ),
        (
            "variable-root-value-in-trailer",
            False,
            12,
            variable_root_value_in_trailer,
            r"node 0xc .*TOC entry 0: value range .* is outside the root btree_info area \[0x0,0xfd8\)",
        ),
        (
            "fixed-root-value-in-trailer",
            True,
            12,
            fixed_root_value_in_trailer,
            r"node 0xc .*TOC entry 0: value range .* is outside the root btree_info area \[0x0,0xfd8\)",
        ),
        (
            "variable-root-key-in-trailer",
            False,
            12,
            variable_root_key_in_trailer,
            r"node 0xc .*TOC entry 0: key range .* into the root btree_info area",
        ),
        (
            "root-node-size-too-small",
            False,
            12,
            root_node_size_too_small,
            r"B-tree root node 0xc: btree_info node size 0x38 is too small",
        ),
        (
            "root-node-size-past-block",
            False,
            12,
            root_node_size_past_block,
            r"B-tree root node 0xc: btree_info node size 0x2000 exceeds block length 0x1000",
        ),
    ]


@pytest.mark.parametrize(
    ("fixed", "address", "edit", "match"),
    [case[1:] for case in _malformed_cases()],
    ids=[case[0] for case in _malformed_cases()],
)
def test_malformed_node_rejected_by_search(
    fixed: bool, address: int, edit: Callable[[bytearray], None], match: str
) -> None:
    """Search rejects a structurally invalid node even though its checksum is correct."""
    tree = _tree(fixed=fixed)
    _mutate(tree, address, edit)
    _assert_checksum_only_accepts(tree, address)

    key = _variable_key(0) if not fixed else _fixed_key(0)
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, key)


@pytest.mark.parametrize(
    ("fixed", "address", "edit", "match"),
    [case[1:] for case in _malformed_cases()],
    ids=[case[0] for case in _malformed_cases()],
)
def test_malformed_node_rejected_by_walk(
    fixed: bool, address: int, edit: Callable[[bytearray], None], match: str
) -> None:
    """Walk rejects a structurally invalid node even though its checksum is correct."""
    tree = _tree(fixed=fixed)
    _mutate(tree, address, edit)
    _assert_checksum_only_accepts(tree, address)

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def test_out_of_range_key_never_becomes_empty_key() -> None:
    """A key offset outside the node must not silently degrade to b'' through slicing."""
    tree = _tree(fixed=False)
    _mutate(tree, 10, lambda block: _edit_toc(block, 0, lambda entry: setattr(entry.k, "off", 0xFFFF)))

    with pytest.raises(InvalidBTreeNode, match=r"key range .* extends past data end"):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=r"key range .* extends past data end"):
        list(_walk(tree))


def test_child_level_mismatch_rejected() -> None:
    """A child node must be exactly one level below its parent."""
    tree = _tree(fixed=False)

    def child_claims_parent_level(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node, "btn_level", 1))
        _edit_header(block, lambda node: setattr(node, "btn_flags", node.btn_flags & ~BTNODE_LEAF))

    _mutate(tree, 10, child_claims_parent_level)
    _assert_checksum_only_accepts(tree, 10)

    match = r"child node 0xa is at level 1, expected level 0"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def test_level_zero_node_marked_non_leaf_rejected() -> None:
    """A level-zero node without the leaf flag cannot be treated as an index node."""
    tree = _tree(fixed=False)

    def leaf_claims_non_leaf(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node, "btn_flags", node.btn_flags & ~BTNODE_LEAF))

    _mutate(tree, 10, leaf_claims_non_leaf)
    _assert_checksum_only_accepts(tree, 10)

    match = r"leaf flag is unset for level 0"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def test_leaf_flagged_node_above_level_zero_rejected() -> None:
    """A node above level zero cannot be flagged as a leaf."""
    tree = _tree(fixed=False)

    def leaf_claims_level_one(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node, "btn_level", 1))

    _mutate(tree, 10, leaf_claims_level_one)
    _assert_checksum_only_accepts(tree, 10)

    match = r"leaf flag is set for level 1"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def test_self_referencing_child_terminates_with_structure_error() -> None:
    """A child pointer back to its own node must not cause endless traversal."""
    tree = _tree(fixed=False)

    def point_child_at_root(block: bytearray) -> None:
        node = _header(block)
        first_value_offset = _toc_entry(block, 0).v.off
        value_start = NODE_SIZE - INFO_SIZE - first_value_offset
        block[value_start : value_start + 8] = struct.pack("<Q", tree.root)
        assert node.btn_level == 1

    _mutate(tree, tree.root, point_child_at_root)
    _assert_checksum_only_accepts(tree, tree.root)

    match = r"node 0xc: TOC entry 0: child OID 0xc points to the node itself"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def _three_level_tree() -> Tree:
    """Build a root with two index children, each with one leaf child."""
    tree = _tree(fixed=False)
    first_leaf, second_leaf = (entries for _, entries in tree.leaves)

    index_addresses = (20, 21)
    for address, leaf_address, entries in zip(index_addresses, LEAF_ADDRESSES, (first_leaf, second_leaf), strict=True):
        tree.blocks[address] = _write_node(
            address,
            NodeSpec(
                [(entries[0][0], struct.pack("<Q", leaf_address))],
                level=1,
                is_leaf=False,
            ),
        )

    root_entries = [
        (first_leaf[0][0], struct.pack("<Q", index_addresses[0])),
        (second_leaf[0][0], struct.pack("<Q", index_addresses[1])),
    ]
    tree.blocks[ROOT_ADDRESS] = _write_node(
        ROOT_ADDRESS,
        NodeSpec(root_entries, level=2, is_root=True, is_leaf=False),
    )

    return tree


def test_valid_three_level_tree_walk() -> None:
    """Walk descends multiple index levels and still returns every leaf record in order."""
    tree = _three_level_tree()

    assert list(_walk(tree)) == tree.entries
    for key, value in tree.entries:
        assert _search(tree, key) == value


def _chain_tree(levels: int) -> Tree:
    """Build a degenerate one-entry-per-node tree with the given number of levels (root included)."""
    leaves = []
    address = 100
    child_address = None
    blocks = {}

    for level in range(levels):
        is_root = level == levels - 1
        if child_address is None:
            entries = [(_variable_key(0), _variable_value(0))]
            leaves.append((address, entries))
            spec = NodeSpec(entries, level=level)
        else:
            entries = [(_variable_key(0), struct.pack("<Q", child_address))]
            spec = NodeSpec(entries, level=level, is_root=is_root, is_leaf=False)

        blocks[address] = _write_node(address, spec)
        child_address = address
        address += 1

    return Tree(blocks=blocks, root=child_address, leaves=leaves)


def test_excessively_deep_tree_rejected() -> None:
    """A chain deeper than the supported maximum is rejected as a structure error, not traversed forever."""
    tree = _chain_tree(66)
    _assert_checksum_only_accepts(tree, tree.root)

    with pytest.raises(InvalidBTreeNode, match=r"exceeded the maximum tree depth"):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=r"exceeded the maximum tree depth"):
        list(_walk(tree))


def test_index_node_cycle_terminates_with_level_error() -> None:
    """Two index nodes pointing at each other are rejected by the level check instead of looping forever."""
    tree = _three_level_tree()

    def point_index_at_sibling_index(block: bytearray) -> None:
        node = _header(block)
        first_value_offset = _toc_entry(block, 0).v.off
        value_start = NODE_SIZE - first_value_offset
        block[value_start : value_start + 8] = struct.pack("<Q", 21)
        assert node.btn_level == 1

    _mutate(tree, 20, point_index_at_sibling_index)
    _assert_checksum_only_accepts(tree, 20)

    match = r"node 0x14: TOC entry 0: child node 0x15 is at level 1, expected level 0"
    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))

    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))


def test_child_object_type_mismatch_rejected() -> None:
    """A child index entry must resolve to a BTREE_NODE, not just any checksummed object."""
    tree = _tree(fixed=False)
    _mutate(
        tree,
        10,
        lambda block: _edit_header(block, lambda node: setattr(node.btn_o, "o_type", BTREE_TYPE)),
    )
    _assert_checksum_only_accepts(tree, 10)

    match = r"child node 0xa has object type BTREE, expected BTREE_NODE"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def test_root_object_type_mismatch_rejected() -> None:
    """The root node must advertise itself as a BTREE object."""
    tree = _tree(fixed=False)
    _mutate(
        tree,
        tree.root,
        lambda block: _edit_header(block, lambda node: setattr(node.btn_o, "o_type", BTNODE_TYPE)),
    )
    _assert_checksum_only_accepts(tree, tree.root)

    with pytest.raises(InvalidBTreeNode, match=r"B-tree root node 0xc: object type is BTREE_NODE, expected BTREE"):
        BTree(FakeContainer(tree.blocks), tree.root)


def test_child_subtype_mismatch_rejected() -> None:
    """Child nodes must carry the same object subtype as their parent."""
    tree = _tree(fixed=False)
    _mutate(
        tree,
        10,
        lambda block: _edit_header(block, lambda node: setattr(node.btn_o, "o_subtype", 0x10)),
    )
    _assert_checksum_only_accepts(tree, 10)

    match = r"child node 0xa has subtype SNAPMETATREE, expected FSTREE"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))


def test_empty_index_node_rejected() -> None:
    """A non-leaf node with no keys cannot select a child."""
    tree = _tree(fixed=False)

    def clear_index(block: bytearray) -> None:
        _edit_header(block, lambda node: setattr(node, "btn_nkeys", 0))

    _mutate(tree, tree.root, clear_index)
    _assert_checksum_only_accepts(tree, tree.root)

    match = r"B-tree node 0xc \(level 1\): non-leaf node has no keys"
    with pytest.raises(InvalidBTreeNode, match=match):
        _search(tree, _variable_key(0))

    with pytest.raises(InvalidBTreeNode, match=match):
        list(_walk(tree))
