from __future__ import annotations

from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, Any, Literal

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import InvalidBTreeNode
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree_node import BTreeNode
from dissect.apfs.util import cmp_default

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.fve.crypto import Cipher

    from dissect.apfs.apfs import APFS
    from dissect.apfs.objects.omap import ObjectMap

MAX_TREE_DEPTH = 64


class BTree(Object):
    """APFS B-tree object."""

    __type__ = c_apfs.OBJECT_TYPE_BTREE
    object: c_apfs.btree_node_phys

    def __init__(self, container: APFS, address: int, *, block: bytes | None = None, cipher: Cipher | None = None):
        # Break object model a bit here for convenience of having the root node as a separate object
        self.container = container
        self.address = address

        self.root = BTreeNode(container, address, block=block, cipher=cipher)
        self.block = self.root.block
        self.cipher = self.root.cipher
        self.object = self.root.object
        self.header = self.root.header

        # Root nodes have a btree_info struct at the end of the block
        if len(self.root.block) < len(c_apfs.btree_info):
            raise InvalidBTreeNode(
                f"B-tree root node {address:#x}: block of 0x{len(self.root.block):x} bytes is too small "
                f"for the 0x{len(c_apfs.btree_info):x}-byte btree_info trailer"
            )

        self.info = c_apfs.btree_info(self.root.block[-len(c_apfs.btree_info) :])

        if not self.root.is_root:
            raise InvalidBTreeNode(f"B-tree root node {address:#x} does not have the root flag set")

        if self.root.type != c_apfs.OBJECT_TYPE.BTREE:
            raise InvalidBTreeNode(
                f"B-tree root node {address:#x}: object type is {_type_name(self.root.type)}, expected BTREE"
            )

        if self.info.bt_fixed.bt_node_size < len(c_apfs.btree_node_phys) + len(c_apfs.btree_info):
            raise InvalidBTreeNode(
                f"B-tree root node {address:#x}: btree_info node size 0x{self.info.bt_fixed.bt_node_size:x} "
                f"is too small for the node header and btree_info trailer"
            )

        if self.info.bt_fixed.bt_node_size > len(self.root.block):
            raise InvalidBTreeNode(
                f"B-tree root node {address:#x}: btree_info node size 0x{self.info.bt_fixed.bt_node_size:x} "
                f"exceeds block length 0x{len(self.root.block):x}"
            )

        self._read_key = lru_cache(128)(self._read_key)
        self._node_child = lru_cache(128)(self._node_child)
        self._node_search = lru_cache(128)(self._node_search)

    def __repr__(self) -> str:
        return f"<BTree flags={self.flags}>"

    @cached_property
    def flags(self) -> c_apfs.BTREE:
        """The B-tree's flags."""
        return c_apfs.BTREE(self.info.bt_fixed.bt_flags)

    @cached_property
    def _uses_physical_oid(self) -> bool:
        """Whether the B-tree uses physical OIDs."""
        return bool(self.flags & c_apfs.BTREE_PHYSICAL)

    @cached_property
    def _uses_ephemeral_oid(self) -> bool:
        """Whether the B-tree uses ephemeral OIDs."""
        return bool(self.flags & c_apfs.BTREE_EPHEMERAL)

    @cached_property
    def _uses_virtual_oid(self) -> bool:
        """Whether the B-tree uses virtual OIDs."""
        return not self._uses_physical_oid and not self._uses_ephemeral_oid

    @cached_property
    def _node_size(self) -> int:
        """The B-tree node size."""
        return self.info.bt_fixed.bt_node_size

    @cached_property
    def _key_size(self) -> int:
        """The B-tree key size."""
        return self.info.bt_fixed.bt_key_size

    @cached_property
    def _val_size(self) -> int:
        """The B-tree value size."""
        return self.info.bt_fixed.bt_val_size

    def _read_key(self, node: BTreeNode, idx: int) -> bytes:
        """Read a key from a B-tree node.

        Args:
            node: The B-tree node to read from.
            idx: The index of the key to read.
        """
        self._validate(node)
        entry = node.toc[idx]

        if node._has_fixed_kv_size:
            offset = entry.k
            size = self._key_size
        else:
            offset = entry.k.off
            size = entry.k.len

        return bytes(node.block[node._key_offset + offset : node._key_offset + offset + size])

    def _read_value(self, node: BTreeNode, idx: int) -> bytes:
        """Read a value from a B-tree node.

        Args:
            node: The B-tree node to read from.
            idx: The index of the value to read.
        """
        self._validate(node)
        entry = node.toc[idx]

        if node._has_fixed_kv_size:
            offset = entry.v
            size = len(c_apfs.oid_t) if node.is_nonleaf else self._val_size
        else:
            offset = entry.v.off
            size = entry.v.len

        value_offset = self._node_size - (len(c_apfs.btree_info) if node.is_root else 0)
        return bytes(node.block[value_offset - offset : value_offset - offset + size])

    def _validate(self, node: BTreeNode) -> None:
        """Validate the layout of a B-tree node."""
        node.check(node_size=self._node_size, key_size=self._key_size, val_size=self._val_size)

    def _node_child(
        self, node: BTreeNode, idx: int, omap: ObjectMap | None = None, oid: int = 0, xid: int | None = None
    ) -> BTreeNode:
        """Get a child node from a B-tree node.

        Args:
            node: The B-tree node to get the child from.
            idx: The index of the child to get.
            omap: The object map to use for resolving virtual child objects.
            oid: The base object ID to use for resolving virtual child objects.
            xid: The transaction ID to use for resolving virtual child objects.
        """
        if node.is_leaf:
            raise TypeError("Cannot traverse from a leaf node")

        self._validate(node)

        raw_child_oid = self._read_value(node, idx)
        if len(raw_child_oid) != len(c_apfs.oid_t):
            raise InvalidBTreeNode(
                f"B-tree node {node.address:#x}: TOC entry {idx}: child OID is {len(raw_child_oid)} bytes, "
                f"expected {len(c_apfs.oid_t)}"
            )

        child_oid = c_apfs.oid_t(raw_child_oid)

        if self._uses_physical_oid:
            child_node = BTreeNode.from_address(self.container, child_oid, cipher=self.cipher)
        elif self._uses_ephemeral_oid:
            raise NotImplementedError("Ephemeral OIDs are not yet supported")
        elif self._uses_virtual_oid:
            if not omap:
                raise ValueError("Cannot resolve virtual OID without an Object Map")
            child_node = BTreeNode.from_address(self.container, omap.lookup(oid + child_oid, xid), cipher=self.cipher)

        if child_node.address == node.address:
            raise InvalidBTreeNode(
                f"B-tree node {node.address:#x}: TOC entry {idx}: child OID {child_oid:#x} points to the node itself"
            )

        if child_node.type != c_apfs.OBJECT_TYPE.BTREE_NODE:
            raise InvalidBTreeNode(
                f"B-tree node {node.address:#x}: TOC entry {idx}: child node {child_node.address:#x} has "
                f"object type {_type_name(child_node.type)}, expected BTREE_NODE"
            )

        if child_node.subtype != node.subtype:
            raise InvalidBTreeNode(
                f"B-tree node {node.address:#x}: TOC entry {idx}: child node {child_node.address:#x} has "
                f"subtype {_type_name(child_node.subtype)}, expected {_type_name(node.subtype)}"
            )

        self._validate(child_node)

        if child_node.level != node.level - 1:
            raise InvalidBTreeNode(
                f"B-tree node {node.address:#x}: TOC entry {idx}: child node {child_node.address:#x} is at "
                f"level {child_node.level}, expected level {node.level - 1}"
            )

        return child_node

    def _node_search(
        self,
        node: BTreeNode,
        key: Any,
        *,
        exact: bool = False,
        cmp: Callable[[Any, bytes], Literal[-1, 0, 1]] = cmp_default,
    ) -> int:
        """Search for a key in a B-tree node.

        Args:
            node: The B-tree node to search.
            key: The key to search for.
            exact: If ``True``, only return if an exact match is found.
            cmp: Comparison function to use. Should return -1, 0, or 1
        """
        self._validate(node)

        if node.nkeys == 0:
            return -1

        lo, hi = 0, node.nkeys - 1

        while lo <= hi:
            mid = (lo + hi) // 2

            res = cmp(key, self._read_key(node, mid))
            if res == 0:
                break

            if res < 0:
                lo = mid + 1
            else:
                hi = mid - 1

        if exact:
            return mid if res == 0 else -1

        return mid if res <= 0 else mid - 1

    def search(
        self,
        key: bytes,
        *,
        exact: bool = False,
        cmp: Callable[[Any, bytes], Literal[-1, 0, 1]] = cmp_default,
        omap: ObjectMap | None = None,
        oid: int = 0,
        xid: int | None = None,
    ) -> bytes | None:
        """Search for a key in the B-tree.

        Args:
            key: Key to search for.
            exact: If ``True``, only return if an exact match is found.
            cmp: Comparison function to use. Should return -1, 0, or 1.
            omap: The object map to use for resolving virtual child objects.
            oid: The base object ID to use for resolving virtual child objects.
            xid: The transaction ID to use for resolving virtual child objects.
        """
        node = self.root
        visited = {node.address}

        while node.is_nonleaf:
            if len(visited) > MAX_TREE_DEPTH:
                raise InvalidBTreeNode(
                    f"B-tree search exceeded the maximum tree depth of {MAX_TREE_DEPTH} nodes "
                    f"(node {node.address:#x})"
                )

            idx = self._node_search(node, key, cmp=cmp)
            node = self._node_child(node, idx, omap, oid, xid)

            if node.address in visited:
                raise InvalidBTreeNode(f"B-tree search encountered a cycle through node {node.address:#x}")

            visited.add(node.address)

        idx = self._node_search(node, key, exact=exact, cmp=cmp)
        if idx >= node.nkeys or idx == -1:
            raise KeyError(f"Key not found: {key!r}")

        return self._read_value(node, idx)


def _type_name(value: c_apfs.OBJECT_TYPE) -> str:
    """Render an object type or subtype, including values without an enum name."""
    return value.name or f"{int(value):#x}"
