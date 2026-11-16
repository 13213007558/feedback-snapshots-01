from __future__ import annotations

from functools import cached_property
from itertools import pairwise

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import InvalidBTreeNode
from dissect.apfs.objects.base import Object


class BTreeNode(Object):
    """APFS B-tree Node object."""

    __type__ = c_apfs.OBJECT_TYPE_BTREE_NODE
    __struct__ = c_apfs.btree_node_phys
    object: c_apfs.btree_node_phys

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._data_offset = len(self.__struct__)
        self._key_offset = self._data_offset + self.object.btn_table_space.off + self.object.btn_table_space.len
        self._checked = False

    def __repr__(self) -> str:
        return f"<BTreeNode flags={self.flags} nkeys={self.object.btn_nkeys}>"

    @cached_property
    def toc(self) -> list[c_apfs.kvoff | c_apfs.kvloc]:
        """The B-tree node's table of contents."""
        nkeys = self.object.btn_nkeys
        buf = self.block[self._data_offset + self.object.btn_table_space.off :]

        if self._has_fixed_kv_size:
            return c_apfs.kvoff[nkeys](buf)

        return c_apfs.kvloc[nkeys](buf)

    @cached_property
    def flags(self) -> c_apfs.BTNODE:
        """The B-tree node's flags."""
        return c_apfs.BTNODE(self.object.btn_flags)

    @cached_property
    def is_root(self) -> bool:
        """Whether the node is the root node."""
        return bool(self.object.btn_flags & c_apfs.BTNODE_ROOT)

    @cached_property
    def is_leaf(self) -> bool:
        """Whether the node is a leaf node."""
        return bool(self.object.btn_flags & c_apfs.BTNODE_LEAF)

    @cached_property
    def is_nonleaf(self) -> bool:
        """Whether the node is a non-leaf node."""
        return not self.is_leaf

    @cached_property
    def _has_fixed_kv_size(self) -> bool:
        """Whether the B-tree node has fixed key/value sizes."""
        return bool(self.object.btn_flags & c_apfs.BTNODE_FIXED_KV_SIZE)

    @cached_property
    def level(self) -> int:
        """The B-tree node's level."""
        return self.object.btn_level

    @cached_property
    def nkeys(self) -> int:
        """The number of keys in the B-tree node."""
        return self.object.btn_nkeys

    def check(self, *, node_size: int, key_size: int, val_size: int) -> None:
        """Validate the on-disk layout of this node.

        The checksum only covers the raw bytes and says nothing about whether offsets in the node make sense.
        Validate the table of contents and every key/value range against the node boundaries so a malformed node
        cannot masquerade as a set of valid records.

        Args:
            node_size: The B-tree node size from the root ``btree_info``.
            key_size: The fixed key size from the root ``btree_info``.
            val_size: The fixed value size from the root ``btree_info``.

        Raises:
            InvalidBTreeNode: If any part of the node layout is invalid.
        """
        if self._checked:
            return

        node = f"B-tree node {self.address:#x} (level {self.level})"
        data_end = node_size - (len(c_apfs.btree_info) if self.is_root else 0)

        if len(self.block) < node_size:
            raise InvalidBTreeNode(
                f"{node}: block is 0x{len(self.block):x} bytes, shorter than node size 0x{node_size:x}"
            )

        if data_end < self._data_offset:
            raise InvalidBTreeNode(
                f"{node}: node size 0x{node_size:x} leaves no room for data after the "
                f"0x{self._data_offset:x}-byte header and root btree_info area"
            )

        if self.is_leaf != (self.level == 0):
            raise InvalidBTreeNode(
                f"{node}: leaf flag is {'set' if self.is_leaf else 'unset'} for level {self.level} "
                "(a leaf must be level 0 and a non-leaf must be above level 0)"
            )

        if self.is_nonleaf and self.nkeys == 0:
            raise InvalidBTreeNode(f"{node}: non-leaf node has no keys, so it cannot have children")

        entry_size = len(c_apfs.kvoff) if self._has_fixed_kv_size else len(c_apfs.kvloc)
        if self._has_fixed_kv_size and key_size == 0:
            raise InvalidBTreeNode(f"{node}: fixed key/value flag is set, but btree_info has key size 0x{key_size:x}")

        if self._has_fixed_kv_size and not self.is_nonleaf and val_size == 0:
            raise InvalidBTreeNode(f"{node}: fixed key/value flag is set, but btree_info has value size 0x{val_size:x}")

        # bt_val_size describes records in leaf nodes. Index nodes always store a child OID, even when the
        # fixed key/value size flag is set, so their values are only as large as an OID.
        entry_val_size = len(c_apfs.oid_t) if self.is_nonleaf else val_size

        table_offset = self._data_offset + self.object.btn_table_space.off
        table_end = table_offset + self.object.btn_table_space.len
        toc_used = self.nkeys * entry_size

        if self.object.btn_table_space.len < toc_used:
            raise InvalidBTreeNode(
                f"{node}: btn_table_space.len 0x{self.object.btn_table_space.len:x} is too small for "
                f"{self.nkeys} TOC entries of 0x{entry_size:x} bytes (need 0x{toc_used:x})"
            )

        if table_end > data_end:
            raise InvalidBTreeNode(
                f"{node}: TOC at [0x{table_offset:x},0x{table_end:x}) extends past data end 0x{data_end:x}"
            )

        key_area_start = table_end
        free_start = key_area_start + self.object.btn_free_space.off
        free_end = free_start + self.object.btn_free_space.len

        if free_end > data_end:
            raise InvalidBTreeNode(
                f"{node}: btn_free_space range [0x{free_start:x},0x{free_end:x}) extends past data end "
                f"0x{data_end:x}"
            )

        key_ranges = []
        value_ranges = []

        for idx, entry in enumerate(self.toc):
            if self._has_fixed_kv_size:
                key_offset, key_length = entry.k, key_size
                val_offset, val_length = entry.v, entry_val_size
            else:
                key_offset, key_length = entry.k.off, entry.k.len
                val_offset, val_length = entry.v.off, entry.v.len

            key_start = key_area_start + key_offset
            key_end = key_start + key_length
            value_start = data_end - val_offset
            value_end = value_start + val_length

            if key_length == 0:
                raise InvalidBTreeNode(f"{node}: TOC entry {idx}: key has zero length")

            if key_end > data_end:
                where = "root btree_info area" if self.is_root else "node data area"
                raise InvalidBTreeNode(
                    f"{node}: TOC entry {idx}: key range [0x{key_start:x},0x{key_end:x}) extends past "
                    f"data end 0x{data_end:x} into the {where}"
                )

            if value_start < 0 or value_end > data_end:
                where = "root btree_info area" if self.is_root and value_end > data_end else "node data area"
                raise InvalidBTreeNode(
                    f"{node}: TOC entry {idx}: value range [0x{value_start:x},0x{value_end:x}) is outside "
                    f"the {where} [0x0,0x{data_end:x})"
                )

            key_ranges.append((key_start, key_end, idx))
            value_ranges.append((value_start, value_end, idx))

        # Check overlaps before the free space bookkeeping, so that the reported violation is the actual
        # overlapping ranges instead of a misleading free space boundary.
        _check_overlaps(node, "key", key_ranges)
        _check_overlaps(node, "value", value_ranges)

        for key_start, key_end, key_idx in key_ranges:
            for value_start, value_end, value_idx in value_ranges:
                if key_start < value_end and value_start < key_end:
                    raise InvalidBTreeNode(
                        f"{node}: key {key_idx} range [0x{key_start:x},0x{key_end:x}) overlaps "
                        f"value {value_idx} range [0x{value_start:x},0x{value_end:x})"
                    )

        for key_start, key_end, idx in key_ranges:
            if key_end > free_start:
                raise InvalidBTreeNode(
                    f"{node}: TOC entry {idx}: key range [0x{key_start:x},0x{key_end:x}) extends past "
                    f"key area end 0x{free_start:x} (start of btn_free_space)"
                )

        for value_start, value_end, idx in value_ranges:
            if value_start < free_end:
                raise InvalidBTreeNode(
                    f"{node}: TOC entry {idx}: value range [0x{value_start:x},0x{value_end:x}) starts before "
                    f"the end of btn_free_space 0x{free_end:x}"
                )

        self._checked = True


def _check_overlaps(node: str, kind: str, ranges: list[tuple[int, int, int]]) -> None:
    ranges = sorted(ranges)
    for (start, end, idx), (next_start, next_end, next_idx) in pairwise(ranges):
        if next_start < end:
            raise InvalidBTreeNode(
                f"{node}: {kind} {idx} range [0x{start:x},0x{end:x}) overlaps "
                f"{kind} {next_idx} range [0x{next_start:x},0x{next_end:x})"
            )
