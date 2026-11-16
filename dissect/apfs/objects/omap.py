from __future__ import annotations

import struct
from functools import cached_property, lru_cache

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.util import cmp_omap

_QQ = struct.Struct("<QQ")


class ObjectMap(Object):
    """APFS Object Map (OMAP) object."""

    __type__ = c_apfs.OBJECT_TYPE_OMAP
    __struct__ = c_apfs.omap_phys
    object: c_apfs.omap_phys

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lookup = lru_cache(128)(self.lookup)

    def is_valid(self) -> bool:
        return (
            super().is_valid()
            and self.type == c_apfs.OBJECT_TYPE.OMAP
            and self.subtype == 0
            and self.is_physical
            and self.oid == self.address
        )

    @cached_property
    def btree(self) -> BTree:
        """The B-tree of the object map."""
        return BTree(self.container, self.object.om_tree_oid)

    def lookup(self, oid: int, xid: int | None = None) -> int:
        """Lookup the physical address of an object by its OID and optional transaction ID.

        Only the most recent mapping at or before ``xid`` is returned. If the object has no
        mapping for that transaction, or its latest mapping is deleted, a ``KeyError`` is
        raised instead of falling back to another object's mapping.

        Args:
            oid: The object ID to look up.
            xid: Optional transaction ID to look up. If not provided, the first version is returned.
        """
        cursor = Cursor(self.btree)
        cursor.search((oid, xid or 0), cmp=cmp_omap)

        found_oid, found_xid = _QQ.unpack_from(cursor.key())
        if found_oid != oid:
            raise KeyError(f"Object {oid} not found at xid {xid}")

        value = c_apfs.omap_val(cursor.value())
        if value.ov_flags & c_apfs.OMAP_VAL_DELETED:
            raise KeyError(f"Object {oid} is deleted at xid {found_xid}")

        return value.ov_paddr
