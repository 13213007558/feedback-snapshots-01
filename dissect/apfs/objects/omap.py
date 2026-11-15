from __future__ import annotations

from functools import cached_property, lru_cache

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.util import cmp_omap

#: Transaction ID used to request the most recent version of an object.
XID_MAX = (1 << 64) - 1


class ObjectMap(Object):
    """APFS Object Map (OMAP) object."""

    __type__ = c_apfs.OBJECT_TYPE_OMAP
    __struct__ = c_apfs.omap_phys
    object: c_apfs.omap_phys

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Cached per (oid, xid) query, so lookups for different transactions don't pollute each other
        self.lookup_value = lru_cache(128)(self.lookup_value)

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

    def lookup_value(self, oid: int, xid: int | None = None) -> c_apfs.omap_val:
        """Look up the OMAP record of an object by its OID and optional transaction ID.

        Returns the record of the newest version of the object that was committed in or before
        transaction ``xid``. A record flagged with ``OMAP_VAL_DELETED`` marks the object as
        deleted as of that transaction and prevents falling back to older versions; it is
        returned as-is so callers can inspect the flags (e.g. ``OMAP_VAL_DELETED``,
        ``OMAP_VAL_NOHEADER``). Use :func:`lookup` if only the physical address of a live
        object is needed.

        Args:
            oid: The object ID to look up.
            xid: Optional transaction ID to look up. If not provided, the most recent
                version of the object is returned.

        Raises:
            KeyError: If no version of the object exists at or before the given transaction.
        """
        key, value = self.btree.search_entry((oid, xid if xid is not None else XID_MAX), cmp=cmp_omap)

        omap_key = c_apfs.omap_key(key)
        if omap_key.ok_oid != oid:
            # The B-tree floor search may land on a record of a neighbouring (lower) OID.
            # That record does not describe this object, so the object is not visible.
            raise KeyError(f"No record for object {oid} at transaction {xid}")

        return c_apfs.omap_val(value)

    def lookup(self, oid: int, xid: int | None = None) -> int:
        """Look up the physical address of an object by its OID and optional transaction ID.

        Returns the address of the newest version of the object that is visible at transaction
        ``xid``, i.e. committed in or before that transaction. If that version is flagged with
        ``OMAP_VAL_DELETED``, the object was deleted as of that transaction and is not visible;
        older versions are not used as a fallback.

        Args:
            oid: The object ID to look up.
            xid: Optional transaction ID to look up. If not provided, the most recent
                version of the object is returned.

        Raises:
            KeyError: If no version of the object is visible at the given transaction.
        """
        omap_val = self.lookup_value(oid, xid)

        if omap_val.ov_flags & c_apfs.OMAP_VAL_DELETED:
            raise KeyError(f"Object {oid} is deleted at transaction {xid}")

        return omap_val.ov_paddr
