from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property, lru_cache

from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.objects.base import Object
from dissect.apfs.objects.btree import BTree
from dissect.apfs.util import cmp_omap

MAX_XID = (1 << 64) - 1


@dataclass(frozen=True)
class OmapEntry:
    """A single object map entry for an object ID and transaction ID.

    Args:
        oid: The object ID the entry belongs to.
        xid: The transaction ID the entry was written in.
        flags: The raw ``omap_val`` flags.
        size: The size of the mapped object.
        paddr: The physical address of the mapped object.
    """

    oid: int
    xid: int
    flags: int
    size: int
    paddr: int

    @property
    def is_deleted(self) -> bool:
        """Whether the entry marks the object as deleted."""
        return bool(self.flags & c_apfs.OMAP_VAL_DELETED)

    @property
    def is_noheader(self) -> bool:
        """Whether the mapped object is stored without an object header."""
        return bool(self.flags & c_apfs.OMAP_VAL_NOHEADER)

    @property
    def is_encrypted(self) -> bool:
        """Whether the mapped object is encrypted."""
        return bool(self.flags & c_apfs.OMAP_VAL_ENCRYPTED)

    @property
    def is_visible(self) -> bool:
        """Whether the entry maps to an object that exists in this transaction.

        A deleted entry is a tombstone: it hides all older versions of the object, but does not map to an object
        itself. A headerless entry still maps to a block; it just needs to be interpreted without an ``obj_phys``
        header.
        """
        return not self.is_deleted


class ObjectMap(Object):
    """APFS Object Map (OMAP) object."""

    __type__ = c_apfs.OBJECT_TYPE_OMAP
    __struct__ = c_apfs.omap_phys
    object: c_apfs.omap_phys

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.lookup = lru_cache(128)(self.lookup)
        self.lookup_entry = lru_cache(128)(self.lookup_entry)

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

    def lookup_entry(self, oid: int, xid: int | None = None) -> OmapEntry:
        """Look up the object map entry that is visible for an object ID and transaction ID.

        The entry returned is the newest version of ``oid`` that was written in ``xid`` or earlier. A version from a
        later transaction is never returned. If a version was deleted in ``xid`` or earlier, the deletion is the
        visible entry: older versions are hidden by it and are not returned.

        Args:
            oid: The object ID to look up.
            xid: Optional transaction ID. If not provided, the newest version of ``oid`` is returned regardless of the
                transaction it was written in. Pass an explicit transaction ID to ask what was visible at that point
                in time.

        Raises:
            KeyError: If ``oid`` has no version at or before ``xid``.
        """
        # Without an explicit transaction ID, the newest known version is requested.
        search_xid = MAX_XID if xid is None else xid

        try:
            key, value = self.btree.search_item((oid, search_xid), cmp=cmp_omap)
        except KeyError:
            raise KeyError(self._not_found_message(oid, xid)) from None

        omap_key = c_apfs.omap_key(key)
        if omap_key.ok_oid != oid:
            # The B-tree search returns the closest predecessor, which may belong to an adjacent object ID.
            raise KeyError(self._not_found_message(oid, xid))

        if omap_key.ok_xid > search_xid:
            raise KeyError(self._not_found_message(oid, xid))

        omap_val = c_apfs.omap_val(value)
        return OmapEntry(
            oid=int(omap_key.ok_oid),
            xid=int(omap_key.ok_xid),
            flags=int(omap_val.ov_flags),
            size=int(omap_val.ov_size),
            paddr=int(omap_val.ov_paddr),
        )

    @staticmethod
    def _not_found_message(oid: int, xid: int | None) -> str:
        """Format the error message for an object that has no version in the requested view."""
        if xid is None:
            return f"Object ID {oid} not found in object map"
        return f"Object ID {oid} has no version at or before xid {xid}"

    def lookup(self, oid: int, xid: int | None = None) -> int:
        """Lookup the physical address of an object by its OID and optional transaction ID.

        The address returned belongs to the newest version of ``oid`` that was visible in ``xid`` or earlier.
        Versions written after ``xid`` are never returned, and an adjacent object ID is never substituted when
        ``oid`` itself is absent. A deleted version is a tombstone: it hides older versions and is reported as not
        found.

        Args:
            oid: The object ID to look up.
            xid: Optional transaction ID to look up. If not provided, the newest version is returned regardless of its
                transaction ID.

        Raises:
            KeyError: If ``oid`` is not present (or is deleted) at or before ``xid``.
        """
        entry = self.lookup_entry(oid, xid)
        if entry.is_deleted:
            raise KeyError(f"Object ID {oid} is deleted at xid {entry.xid}")

        return entry.paddr
