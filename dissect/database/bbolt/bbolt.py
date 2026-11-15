from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from dissect.database.bbolt.c_bbolt import BucketLeafFlag, PageFlag, c_bbolt
from dissect.database.bbolt.exception import InvalidDatabase
from dissect.database.bbolt.meta import select_meta

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.database.bbolt.meta import MetaSelection


class Bbolt:
    """bbolt database implementation.

    bbolt keeps two meta pages in the first two pages of the file. A crash can
    leave the newest of the two damaged while the older one is still a complete,
    committed snapshot. On open, both meta pages are validated and the newest
    snapshot with a verified checksum and a self-consistent page graph is used.
    If neither candidate can be trusted, or two valid candidates describe
    conflicting transaction views, opening fails instead of mixing pages.

    The decision and the evidence behind it are available through
    :attr:`meta_selection` and :meth:`explain_selection`.

    References:
        - https://github.com/etcd-io/bbolt
        - https://www.qtmuniao.com/en/2020/11/29/bolt-data-organised/
        - https://www.qtmuniao.com/en/2020/12/14/bolt-index-design/
    """

    def __init__(self, fh: BinaryIO | Path) -> None:
        if isinstance(fh, Path):
            self.path = fh
            self.fh = fh.open("rb")
        elif hasattr(fh, "read"):
            self.path = None
            self.fh = fh
        else:
            raise TypeError("Argument fh must be Path or BytesIO-like object")

        self.meta_selection: MetaSelection = select_meta(self.fh)

        if self.meta_selection.selected is None:
            if self.path is not None:
                self.fh.close()
            raise InvalidDatabase(self.meta_selection.explain())

        self.meta = self.meta_selection.selected.meta
        self.meta_index = self.meta_selection.selected_index
        self.version = self.meta.version
        self.page_size = self.meta.pageSize
        self.root_pgid = self.meta_selection.selected.root
        self.high_water = self.meta_selection.selected.high_water
        self.txid = self.meta_selection.selected.txid

        if self.meta.magic != c_bbolt.Magic:
            raise ValueError(f"Unexpected bbolt meta magic value {self.meta.magic:x}")

        try:
            self.root = Page(self, self.root_pgid)
        except Exception:
            if self.path is not None:
                self.fh.close()
            raise

    def __repr__(self) -> str:
        return (
            f"<Bbolt version={self.version} page_size={self.page_size} txid={self.txid} "
            f"meta={self.meta_index} path={self.path or self.fh}>"
        )

    def explain_selection(self) -> str:
        """Return a human readable explanation of the meta page selection."""
        return self.meta_selection.explain()

    def _iter(self, type: Literal["page", "value"], path: str | None, sep: str) -> Page | bytes | None:
        """Iterate over :class:`Page`` and :class:`Inode` until the requested page or key value is found."""
        # Return the root page if no path was given
        if not path or path == sep:
            return self.root

        page = self.root
        parts = path.split(sep)
        for i, part in enumerate(parts):
            # Search for the current part in each inode of the current page
            for inode in page.inodes():
                if inode.key == part:
                    if inode.flags == BucketLeafFlag:
                        # An inline bucket has no root page; its page follows the 16 byte bucket header
                        if len(inode.value) >= 16 and not c_bbolt.InBucket(inode.value).root:
                            page = Page(self, 0, inode._value_offset + 0x10)

                        # Read the page this inode points to
                        else:
                            pgid = c_bbolt.InBucket(inode.value).root if not inode.pgid else inode.pgid
                            page = Page(self, pgid)

                    # If the new page has an inode 0 with BucketLeafFlag, read that bucket instead
                    if (
                        page.count
                        and (inode_nested := page.inode(0)).flags == BucketLeafFlag
                        and inode_nested.key == part
                    ):
                        page = Page(self, 0, inode_nested._value_offset + 0x10)

                    # Spec dictates we should ignore pages with no inodes
                    if not page.count:
                        continue

                    if i + 1 == len(parts):
                        if type == "page":
                            return page
                        if type == "value" and inode.value:
                            return inode.value

                    # We can stop iterating over more inodes of this page, continue to the next path part
                    break
            else:
                # Return early if we did not find the current part in any of the inodes in this page
                return None

        return None

    def keys(self, path: str | None = None, *, sep: str = " ") -> list[str] | None:
        """Get a list of key names from the given path."""
        if not (page := self._iter("page", path, sep)):
            return None
        return [child.key for child in page.inodes()]

    def get(self, path: str | None, *, sep: str = " ", decode: bool = True) -> str | bytes | None:
        """Get a key value from the given path."""
        if not (value := self._iter("value", path, sep)):
            return None
        return value.decode() if decode else value


class Page:
    """Represents a bbolt page (meta, freelist, branch or leaf)."""

    def __init__(self, db: Bbolt, pgid: int, offset: int | None = None) -> None:
        self.db = db
        self.pgid = pgid

        self.offset = db.fh.seek(pgid * db.page_size) if not offset else db.fh.seek(offset)

        self.page = c_bbolt.Page(db.fh)

        self.flags = self.page.flags
        self.count = self.page.count
        self.overflow = self.page.overflow

        if self.flags == PageFlag.Leaf and self.count:
            self.key = self.inode(0).key
        else:
            self.key = None

    def __repr__(self) -> str:
        return f"<Page offset=0x{self.offset:x} pgid={self.pgid} flags={self.flags} count={self.count} overflow={self.overflow} key={self.key}>"  # noqa: E501

    def inode(self, i: int) -> Inode:
        """Return the :class:`Inode` corresponding to the given index number."""
        if i >= self.count or i < 0:
            raise ValueError(f"invalid inode number: got {i}, should be 0-{self.count - 1}")

        offset = self.offset + self.page.size + (i * 16)

        if self.flags == PageFlag.Leaf:
            return InodeLeaf(self, c_bbolt.leafPageElement, offset)

        if self.flags == PageFlag.Branch:
            return InodeBranch(self, c_bbolt.branchPageElement, offset)

        raise NotImplementedError(self.pgid, self.flags)

    def inodes(self) -> Iterable[InodeLeaf]:
        """Yield all :class:`Inode` present in this :class:`Page`.

        References:
            - internal/common/inode.go @ ReadInodeFromPage
        """
        offset = self.offset + self.page.size
        for i in range(self.count):
            element_offset = offset + (i * 16)

            if self.flags == PageFlag.Leaf:
                yield InodeLeaf(self, c_bbolt.leafPageElement, element_offset)
            elif self.flags == PageFlag.Branch:
                # For easier enumeration we iterate all inodes from the page this branch inode points to,
                # and do not yield the branch inode.
                branch = InodeBranch(self, c_bbolt.branchPageElement, element_offset)
                page = Page(self.db, branch.pgid)
                yield from page.inodes()
            else:
                raise NotImplementedError(self.flags)


class Inode:
    """Represents a bbolt Inode branch or leaf element.

    Only for internal use, see :class:`InodeLeaf` and :class:`InodeBranch`.
    """

    def __init__(self, page: Page, structure: c_bbolt.leafPageElement | c_bbolt.branchPageElement, offset: int) -> None:
        self.page = page
        self.offset = offset

        page.db.fh.seek(offset)
        element = structure(page.db.fh)
        self.element = element

        self.flags = None
        self.value = None
        self.pgid = None

        page.db.fh.seek(offset)
        page.db.fh.read(element.pos)

        self.key = page.db.fh.read(element.ksize).decode()


class InodeLeaf(Inode):
    """Represents a bbolt Inode leaf element."""

    def __init__(self, page: Page, structure: c_bbolt.leafPageElement, offset: int) -> None:
        super().__init__(page, structure, offset)

        self.flags = self.element.flags
        self._value_offset = page.db.fh.tell()
        self.value = page.db.fh.read(self.element.vsize)

    def __repr__(self) -> str:
        return f"<Inode type=leaf flags={self.flags} key={self.key} value={self.value}>"


class InodeBranch(Inode):
    """Represents a bbolt Inode branch element."""

    def __init__(self, page: Page, structure: c_bbolt.branchPageElement, offset: int) -> None:
        super().__init__(page, structure, offset)

        self.pgid = self.element.pgid

    def __repr__(self) -> str:
        return f"<Inode type=branch pgid={self.pgid} (first)key={self.key}>"
