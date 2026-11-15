from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from dissect.database.bbolt.c_bbolt import BucketLeafFlag, PageFlag, c_bbolt

if TYPE_CHECKING:
    from collections.abc import Iterable


class EntryType(Enum):
    """Type of a :class:`Entry` lookup result."""

    NOT_FOUND = "not-found"
    VALUE = "value"
    BUCKET = "bucket"


class Entry:
    """Result of a raw key lookup in a bbolt database.

    Distinguishes missing keys, (empty) values and sub-buckets, and records
    where the entry was found: the page number for regular pages, or the
    file offset for inline buckets (which have page number 0).
    """

    def __init__(
        self,
        type: EntryType,
        key: bytes | None = None,
        value: bytes | None = None,
        page: Page | None = None,
    ) -> None:
        self.type = type
        self.key = key
        self.value = value
        self.page = page

    def __repr__(self) -> str:
        return f"<Entry type={self.type} key={self.key} value={self.value} pgid={self.pgid} offset={self.offset}>"

    @property
    def found(self) -> bool:
        """Whether the requested key path exists."""
        return self.type is not EntryType.NOT_FOUND

    @property
    def pgid(self) -> int | None:
        """Page number of the page the entry was found in, 0 for inline buckets."""
        return self.page.pgid if self.page is not None else None

    @property
    def offset(self) -> int | None:
        """File offset of the page the entry was found in, i.e. the inline position for inline buckets."""
        return self.page.offset if self.page is not None else None


class Bbolt:
    """bbolt database implementation.

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

        self.meta = c_bbolt.Meta(self.fh)
        self.version = self.meta.version
        self.page_size = self.meta.pageSize

        if self.meta.magic != c_bbolt.Magic:
            raise ValueError(f"Unexpected bbolt meta magic value {self.meta.magic:x}")

        self.root = Page(self, self.meta.root.root)

    def __repr__(self) -> str:
        return f"<Bbolt version={self.version} page_size={self.page_size} path={self.path or self.fh}>"

    def _bucket_page(self, inode: InodeLeaf, key: bytes) -> Page:
        """Resolve the :class:`Page` of the bucket stored in the given inode."""
        # Read the page inside the inode
        if inode.value.startswith(16 * b"\x00"):
            page = Page(self, 0, inode._value_offset + 0x10)

        # Read the page this inode points to
        else:
            pgid = c_bbolt.InBucket(inode.value).root if not inode.pgid else inode.pgid
            page = Page(self, pgid)

        # If the new page has an inode 0 with BucketLeafFlag, read that bucket instead
        if page.count and (inode_nested := page.inode(0)).flags == BucketLeafFlag and inode_nested.key == key:
            page = Page(self, 0, inode_nested._value_offset + 0x10)

        return page

    def _iter(self, type: Literal["page", "value"], parts: list[bytes] | None) -> Page | bytes | None:
        """Iterate over :class:`Page`` and :class:`Inode` until the requested page or key value is found."""
        # Return the root page if no path was given
        if not parts:
            return self.root

        page = self.root
        for i, part in enumerate(parts):
            # Search for the current part in each inode of the current page
            for inode in page.inodes():
                if inode.key == part:
                    if inode.flags == BucketLeafFlag:
                        page = self._bucket_page(inode, part)

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

    def _split(self, path: str | None, sep: str) -> list[bytes] | None:
        """Split a text path into raw key bytes.

        The separator is a convention of the text convenience interface only;
        encoding to bytes is injective, so distinct keys are never merged here.
        """
        if not path or path == sep:
            return None
        return [part.encode() for part in path.split(sep)]

    def keys(self, path: str | None = None, *, sep: str = " ") -> list[str] | None:
        """Get a list of key names from the given path."""
        if not (page := self._iter("page", self._split(path, sep))):
            return None
        return [child.key.decode() for child in page.inodes()]

    def get(self, path: str | None, *, sep: str = " ", decode: bool = True) -> str | bytes | None:
        """Get a key value from the given path."""
        if not (value := self._iter("value", self._split(path, sep))):
            return None
        return value.decode() if decode else value

    def lookup(self, path: Iterable[bytes] | bytes) -> Entry:
        """Look up an entry by a sequence of raw key bytes.

        Unlike the text convenience interface, no separator is involved and keys
        are compared as raw bytes, so keys containing spaces, empty values and
        non UTF-8 keys can be addressed unambiguously. The returned :class:`Entry`
        distinguishes missing keys, (empty) values and sub-buckets, and records
        the page number or inline position where the entry was found.
        """
        if isinstance(path, bytes):
            parts = [path]
        else:
            parts = [bytes(part) for part in path]

        if not parts:
            return Entry(EntryType.BUCKET, page=self.root)

        page = self.root
        for i, part in enumerate(parts):
            last = i + 1 == len(parts)
            for inode in page.inodes():
                if inode.key != part:
                    continue

                if inode.flags == BucketLeafFlag:
                    bucket_page = self._bucket_page(inode, part)
                    if last:
                        return Entry(EntryType.BUCKET, key=part, page=bucket_page)
                    if bucket_page.count:
                        page = bucket_page
                        break
                    # Spec dictates we should ignore pages with no inodes
                    return Entry(EntryType.NOT_FOUND, key=part, page=bucket_page)

                # A regular value cannot be descended into
                if not last:
                    return Entry(EntryType.NOT_FOUND, key=part, page=page)
                return Entry(EntryType.VALUE, key=part, value=inode.value, page=page)
            else:
                return Entry(EntryType.NOT_FOUND, key=part, page=page)

        return Entry(EntryType.NOT_FOUND, page=self.root)

    def get_raw(self, path: Iterable[bytes] | bytes) -> bytes | None:
        """Get the exact value bytes for a sequence of raw key bytes.

        Returns an empty ``bytes`` for present-but-empty values, and ``None``
        if the path does not exist or addresses a sub-bucket. Use
        :meth:`lookup` if the distinction matters.
        """
        entry = self.lookup(path)
        if entry.type is EntryType.VALUE:
            return entry.value
        return None

    def keys_raw(self, path: Iterable[bytes] | bytes | None = None) -> list[bytes] | None:
        """Get a list of raw key bytes from the bucket at the given raw key path.

        Returns ``None`` if the path does not exist or does not address a bucket.
        """
        entry = self.lookup(path or [])
        if entry.type is not EntryType.BUCKET:
            return None
        return [inode.key for inode in entry.page.inodes()]


class Page:
    """Represents a bbolt page (meta, freelist, branch or leaf)."""

    def __init__(self, db: Bbolt, pgid: int, offset: int | None = None) -> None:
        self.db = db
        self.pgid = pgid

        if not offset:
            self.offset = db.fh.seek(pgid * db.page_size)
        else:
            self.offset = db.fh.seek(offset)

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

        self.key = page.db.fh.read(element.ksize)


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
