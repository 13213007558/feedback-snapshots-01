from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Literal

from dissect.database.bbolt.c_bbolt import BucketLeafFlag, PageFlag, c_bbolt

if TYPE_CHECKING:
    from collections.abc import Iterable

# bbolt always writes two meta pages: page 0 and page 1
META_PAGE_COUNT = 2

# Page size bounds as used by bbolt
MIN_PAGE_SIZE = 0x200
MAX_PAGE_SIZE = 0x10000

# Page sizes to probe for the second meta page if the first one cannot tell us the page size
PROBE_PAGE_SIZES = (0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x200, 0x400, 0x800)

SUPPORTED_VERSION = 2

# bbolt writes this value as freelist pgid when no freelist is persisted
PGID_NO_FREELIST = 0xFFFFFFFFFFFFFFFF

_FNV1A64_OFFSET_BASIS = 14695981039346656037
_FNV1A64_PRIME = 1099511628211

_PAGE_HEADER_SIZE = len(c_bbolt.Page)
_META_SIZE = len(c_bbolt.Meta)
# The meta checksum covers all meta fields after the page header, up to the checksum field
_CHECKSUM_START = _PAGE_HEADER_SIZE
_CHECKSUM_END = _META_SIZE - 8


def fnv1a64(data: bytes) -> int:
    """Return the FNV-1a 64-bit hash of ``data``, used by bbolt to checksum meta pages."""
    h = _FNV1A64_OFFSET_BASIS
    for byte in data:
        h = ((h ^ byte) * _FNV1A64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


def _is_plausible_page_size(page_size: int) -> bool:
    return MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE and page_size & (page_size - 1) == 0


@dataclass
class MetaCandidate:
    """Forensic diagnostics for one of the two meta pages of a bbolt database.

    Records what was found at each meta page, whether it could be proven valid,
    and why it was or was not selected as the active transaction view.
    """

    index: int
    offset: int | None
    meta: c_bbolt.Meta | None = field(default=None, repr=False)
    txid: int | None = None
    page_size: int | None = None
    valid: bool = False
    selected: bool = False
    reason: str = ""


class Bbolt:
    """bbolt database implementation.

    References:
        - https://github.com/etcd-io/bbolt
        - https://www.qtmuniao.com/en/2020/11/29/bolt-data-organised/
        - https://www.qtmuniao.com/en/2020/12/14/bolt-index-design/

    A bbolt file contains two meta pages. When opening a (possibly crashed) database offline,
    both are validated independently and the newest provably valid one is selected as the
    active transaction view. The per-candidate diagnostics of this selection are available
    in :attr:`meta_candidates`.
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

        self.fh.seek(0, 2)
        self.file_size = self.fh.tell()

        self.meta_candidates = self._read_meta_candidates()
        self.meta = self._select_meta(self.meta_candidates)
        self.version = self.meta.version
        self.page_size = self.meta.pageSize
        self.txid = self.meta.txid

        self.root = Page(self, self.meta.root.root)

    def __repr__(self) -> str:
        return f"<Bbolt version={self.version} page_size={self.page_size} path={self.path or self.fh}>"

    def _read_meta_candidates(self) -> list[MetaCandidate]:
        """Read and validate both meta pages, returning per-candidate diagnostics."""
        candidates = [self._read_meta_at(0, 0)]

        first = candidates[0]
        if first.page_size is not None and _is_plausible_page_size(first.page_size):
            # The second meta page lives exactly one page after the first
            candidates.append(self._read_meta_at(1, first.page_size))
            return candidates

        # The first meta page cannot tell us the page size; probe common page sizes
        # for a page that looks like a meta page
        candidate = None
        fallback = None
        for page_size in PROBE_PAGE_SIZES:
            probed = self._read_meta_at(1, page_size)
            if probed.meta is not None and probed.meta.magic == c_bbolt.Magic:
                candidate = probed
                break
            if fallback is None and probed.meta is not None:
                fallback = probed
        else:
            candidate = fallback

        if candidate is None:
            candidate = MetaCandidate(index=1, offset=None, reason="no second meta page found")
        candidates.append(candidate)
        return candidates

    def _read_meta_at(self, index: int, offset: int) -> MetaCandidate:
        """Parse and validate the meta page at ``offset``."""
        self.fh.seek(offset)
        buf = self.fh.read(_META_SIZE)
        if len(buf) < _META_SIZE:
            return MetaCandidate(index=index, offset=offset, reason="not enough data for a meta page")

        meta = c_bbolt.Meta(buf)
        candidate = MetaCandidate(index=index, offset=offset, meta=meta, txid=meta.txid, page_size=meta.pageSize)
        reason = self._validate_meta(meta, buf)
        candidate.valid = reason is None
        candidate.reason = reason or "valid"
        return candidate

    def _validate_meta(self, meta: c_bbolt.Meta, buf: bytes) -> str | None:
        """Return ``None`` if the meta page is provably valid, otherwise a human readable reason."""
        if meta.page.flags != PageFlag.Meta:
            return f"page flags {meta.page.flags} do not mark a meta page"
        if meta.magic != c_bbolt.Magic:
            return f"bad magic 0x{meta.magic:x}"
        if meta.version != SUPPORTED_VERSION:
            return f"unsupported version {meta.version}"
        if not _is_plausible_page_size(meta.pageSize):
            return f"implausible page size {meta.pageSize}"
        checksum = fnv1a64(buf[_CHECKSUM_START:_CHECKSUM_END])
        if meta.checksum != checksum:
            return f"checksum mismatch (stored 0x{meta.checksum:x}, computed 0x{checksum:x})"
        if meta.root.root < META_PAGE_COUNT or meta.root.root >= meta.pgid:
            return f"root bucket page {meta.root.root} is outside the page high-water mark {meta.pgid}"
        if meta.freelist != PGID_NO_FREELIST and meta.freelist >= meta.pgid:
            return f"freelist page {meta.freelist} is outside the page high-water mark {meta.pgid}"
        if meta.pgid * meta.pageSize > self.file_size:
            return f"page high-water mark {meta.pgid} reaches beyond the end of the file"
        return None

    def _select_meta(self, candidates: list[MetaCandidate]) -> c_bbolt.Meta:
        """Select a single consistent transaction view from the validated meta pages.

        The newest (highest txid) provably valid meta page wins. If both candidates are valid
        but disagree on the page size, their views can never be mixed: only the selected
        meta's page size, root bucket and high-water mark are used.
        """
        valid = [candidate for candidate in candidates if candidate.valid]
        if not valid:
            reasons = "; ".join(f"meta{candidate.index}: {candidate.reason}" for candidate in candidates)
            raise ValueError(f"No valid bbolt meta page found ({reasons})")

        chosen = max(valid, key=lambda candidate: candidate.txid)
        chosen.selected = True
        chosen.reason = f"selected: highest valid txid {chosen.txid}"

        conflicting = [
            candidate for candidate in valid if candidate is not chosen and candidate.page_size != chosen.page_size
        ]
        if conflicting:
            others = ", ".join(f"meta{candidate.index} ({candidate.page_size})" for candidate in conflicting)
            chosen.reason += f"; page size conflict with {others}; views were not mixed"

        for candidate in candidates:
            if candidate is chosen:
                continue
            if candidate.valid:
                candidate.reason = f"valid but not selected: older txid {candidate.txid} < {chosen.txid}"
                if candidate.page_size != chosen.page_size:
                    candidate.reason += (
                        f"; conflicting page size {candidate.page_size} (selected {chosen.page_size}), "
                        "views were not mixed"
                    )
            elif candidate.txid is not None and candidate.txid > chosen.txid:
                candidate.reason += f"; txid {candidate.txid} is newer but cannot be proven valid"

        return chosen.meta

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
                        # Read the page inside the inode
                        if inode.value.startswith(16 * b"\x00"):
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
