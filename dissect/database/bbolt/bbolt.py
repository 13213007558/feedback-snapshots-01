from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.bbolt.c_bbolt import BucketLeafFlag, PageFlag, c_bbolt

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

# Text access is lossless only when invalid UTF-8 is round-tripped through surrogate escapes.
# Using replacement characters would merge distinct binary keys into the same display name.
ENCODING = "utf-8"
ERRORS = "surrogateescape"


def _decode(value: bytes) -> str:
    return value.decode(ENCODING, ERRORS)


def _encode(value: str) -> bytes:
    return value.encode(ENCODING, ERRORS)


def _normalize_path(key_path: Sequence[bytes | str] | bytes | str) -> tuple[bytes, ...]:
    """Normalize a raw path to a tuple of exact key bytes.

    A single :class:`bytes` or :class:`str` argument is one key.  A list or
    tuple argument is a sequence of keys, which allows callers to pass an
    already-built path without unpacking it.  No separator is ever interpreted.
    """
    if isinstance(key_path, (bytes, str)):
        key_path = (key_path,)

    keys = []
    for key in key_path:
        if isinstance(key, str):
            keys.append(_encode(key))
        elif isinstance(key, (bytes, bytearray, memoryview)):
            keys.append(bytes(key))
        else:
            raise TypeError(f"Keys must be bytes or str, not {type(key).__name__}")
    return tuple(keys)


def _join_path(
    key_path: tuple[bytes | str, ...], path: Sequence[bytes | str] | bytes | str | None
) -> tuple[bytes | str, ...]:
    """Combine positional keys and an optional explicit path argument."""
    if path is None:
        if len(key_path) == 1 and isinstance(key_path[0], (list, tuple)):
            return tuple(key_path[0])
        return key_path
    if key_path:
        raise TypeError("Use either positional keys or the path argument, not both")
    if isinstance(path, (bytes, str)):
        return (path,)
    return tuple(path)


@dataclass(frozen=True, slots=True)
class Entry:
    """A bbolt key, value or sub-bucket together with its exact origin.

    A regular key/value pair has :attr:`value` set to the raw bytes (which may be
    empty) and :attr:`is_bucket` set to ``False``.  A sub-bucket has
    :attr:`value` set to ``None`` and :attr:`is_bucket` set to ``True``; its
    contents are described by :attr:`root`, :attr:`bucket_inline` and
    :attr:`bucket_offset`.  A key that does not exist is never represented by an
    :class:`Entry`, :meth:`Bbolt.entry` returns ``None`` for it.

    Entries store where they were read from.  :attr:`pgid` is the page id from
    the header holding the leaf element and :attr:`offset` is the absolute
    offset of that header in the file.  Inline bucket pages have no page id of
    their own, so :attr:`inline` is ``True``, :attr:`pgid` is ``0``,
    :attr:`offset` is the absolute offset of the embedded inline page header
    and :attr:`container_pgid` is the physical page that encloses it.  Nested
    inline pages can share one physical page, so the inline offset is what
    makes their origins distinct.
    """

    key: bytes
    """The key exactly as stored in the database."""

    value: bytes | None
    """The value bytes, or ``None`` when this entry is a sub-bucket."""

    is_bucket: bool
    """Whether this entry is a sub-bucket instead of a key/value pair."""

    pgid: int
    """Page id from the page header holding the leaf element (``0`` for inline pages)."""

    offset: int
    """Absolute file offset of the containing page header (or inline page header)."""

    container_pgid: int | None = None
    """Physical page id that contains this entry.

    For regular pages this equals :attr:`pgid`.  For inline pages it identifies
    the enclosing physical page, which is the only on-disk page id an inline
    entry can be attributed to.  Together with :attr:`inline_offset` this
    locates the entry unambiguously even when several inline pages are nested
    in the same physical page.
    """

    element_offset: int | None = None
    """Absolute file offset of the leaf element that produced this entry."""

    value_offset: int | None = None
    """Absolute file offset of the value (or bucket header) bytes."""

    value_size: int | None = None
    """Size in bytes of the value (or bucket header + inline page).

    For sub-buckets this includes the 16-byte bucket header and, when inline,
    the embedded page.  ``value_offset + value_size`` is therefore the end of
    the entry's raw value region in the file.
    """

    inline: bool = False
    """Whether the leaf element is stored in an inline bucket page."""

    root: int | None = None
    """Page id of the bucket root for sub-buckets, if it has a real page."""

    sequence: int | None = None
    """Sequence number stored in the sub-bucket header."""

    bucket_inline: bool = False
    """Whether the sub-bucket contents are stored as an inline page."""

    bucket_offset: int | None = None
    """Absolute file offset of the sub-bucket's inline page header."""

    @property
    def key_text(self) -> str:
        """Decode the key for display without merging distinct byte sequences."""
        return _decode(self.key)

    @property
    def value_text(self) -> str | None:
        """Decode the value for display, or ``None`` for a sub-bucket."""
        return None if self.value is None else _decode(self.value)

    @property
    def inline_offset(self) -> int | None:
        """Absolute inline page offset, or ``None`` for a regular page."""
        return self.offset if self.inline else None


class Bbolt:
    """bbolt database implementation.

    Keys are arbitrary byte strings.  Use :meth:`entry`, :meth:`entries`,
    :meth:`keys_raw` and :meth:`get_raw` with an exact sequence of keys when
    key identity or provenance matters.  The textual :meth:`keys` and
    :meth:`get` helpers remain available and also losslessly round-trip keys
    that are not valid UTF-8.

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

    def _resolve(self, key_path: Sequence[bytes | str]) -> Entry | None:
        """Resolve an exact sequence of raw keys without interpreting separators."""
        keys = _normalize_path(key_path)

        if not keys:
            return Entry(
                key=b"",
                value=None,
                is_bucket=True,
                pgid=self.root.pgid,
                offset=self.root.offset,
                root=self.root.pgid,
                sequence=self.meta.root.sequence,
            )

        page: Page | None = self.root
        for i, key in enumerate(keys):
            if page is None:
                return None

            inode = self._find_page_key(page, key)
            if inode is None:
                return None

            if i + 1 == len(keys):
                return self._entry(inode)

            page = self._bucket_page(inode)

        return None

    def _find_page_key(self, page: Page, key: bytes) -> InodeLeaf | None:
        """Find an exact byte key in a leaf page or in the leaves below a branch page."""
        for inode in page.inodes():
            if inode.key_raw == key:
                return inode
        return None

    def _bucket_page(self, inode: InodeLeaf) -> Page | None:
        """Return the page holding the contents of a sub-bucket inode, if any."""
        if inode.flags != BucketLeafFlag or len(inode.value) < c_bbolt.InBucket.size:
            return None

        header = c_bbolt.InBucket(inode.value)
        if header.root:
            return Page(self, header.root)

        # root == 0 means the bucket contents are either inline or the bucket is empty.
        # bbolt writes a bucket value as header + inline page whenever it has data, so
        # anything beyond the 16-byte header is an embedded page (which may itself be
        # nested inside another inline page).
        if len(inode.value) > c_bbolt.InBucket.size:
            return Page(
                self,
                0,
                inode._value_offset + c_bbolt.InBucket.size,
                inline=True,
                container_pgid=inode.page.container_pgid,
            )

        return None

    def _entry(self, inode: InodeLeaf) -> Entry:
        """Turn a leaf inode into an :class:`Entry` with its exact provenance."""
        page = inode.page
        is_bucket = inode.flags == BucketLeafFlag

        root = None
        sequence = None
        bucket_inline = False
        bucket_offset = None

        if is_bucket:
            if len(inode.value) >= c_bbolt.InBucket.size:
                header = c_bbolt.InBucket(inode.value)
                root = header.root or None
                sequence = header.sequence

            if (bucket_page := self._bucket_page(inode)) is not None:
                if bucket_page.inline:
                    bucket_inline = True
                    bucket_offset = bucket_page.offset
                else:
                    root = bucket_page.pgid

        return Entry(
            key=inode.key_raw,
            value=None if is_bucket else inode.value,
            is_bucket=is_bucket,
            pgid=page.pgid,
            offset=page.offset,
            container_pgid=page.container_pgid,
            element_offset=inode.offset,
            value_offset=inode._value_offset,
            value_size=inode.element.vsize,
            inline=page.inline,
            root=root,
            sequence=sequence,
            bucket_inline=bucket_inline,
            bucket_offset=bucket_offset,
        )

    def _entry_page(self, entry: Entry) -> Page | None:
        """Return the page described by a sub-bucket entry."""
        if entry.bucket_inline:
            return Page(self, 0, entry.bucket_offset, inline=True, container_pgid=entry.container_pgid)
        if entry.root is not None:
            return Page(self, entry.root)
        return None

    def entry(self, *key_path: bytes | str, path: Sequence[bytes | str] | bytes | str | None = None) -> Entry | None:
        """Get a single entry by an exact sequence of raw keys.

        Each argument is one key.  Alternatively, pass a list or tuple of keys
        as the single argument (or as the ``path`` keyword).  Keys are compared
        to the stored bytes as-is; no separator is interpreted, so keys
        containing spaces, NUL bytes or invalid UTF-8 can be addressed
        unambiguously.  ``str`` keys are encoded using UTF-8 with surrogate
        escapes, which allows values returned by :attr:`Entry.key_text` to be
        passed back losslessly.

        Returns ``None`` when the path does not exist.  An existing key with an
        empty value returns an entry with ``value == b""``, while a sub-bucket
        returns ``is_bucket == True`` and ``value is None``.
        """
        return self._resolve(_join_path(key_path, path))

    def entries(
        self, *key_path: bytes | str, path: Sequence[bytes | str] | bytes | str | None = None
    ) -> list[Entry] | None:
        """List all entries in a bucket addressed by an exact sequence of raw keys.

        Returns ``None`` when the bucket does not exist or the path points at a
        key/value pair.  An existing but empty bucket returns an empty list.
        """
        key_path = _join_path(key_path, path)
        if key_path:
            entry = self._resolve(key_path)
            if entry is None or not entry.is_bucket:
                return None

            page = self._entry_page(entry)
            if page is None:
                return []
        else:
            page = self.root

        return [self._entry(inode) for inode in page.inodes()]

    def keys_raw(
        self, *key_path: bytes | str, path: Sequence[bytes | str] | bytes | str | None = None
    ) -> list[bytes] | None:
        """Get the raw key bytes in a bucket addressed by a sequence of raw keys."""
        entries = self.entries(*key_path, path=path)
        if entries is None:
            return None
        return [entry.key for entry in entries]

    def get_raw(self, *key_path: bytes | str, path: Sequence[bytes | str] | bytes | str | None = None) -> bytes | None:
        """Get a raw value by an exact sequence of raw keys.

        An empty value is returned as ``b""`` and is therefore distinct from a
        missing key, which returns ``None``.  A sub-bucket also returns ``None``;
        use :meth:`entry` when the difference between a bucket and a missing
        key is relevant.
        """
        entry = self._resolve(_join_path(key_path, path))
        if entry is None or entry.is_bucket:
            return None
        return entry.value

    def _split_path(self, path: str | None, sep: str) -> tuple[bytes, ...]:
        """Split a legacy display path, encoding each part losslessly."""
        if not path or path == sep:
            return ()
        return tuple(_encode(part) for part in path.split(sep))

    def _legacy_or_raw_path(self, path: str | bytes | Sequence[bytes | str] | None, sep: str) -> tuple[bytes, ...]:
        """Interpret a path for the convenience interface.

        ``str``/``None`` keep the historic separator behaviour.  A ``bytes``
        key or a sequence of keys is treated as an exact raw path, so callers
        can use the familiar methods without the separator being involved.
        """
        if path is None or isinstance(path, str):
            return self._split_path(path, sep)
        return _normalize_path(path)

    def keys(self, path: str | bytes | Sequence[bytes | str] | None = None, *, sep: str = " ") -> list[str] | None:
        """Get a list of key names from the given path.

        This is the textual convenience interface.  ``path`` may be a string
        using ``sep`` between bucket names, or an exact raw key sequence (a
        ``bytes`` key or a list/tuple of keys).  Keys are decoded with surrogate
        escapes so invalid UTF-8 round-trips instead of raising or colliding.
        Use :meth:`keys_raw` when key identity must be byte-exact.
        """
        entries = self.entries(*self._legacy_or_raw_path(path, sep))
        if entries is None:
            return None
        return [entry.key_text for entry in entries]

    def get(
        self,
        path: str | bytes | Sequence[bytes | str] | None,
        *,
        sep: str = " ",
        decode: bool = True,
    ) -> str | bytes | None:
        """Get a key value from the given path.

        This is the textual convenience interface.  ``path`` may be a string
        using ``sep`` between bucket names, or an exact raw key sequence (a
        ``bytes`` key or a list/tuple of keys).  An empty value is returned as
        ``""`` or ``b""`` instead of being confused with a missing key, and
        sub-buckets return ``None``.  Use :meth:`entry` or :meth:`get_raw` for
        byte-exact access.
        """
        parts = self._legacy_or_raw_path(path, sep)
        if not parts:
            return None

        entry = self._resolve(parts)
        if entry is None or entry.is_bucket:
            return None
        return entry.value_text if decode else entry.value


class Page:
    """Represents a bbolt page (meta, freelist, branch or leaf)."""

    def __init__(
        self,
        db: Bbolt,
        pgid: int,
        offset: int | None = None,
        *,
        inline: bool = False,
        container_pgid: int | None = None,
    ) -> None:
        self.db = db
        self.pgid = pgid
        self.inline = inline
        # Inline pages have no page id of their own; remember the physical page
        # that holds them so provenance is not lost.
        self.container_pgid = container_pgid if inline and container_pgid is not None else pgid

        self.offset = pgid * db.page_size if offset is None else offset
        db.fh.seek(self.offset)
        self.page = c_bbolt.Page(db.fh)

        self.flags = self.page.flags
        self.count = self.page.count
        self.overflow = self.page.overflow

        if self.flags == PageFlag.Leaf and self.count:
            self.key = self.inode(0).key_text
        else:
            self.key = None

    def __repr__(self) -> str:
        return f"<Page offset=0x{self.offset:x} pgid={self.pgid} container_pgid={self.container_pgid} inline={self.inline} flags={self.flags} count={self.count} overflow={self.overflow} key={self.key}>"  # noqa: E501

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

        page.db.fh.seek(offset + element.pos)

        # Keep the raw bytes for exact comparisons.  The textual attribute is
        # decoded with surrogate escapes, so non-UTF-8 keys stay distinct
        # instead of raising or being merged by replacement characters.
        self.key_raw = page.db.fh.read(element.ksize)
        self.key = _decode(self.key_raw)

    @property
    def key_text(self) -> str:
        """The key decoded without losing bytes (alias of :attr:`key`)."""
        return self.key

    def __repr__(self) -> str:
        return f"<Inode type=generic key={self.key_raw!r}>"


class InodeLeaf(Inode):
    """Represents a bbolt Inode leaf element."""

    def __init__(self, page: Page, structure: c_bbolt.leafPageElement, offset: int) -> None:
        super().__init__(page, structure, offset)

        self.flags = self.element.flags
        self._value_offset = page.db.fh.tell()
        self.value = page.db.fh.read(self.element.vsize)

    def __repr__(self) -> str:
        return f"<Inode type=leaf flags={self.flags} key={self.key_raw!r} value={self.value!r}>"


class InodeBranch(Inode):
    """Represents a bbolt Inode branch element."""

    def __init__(self, page: Page, structure: c_bbolt.branchPageElement, offset: int) -> None:
        super().__init__(page, structure, offset)

        self.pgid = self.element.pgid

    def __repr__(self) -> str:
        return f"<Inode type=branch pgid={self.pgid} (first)key={self.key_raw!r}>"
