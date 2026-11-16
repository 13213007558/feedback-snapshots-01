"""SquashFS extended attribute records and value provenance."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import XattrError

if TYPE_CHECKING:
    from collections.abc import Iterator

XATTR_NAME_MAX = 255
XATTR_SIZE_MAX = 65536
XATTR_REF_BLOCK_SHIFT = 16
XATTR_REF_OFFSET_MASK = 0xFFFF

XATTR_PREFIXES = {
    c_squashfs.SQUASHFS_XATTR_USER: "user",
    c_squashfs.SQUASHFS_XATTR_TRUSTED: "trusted",
    c_squashfs.SQUASHFS_XATTR_SECURITY: "security",
}


@dataclass(frozen=True)
class XattrSource:
    """Location of an xattr name/value in the SquashFS xattr metadata table.

    References use the SquashFS ``(block << 16) | offset`` encoding, where ``block`` is a
    byte offset relative to the start of the xattr table and ``offset`` is an offset in the
    decompressed metadata block.

    Args:
        xattr_id: Index of the xattr ID that references this attribute.
        entry_ref: Reference to the ``squashfs_xattr_entry`` header.
        value_ref: Reference to the value payload itself. For out-of-line values this is
            the location of the shared ``squashfs_xattr_val``.
        value_size: Size of the resolved value in bytes.
        out_of_line: Whether the value was stored in the shared out-of-line value area.
        ool_ref: Raw out-of-line reference from the attribute, if any.
    """

    xattr_id: int | None = None
    entry_ref: int | None = None
    value_ref: int | None = None
    value_size: int | None = None
    out_of_line: bool = False
    ool_ref: int | None = None


@dataclass(frozen=True)
class Xattr:
    """A decoded SquashFS extended attribute.

    Args:
        name: Full xattr name, including the namespace prefix (for example
            ``security.capability``).
        value: Complete, resolved value bytes.
        type: Raw type field from ``squashfs_xattr_entry``.
        prefix: Namespace prefix (``type & SQUASHFS_XATTR_PREFIX_MASK``).
        suffix: Name as stored on disk, without the namespace prefix.
        source: Location and storage form of the attribute and its value.
    """

    name: str
    value: bytes
    type: int
    prefix: int
    suffix: str
    source: XattrSource

    @property
    def raw(self) -> bytes:
        """The complete stored value."""
        return self.value

    @property
    def value_source(self) -> XattrSource:
        """Alias for :attr:`source`, describing where the value bytes came from."""
        return self.source

    @property
    def out_of_line(self) -> bool:
        """Whether the value was stored in the shared out-of-line value area."""
        return self.source.out_of_line


# Common alternative capitalisation for callers that prefer XAttr.
XAttr = Xattr


def decode_xattr_entry(
    entry_type: int,
    suffix: bytes,
    value: bytes,
    *,
    xattr_id: int | None = None,
    entry_ref: int | None = None,
    value_ref: int | None = None,
    ool_ref: int | None = None,
) -> Xattr:
    """Build an :class:`Xattr` from the fields of an on-disk xattr entry."""
    prefix = entry_type & c_squashfs.SQUASHFS_XATTR_PREFIX_MASK
    out_of_line = bool(entry_type & c_squashfs.SQUASHFS_XATTR_VALUE_OOL)

    try:
        suffix_text = suffix.decode("utf-8", errors="surrogateescape")
    except Exception as e:  # pragma: no cover - surrogateescape should not fail
        raise XattrError(f"invalid xattr name: {suffix!r}") from e

    namespace = XATTR_PREFIXES.get(prefix)
    name = f"{namespace}.{suffix_text}" if namespace is not None else f"<prefix:{prefix}>.{suffix_text}"

    return Xattr(
        name=name,
        value=value,
        type=entry_type,
        prefix=prefix,
        suffix=suffix_text,
        source=XattrSource(
            xattr_id=xattr_id,
            entry_ref=entry_ref,
            value_ref=value_ref,
            value_size=len(value),
            out_of_line=out_of_line,
            ool_ref=ool_ref,
        ),
    )


def iter_xattr_records(data: bytes) -> Iterator[tuple[int, bytes, bytes]]:
    """Yield ``(type, name_suffix, value)`` records from a raw xattr value stream.

    This helper is primarily useful for tests or for callers that already have an xattr
    value in memory. It performs no metadata-block walking and treats out-of-line
    references as ordinary values.

    Raises:
        XattrError: If the stream is truncated or contains an invalid record.
    """
    pos = 0
    size = len(data)
    while pos < size:
        if size - pos < 4:
            raise XattrError(f"truncated xattr entry header at offset {pos}")
        entry_type, name_size = struct.unpack_from("<HH", data, pos)
        pos += 4

        if name_size > XATTR_NAME_MAX + 1 or pos + name_size > size:
            raise XattrError(f"invalid xattr name size {name_size} at offset {pos - 4}")
        name = data[pos : pos + name_size]
        pos += name_size

        if size - pos < 4:
            raise XattrError(f"truncated xattr value header at offset {pos}")
        value_size = struct.unpack_from("<I", data, pos)[0]
        pos += 4

        if value_size > XATTR_SIZE_MAX or pos + value_size > size:
            raise XattrError(f"invalid xattr value size {value_size} at offset {pos - 4}")
        value = data[pos : pos + value_size]
        pos += value_size

        yield entry_type, name, value
