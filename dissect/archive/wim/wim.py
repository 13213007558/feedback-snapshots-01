from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, BufferedStream, RelativeStream
from dissect.util.ts import wintimestamp

from dissect.archive.exception import (
    EmptySecurityDescriptorError,
    FileNotFoundError,
    InvalidDirectoryEntryError,
    InvalidHeaderError,
    InvalidSecurityDataError,
    NotADirectoryError,
    NotAReparsePointError,
    SecurityIdOutOfRangeError,
)
from dissect.archive.wim.c_wim import (
    DECOMPRESSOR_MAP,
    FILE_ATTRIBUTE,
    HEADER_FLAG,
    IO_REPARSE_TAG,
    RESHDR_FLAG,
    SYMLINK_FLAG,
    WIM_IMAGE_TAG,
    c_wim,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from datetime import datetime

DEFAULT_CHUNK_SIZE = 32 * 1024

# SecurityId 0xffffffff means that a directory entry has no security descriptor.
SECURITY_ID_NONE = 0xFFFFFFFF
# Size of the fixed part of a directory entry, excluding the variable name fields.
DIRECTORY_ENTRY_MIN_SIZE = len(c_wim._DIRENTRY)


class WIM:
    """Windows Imaging Format implementation.

    Supports reading resources and browsing images from WIM files.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_wim.WIMHEADER_V1_PACKED(fh)

        if self.header.ImageTag != WIM_IMAGE_TAG:
            raise InvalidHeaderError(f"Expected MSWIM header, got: {self.header.ImageTag!r}")

        if self.header.Version != c_wim.VERSION_DEFAULT:
            raise NotImplementedError(f"Only WIM version {c_wim.VERSION_DEFAULT:#x} is supported right now")

        if self.header.Flags & HEADER_FLAG.SPANNED:
            raise NotImplementedError("Spanned WIM files are not yet supported")

        self._resource_table, self._images = self._read_resource_table()

    def _read_resource_table(self) -> tuple[dict[bytes, Resource], list[Resource]]:
        # Read the resource table in one go and separate images out
        # If this turns out to be slow for large WIM files, we can add some clever caching
        table = {}
        images = []
        with Resource.from_short_header(self, self.header.OffsetTable).open() as fh:
            for _ in range(fh.size // len(c_wim._RESHDR_DISK)):
                resource = Resource.from_header(self, c_wim._RESHDR_DISK(fh))
                table[resource.hash] = resource

                if resource.is_metadata:
                    images.append(resource)

        return table, images

    @property
    def resources(self) -> dict[bytes, Resource]:
        """Return the table of resources in the WIM file."""
        return self._resource_table

    def images(self) -> Iterator[Image]:
        """Iterate over all images in the WIM file."""
        for resource in self._images:
            yield Image(self, resource.open(), resource)


class Resource:
    __slots__ = (
        "flags",
        "hash",
        "offset",
        "original_size",
        "part_number",
        "reference_count",
        "size",
        "wim",
    )

    def __init__(
        self,
        wim: WIM,
        size: int,
        flags: RESHDR_FLAG,
        offset: int,
        original_size: int,
        part_number: int | None = None,
        reference_count: int | None = None,
        hash: bytes | None = None,
    ):
        self.wim = wim
        self.size = size
        self.flags = flags
        self.offset = offset
        self.original_size = original_size

        self.part_number = part_number
        self.reference_count = reference_count
        self.hash = hash

    @classmethod
    def from_short_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK_SHORT) -> Resource:
        return cls(
            wim,
            int.from_bytes(reshdr.Size, "little"),
            reshdr.Flags,
            reshdr.Offset,
            reshdr.OriginalSize,
        )

    @classmethod
    def from_header(cls, wim: WIM, reshdr: c_wim.RESHDR_DISK) -> Resource:
        obj = cls.from_short_header(wim, reshdr.Base)
        obj.part_number = reshdr.PartNumber
        obj.reference_count = reshdr.RefCount
        obj.hash = reshdr.Hash
        return obj

    @property
    def is_metadata(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.METADATA)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.COMPRESSED)

    @property
    def is_spanned(self) -> bool:
        return bool(self.flags & RESHDR_FLAG.SPANNED)

    def open(self) -> BinaryIO:
        if self.is_spanned:
            raise NotImplementedError("Spanned resources are not yet supported")

        if self.is_compressed:
            compression_flags = self.wim.header.Flags & 0xFFFF0000
            decompressor = DECOMPRESSOR_MAP.get(compression_flags)
            if decompressor is None:
                raise NotImplementedError(f"Compression algorithm not yet supported: {compression_flags}")
            return CompressedStream(
                self.wim.fh, self.offset, self.size, self.original_size, decompressor, self.wim.header.CompressionSize
            )

        return RelativeStream(self.wim.fh, self.offset, self.size)


class Image:
    def __init__(self, wim: WIM, fh: BinaryIO, resource: Resource | None = None):
        self.wim = wim
        self.resource = resource
        self.metadata = fh
        self.security = SecurityBlock(fh)

        offset = fh.tell()
        fh.seek(offset + (-offset & 7))
        self.root = DirectoryEntry(self, fh)

    def __repr__(self) -> str:
        return "<Image>"

    def get(self, path: str, entry: DirectoryEntry | None = None) -> DirectoryEntry:
        # Programmatically we will often use the `/` separator, so replace it with the native path separator of NTFS
        # `/` is an illegal character in NTFS filenames, so it's safe to replace
        search_path = path.replace("/", "\\")

        parts = search_path.split("\\")
        entry = entry or self.root
        prev_entry = None

        for part in parts:
            if not part or part == ".":
                continue

            if part == "..":
                entry = prev_entry or self.root
                continue

            while entry.is_symlink():
                entry = self.get(entry.readlink(), prev_entry)

            # Traverse to the target path from our root node
            for subentry in entry.iterdir():
                if subentry.name == part:
                    prev_entry = entry
                    entry = subentry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return entry


class SecurityBlock:
    """Security data of an image.

    The security data starts with a header containing the number of security
    descriptor slots and the size of each slot. The descriptor data directly
    follows the header, without per-entry padding. Slot ``0`` is a valid index;
    it is not a "no security descriptor" marker.

    Every slot is kept in :attr:`entries` and :attr:`descriptors`, including
    zero-length slots. This preserves the SecurityId index space used by
    directory entries, so a later descriptor is never shifted to an earlier
    index by an empty slot.

    Args:
        fh: A file-like object positioned at the start of the security data.

    Attributes:
        offset: Offset of the security data relative to the metadata stream.
        header: The on-disk security data header.
        entries: Index preserving list of :class:`SecurityEntry` objects.
        entry_lengths: The raw per-slot lengths from the table header.
        descriptors: Index preserving list of raw descriptor bytes. Entries
            without descriptor data are ``None``.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.offset = fh.tell()

        raw_header = fh.read(8)
        if len(raw_header) != 8:
            raise InvalidSecurityDataError(
                f"Truncated security data header at offset {self.offset}: expected 8 bytes, got {len(raw_header)}"
            )

        total_length, num_entries = struct.unpack("<II", raw_header)
        header_length = 8 + (num_entries * 8)
        if total_length < header_length:
            raise InvalidSecurityDataError(
                f"Security data at offset {self.offset} declares {num_entries} entries, "
                f"requiring {header_length} bytes of header, but total length is {total_length}"
            )

        raw_lengths = fh.read(num_entries * 8)
        if len(raw_lengths) != num_entries * 8:
            raise InvalidSecurityDataError(
                f"Truncated security data entry length array at offset {self.offset + 8}: "
                f"expected {num_entries * 8} bytes, got {len(raw_lengths)}"
            )

        self.header = c_wim._SECURITYBLOCK_DISK(raw_header + raw_lengths)
        self.entry_lengths = struct.unpack(f"<{num_entries}Q", raw_lengths)

        payload_length = total_length - header_length
        table_length = sum(self.entry_lengths)
        if table_length != payload_length:
            raise InvalidSecurityDataError(
                f"Security data at offset {self.offset} has inconsistent table end: "
                f"entry lengths sum to {table_length} bytes after the header, "
                f"but total length leaves {payload_length} bytes"
            )

        entries = []
        entry_offset = header_length
        for index, size in enumerate(self.entry_lengths):
            if size % 4:
                raise InvalidSecurityDataError(
                    f"Security descriptor {index} at offset {self.offset + entry_offset} is not 4-byte aligned: "
                    f"{size} bytes"
                )

            data = fh.read(size) if size else None
            if size and len(data) != size:
                raise InvalidSecurityDataError(
                    f"Truncated security descriptor {index} at offset {self.offset + entry_offset}: "
                    f"expected {size} bytes, got {len(data)}"
                )

            entries.append(SecurityEntry(index=index, offset=entry_offset, length=size, data=data))
            entry_offset += size

        self.entries = entries
        self.descriptors = [entry.data for entry in entries]

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[SecurityEntry]:
        return iter(self.entries)

    def __getitem__(self, index: int | slice) -> SecurityEntry | list[SecurityEntry]:
        """Return the security entry or entries at ``index``, including empty slots."""
        return self.entries[index]

    def resolve(self, security_id: int) -> SecurityEntry | None:
        """Resolve a directory entry SecurityId to its security table slot.

        Args:
            security_id: The SecurityId from a directory entry.

        Returns:
            The matching :class:`SecurityEntry` (which may be an empty
            placeholder, check :attr:`SecurityEntry.is_empty`), or ``None`` if
            the directory entry has no security descriptor (SecurityId
            ``0xffffffff``).

        Raises:
            SecurityIdOutOfRangeError: If the SecurityId is not in the table.
        """
        if security_id == SECURITY_ID_NONE:
            return None

        if security_id >= len(self.entries):
            raise SecurityIdOutOfRangeError(security_id, len(self.entries))

        return self.entries[security_id]

    def descriptor(self, security_id: int) -> bytes | None:
        """Return the raw security descriptor bytes for a directory entry SecurityId.

        Returns ``None`` if the directory entry has no security descriptor.

        Raises:
            SecurityIdOutOfRangeError: If the SecurityId is not in the table.
            EmptySecurityDescriptorError: If the SecurityId refers to an empty
                placeholder slot, which has no descriptor bytes to return.
        """
        entry = self.resolve(security_id)
        if entry is None:
            return None

        if entry.is_empty:
            raise EmptySecurityDescriptorError(security_id, self.offset + entry.offset)

        return entry.data

    @property
    def end_offset(self) -> int:
        """Return the metadata stream offset just past the security data."""
        return self.offset + self.header.TotalLength


@dataclass(frozen=True)
class SecurityEntry:
    """One slot in an image security table.

    Attributes:
        index: The SecurityId index of this slot.
        offset: Offset of the slot data relative to the start of the security block.
        length: Length of the slot in bytes. Zero means an empty placeholder slot.
        data: Raw self-relative security descriptor bytes, or ``None`` for an
            empty placeholder.
    """

    index: int
    offset: int
    length: int
    data: bytes | None

    @property
    def is_empty(self) -> bool:
        """Return whether this slot is an empty placeholder."""
        return self.length == 0

    @property
    def descriptor(self) -> bytes | None:
        """Return the raw security descriptor bytes of this slot."""
        return self.data


class DirectoryEntry:
    def __init__(self, image: Image, fh: BinaryIO):
        self.image = image
        self.fh = fh

        start = fh.tell()
        try:
            self.entry = c_wim._DIRENTRY(fh)
        except EOFError as e:
            raise InvalidDirectoryEntryError(f"Truncated directory entry header at offset {start}") from e

        self.name = None
        self.short_name = None
        self.extra = None

        self._validate_header(start)

        if length := self.entry.FileNameLength:
            self.name = _read_name(fh, length, start)
            fh.read(2)

        if length := self.entry.ShortNameLength:
            self.short_name = _read_name(fh, length, start)
            fh.read(2)

        # If there's any trailing data after the aligned end, read it and store it
        end = fh.tell()
        consumed = end - start
        if consumed > self.entry.Length:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} declares length {self.entry.Length}, "
                f"but its name fields consume {consumed} bytes"
            )

        if length := self.entry.Length - consumed:
            self.extra = fh.read(length)
            if len(self.extra) != length:
                raise InvalidDirectoryEntryError(
                    f"Truncated directory entry at offset {start}: expected {length} trailing bytes, "
                    f"got {len(self.extra)}"
                )
        else:
            # Keep the parse position inside the entry even when no trailing
            # data was declared; streams may still start at the next boundary.
            fh.seek(start + self.entry.Length)

        self.streams = {}
        if self.entry.Streams:
            for index in range(self.entry.Streams):
                # Stream entries are 8 byte aligned
                stream_start = (fh.tell() + 7) & (-8)
                fh.seek(stream_start)

                try:
                    stream = c_wim._STREAMENTRY(fh)
                except EOFError as e:
                    raise InvalidDirectoryEntryError(
                        f"Truncated stream entry {index} at offset {stream_start}"
                    ) from e

                if stream.Length < len(c_wim._STREAMENTRY):
                    raise InvalidDirectoryEntryError(
                        f"Stream entry {index} at offset {stream_start} declares invalid length {stream.Length}"
                    )

                name = ""
                name_length = stream.StreamNameLength
                if name_length:
                    name = _read_name(fh, name_length, stream_start)
                    name_length += 2
                    fh.read(2)

                self.streams[name] = stream.Hash

                if remaining := stream.Length - len(c_wim._STREAMENTRY) - name_length:
                    fh.read(remaining)

                stream_end = stream_start + stream.Length
                if fh.tell() != stream_end:
                    raise InvalidDirectoryEntryError(
                        f"Stream entry {index} at offset {stream_start} declares length {stream.Length}, "
                        f"but parsing ended at offset {fh.tell()}"
                    )
        else:
            # Add the entry hash as the default stream
            self.streams[""] = self.entry.Hash

    def _validate_header(self, start: int) -> None:
        length = self.entry.Length
        if length < DIRECTORY_ENTRY_MIN_SIZE:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} has invalid length {length} "
                f"(minimum {DIRECTORY_ENTRY_MIN_SIZE})"
            )

        if length % 8:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} has unaligned length {length} (must be a multiple of 8)"
            )

        header_size = DIRECTORY_ENTRY_MIN_SIZE
        remaining = _stream_remaining(self.fh)
        if remaining is not None and length - header_size > remaining:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} declares length {length}, "
                f"but only {header_size + remaining} bytes are available"
            )

        if self.entry.FileNameLength % 2:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} has odd file name length {self.entry.FileNameLength}"
            )
        if self.entry.ShortNameLength % 2:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} has odd short name length {self.entry.ShortNameLength}"
            )

        name_size = 0
        if self.entry.FileNameLength:
            name_size += self.entry.FileNameLength + 2
        if self.entry.ShortNameLength:
            name_size += self.entry.ShortNameLength + 2

        if header_size + name_size > length:
            raise InvalidDirectoryEntryError(
                f"Directory entry at offset {start} declares length {length}, "
                f"but its name fields require at least {header_size + name_size} bytes"
            )

    @property
    def security_id(self) -> int:
        """Return the raw SecurityId of this directory entry.

        ``0xffffffff`` means the entry has no security descriptor. Any other
        value is an index into this image's own security table.
        """
        return self.entry.SecurityId

    @property
    def security_entry(self) -> SecurityEntry | None:
        """Return this entry's security table slot, or ``None`` if it has no descriptor.

        An empty placeholder slot is returned as-is; check
        :attr:`SecurityEntry.is_empty` before using it as a descriptor.

        Raises:
            SecurityIdOutOfRangeError: If the SecurityId is not in this image's table.
        """
        return self.image.security.resolve(self.entry.SecurityId)

    @property
    def security_descriptor(self) -> bytes | None:
        """Return the raw security descriptor bytes for this entry, if it has one."""
        return self.image.security.descriptor(self.entry.SecurityId)

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name!r}>"

    def is_dir(self) -> bool:
        """Return whether this entry is a directory."""
        return (
            self.entry.Attributes & (FILE_ATTRIBUTE.DIRECTORY | FILE_ATTRIBUTE.REPARSE_POINT)
            == FILE_ATTRIBUTE.DIRECTORY
        )

    def is_file(self) -> bool:
        """Return whether this entry is a regular file."""
        return not self.is_dir()

    def is_reparse_point(self) -> bool:
        """Return whether this entry is a reparse point."""
        return bool(self.entry.Attributes & FILE_ATTRIBUTE.REPARSE_POINT)

    def is_symlink(self) -> bool:
        """Return whether this entry is a symlink reparse point."""
        return self.is_reparse_point() and self.entry.ReparseTag == IO_REPARSE_TAG.SYMLINK

    def is_mount_point(self) -> bool:
        """Return whether this entry is a mount point reparse point."""
        return self.is_reparse_point() and self.entry.ReparseTag == IO_REPARSE_TAG.MOUNT_POINT

    @cached_property
    def reparse_point(self) -> ReparsePoint:
        """Return parsed reparse point data if this directory entry is a reparse point."""
        if not self.is_reparse_point():
            raise NotAReparsePointError(f"{self} is not a reparse point")

        return ReparsePoint(self.entry.ReparseTag, self.open())

    def readlink(self) -> str:
        return self.reparse_point.substitute_name

    def size(self, name: str = "") -> int:
        """Return the entry size."""
        with self.open(name) as fh:
            return fh.size

    @cached_property
    def creation_time(self) -> datetime:
        """Return the creation time."""
        return wintimestamp(self.entry.CreationTime)

    @cached_property
    def creation_time_ns(self) -> int:
        """Return the creation time in nanoseconds."""
        return _ts_to_ns(self.entry.CreationTime)

    @cached_property
    def last_access_time(self) -> datetime:
        """Return the last access time."""
        return wintimestamp(self.entry.LastAccessTime)

    @cached_property
    def last_access_time_ns(self) -> int:
        """Return the last access time in nanoseconds."""
        return _ts_to_ns(self.entry.LastAccessTime)

    @cached_property
    def last_write_time(self) -> datetime:
        """Return the last write time."""
        return wintimestamp(self.entry.LastWriteTime)

    @property
    def last_write_time_ns(self) -> int:
        """Return the last write time in nanoseconds."""
        return _ts_to_ns(self.entry.LastWriteTime)

    def listdir(self) -> dict[str, DirectoryEntry]:
        """Return a directory listing."""
        return {entry.name: entry for entry in self.iterdir()}

    def iterdir(self) -> Iterator[DirectoryEntry]:
        """Iterate directory contents."""
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        fh = self.fh
        list_start = self.entry.SubdirOffset
        fh.seek(list_start)
        while True:
            entry_start = fh.tell()
            raw_length = fh.read(8)
            if len(raw_length) != 8:
                raise InvalidDirectoryEntryError(
                    f"Truncated directory listing at offset {entry_start}: "
                    "expected an entry length or list terminator"
                )

            length = int.from_bytes(raw_length, "little")
            if length == 0:
                # A zero length terminates the directory listing
                break
            if length < DIRECTORY_ENTRY_MIN_SIZE:
                raise InvalidDirectoryEntryError(
                    f"Invalid directory entry length {length} at offset {entry_start} "
                    f"(minimum {DIRECTORY_ENTRY_MIN_SIZE})"
                )

            fh.seek(entry_start)
            entry = DirectoryEntry(self.image, fh)
            offset = fh.tell()

            yield entry

            # Align to the next 8 byte boundary
            fh.seek((offset + 7) & (-8))

    def open(self, name: str = "") -> BinaryIO:
        """Return a file-like object for the contents of this directory entry.

        Args:
            name: Optional alternate stream name to open.
        """
        stream_hash = self.streams.get(name)
        if stream_hash is None:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r}")

        if stream_hash.strip(b"\x00") == b"":
            return BufferedStream(io.BytesIO(b""), size=0)

        if resource := self.image.wim.resources.get(stream_hash):
            return resource.open()

        raise FileNotFoundError(f"Unable to find resource for directory entry {self}")


class ReparsePoint:
    """Utility class for parsing reparse point buffers.

    Args:
        tag: The type of reparse point to parse.
        fh: A file-like object of the reparse point buffer.
    """

    def __init__(self, tag: IO_REPARSE_TAG, fh: BinaryIO):
        self.tag = tag
        self.info = None

        if tag == IO_REPARSE_TAG.MOUNT_POINT:
            self.info = c_wim._MOUNT_POINT_REPARSE_BUFFER(fh)
        elif tag == IO_REPARSE_TAG.SYMLINK:
            self.info = c_wim._SYMBOLIC_LINK_REPARSE_BUFFER(fh)

        self._buf = fh.read()

    @property
    def substitute_name(self) -> str | None:
        if not self.info:
            return None

        offset = self.info.SubstituteNameOffset
        length = self.info.SubstituteNameLength
        return self._buf[offset : offset + length].decode("utf-16-le")

    @property
    def print_name(self) -> str | None:
        if not self.info:
            return None

        offset = self.info.PrintNameOffset
        length = self.info.PrintNameLength
        return self._buf[offset : offset + length].decode("utf-16-le")

    @property
    def absolute(self) -> bool:
        if self.tag != IO_REPARSE_TAG.SYMLINK:
            return True

        return self.info.Flags == SYMLINK_FLAG.ABSOLUTE

    @property
    def relative(self) -> bool:
        if self.tag != IO_REPARSE_TAG.SYMLINK:
            return False

        return self.info.Flags == SYMLINK_FLAG.RELATIVE


class CompressedStream(AlignedStream):
    def __init__(
        self,
        fh: BinaryIO,
        offset: int,
        compressed_size: int,
        original_size: int,
        decompressor: Callable[[bytes], bytes],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        self.fh = fh
        self.offset = offset
        self.compressed_size = compressed_size
        self.original_size = original_size
        self.decompressor = decompressor
        self.chunk_size = chunk_size

        # Read the chunk table in advance
        fh.seek(self.offset)
        num_chunks = (original_size + self.chunk_size - 1) // self.chunk_size - 1
        if num_chunks == 0:
            self._chunks = (0,)
        else:
            entry_size = "Q" if original_size > 0xFFFFFFFF else "I"
            pattern = f"<{num_chunks}{entry_size}"
            self._chunks = (0, *struct.unpack(pattern, fh.read(struct.calcsize(pattern))))

        self._data_offset = fh.tell()

        self._read_chunk = lru_cache(32)(self._read_chunk)
        super().__init__(self.original_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        num_chunks = len(self._chunks)
        chunk, offset_in_chunk = divmod(offset, self.chunk_size)

        while length:
            if chunk >= num_chunks:
                # We somehow requested more data than we have runs for
                break

            chunk_offset = self._chunks[chunk]
            if chunk < num_chunks - 1:
                next_chunk_offset = self._chunks[chunk + 1]
                chunk_remaining = self.chunk_size - offset_in_chunk
            else:
                next_chunk_offset = self.compressed_size
                chunk_remaining = (self.original_size - (chunk * self.chunk_size)) - offset_in_chunk

            read_length = min(chunk_remaining, length)

            buf = self._read_chunk(chunk_offset, next_chunk_offset - chunk_offset)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_length])

            length -= read_length
            offset += read_length
            chunk += 1

        return b"".join(result)

    def _read_chunk(self, offset: int, size: int) -> bytes:
        self.fh.seek(self._data_offset + offset)
        buf = self.fh.read(size)
        return self.decompressor(buf)


def _stream_remaining(fh: BinaryIO) -> int | None:
    """Return the number of unread bytes in ``fh`` if its size is known."""
    size = getattr(fh, "size", None)
    if not isinstance(size, int):
        return None

    try:
        offset = fh.tell()
    except (AttributeError, OSError):
        return None

    return max(size - offset, 0)


def _ts_to_ns(ts: int) -> int:
    """Convert Windows timestamps to nanosecond timestamps."""
    return (ts * 100) - 11644473600000000000


def _read_name(fh: BinaryIO, length: int, offset: int) -> str:
    data = fh.read(length)
    if len(data) != length:
        raise InvalidDirectoryEntryError(
            f"Truncated name at offset {offset}: expected {length} bytes, got {len(data)}"
        )

    try:
        return data.decode("utf-16-le")
    except UnicodeDecodeError as e:
        raise InvalidDirectoryEntryError(f"Invalid UTF-16 name at offset {offset}: {e}") from e
