from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass
from enum import Enum
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.archive.exception import (
    AmbiguousResourceError,
    FileNotFoundError,
    InvalidHeaderError,
    NotADirectoryError,
    NotAReparsePointError,
    NotFileContentError,
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
from dissect.util.stream import AlignedStream, BufferedStream, RelativeStream
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from datetime import datetime

DEFAULT_CHUNK_SIZE = 32 * 1024

EMPTY_HASH = hashlib.sha1(b"").digest()
"""SHA-1 digest WIM uses for empty content, which does not need a resource table row."""

VERIFY_CHUNK_SIZE = 1024 * 1024


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

        self._resource_table, self._images, self._resource_entries = self._read_resource_table()
        self._image_list: list[Image] | None = None
        self._descriptors_by_hash: dict[bytes, list[Resource]] = {}
        for resource in self._resource_entries:
            self._descriptors_by_hash.setdefault(bytes(resource.hash), []).append(resource)
        self._verification_cache: dict[tuple[int, int, bool], ResourceVerification] = {}
        self._fh_size: int | None = None

    def _read_resource_table(self) -> tuple[dict[bytes, Resource], list[Resource], list[Resource]]:
        # Read the resource table in one go and separate images out
        # If this turns out to be slow for large WIM files, we can add some clever caching
        table = {}
        images = []
        entries = []
        with Resource.from_short_header(self, self.header.OffsetTable).open() as fh:
            for _ in range(fh.size // len(c_wim._RESHDR_DISK)):
                resource = Resource.from_header(self, c_wim._RESHDR_DISK(fh))
                resource.index = len(entries)
                entries.append(resource)
                table[resource.hash] = resource

                if resource.is_metadata:
                    images.append(resource)

        return table, images, entries

    @property
    def resources(self) -> dict[bytes, Resource]:
        """Return the table of resources in the WIM file.

        The table is keyed by hash for backwards compatibility. When a hash has more than one resource
        descriptor, the last one wins here; use :attr:`resource_entries` or :meth:`resource_descriptors`
        to retain every row.
        """
        return self._resource_table

    @property
    def resource_entries(self) -> list[Resource]:
        """Return every resource table entry in on-disk order, including duplicate hashes."""
        return self._resource_entries

    @cached_property
    def _reference_index(self) -> dict[bytes, list[ResourceReference]]:
        index: dict[bytes, list[ResourceReference]] = {}
        for image_index, image in enumerate(self._all_images()):
            for path, entry in _iter_entries(image):
                if entry.is_dir():
                    # Directory metadata has its own resource; it is not file content.
                    continue

                for stream_name, stream_hash in entry.streams.items():
                    digest = bytes(stream_hash)
                    references = tuple(self._descriptors_by_hash.get(digest, ()))

                    if _is_empty_hash(digest):
                        status = ReferenceStatus.EMPTY
                    elif not references:
                        status = ReferenceStatus.MISSING
                    elif not any(not resource.is_metadata for resource in references):
                        status = ReferenceStatus.METADATA
                    else:
                        status = ReferenceStatus.RESOLVED

                    reference = ResourceReference(
                        image=image,
                        image_index=image_index,
                        path=path,
                        entry=entry,
                        entry_offset=entry.offset,
                        stream_name=stream_name,
                        stream_kind=StreamKind.DEFAULT if not stream_name else StreamKind.ADS,
                        hash=digest,
                        status=status,
                        resources=references,
                        resource_indices=tuple(resource.index for resource in references),
                    )
                    index.setdefault(digest, []).append(reference)

        return index

    def resource_descriptors(self, content_hash: bytes | str | Resource) -> list[Resource]:
        """Return every resource table row for ``content_hash``, in table order.

        Duplicate hashes are intentionally not collapsed: each descriptor is a separate piece of evidence.
        """
        return list(self._descriptors_by_hash.get(_coerce_hash(content_hash), ()))

    def resource_for(self, content_hash: bytes | str | Resource, *, content: bool = True) -> Resource | None:
        """Return the single descriptor for ``content_hash``, or ``None`` when it is not present.

        Args:
            content_hash: The SHA-1 content hash, as bytes or a hex string.
            content: When ``True``, metadata resources are ignored because they are not file content.

        Raises:
            AmbiguousResourceError: If more than one matching descriptor exists. Use
                :meth:`resource_descriptors` to inspect and verify each one instead.
        """
        digest = _coerce_hash(content_hash)
        rows = self._descriptors_by_hash.get(digest, ())
        if content:
            rows = [resource for resource in rows if not resource.is_metadata]

        if not rows:
            return None

        if len(rows) > 1:
            raise AmbiguousResourceError(
                f"Hash {digest.hex()} has {len(rows)} resource descriptors; refusing to choose one"
            )

        return rows[0]

    def resource_references(self, content_hash: bytes | str | Resource) -> ResourceReferences:
        """Return every image, file and alternate stream that references ``content_hash``.

        This is the reverse lookup of :attr:`resources`: a shared content hash produces one reference per
        directory entry and stream, never one merged record. Missing hashes still produce references, so an
        unresolved file remains visible as evidence.

        Args:
            content_hash: The SHA-1 content hash, as bytes or a hex string, or a :class:`Resource`.
        """
        digest = _coerce_hash(content_hash)
        return ResourceReferences(
            hash=digest,
            references=list(self._reference_index.get(digest, ())),
            descriptors=list(self._descriptors_by_hash.get(digest, ())),
        )

    def references(self, content_hash: bytes | str | Resource) -> ResourceReferences:
        """Alias for :meth:`resource_references`."""
        return self.resource_references(content_hash)

    def referrers(self, content_hash: bytes | str | Resource) -> ResourceReferences:
        """Alias for :meth:`resource_references`."""
        return self.resource_references(content_hash)

    def resource_references_for(self, entry: DirectoryEntry, stream_name: str | None = None) -> list[ResourceReference]:
        """Return the reverse references belonging to one directory entry.

        Entries are matched by their image and metadata offset, so a freshly resolved directory entry
        is still recognized as the same identity.

        Args:
            entry: The directory entry to inspect.
            stream_name: Optional stream name to restrict the result to.
        """
        references = []
        for stream in entry.streams:
            if stream_name is not None and stream != stream_name:
                continue

            references.extend(
                reference
                for reference in self.resource_references(entry.streams[stream]).references
                if reference.image_index == entry.image.index and reference.entry_offset == entry.offset
            )
        return references

    def verify_resource(self, resource: Resource, *, as_content: bool = False) -> ResourceVerification:
        """Verify a resource descriptor and cache the conclusion for that exact descriptor.

        A shared content resource is therefore read and hashed once, regardless of how many files or
        images reference it. Duplicate descriptors for the same hash remain separate entries and may
        produce different conclusions.

        Args:
            resource: The descriptor to verify.
            as_content: Refuse metadata resources, which cannot be used as ordinary file content.
        """
        key = (id(resource.wim), resource.index if resource.index is not None else id(resource), as_content)
        if key in self._verification_cache:
            return self._verification_cache[key]

        result = _verify_resource(self, resource, as_content=as_content)
        self._verification_cache[key] = result
        return result

    def images(self) -> Iterator[Image]:
        """Iterate over all images in the WIM file.

        Images are constructed once, so directory entries stay identical across repeated calls.
        """
        yield from self._all_images()

    def _all_images(self) -> list[Image]:
        if self._image_list is None:
            self._image_list = [
                Image(self, resource.open(), index=index, resource=resource)
                for index, resource in enumerate(self._images)
            ]
        return self._image_list


class Resource:
    __slots__ = (
        "flags",
        "hash",
        "index",
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
        index: int | None = None,
    ):
        self.wim = wim
        self.size = size
        self.flags = flags
        self.offset = offset
        self.original_size = original_size

        self.part_number = part_number
        self.reference_count = reference_count
        self.hash = hash
        self.index = index

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
        obj.hash = bytes(reshdr.Hash)
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

    @property
    def location(self) -> tuple[int, int]:
        """Return the physical ``[start, end)`` byte range of this descriptor in the WIM file."""
        return (self.offset, self.offset + self.size)

    @property
    def references(self) -> ResourceReferences:
        """Return every directory entry stream that references this descriptor's hash."""
        return self.wim.resource_references(self.hash)

    @property
    def referrers(self) -> ResourceReferences:
        """Alias for :attr:`references`."""
        return self.references

    def verify(self, *, as_content: bool = False) -> ResourceVerification:
        """Verify this descriptor's SHA-1 and report the byte range actually covered.

        Args:
            as_content: Refuse metadata resources, which cannot be used as ordinary file content.
        """
        return self.wim.verify_resource(self, as_content=as_content)

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
    def __init__(self, wim: WIM, fh: BinaryIO, index: int = 0, resource: Resource | None = None):
        self.wim = wim
        self.index = index
        self.resource = resource
        self.security = SecurityBlock(fh)

        offset = fh.tell()
        fh.seek(offset + (-offset & 7))
        self.root = DirectoryEntry(self, fh)

    def __repr__(self) -> str:
        return "<Image>"

    def resource_references(self, content_hash: bytes | str | Resource) -> ResourceReferences:
        """Return the references to ``content_hash`` that belong to this image."""
        references = self.wim.resource_references(content_hash)
        return ResourceReferences(
            hash=references.hash,
            references=[reference for reference in references.references if reference.image_index == self.index],
            descriptors=references.descriptors,
        )

    def references(self, content_hash: bytes | str) -> ResourceReferences:
        """Alias for :meth:`resource_references`."""
        return self.resource_references(content_hash)

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
    def __init__(self, fh: BinaryIO):
        self.header = c_wim._SECURITYBLOCK_DISK(fh)
        self.descriptors = []
        for size in self.header.EntryLength:
            if size == 0:
                continue

            self.descriptors.append(fh.read(size))


class DirectoryEntry:
    def __init__(self, image: Image, fh: BinaryIO):
        self.image = image
        self.fh = fh

        start = fh.tell()
        self.offset = start
        self.entry = c_wim._DIRENTRY(fh)
        self.name = None
        self.short_name = None
        self.extra = None

        if length := self.entry.FileNameLength:
            self.name = _read_name(fh, length)
            fh.read(2)

        if length := self.entry.ShortNameLength:
            self.short_name = _read_name(fh, length)
            fh.read(2)

        # If there's any trailing data after the aligned end, read it and store it
        end = fh.tell()
        if (length := self.entry.Length - (((end + 7) & (-8)) - start)) > 0 or (
            length := self.entry.Length - (end - start)
        ) > 0:
            self.extra = fh.read(length)

        self.streams = {}
        if self.entry.Streams:
            for _ in range(self.entry.Streams):
                # Stream entries are 8 byte aligned
                fh.seek((fh.tell() + 7) & (-8))

                name = ""
                stream = c_wim._STREAMENTRY(fh)
                if name_length := stream.StreamNameLength:
                    name = _read_name(fh, name_length)
                    name_length += 2
                    fh.read(2)

                self.streams[name] = stream.Hash

                if remaining := stream.Length - len(c_wim._STREAMENTRY) - name_length:
                    fh.read(remaining)
        else:
            # Add the entry hash as the default stream
            self.streams[""] = self.entry.Hash

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
        fh.seek(self.entry.SubdirOffset)
        while True:
            length = int.from_bytes(fh.read(8), "little")
            if length <= 8:
                break

            fh.seek(-8, io.SEEK_CUR)
            entry = DirectoryEntry(self.image, fh)
            offset = fh.tell()

            yield entry

            # Align to the next 8 byte boundary
            fh.seek((offset + 7) & (-8))

    def resource_references(self, name: str | None = None) -> list[ResourceReference]:
        """Return the reverse references for this entry's streams.

        Args:
            name: Optional stream name to restrict the result to.
        """
        return self.image.wim.resource_references_for(self, name)

    def open(self, name: str = "") -> BinaryIO:
        """Return a file-like object for the contents of this directory entry.

        Args:
            name: Optional alternate stream name to open.
        """
        stream_hash = self.streams.get(name)
        if stream_hash is None:
            raise FileNotFoundError(f"Stream not found in directory entry {self}: {name!r}")

        stream_hash = bytes(stream_hash)
        if _is_empty_hash(stream_hash):
            return BufferedStream(io.BytesIO(b""), size=0)

        descriptors = self.image.wim.resource_descriptors(stream_hash)
        content = [resource for resource in descriptors if not resource.is_metadata]
        if not content:
            if descriptors:
                raise NotFileContentError(f"Resource for directory entry {self} is image metadata, not file content")
            raise FileNotFoundError(f"Unable to find resource for directory entry {self}")

        if len(content) > 1:
            indices = ", ".join(str(resource.index) for resource in content)
            raise AmbiguousResourceError(
                f"Directory entry {self} stream {name!r} has {len(content)} content resource descriptors "
                f"(rows {indices}); use WIM.resource_references() and verify each descriptor"
            )

        return content[0].open()


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


def _ts_to_ns(ts: int) -> int:
    """Convert Windows timestamps to nanosecond timestamps."""
    return (ts * 100) - 11644473600000000000


def _read_name(fh: BinaryIO, length: int) -> str:
    return fh.read(length).decode("utf-16-le")


def _coerce_hash(content_hash: bytes | str | Resource) -> bytes:
    if isinstance(content_hash, Resource):
        return bytes(content_hash.hash)
    if isinstance(content_hash, str):
        try:
            return bytes.fromhex(content_hash)
        except ValueError as e:
            raise ValueError(f"Invalid content hash: {content_hash!r}") from e

    return bytes(content_hash)


def _is_empty_hash(content_hash: bytes) -> bool:
    """Return whether a stream hash denotes empty content rather than a resource row."""
    return not content_hash.strip(b"\x00") or content_hash == EMPTY_HASH


def _iter_entries(
    image: Image,
    path: str = "",
    entry: DirectoryEntry | None = None,
    ancestors: set[int] | None = None,
) -> Iterator[tuple[str, DirectoryEntry]]:
    entry = entry or image.root
    ancestors = ancestors or set()

    yield path, entry

    if not entry.is_dir() or entry.offset in ancestors:
        return

    ancestors = ancestors | {entry.offset}
    for child in entry.iterdir():
        child_path = f"{path}\\{child.name}" if path else (child.name or "")
        yield from _iter_entries(image, child_path, child, ancestors)


class StreamKind(str, Enum):
    """Which kind of stream a reference describes."""

    DEFAULT = "default"
    """The unnamed stream of a directory entry."""

    ADS = "ads"
    """A named alternate data stream (ADS)."""

    ALTERNATE = "ads"
    """Alias for :attr:`ADS`."""


class ReferenceStatus(str, Enum):
    """How a directory entry stream resolves against the resource table."""

    RESOLVED = "resolved"
    """At least one content resource descriptor exists for the stream hash."""

    EMPTY = "empty"
    """The stream explicitly denotes empty content and needs no resource."""

    MISSING = "missing"
    """No resource table row has this hash."""

    METADATA = "metadata"
    """The hash only points at image metadata resources, which are not file content."""


class VerificationStatus(str, Enum):
    """Outcome of hashing a resource descriptor."""

    VERIFIED = "verified"
    """The covered bytes hash to the descriptor's declared hash."""

    MISMATCH = "mismatch"
    """The descriptor's declared hash does not match the covered bytes."""

    TRUNCATED = "truncated"
    """The descriptor extends past the end of the WIM and only part of it could be read."""

    UNREADABLE = "unreadable"
    """The descriptor could not be read (for example an unsupported compressed stream)."""

    METADATA = "metadata"
    """The descriptor is image metadata and was not verified as ordinary file content."""

    EMPTY = "empty"
    """The stream denotes empty content, so there are no bytes to verify."""

    MISSING = "missing"
    """No resource descriptor exists for the stream hash, so there is nothing to verify."""


def _verify_resource(wim: WIM, resource: Resource, *, as_content: bool) -> ResourceVerification:
    declared = bytes(resource.hash)

    if as_content and resource.is_metadata:
        return ResourceVerification(
            resource=resource,
            status=VerificationStatus.METADATA,
            declared_hash=declared,
            computed_hash=None,
            coverages=(),
            detail="Image metadata resource is not ordinary file content",
        )

    if resource.is_spanned:
        return ResourceVerification(
            resource=resource,
            status=VerificationStatus.UNREADABLE,
            declared_hash=declared,
            computed_hash=None,
            coverages=(),
            detail="Spanned resources are not yet supported",
        )

    file_size = _wim_file_size(wim)
    physical_available = max(0, min(resource.size, file_size - resource.offset))

    try:
        stream = resource.open()
    except Exception as e:
        return ResourceVerification(
            resource=resource,
            status=VerificationStatus.UNREADABLE,
            declared_hash=declared,
            computed_hash=None,
            coverages=(),
            detail=f"Unable to open resource: {e}",
        )

    hasher = hashlib.sha1()
    logical_length = 0
    try:
        while chunk := stream.read(VERIFY_CHUNK_SIZE):
            hasher.update(chunk)
            logical_length += len(chunk)
    except Exception as e:
        return ResourceVerification(
            resource=resource,
            status=VerificationStatus.UNREADABLE,
            declared_hash=declared,
            computed_hash=None,
            coverages=(
                VerificationRange(
                    physical_offset=resource.offset,
                    physical_length=min(physical_available, logical_length),
                    logical_offset=0,
                    logical_length=logical_length,
                ),
            ),
            detail=f"Unable to read resource: {e}",
        )

    # Uncompressed resources map one stored byte to one logical byte, so the covered physical range is
    # exactly the read amount. Compressed resources report what was actually available on disk and the
    # full decompressed scope separately.
    physical_length = physical_available if resource.is_compressed else logical_length

    coverage = VerificationRange(
        physical_offset=resource.offset,
        physical_length=physical_length,
        logical_offset=0,
        logical_length=logical_length,
    )

    computed = hasher.digest()
    expected_logical = resource.original_size
    if physical_available < resource.size or logical_length < expected_logical:
        status = VerificationStatus.TRUNCATED
        detail = (
            f"Read {logical_length} of {expected_logical} decompressed bytes "
            f"and {physical_available} of {resource.size} stored bytes"
        )
    elif computed == declared:
        status = VerificationStatus.VERIFIED
        detail = None
    else:
        status = VerificationStatus.MISMATCH
        detail = "Computed hash does not match the resource table row"

    return ResourceVerification(
        resource=resource,
        status=status,
        declared_hash=declared,
        computed_hash=computed,
        coverages=(coverage,),
        detail=detail,
    )


def _wim_file_size(wim: WIM) -> int:
    if wim._fh_size is not None:
        return wim._fh_size

    pos = wim.fh.tell()
    try:
        wim.fh.seek(0, io.SEEK_END)
        wim._fh_size = wim.fh.tell()
    finally:
        wim.fh.seek(pos)

    return wim._fh_size


@dataclass(frozen=True)
class VerificationRange:
    """A byte range covered by a verification, with both physical and logical coordinates."""

    physical_offset: int
    """Offset of the first covered byte in the WIM file."""

    physical_length: int
    """Number of bytes covered in the WIM file."""

    logical_offset: int
    """Offset of the first covered byte in the decompressed resource content."""

    logical_length: int
    """Number of decompressed bytes covered by the verification."""

    @property
    def physical_end(self) -> int:
        """Exclusive end offset of the physical range."""
        return self.physical_offset + self.physical_length

    @property
    def logical_end(self) -> int:
        """Exclusive end offset of the logical range."""
        return self.logical_offset + self.logical_length


@dataclass(frozen=True)
class ResourceVerification:
    """The result of hashing one resource descriptor and the byte scope it actually covered."""

    resource: Resource | None
    status: VerificationStatus
    declared_hash: bytes
    """The SHA-1 declared by the resource table row."""
    computed_hash: bytes | None
    """The SHA-1 of the bytes actually covered, or ``None`` if nothing was hashed."""
    coverages: tuple[VerificationRange, ...]
    """The covered ranges. Empty when the resource was not read at all."""
    detail: str | None = None
    """Human-readable explanation for non-verified outcomes."""

    @property
    def ok(self) -> bool:
        """Return whether the descriptor's declared hash matches the covered content."""
        return self.status is VerificationStatus.VERIFIED

    @property
    def physical_range(self) -> tuple[int, int]:
        """Return the combined physical ``[start, end)`` range that was read."""
        if not self.coverages:
            return (0, 0)
        return (self.coverages[0].physical_offset, self.coverages[-1].physical_end)

    @property
    def logical_range(self) -> tuple[int, int]:
        """Return the combined logical ``[start, end)`` range that was hashed."""
        if not self.coverages:
            return (0, 0)
        return (self.coverages[0].logical_offset, self.coverages[-1].logical_end)

    @property
    def covered_ranges(self) -> tuple[VerificationRange, ...]:
        """Alias for :attr:`coverages`."""
        return self.coverages

    @property
    def covers_full_resource(self) -> bool:
        """Return whether the verification covered the full logical resource."""
        return (
            self.resource is not None
            and bool(self.coverages)
            and self.logical_range == (0, self.resource.original_size)
            and self.physical_range == self.resource.location
        )

    @property
    def covered_physical(self) -> tuple[int, int]:
        """Alias for :attr:`physical_range`."""
        return self.physical_range

    @property
    def covered_logical(self) -> tuple[int, int]:
        """Alias for :attr:`logical_range`."""
        return self.logical_range


@dataclass(frozen=True)
class ResourceReference:
    """One directory entry stream that references a content hash.

    Each reference keeps its image, file path, directory entry and stream name, so different files that
    share content never collapse into one evidence record.
    """

    image: Image
    image_index: int
    path: str
    entry: DirectoryEntry
    entry_offset: int
    stream_name: str
    stream_kind: StreamKind
    hash: bytes
    status: ReferenceStatus
    resources: tuple[Resource, ...]
    """Every resource table row for this hash, including metadata rows and duplicates."""
    resource_indices: tuple[int, ...]
    """Table row indices for :attr:`resources`."""

    @property
    def is_default(self) -> bool:
        """Return whether this is the unnamed default stream."""
        return self.stream_kind is StreamKind.DEFAULT

    @property
    def is_alternate(self) -> bool:
        """Return whether this is a named alternate data stream."""
        return self.stream_kind is StreamKind.ADS

    @property
    def is_ads(self) -> bool:
        """Alias for :attr:`is_alternate`."""
        return self.is_alternate

    @property
    def kind(self) -> StreamKind:
        """Alias for :attr:`stream_kind`."""
        return self.stream_kind

    @property
    def identity(self) -> tuple[int, int, int]:
        """Return the stable identity of this reference.

        The tuple is ``(image index, directory entry offset, stream name)`` and stays stable across
        repeated :meth:`WIM.images` calls.
        """
        return (self.image_index, self.entry_offset, self.stream_name)

    @property
    def entry_path(self) -> str:
        """Return the directory entry path without the stream name."""
        return self.path

    @property
    def offset(self) -> int:
        """Alias for :attr:`entry_offset`."""
        return self.entry_offset

    @property
    def content_resources(self) -> tuple[Resource, ...]:
        """Return the non-metadata descriptors for this hash."""
        return tuple(resource for resource in self.resources if not resource.is_metadata)

    @property
    def metadata_resources(self) -> tuple[Resource, ...]:
        """Return the metadata descriptors for this hash."""
        return tuple(resource for resource in self.resources if resource.is_metadata)

    @property
    def has_conflict(self) -> bool:
        """Return whether this hash has more than one resource descriptor."""
        return len(self.resources) > 1

    @property
    def display_path(self) -> str:
        """Return the path including the stream name, e.g. ``file.txt:secret``."""
        if self.stream_kind is StreamKind.DEFAULT:
            return self.path or "."
        return f"{self.path}:{self.stream_name}"

    def verify(self, resource: Resource | None = None) -> ResourceVerification:
        """Verify a descriptor for this reference.

        Args:
            resource: The descriptor to verify. Defaults to the single content descriptor, or the
                single metadata descriptor when this reference has no content.

        Raises:
            FileNotFoundError: If the reference has no resource descriptor at all.
            AmbiguousResourceError: If the default descriptor would be ambiguous.
        """
        if resource is not None:
            return self.image.wim.verify_resource(resource, as_content=True)

        if self.content_resources:
            return self.image.wim.verify_resource(self.resource(), as_content=True)

        if self.metadata_resources:
            if len(self.metadata_resources) > 1:
                raise AmbiguousResourceError(
                    f"Reference {self.display_path} has {len(self.metadata_resources)} metadata descriptors"
                )
            return self.image.wim.verify_resource(self.metadata_resources[0], as_content=True)

        status = VerificationStatus.EMPTY if self.status is ReferenceStatus.EMPTY else VerificationStatus.MISSING
        detail = (
            "Stream denotes empty content"
            if self.status is ReferenceStatus.EMPTY
            else "No resource descriptor exists for this stream hash"
        )
        return ResourceVerification(
            resource=None,
            status=status,
            declared_hash=self.hash,
            computed_hash=None,
            coverages=(),
            detail=detail,
        )

    def resource(self) -> Resource:
        """Return the sole content descriptor for this reference.

        Raises:
            FileNotFoundError: If no content descriptor exists.
            AmbiguousResourceError: If more than one content descriptor exists.
        """
        content = self.content_resources
        if not content:
            raise FileNotFoundError(f"No content resource for reference {self.display_path}")
        if len(content) > 1:
            raise AmbiguousResourceError(f"Reference {self.display_path} has {len(content)} content descriptors")
        return content[0]


@dataclass(frozen=True)
class ResourceReferences:
    """Reverse lookup result for one content hash.

    The result keeps the resource descriptors, the per-file/stream references and any conflicts
    between descriptors separate.
    """

    hash: bytes
    references: list[ResourceReference]
    descriptors: list[Resource]
    """Every resource table row for this hash, in table order."""

    @property
    def paths(self) -> list[str]:
        """Return every distinct referencing path, in first-seen order."""
        return list(dict.fromkeys(reference.path for reference in self.references))

    @property
    def display_paths(self) -> list[str]:
        """Return every reference path including stream names, in first-seen order."""
        return [reference.display_path for reference in self.references]

    @property
    def images(self) -> list[Image]:
        """Return the distinct images that contain a reference, in first-seen order."""
        return list({reference.image_index: reference.image for reference in self.references}.values())

    @property
    def content_descriptors(self) -> list[Resource]:
        """Return the non-metadata resource descriptors for this hash."""
        return [resource for resource in self.descriptors if not resource.is_metadata]

    @property
    def metadata_descriptors(self) -> list[Resource]:
        """Return the metadata resource descriptors for this hash."""
        return [resource for resource in self.descriptors if resource.is_metadata]

    @property
    def is_shared(self) -> bool:
        """Return whether more than one file/stream identity references this hash."""
        return len({reference.identity for reference in self.references}) > 1

    @property
    def has_conflict(self) -> bool:
        """Return whether more than one resource descriptor exists for this hash."""
        return len(self.descriptors) > 1

    @property
    def unresolved(self) -> list[ResourceReference]:
        """Return references that cannot be read as file content."""
        return [
            reference
            for reference in self.references
            if reference.status in (ReferenceStatus.MISSING, ReferenceStatus.METADATA)
        ]

    @property
    def missing(self) -> list[ResourceReference]:
        """Return references whose hash has no resource table row."""
        return [reference for reference in self.references if reference.status is ReferenceStatus.MISSING]

    @property
    def metadata_only(self) -> list[ResourceReference]:
        """Return references whose hash only resolves to metadata resources."""
        return [reference for reference in self.references if reference.status is ReferenceStatus.METADATA]

    def __iter__(self) -> Iterator[ResourceReference]:
        """Iterate over the individual file/stream references."""
        return iter(self.references)

    def __len__(self) -> int:
        """Return the number of references."""
        return len(self.references)

    def __getitem__(self, index: int) -> ResourceReference:
        """Return a reference by position."""
        return self.references[index]

    def __bool__(self) -> bool:
        """Return whether this hash has any references."""
        return bool(self.references)

    def verify(self, resource: Resource | None = None) -> list[ResourceVerification]:
        """Verify all resource descriptors for this hash, reusing the cached conclusion per descriptor.

        A shared content resource is read and hashed once. Multiple descriptors for the same hash are all
        verified and returned separately, so a descriptor conflict is never reduced to one verdict.

        Args:
            resource: When given, only verify that descriptor.
        """
        if resource is not None:
            return [resource.wim.verify_resource(resource, as_content=True)]

        # Every descriptor row is verified separately, so a content/metadata conflict is never reduced
        # to one verdict. Metadata rows report an explicit METADATA status instead of file content.
        return [_verify_descriptor(descriptor) for descriptor in self.descriptors]

    def verify_one(self) -> ResourceVerification:
        """Verify the single content descriptor for this hash.

        Raises:
            FileNotFoundError: If there is no content descriptor.
            AmbiguousResourceError: If more than one content descriptor exists.
        """
        content = self.content_descriptors
        if not content:
            raise FileNotFoundError(f"No content resource for hash {self.hash.hex()}")
        if len(content) > 1:
            raise AmbiguousResourceError(
                f"Hash {self.hash.hex()} has {len(content)} content descriptors; use verify() or pass one"
            )

        return _verify_descriptor(content[0])

    @property
    def verifications(self) -> list[ResourceVerification]:
        """Return the cached verification of every resource descriptor."""
        return self.verify()

    @property
    def empty(self) -> list[ResourceReference]:
        """Return references that explicitly denote empty content."""
        return [reference for reference in self.references if reference.status is ReferenceStatus.EMPTY]

    @property
    def conflicts(self) -> list[Resource]:
        """Return all descriptors when a hash has more than one, or an empty list."""
        return list(self.descriptors) if self.has_conflict else []


def _verify_descriptor(resource: Resource) -> ResourceVerification:
    return resource.wim.verify_resource(resource, as_content=True)
