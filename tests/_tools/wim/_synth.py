"""Synthetic, hash-correct WIM archives for hermetic forensics tests.

Real WIM captures cannot exercise every reverse-reference edge case (missing resources,
duplicate descriptors for one hash, images sharing one blob under different names), so tests
build minimal valid uncompressed WIM files from scratch. Every on-disk structure is emitted
through the same :mod:`c_wim` definitions the parser reads, and every stored hash is computed
with the same plain SHA-1 / chunked WIMHASH rules the verification code checks.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from dissect.archive.wim.c_wim import FILE_ATTRIBUTE, RESHDR_FLAG, WIM_IMAGE_TAG, c_wim

HASH_SIZE = c_wim.HASH_SIZE
ZERO_HASH = b"\x00" * HASH_SIZE
DEFAULT_CHUNK_SIZE = 32 * 1024
WIMHASH_PLAIN_THRESHOLD = 1024 * 1024
WIMHASH_HEADER_SIZE = 12
# Fixed timestamp so generated archives are byte-for-byte reproducible.
FIXED_TIMESTAMP = 0x01DA01FC7E376E86
HEADER_SIZE = len(c_wim.WIMHEADER_V1_PACKED)
DIRENTRY_SIZE = len(c_wim._DIRENTRY)
STREAMENTRY_SIZE = len(c_wim._STREAMENTRY)


def wim_hash(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """Compute the resource hash WIM stores for ``data`` (plain SHA-1 or chunked WIMHASH)."""
    if len(data) <= WIMHASH_PLAIN_THRESHOLD:
        return hashlib.sha1(data).digest()

    return make_wimhash(data, chunk_size)


def make_wimhash(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """Build a serialized WIMHASH structure with per-chunk hashes plus an overall hash.

    The element count is one more than the number of chunks: one SHA-1 per chunk followed by a
    final SHA-1 over the whole uncompressed data.
    """
    chunk_hashes = [
        hashlib.sha1(data[start : start + chunk_size]).digest()
        for start in range(0, len(data), chunk_size)
    ]
    overall_hash = hashlib.sha1(data).digest()
    element_count = len(chunk_hashes) + 1
    size = WIMHASH_HEADER_SIZE + element_count * HASH_SIZE
    return struct.pack("<III", size, element_count, chunk_size) + b"".join(chunk_hashes) + overall_hash


@dataclass(slots=True)
class SynthStream:
    """A stream of a synthetic directory entry.

    ``data`` of ``None`` models a reference to a resource that is absent from the resource
    table; ``b""`` models an empty stream (zero hash, no backing resource).
    """

    name: str
    data: bytes | None
    hash: bytes = b""

    def __post_init__(self) -> None:
        if self.hash:
            return

        if self.data is None:
            self.hash = hashlib.sha1(b"missing-resource:" + self.name.encode()).digest()
        elif self.data == b"":
            self.hash = ZERO_HASH
        else:
            self.hash = wim_hash(self.data)


@dataclass(slots=True)
class SynthEntry:
    """A directory entry in a synthetic image tree."""

    name: str | None
    is_directory: bool = False
    streams: list[SynthStream] = field(default_factory=list)
    children: list[SynthEntry] = field(default_factory=list)

    def find(self, name: str) -> SynthEntry:
        for child in self.children:
            if child.name == name:
                return child

        raise KeyError(name)


def file_entry(name: str, data: bytes = b"", alternate_streams: dict[str, bytes] | None = None) -> SynthEntry:
    """Build a regular file entry with a default stream and optional named streams."""
    streams = [SynthStream("", data)]
    for stream_name, stream_data in (alternate_streams or {}).items():
        streams.append(SynthStream(stream_name, stream_data))

    return SynthEntry(name=name, is_directory=False, streams=streams)


def directory_entry(name: str | None, children: list[SynthEntry]) -> SynthEntry:
    return SynthEntry(name=name, is_directory=True, children=children)


def missing_stream_entry(name: str, stream_name: str) -> SynthEntry:
    """Build a file whose named stream points at a resource missing from the table."""
    return SynthEntry(
        name=name,
        is_directory=False,
        streams=[SynthStream("", b""), SynthStream(stream_name, None)],
    )


@dataclass(slots=True)
class _Descriptor:
    hash: bytes
    blob: bytes
    flags: RESHDR_FLAG
    offset: int = 0
    ref_count: int = 0


@dataclass(slots=True)
class _Layout:
    entry_start: int
    entry_size: int
    subdir_offset: int


def build_wim(
    images: list[SynthEntry],
    *,
    duplicate_hashes: set[bytes] | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Serialize synthetic image trees into a complete uncompressed WIM file."""
    duplicate_hashes = duplicate_hashes or set()

    descriptors: dict[bytes, _Descriptor] = {}
    metadata_blobs: list[bytes] = []

    def register_data(stream: SynthStream) -> None:
        if stream.data is None or stream.data == b"":
            return

        if len(stream.data) > WIMHASH_PLAIN_THRESHOLD:
            raise ValueError(
                "Synthetic WIM resources must be at most one megabyte: larger resources store "
                "their chunked WIMHASH in a separate hash resource this minimal builder does not emit"
            )

        descriptor = descriptors.get(stream.hash)
        if descriptor is None:
            descriptors[stream.hash] = _Descriptor(stream.hash, stream.data, RESHDR_FLAG(0))

        descriptors[stream.hash].ref_count += 1

    for root in images:
        _collect_streams(root, register_data)
        metadata_blobs.append(_build_metadata(root))

    for blob in metadata_blobs:
        metadata_hash = wim_hash(blob, chunk_size)
        descriptor = descriptors.setdefault(metadata_hash, _Descriptor(metadata_hash, blob, RESHDR_FLAG.METADATA))
        descriptor.ref_count = 1

    xml_blob = _build_xml(images)

    cursor = HEADER_SIZE
    ordered: list[_Descriptor] = []
    for descriptor in descriptors.values():
        descriptor.offset = cursor
        cursor += len(descriptor.blob)
        ordered.append(descriptor)

        if descriptor.hash in duplicate_hashes and not descriptor.flags & RESHDR_FLAG.METADATA:
            duplicate = _Descriptor(descriptor.hash, descriptor.blob, descriptor.flags, cursor, descriptor.ref_count)
            cursor += len(duplicate.blob)
            ordered.append(duplicate)

    table_blob = b"".join(_pack_resource_descriptor(descriptor) for descriptor in ordered)
    table_descriptor = _Descriptor(wim_hash(table_blob, chunk_size), table_blob, RESHDR_FLAG.METADATA, cursor)
    cursor += len(table_blob)

    xml_descriptor = _Descriptor(wim_hash(xml_blob, chunk_size), xml_blob, RESHDR_FLAG(0), cursor)
    cursor += len(xml_blob)

    header = _build_header(len(images), table_descriptor, xml_descriptor, chunk_size)

    result = bytearray(cursor)
    result[0:HEADER_SIZE] = header
    for descriptor in [*ordered, table_descriptor, xml_descriptor]:
        result[descriptor.offset : descriptor.offset + len(descriptor.blob)] = descriptor.blob

    return bytes(result)


def _collect_streams(entry: SynthEntry, callback) -> None:
    for stream in entry.streams:
        callback(stream)

    for child in entry.children:
        _collect_streams(child, callback)


def _build_metadata(root: SynthEntry) -> bytes:
    # Minimal security block with no descriptor entries. The parser skips it entirely and the
    # root directory entry starts on the next 8-byte boundary.
    security = struct.pack("<II", 8, 0)

    layouts: dict[int, _Layout] = {}
    total_size = _place_root(root, 8, layouts)

    blob = bytearray(total_size)
    blob[0:8] = security
    _write_node(root, layouts, blob)
    return bytes(blob)


def _place_block(directory: SynthEntry, block_start: int, layouts: dict[int, "_Layout"]) -> int:
    """Place one directory's child block and all nested blocks, returning the offset past them.

    The directory's own entry was placed by its parent. This function lays out every direct
    child entry back-to-back starting at ``block_start`` (files and nested directories alike),
    writes the eight-byte zero marker that ends the child block, then appends the child blocks
    of the nested directories. The directory's ``SubdirOffset`` is patched to ``block_start``.
    """
    layouts[id(directory)].subdir_offset = block_start

    child_cursor = block_start
    nested_directories = []
    for child in directory.children:
        child_blob, child_streams = _encode_entry(child, subdir_offset=0)
        child_start = _aligned(child_cursor)
        child_size = len(child_blob) + len(child_streams)
        layouts[id(child)] = _Layout(child_start, child_size, 0)
        child_cursor = child_start + child_size
        if child.is_directory:
            nested_directories.append(child)

    # The marker is 8-aligned and terminates the direct-child block; nested blocks follow.
    nested_cursor = _aligned(child_cursor) + 8
    for child in nested_directories:
        nested_cursor = _place_block(child, nested_cursor, layouts)

    return nested_cursor


def _place_root(root: SynthEntry, cursor: int, layouts: dict[int, "_Layout"]) -> int:
    """Place the root directory entry, then its child block via :func:`_place_block`."""
    entry_blob, stream_blob = _encode_entry(root, subdir_offset=0)
    entry_start = _aligned(cursor)
    entry_size = len(entry_blob) + len(stream_blob)
    layouts[id(root)] = _Layout(entry_start, entry_size, 0)
    return _place_block(root, entry_start + entry_size, layouts)


def _write_node(entry: SynthEntry, layouts: dict[int, "_Layout"], blob: bytearray) -> None:
    layout = layouts[id(entry)]
    entry_blob, stream_blob = _encode_entry(entry, subdir_offset=layout.subdir_offset)
    blob[layout.entry_start : layout.entry_start + layout.entry_size] = entry_blob + stream_blob

    for child in entry.children:
        _write_node(child, layouts, blob)


def _encode_entry(entry: SynthEntry, subdir_offset: int) -> tuple[bytes, bytes]:
    name_encoded = entry.name.encode("utf-16-le") if entry.name is not None else b""
    name_bytes = name_encoded + b"\x00\x00" if entry.name is not None else b""
    name_length = len(name_encoded)

    explicit_streams = len(entry.streams) > 1 or any(stream.name for stream in entry.streams)
    default_hash = ZERO_HASH
    stream_entries = b""

    if explicit_streams:
        stream_entries = b"".join(_encode_stream(stream) for stream in entry.streams)
    elif entry.streams:
        default_hash = entry.streams[0].hash

    body = bytearray(DIRENTRY_SIZE)
    body.extend(name_bytes)
    entry_length = _aligned(len(body))
    body.extend(b"\x00" * (entry_length - len(body)))

    attributes = FILE_ATTRIBUTE.DIRECTORY if entry.is_directory else FILE_ATTRIBUTE.ARCHIVE
    struct.pack_into(
        "<qIIq",
        body,
        0,
        entry_length,
        int(attributes),
        0,
        subdir_offset,
    )
    struct.pack_into("<qqq", body, 40, FIXED_TIMESTAMP, FIXED_TIMESTAMP, FIXED_TIMESTAMP)
    body[64:84] = default_hash
    struct.pack_into(
        "<HHH",
        body,
        96,
        len(entry.streams) if explicit_streams else 0,
        0,
        name_length,
    )

    return bytes(body), stream_entries


def _encode_stream(stream: SynthStream) -> bytes:
    name_encoded = stream.name.encode("utf-16-le")
    name_bytes = name_encoded + b"\x00\x00"
    name_length = len(name_encoded)

    body = bytearray()
    body.extend(struct.pack("<qq", STREAMENTRY_SIZE + len(name_bytes), 0))
    body.extend(stream.hash)
    body.extend(struct.pack("<H", name_length))
    body.extend(name_bytes)
    return _aligned_bytes(body)


def _pack_resource_descriptor(descriptor: _Descriptor) -> bytes:
    return c_wim._RESHDR_DISK(
        Base=_pack_short_header(descriptor),
        PartNumber=1,
        RefCount=descriptor.ref_count,
        Hash=descriptor.hash,
    ).dumps()


def _build_header(image_count: int, table: _Descriptor, xml: _Descriptor, chunk_size: int) -> bytes:
    empty = _Descriptor(ZERO_HASH, b"", c_wim.RESHDR_FLAG(0))
    header = c_wim.WIMHEADER_V1_PACKED(
        ImageTag=WIM_IMAGE_TAG,
        Size=HEADER_SIZE,
        Version=c_wim.VERSION_DEFAULT,
        Flags=c_wim.HEADER_FLAG(0),
        CompressionSize=chunk_size,
        WIMGuid=b"\x00" * 16,
        PartNumber=1,
        TotalParts=1,
        ImageCount=image_count,
        OffsetTable=_pack_short_header(table),
        XmlData=_pack_short_header(xml),
        BootMetadata=_pack_short_header(empty),
        BootIndex=0,
        Integrity=_pack_short_header(empty),
        Unused=b"\x00" * 60,
    )
    return header.dumps()


def _pack_short_header(descriptor: _Descriptor) -> c_wim._RESHDR_DISK_SHORT:
    return c_wim._RESHDR_DISK_SHORT(
        Size=len(descriptor.blob).to_bytes(7, "little"),
        Flags=descriptor.flags,
        Offset=descriptor.offset,
        OriginalSize=len(descriptor.blob),
    )


def _build_xml(images: list[SynthEntry]) -> bytes:
    parts = ['﻿<WIM>']
    for index, root in enumerate(images, start=1):
        file_count = _count_files(root)
        total_bytes = _count_bytes(root)
        parts.append(
            f'<IMAGE INDEX="{index}"><DIRCOUNT>0</DIRCOUNT><FILECOUNT>{file_count}</FILECOUNT>'
            f"<TOTALBYTES>{total_bytes}</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES>"
            f"<CREATIONTIME><HIGHPART>0x01DA01FC</HIGHPART><LOWPART>0x7E376E86</LOWPART></CREATIONTIME>"
            f"<LASTMODIFICATIONTIME><HIGHPART>0x01DA01FC</HIGHPART><LOWPART>0x7E376E86</LOWPART>"
            f'</LASTMODIFICATIONTIME><WIMBOOT>0</WIMBOOT><NAME>SynthImage{index}</NAME></IMAGE>'
        )
    parts.append("</WIM>")
    return "".join(parts).encode("utf-16-le")


def _count_files(entry: SynthEntry) -> int:
    own = 0 if entry.is_directory else 1
    return own + sum(_count_files(child) for child in entry.children)


def _count_bytes(entry: SynthEntry) -> int:
    own = sum(len(stream.data) for stream in entry.streams if stream.data)
    return own + sum(_count_bytes(child) for child in entry.children)


def _aligned(value: int) -> int:
    return (value + 7) & -8


def _aligned_bytes(value: bytes | bytearray) -> bytes:
    padding = _aligned(len(value)) - len(value)
    return bytes(value) + b"\x00" * padding
