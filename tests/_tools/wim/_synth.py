"""Synthetic WIM builders for resource-reference tests.

The committed WIM fixtures contain a single image, so they cannot express the cases this
API needs: two images sharing content, alternate streams with different names, a duplicate
resource descriptor for one hash, or references that resolve to nothing. These builders
assemble a minimal uncompressed WIM from the same :mod:`c_wim` structures the parser reads,
so a builder cannot drift from the on-disk layout.

A built WIM has the following layout::

    header
    content resource data (deduplicated by SHA-1)
    optional duplicate resource descriptor
    one metadata resource per image (security block + directory entry tree)
    offset table
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.archive.wim.c_wim import FILE_ATTRIBUTE, HEADER_FLAG, RESHDR_FLAG, WIM_IMAGE_TAG, c_wim

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from dissect.archive.wim.wim import WIM

ZERO_HASH = b"\x00" * 20


@dataclass
class Node:
    """A directory entry in a synthetic image tree."""

    name: str
    """Entry name. The root uses an empty name."""
    attributes: FILE_ATTRIBUTE = FILE_ATTRIBUTE.ARCHIVE
    streams: Mapping[str, bytes] = field(default_factory=dict)
    """Stream content keyed by name; the empty name is the default stream."""
    stream_hashes: Mapping[str, bytes] = field(default_factory=dict)
    """Optional hash overrides, to model references without a backing resource row."""
    children: list[Node] = field(default_factory=list)
    security_id: int = 0xFFFFFFFF


@dataclass
class ImageSpec:
    """One image in a synthetic WIM: a root tree and its own security table."""

    root: Node
    security_descriptors: Sequence[bytes | None] = field(default_factory=tuple)


@dataclass
class ResourceSpec:
    """An extra resource table row for an existing hash.

    Can be used to create a duplicate descriptor (``content`` set) or a descriptor with
    arbitrary bytes under a chosen hash (``content`` left as ``None``).
    """

    hash: bytes
    content: bytes | None = None
    flags: int = 0
    reference_count: int = 1


def build_wim(
    root: Node,
    security_descriptors: Sequence[bytes | None] = (),
    *,
    extra_resources: Sequence[ResourceSpec] = (),
    drop_resources: Sequence[bytes] = (),
) -> bytes:
    """Build a minimal uncompressed WIM with a single image.

    Args:
        root: The image root node.
        security_descriptors: The image security table.
        extra_resources: Additional resource table rows.
        drop_resources: Hashes whose collected content row should be omitted, to model references
            without a backing resource.
    """
    return build_wim_images(
        [ImageSpec(root, security_descriptors)],
        extra_resources=extra_resources,
        drop_resources=drop_resources,
    )


def build_wim_images(
    images: Sequence[ImageSpec],
    *,
    extra_resources: Sequence[ResourceSpec] = (),
    drop_resources: Sequence[bytes] = (),
) -> bytes:
    """Build a minimal uncompressed WIM with one metadata resource per image.

    Content is deduplicated by SHA-1 exactly like a real WIM: two images or two files with
    identical bytes share one content resource row.
    """
    if not images:
        raise ValueError("at least one image is required")

    metadatas = [build_metadata(spec.root, spec.security_descriptors) for spec in images]

    contents: dict[bytes, bytes] = {}

    def collect(node: Node) -> None:
        for name, content in node.streams.items():
            if name in node.stream_hashes:
                # A hash override models a reference without a backing content row.
                continue
            digest = hashlib.sha1(content).digest()
            if digest.strip(b"\x00") and content:
                contents.setdefault(digest, content)
        for child in node.children:
            collect(child)

    for spec in images:
        collect(spec.root)

    for digest in drop_resources:
        contents.pop(digest, None)

    out = bytearray(b"\x00" * len(c_wim.WIMHEADER_V1_PACKED))
    resources: list[tuple[bytes, int, int, int, int]] = []

    for digest in sorted(contents):
        _align(out)
        offset = len(out)
        out += contents[digest]
        resources.append((digest, int(RESHDR_FLAG(0)), offset, len(contents[digest]), 1))

    for extra in extra_resources:
        content = contents[extra.hash] if extra.content is None else extra.content
        if extra.content is None and extra.hash not in contents:
            raise ValueError(f"no content for hash {extra.hash.hex()}")
        # A row has to live at its own physical location to be independently verifiable.
        _align(out)
        offset = len(out)
        out += content
        resources.append((extra.hash, int(extra.flags), offset, len(content), extra.reference_count))

    for metadata in metadatas:
        _align(out)
        metadata_offset = len(out)
        out += metadata
        resources.append(
            (hashlib.sha1(metadata).digest(), int(RESHDR_FLAG.METADATA), metadata_offset, len(metadata), 1)
        )

    _align(out)
    table_offset = len(out)
    table = bytearray()
    for digest, flags, offset, size, ref_count in resources:
        table += c_wim._RESHDR_DISK(
            Base=c_wim._RESHDR_DISK_SHORT(
                Size=size.to_bytes(7, "little"),
                Flags=RESHDR_FLAG(flags),
                Offset=offset,
                OriginalSize=size,
            ),
            PartNumber=1,
            RefCount=ref_count,
            Hash=digest,
        ).dumps()
    out += table

    header = c_wim._WIMHEADER_V1_PACKED()
    header.ImageTag = WIM_IMAGE_TAG
    header.Size = len(header)
    header.Version = c_wim.VERSION_DEFAULT
    header.Flags = HEADER_FLAG(0)
    header.CompressionSize = 0x1000
    header.WIMGuid = b"\x00" * 16
    header.PartNumber = 1
    header.TotalParts = 1
    header.ImageCount = len(images)
    header.OffsetTable = _short_header(len(table), 0, table_offset)
    header.XmlData = _short_header(0, 0, 0)
    header.BootMetadata = _short_header(0, 0, 0)
    header.BootIndex = 0
    header.Integrity = _short_header(0, 0, 0)
    header.Unused = b"\x00" * 60
    out[: len(header)] = header.dumps()

    return bytes(out)


def build_metadata(root: Node, security_descriptors: Sequence[bytes | None]) -> bytes:
    """Build an image metadata stream: security table followed by directory entries."""
    lengths = [0 if descriptor is None else len(descriptor) for descriptor in security_descriptors]
    out = bytearray(
        c_wim._SECURITYBLOCK_DISK(
            TotalLength=8 + 8 * len(lengths) + sum(lengths),
            NumEntries=len(lengths),
            EntryLength=lengths,
        ).dumps()
    )
    for descriptor in security_descriptors:
        if descriptor is not None:
            out += descriptor
    _align(out)

    offsets: dict[int, int] = {}

    def write_group(nodes: list[Node]) -> int:
        first = -1
        for node in nodes:
            _align(out)
            offsets[id(node)] = len(out)
            if first < 0:
                first = len(out)
            out.extend(_dentry(node))

        for node in nodes:
            if node.children:
                child_offset = write_group(node.children)
                _patch_int(out, offsets[id(node)] + 16, child_offset, 8)
        return first

    root_node = Node("", attributes=FILE_ATTRIBUTE.DIRECTORY, security_id=root.security_id)
    root_offset = len(out)
    out.extend(_dentry(root_node))

    if root.children:
        child_offset = write_group(root.children)
        _patch_int(out, root_offset + 16, child_offset, 8)

    return bytes(out)


def _dentry(node: Node) -> bytes:
    encoded_name = node.name.encode("utf-16-le")

    # Real WIM images put the unnamed default stream in the stream table as soon as any named stream
    # exists. With no named streams, the default hash lives in the directory entry itself.
    named = any(name for name in node.streams)
    stream_items = sorted(node.streams.items()) if named else []

    entry = c_wim._DIRENTRY()
    entry.Length = _align_value(len(c_wim._DIRENTRY) + len(encoded_name) + (2 if encoded_name else 0))
    entry.Attributes = FILE_ATTRIBUTE(node.attributes)
    entry.SecurityId = node.security_id
    entry.SubdirOffset = 0
    entry.Unused1 = 0
    entry.Unused2 = 0
    entry.CreationTime = 0
    entry.LastAccessTime = 0
    entry.LastWriteTime = 0
    entry._Unknown = b"\x00" * 4
    entry.__anonymous_1__.HardLink = 0
    entry.Streams = len(stream_items)
    entry.ShortNameLength = 0
    entry.FileNameLength = len(encoded_name)
    entry.FileName = node.name

    # The entry hash is only used for a sole default stream. A stream table carries every hash itself,
    # and the root has no content identity.
    if node.name and "" in node.streams and not named:
        entry.Hash = node.stream_hashes.get("", hashlib.sha1(node.streams[""]).digest())
    else:
        entry.Hash = ZERO_HASH

    out = bytearray(entry.dumps())
    if encoded_name:
        out += b"\x00\x00"
    out += b"\x00" * (entry.Length - len(out))

    for stream_name, content in stream_items:
        _align(out)
        encoded_stream_name = stream_name.encode("utf-16-le")
        stream = c_wim._STREAMENTRY()
        stream.Length = _align_value(len(c_wim._STREAMENTRY) + len(encoded_stream_name) + 2)
        stream.Unused1 = 0
        stream.Hash = node.stream_hashes.get(stream_name, hashlib.sha1(content).digest())
        stream.StreamNameLength = len(encoded_stream_name)
        stream.StreamName = stream_name
        out += stream.dumps()
        out += b"\x00\x00"
        out += b"\x00" * (stream.Length - len(c_wim._STREAMENTRY) - len(encoded_stream_name) - 2)

    return bytes(out)


def _short_header(size: int, flags: int, offset: int) -> c_wim._RESHDR_DISK_SHORT:
    return c_wim._RESHDR_DISK_SHORT(
        Size=size.to_bytes(7, "little"),
        Flags=RESHDR_FLAG(flags),
        Offset=offset,
        OriginalSize=size,
    )


def _align(buf: bytearray, alignment: int = 8) -> None:
    buf += b"\x00" * (-len(buf) % alignment)


def _align_value(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & -alignment


def _patch_int(buf: bytearray, offset: int, value: int, size: int) -> None:
    buf[offset : offset + size] = value.to_bytes(size, "little")


def load(data: bytes) -> WIM:
    """Load synthetic WIM bytes, imported lazily to keep this module import-light."""
    from dissect.archive.wim.wim import WIM

    return WIM(io.BytesIO(data))
