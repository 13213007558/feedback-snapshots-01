"""Synthetic WIM builders for security-table tests.

The bundled WIM samples only contain a single image with a fully populated
security table. Edge cases such as empty security slots, missing descriptors,
and duplicate SecurityIds across images cannot be produced from those samples,
so these builders assemble minimal valid WIM files from the same :mod:`c_wim`
structures the parser reads.

Security descriptor payloads in the fixtures are deliberately *not* valid
Windows self-relative descriptors: they are tagged byte patterns. That makes
every byte-level association assertion unambiguous, while the parser stays
agnostic about the contents of the descriptors it returns.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, NamedTuple

from dissect.archive.wim.c_wim import FILE_ATTRIBUTE, RESHDR_FLAG, c_wim

if TYPE_CHECKING:
    from collections.abc import Iterable

DIRECTORY_ENTRY_HEADER = len(c_wim._DIRENTRY)
WIM_HEADER = len(c_wim.WIMHEADER_V1_PACKED)
RESOURCE_HEADER = len(c_wim._RESHDR_DISK)

NO_SECURITY = 0xFFFFFFFF
LIST_TERMINATOR = b"\x00" * 8


class FileSpec(NamedTuple):
    """A file in a synthetic image and its raw SecurityId."""

    name: str
    security_id: int


def align8(value: int) -> int:
    """Round ``value`` up to the next 8 byte boundary."""
    return (value + 7) & ~7


def descriptor(tag: str, size: int = 40) -> bytes:
    """A deterministic descriptor payload, unique per tag."""
    if size < 2 or len(tag) > size - 2:
        raise ValueError("tag does not fit descriptor")
    return b"\x01\x00" + tag.encode() + b"\x00" * (size - 2 - len(tag))


def security_block(entries: Iterable[bytes | None]) -> bytes:
    """Build a security data block.

    A ``None`` entry becomes a zero-length slot: it occupies an index but no
    payload bytes. Slots are packed back to back, with no per-entry padding.
    """
    entries = list(entries)
    lengths = [0 if entry is None else len(entry) for entry in entries]
    total_length = 8 + (8 * len(entries)) + sum(lengths)
    header = struct.pack("<II", total_length, len(entries))
    length_array = b"".join(struct.pack("<Q", length) for length in lengths)
    payload = b"".join(entry for entry in entries if entry is not None)
    return header + length_array + payload


def directory_entry(
    name: str = "",
    security_id: int = 0,
    attributes: FILE_ATTRIBUTE = FILE_ATTRIBUTE.ARCHIVE,
    subdir_offset: int = 0,
) -> bytes:
    """Build one directory entry with no extra streams."""
    name_bytes = name.encode("utf-16-le")
    length = align8(DIRECTORY_ENTRY_HEADER + len(name_bytes) + 2)

    entry = c_wim._DIRENTRY()
    for field, value in {
        "Length": length,
        "Attributes": FILE_ATTRIBUTE(attributes),
        "SecurityId": security_id,
        "SubdirOffset": subdir_offset,
        "Unused1": 0,
        "Unused2": 0,
        "CreationTime": 0,
        "LastAccessTime": 0,
        "LastWriteTime": 0,
        "Hash": b"\x00" * 20,
        "_Unknown": b"\x00" * 4,
        "Streams": 0,
        "ShortNameLength": 0,
        "FileNameLength": len(name_bytes),
    }.items():
        setattr(entry, field, value)

    body = entry.dumps() + name_bytes + b"\x00\x00"
    return body + (b"\x00" * (length - len(body)))


def metadata_stream(security: bytes, files: Iterable[FileSpec | tuple[str, int]]) -> bytes:
    """Build a metadata stream from a security block and a flat file listing."""
    files = [FileSpec(*file) for file in files]

    root_start = align8(len(security))
    root_length = align8(DIRECTORY_ENTRY_HEADER + 2)
    children_start = root_start + root_length

    root = directory_entry(attributes=FILE_ATTRIBUTE.DIRECTORY, subdir_offset=children_start)
    children = b"".join(directory_entry(file.name, file.security_id) for file in files)

    return security + (b"\x00" * (root_start - len(security))) + root + children + LIST_TERMINATOR


def wim_file(metadata_streams: Iterable[bytes]) -> bytes:
    """Build a WIM file with one image per metadata stream, in order."""
    metadata_streams = list(metadata_streams)
    image_count = len(metadata_streams)

    table_offset = WIM_HEADER
    data_offset = align8(table_offset + (RESOURCE_HEADER * image_count))

    resources = []
    offsets = []
    for index, metadata in enumerate(metadata_streams):
        offsets.append(data_offset)
        resources.append(
            c_wim._RESHDR_DISK(
                Base=_resource_short(len(metadata), data_offset, RESHDR_FLAG.METADATA),
                PartNumber=1,
                RefCount=1,
                Hash=struct.pack("<I", index + 1) * 5,
            )
        )
        data_offset = align8(data_offset + len(metadata))

    table = b"".join(resource.dumps() for resource in resources)
    zero = _resource_short(0, 0, RESHDR_FLAG(0))

    header = c_wim.WIMHEADER_V1_PACKED(
        ImageTag=b"MSWIM\x00\x00\x00",
        Size=WIM_HEADER,
        Version=c_wim.VERSION_DEFAULT,
        Flags=c_wim.HEADER_FLAG(0),
        CompressionSize=0,
        WIMGuid=b"\x00" * 16,
        PartNumber=1,
        TotalParts=1,
        ImageCount=image_count,
        OffsetTable=_resource_short(len(table), table_offset, RESHDR_FLAG.METADATA),
        XmlData=zero,
        BootMetadata=zero,
        BootIndex=0,
        Integrity=zero,
        Unused=b"\x00" * 60,
    )

    out = bytearray(header.dumps() + table)
    for metadata, offset in zip(metadata_streams, offsets):
        out += b"\x00" * (offset - len(out))
        out += metadata

    return bytes(out)


def _resource_short(size: int, offset: int, flags: RESHDR_FLAG) -> c_wim._RESHDR_DISK_SHORT:
    return c_wim._RESHDR_DISK_SHORT(
        Size=size.to_bytes(7, "little"),
        Flags=flags,
        Offset=offset,
        OriginalSize=size,
    )
