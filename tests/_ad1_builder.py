"""Build small, deterministic AD1 images for chunk-table tests."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from io import BytesIO

from dissect.evidence.ad1 import AD1, FileEntry
from dissect.evidence.ad1.c_ad1 import c_ad1

SEGMENT_HEADER_SIZE = 512
LOGICAL_IMAGE_NAME = b"E:\\AD1_test"
ENTRY_OFFSET = 0x100
TABLE_OFFSET = 0x148
DATA_OFFSET = 0x180
META_OFFSET = 0x400
DEFAULT_CHUNK_SIZE = 0x1000


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class Sample:
    """A synthetic AD1 image with helpers to patch attacker-controlled fields."""

    data: bytearray
    table_offset: int
    data_offset: int
    meta_offset: int
    chunk_size: int = DEFAULT_CHUNK_SIZE
    chunks: list[bytes] = field(default_factory=list)
    payloads: list[bytes] = field(default_factory=list)
    declared_size: int = 0

    @property
    def size(self) -> int:
        return len(self.data)

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, SEGMENT_HEADER_SIZE + offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, SEGMENT_HEADER_SIZE + offset)[0]

    def patch_u64(self, offset: int, value: int) -> None:
        struct.pack_into("<Q", self.data, SEGMENT_HEADER_SIZE + offset, value)

    def patch_u32(self, offset: int, value: int) -> None:
        struct.pack_into("<I", self.data, SEGMENT_HEADER_SIZE + offset, value)

    def table_u64(self, index: int) -> int:
        return self.u64(self.table_offset + 8 + index * 8)

    def patch_table(self, index: int, value: int) -> None:
        self.patch_u64(self.table_offset + 8 + index * 8, value)

    def set_num_chunks(self, value: int) -> None:
        self.patch_u64(self.table_offset, value)

    def set_meta(self, value: int) -> None:
        self.patch_u64(ENTRY_OFFSET + 16, value)

    def set_zlib_meta(self, value: int) -> None:
        self.patch_u64(ENTRY_OFFSET + 24, value)

    def set_size(self, value: int) -> None:
        self.patch_u64(ENTRY_OFFSET + 32, value)

    def set_chunk_size(self, value: int) -> None:
        self.patch_u32(24, value)


def build(
    chunks: list[bytes],
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    payloads: list[bytes] | None = None,
    declared_size: int | None = None,
    table_offset: int = TABLE_OFFSET,
    data_offset: int = DATA_OFFSET,
    meta_offset: int | None = None,
    write_empty_table: bool = False,
) -> Sample:
    """Build a one-file AD1 image.

    ``chunks`` describes the logical chunk sizes. ``payloads`` can override the
    compressed bytes, which is useful for building compressed bombs without
    materializing the expanded data in the test process. An empty file gets no chunk
    table unless ``write_empty_table`` is set.
    """
    if payloads is None:
        payloads = [zlib.compress(chunk, 9) for chunk in chunks]
    if len(payloads) != len(chunks):
        raise ValueError("payloads must match chunks")
    if declared_size is None:
        declared_size = sum(map(len, chunks))

    has_table = bool(chunks) or write_empty_table
    table_size = 8 + 8 * len(chunks) if has_table else 0
    data_offset = max(data_offset, _align(table_offset + table_size))

    offsets = []
    cursor = data_offset
    for payload in payloads:
        offsets.append(cursor)
        cursor += len(payload)

    meta_offset = cursor if meta_offset is None else meta_offset

    name = b"payload.bin"
    entry = c_ad1.FileEntry(
        next=0,
        child=0,
        meta=meta_offset,
        zlib_meta=table_offset if has_table else 0,
        size=declared_size,
        type=c_ad1.EntryType.File,
        name_len=len(name),
        name=name,
        parent_index=0,
    )
    size_field = str(declared_size).encode()
    meta = c_ad1.FileMeta(
        next=0,
        category=3,
        type=c_ad1.MetaType.FileSize,
        len=len(size_field),
        data=size_field,
    )
    logical_size = max(meta_offset + len(meta.dumps()), data_offset + sum(map(len, payloads)), META_OFFSET)
    logical = bytearray(logical_size)

    logical[ENTRY_OFFSET : ENTRY_OFFSET + len(entry.dumps())] = entry.dumps()
    if has_table:
        logical[table_offset : table_offset + 8] = struct.pack("<Q", len(chunks))
        for i, offset in enumerate(offsets):
            logical[table_offset + 8 + i * 8 : table_offset + 16 + i * 8] = struct.pack("<Q", offset)
        for offset, payload in zip(offsets, payloads, strict=True):
            logical[offset : offset + len(payload)] = payload
    logical[meta_offset : meta_offset + len(meta.dumps())] = meta.dumps()

    header = c_ad1.LogicalImageHeader(
        magic=b"ADLOGICALIMAGE\0\0",
        version=4,
        unk1=1,
        chunk_size=chunk_size,
        metadata_offset=0,
        first_file_offset=ENTRY_OFFSET,
        name_len=len(LOGICAL_IMAGE_NAME),
        unk_magic=b"AD\0\0",
        name_offset=0x5C,
        attr_guid_offset=0,
        unk2=0,
        locs_guid_offset=0,
        unk3=0,
        name=LOGICAL_IMAGE_NAME,
    )
    logical[0 : len(header.dumps())] = header.dumps()

    segment = c_ad1.SegmentedFileHeader(
        magic=b"ADSEGMENTEDFILE\0",
        unk1=1,
        unk2=2,
        segment_number=1,
        segment_count=1,
        segment_size=len(logical) + SEGMENT_HEADER_SIZE,
        logical_image_offset=SEGMENT_HEADER_SIZE,
    )
    return Sample(
        data=bytearray(segment.dumps()) + logical,
        table_offset=table_offset,
        data_offset=data_offset,
        meta_offset=meta_offset,
        chunk_size=chunk_size,
        chunks=chunks,
        payloads=payloads,
        declared_size=declared_size,
    )


def open_entry(sample: Sample) -> tuple[AD1, FileEntry]:
    """Open the synthetic image and return the AD1 and its only file entry."""
    fs = AD1(BytesIO(bytes(sample.data)))
    return fs, fs.get("E:/AD1_test/payload.bin")
