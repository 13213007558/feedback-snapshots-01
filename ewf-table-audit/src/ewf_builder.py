"""Minimal, dependency-free EWF (E01) segment builder.

Only implements the subset of the Expert Witness Compression Format needed to
build reproducible single-segment images containing a ``table`` and a
``table2`` section. Layout and checksum conventions follow the structures
parsed by :mod:`dissect.evidence.ewf` (see ``dissect/evidence/ewf/c_ewf.py``):

* file signature (13 bytes) + section descriptors (76 bytes each);
* section descriptor Adler-32 covers the first 72 bytes of the descriptor;
* table inner Adler-32 covers the first 20 bytes of the 24 byte table header;
* uncompressed chunks end with a 4 byte Adler-32 over the chunk data;
* compressed chunks are a bare zlib stream (no trailing checksum).

The builder deliberately exposes raw chunk placement so that a second,
divergent block map can be generated without rewriting any chunk data.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

SEGMENT_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
SEGMENT_HEADER = SEGMENT_SIGNATURE + struct.pack("<BHH", 0x01, 1, 0x00)
DESCRIPTOR_SIZE = 76
TABLE_HEADER_SIZE = 24
CHUNK_SIZE = 512
SECTORS_PER_CHUNK = 1
SECTOR_SIZE = 512
COMPRESSED_FLAG = 0x80000000
OFFSET_MASK = 0x7FFFFFFF


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def descriptor(section_type: str, next_offset: int, size: int) -> bytes:
    """Serialize a 76 byte EWF section descriptor."""
    name = section_type.encode("ascii").ljust(16, b"\x00")
    head = struct.pack("<16sQQ", name, next_offset, size)
    padding = b"\x00" * 40
    checksum = adler32(head + padding)
    return head + padding + struct.pack("<I", checksum)


def volume_section(number_of_chunks: int, number_of_sectors: int) -> tuple[int, bytes]:
    """Return (raw_section_size, section_bytes) for a classic ``volume`` section.

    Field layout mirrors ``c_ewf.VolumeSection``: 1052 byte body, 1128 raw.
    """
    body = b"".join(
        [
            struct.pack("<B", 0x01),  # MediaType.Fixed
            b"\x00" * 3,
            struct.pack("<IIII", number_of_chunks, SECTORS_PER_CHUNK, SECTOR_SIZE, number_of_sectors),
            struct.pack("<Q", number_of_sectors),
            struct.pack("<III", 0, 0, 0),  # CHS cylinders/heads/sectors
            struct.pack("<B", 0x01),  # MediaFlags.Image
            b"\x00" * 3,
            struct.pack("<II", 0, 0),  # palm volume start, unknown
            struct.pack("<I", 0),  # SMART logs start sector
            struct.pack("<B", 0x00),  # CompressionLevel.None
            b"\x00" * 3,
            struct.pack("<II", 0, 0),  # error granularity, unknown
            b"\x00" * 16,  # set identifier
            b"\x00" * 959,  # pad (963 in cstruct includes 4 bytes of alignment)
            b"EVF\x09\x0d",  # signature char[5]
        ]
    )
    if len(body) != 1048:
        raise AssertionError(f"unexpected volume body size before checksum {len(body)}")
    body += struct.pack("<I", adler32(body))
    if len(body) != 1052:
        raise AssertionError(f"unexpected volume body size with checksum {len(body)}")
    raw_size = DESCRIPTOR_SIZE + len(body)
    return raw_size, descriptor("volume", 0, raw_size) + body


def header_section() -> bytes:
    payload = b"1\r\nmain\r\ncase_number\tevidence_number\r\naudit\tbuilt-by-ewf-table-audit\r\n"
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(payload) + compressor.flush()
    raw_size = DESCRIPTOR_SIZE + len(compressed)
    return descriptor("header", 0, raw_size) + compressed


@dataclass
class ChunkRecord:
    """A placed chunk inside the data section."""

    index: int
    logical_data: bytes
    compressed: bool
    stored_bytes: bytes
    relative_offset: int

    @property
    def descriptor_word(self) -> int:
        word = self.relative_offset
        if self.compressed:
            word |= COMPRESSED_FLAG
        return word


@dataclass
class BuildResult:
    image: bytes
    base_offset: int
    data_start: int
    data_end: int
    chunks: list[ChunkRecord]
    table_offset: int
    table2_offset: int
    done_offset: int
    number_of_chunks: int


def table_section(entries: list[int], base_offset: int) -> bytes:
    # Inner checksum covers only the first 16 bytes of the 24 byte header
    # (number_of_entries, reserved, base_offset); matches EnCase/libewf output.
    header_head = struct.pack("<IIQ", len(entries), 0, base_offset)
    header = header_head + b"\x00" * 4 + struct.pack("<I", adler32(header_head))
    body = header + b"".join(struct.pack("<I", entry) for entry in entries)
    raw_size = DESCRIPTOR_SIZE + len(body)
    return descriptor("table", 0, raw_size) + body


def table2_section(entries: list[int], base_offset: int) -> bytes:
    section = table_section(entries, base_offset)
    return section.replace(b"table\x00" + b"\x00" * 10, b"table2\x00" + b"\x00" * 9, 1)


def build_image(
    chunks: list[bytes],
    *,
    compress: bool = False,
    table_entries: list[int] | None = None,
    table2_entries: list[int] | None = None,
    extra_blob: bytes | None = None,
) -> BuildResult:
    """Build a single segment EWF image around the supplied logical chunks.

    When ``table_entries`` / ``table2_entries`` are omitted both block maps are
    generated from the actual chunk placement. Explicit maps allow divergent or
    corrupted tables to be constructed while keeping the chunk data intact.

    ``extra_blob`` is appended to the sectors section after the regular chunks;
    callers supplying their own table entries can map into that extra area. This
    is used to create two complete, physically present block sets inside one
    image so that two structurally valid tables can legitimately disagree.
    """
    number_of_chunks = len(chunks)
    if any(len(chunk) > CHUNK_SIZE for chunk in chunks):
        raise ValueError("chunks must fit in one EWF chunk")
    if number_of_chunks == 0:
        raise ValueError("at least one chunk is required")

    header = header_section()
    volume_raw_size, volume = volume_section(number_of_chunks, number_of_chunks)
    sectors_offset = len(SEGMENT_HEADER) + len(header) + len(volume)
    base_offset = sectors_offset + DESCRIPTOR_SIZE

    records: list[ChunkRecord] = []
    blob = bytearray()
    relative = 0
    for index, logical in enumerate(chunks):
        if compress:
            stored = zlib.compress(logical, 9)
        else:
            stored = logical + struct.pack("<I", adler32(logical))
        records.append(
            ChunkRecord(
                index=index,
                logical_data=logical,
                compressed=compress,
                stored_bytes=stored,
                relative_offset=relative,
            )
        )
        blob.extend(stored)
        relative += len(stored)

    if extra_blob:
        blob.extend(extra_blob)

    data_body = bytes(blob)
    data_raw_size = DESCRIPTOR_SIZE + len(data_body)

    # Conventional EWF layout places the chunk bytes in a "sectors" section
    # before the block maps (as in EnCase/libewf output). The table base
    # offset therefore points at the body of the sectors section; a second
    # "data" section after table2 mirrors the reference fixtures. Keeping the
    # chunks before the tables is what gives the last chunk a deterministic
    # end boundary for both table and table2.
    sectors = descriptor("sectors", 0, data_raw_size) + data_body
    trailing_data = descriptor("data", 0, DESCRIPTOR_SIZE)

    # Block maps precede the trailing data section. Chunk offsets are relative
    # to the sectors section body, whose absolute position is known once the
    # header and volume sizes are fixed.
    primary_entries = table_entries or [record.descriptor_word for record in records]
    backup_entries = table2_entries if table2_entries is not None else list(primary_entries)
    primary = table_section(primary_entries, base_offset)
    backup = table2_section(backup_entries, base_offset)
    done = descriptor("done", 0, 0)

    chain = [header, volume, sectors, primary, backup, trailing_data, done]
    offsets: list[int] = []
    cursor = len(SEGMENT_HEADER)
    for part in chain:
        offsets.append(cursor)
        cursor += len(part)
    (
        header_offset,
        volume_offset,
        sectors_offset,
        table_offset,
        table2_offset,
        data_offset,
        done_offset,
    ) = offsets
    if base_offset != sectors_offset + DESCRIPTOR_SIZE:
        raise AssertionError("base offset must point at the sectors section body")

    image = bytearray(SEGMENT_HEADER)
    for index, (part, self_offset) in enumerate(zip(chain, offsets)):
        next_offset = done_offset if index == len(chain) - 1 else offsets[index + 1]
        image += _relink(part, self_offset, next_offset)

    return BuildResult(
        image=bytes(image),
        base_offset=base_offset,
        data_start=base_offset,
        data_end=base_offset + len(data_body),
        chunks=records,
        table_offset=table_offset,
        table2_offset=table2_offset,
        done_offset=done_offset,
        number_of_chunks=number_of_chunks,
    )


def _relink(section: bytes, self_offset: int, next_offset: int) -> bytes:
    """Rewrite a section descriptor's ``next`` field and its Adler-32."""
    head = section[:32]
    name, _old_next, size = struct.unpack("<16sQQ", head)
    new_head = struct.pack("<16sQQ", name, next_offset, size)
    padding = section[32:72]
    checksum = adler32(new_head + padding)
    return new_head + padding + struct.pack("<I", checksum) + section[76:]


def build_divergent_image(chunks_a: list[bytes], chunks_b: list[bytes]) -> tuple[bytes, dict]:
    """Build an image with two legal tables mapping two separate chunk sets.

    Layout::

        header, volume, sectors(set A), table(A), sectors(set B), table2(B),
        data, done

    Both table sections carry valid descriptor and inner checksums; each base
    offset points at its own sectors section body. The two tables therefore
    disagree without any malformed field, reproducing the hardest case: two
    complete, checksum-valid candidates with no internal tie-breaker.
    """
    if len(chunks_a) != len(chunks_b):
        raise ValueError("both chunk sets must contain the same number of chunks")

    def stored(chunk: bytes) -> bytes:
        return chunk + struct.pack("<I", adler32(chunk))

    blob_a = b"".join(stored(chunk) for chunk in chunks_a)
    blob_b = b"".join(stored(chunk) for chunk in chunks_b)

    def entries_for(chunk_set: list[bytes]) -> list[int]:
        entries = []
        relative = 0
        for chunk in chunk_set:
            entries.append(relative)
            relative += len(stored(chunk))
        return entries

    header = header_section()
    _, volume = volume_section(len(chunks_a), len(chunks_a))

    entries_a = entries_for(chunks_a)
    entries_b = entries_for(chunks_b)
    table_a = table_section(entries_a, 0)
    table_b = table2_section(entries_b, 0)
    part_sizes = [
        len(header),
        len(volume),
        DESCRIPTOR_SIZE + len(blob_a),
        len(table_a),
        DESCRIPTOR_SIZE + len(blob_b),
        len(table_b),
        DESCRIPTOR_SIZE,  # trailing data
        DESCRIPTOR_SIZE,  # done
    ]

    offsets = []
    cursor = len(SEGMENT_HEADER)
    for size in part_sizes:
        offsets.append(cursor)
        cursor += size
    (
        header_off,
        volume_off,
        sectors_a_off,
        table_a_off,
        sectors_b_off,
        table_b_off,
        data_off,
        done_off,
    ) = offsets
    base_a = sectors_a_off + DESCRIPTOR_SIZE
    base_b = sectors_b_off + DESCRIPTOR_SIZE
    table_a = table_section(entries_a, base_a)
    table_b = table2_section(entries_b, base_b)

    chain = [
        header,
        volume,
        descriptor("sectors", 0, DESCRIPTOR_SIZE + len(blob_a)) + blob_a,
        table_a,
        descriptor("sectors", 0, DESCRIPTOR_SIZE + len(blob_b)) + blob_b,
        table_b,
        descriptor("data", 0, DESCRIPTOR_SIZE),
        descriptor("done", 0, 0),
    ]
    image = bytearray(SEGMENT_HEADER)
    for index, (part, self_offset) in enumerate(zip(chain, offsets)):
        next_offset = done_off if index == len(chain) - 1 else offsets[index + 1]
        image += _relink(part, self_offset, next_offset)

    info = {
        "base_a": base_a,
        "base_b": base_b,
        "table_a_offset": table_a_off,
        "table_b_offset": table_b_off,
        "entries_a": entries_a,
        "entries_b": entries_b,
    }
    return bytes(image), info
