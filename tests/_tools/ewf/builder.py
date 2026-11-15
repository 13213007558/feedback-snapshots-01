"""Deterministic EWF builder for metadata regression tests and the sample image.

The builder writes real segment headers, section descriptors, a volume section, one chunk and a
table, so the result can be opened by :class:`dissect.evidence.ewf.EWF` without any shortcuts.
Header payloads are supplied as text and encoded by the caller, which allows tests to pin down
absolute byte offsets inside a decompressed header.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from dissect.evidence.ewf import c_ewf

SEGMENT_HEADER_SIZE = len(c_ewf.SegmentHeader)
SECTION_DESCRIPTOR_SIZE = len(c_ewf.SectionDescriptor)
TABLE_HEADER_SIZE = len(c_ewf.TableSection)
CHUNK_SIZE = 512
SEGMENT_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


def adler32(data: bytes) -> int:
    """Calculate the Adler-32 checksum used by EWF descriptors and sections."""
    return zlib.adler32(data) & 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class HeaderSpec:
    """A header or header2 section to embed in the sample image."""

    kind: str
    text: str
    encoding: str = "utf-8"
    payload_prefix: bytes = b""
    corrupt_descriptor_checksum: bool = False

    def encode(self) -> bytes:
        """Return the compressed payload as it should be stored in the section."""
        data = self.payload_prefix + self.text.encode(self.encoding)
        return zlib.compress(data)


@dataclass(frozen=True, slots=True)
class BuiltImage:
    """A built EWF image and the independently calculated header locations."""

    data: bytes
    header_offsets: list[int]
    header_payloads: list[bytes]
    chunk_offset: int


def _descriptor(kind: str, next_offset: int, size: int, *, corrupt_checksum: bool = False) -> bytes:
    body = struct.pack("<16sQQ", kind.encode(), next_offset, size) + b"\x00" * 40
    checksum = adler32(body)
    if corrupt_checksum:
        checksum ^= 0xFFFFFFFF
    return body + struct.pack("<I", checksum)


def _section(kind: str, payload: bytes, next_offset: int, *, corrupt_checksum: bool = False) -> bytes:
    size = SECTION_DESCRIPTOR_SIZE + len(payload)
    return _descriptor(kind, next_offset, size, corrupt_checksum=corrupt_checksum) + payload


def _volume_section() -> bytes:
    """Build a VolumeSectionSmart for one 512-byte chunk."""
    body = bytearray(94)
    struct.pack_into(
        "<IIIII",
        body,
        0,
        0,  # reserved_1
        1,  # number_of_chunks
        CHUNK_SIZE,  # sectors_per_chunk, with one byte per sector
        1,  # bytes_per_sector
        CHUNK_SIZE,  # number_of_sectors
    )
    body[85:90] = b"STD\x00\x00"
    struct.pack_into("<I", body, 90, adler32(bytes(body[:90])))
    return bytes(body)


def _table_payload(chunk_offset: int) -> bytes:
    entry = SECTION_DESCRIPTOR_SIZE  # chunk data starts after the sectors descriptor
    entries = struct.pack("<I", entry)
    return struct.pack("<IIQII", 1, 0, chunk_offset, 0, 0) + entries + struct.pack("<I", adler32(entries))


def _hash_payload(md5_hex: str) -> bytes:
    md5 = bytes.fromhex(md5_hex)
    if len(md5) != 16:
        raise ValueError("md5 must be 16 bytes")
    unknown = b"\x00" * 16
    return md5 + unknown + struct.pack("<I", adler32(md5 + unknown))


def build_image(
    headers: list[HeaderSpec],
    *,
    chunk_data: bytes = b"A" * CHUNK_SIZE,
    declared_md5: str | None = None,
) -> BuiltImage:
    """Build a single segment EWF image with the given header sections in front."""
    if len(chunk_data) != CHUNK_SIZE:
        raise ValueError(f"chunk data must be exactly {CHUNK_SIZE} bytes")

    declared_md5 = declared_md5 or hashlib.md5(chunk_data).hexdigest()
    if len(declared_md5) != 32:
        raise ValueError("declared_md5 must be a 32 character hex digest")

    encoded_headers = [spec.encode() for spec in headers]
    volume = _volume_section()
    chunk = chunk_data + struct.pack("<I", adler32(chunk_data))
    hash_payload = _hash_payload(declared_md5)

    offset = SEGMENT_HEADER_SIZE
    header_offsets: list[int] = []
    for payload in encoded_headers:
        header_offsets.append(offset)
        offset += SECTION_DESCRIPTOR_SIZE + len(payload)

    volume_offset = offset
    offset += SECTION_DESCRIPTOR_SIZE + len(volume)

    sectors_offset = offset
    offset += SECTION_DESCRIPTOR_SIZE + len(chunk)

    table_offset = offset
    table_payload = _table_payload(sectors_offset)
    offset += SECTION_DESCRIPTOR_SIZE + len(table_payload)

    hash_offset = offset
    offset += SECTION_DESCRIPTOR_SIZE + len(hash_payload)

    done_offset = offset

    data = bytearray(
        c_ewf.SegmentHeader(
            signature=SEGMENT_SIGNATURE,
            fields_start=1,
            segment_number=1,
            fields_end=0,
        ).dumps()
    )

    for idx, (spec, payload) in enumerate(zip(headers, encoded_headers, strict=True)):
        data += _section(
            spec.kind,
            payload,
            header_offsets[idx + 1] if idx + 1 < len(headers) else volume_offset,
            corrupt_checksum=spec.corrupt_descriptor_checksum,
        )

    data += _section("volume", volume, sectors_offset)
    data += _section("sectors", chunk, table_offset)
    data += _section("table", table_payload, hash_offset)
    data += _section("hash", hash_payload, done_offset)
    data += _section("done", b"", done_offset)

    return BuiltImage(
        data=bytes(data),
        header_offsets=header_offsets,
        header_payloads=encoded_headers,
        chunk_offset=sectors_offset + SECTION_DESCRIPTOR_SIZE,
    )


def build_segmented_image(first_headers: list[HeaderSpec], second_headers: list[HeaderSpec]) -> list[bytes]:
    """Build a two segment image with headers in both segments.

    The first segment carries the volume, the single chunk and the table. The second segment
    only carries header sections, which is enough to exercise cross-segment metadata selection.
    """
    first = build_image(first_headers)

    segments: list[bytes] = [first.data]
    done_offset = SEGMENT_HEADER_SIZE
    for spec in second_headers:
        done_offset += SECTION_DESCRIPTOR_SIZE + len(spec.encode())

    second = bytearray(
        c_ewf.SegmentHeader(
            signature=SEGMENT_SIGNATURE,
            fields_start=1,
            segment_number=2,
            fields_end=0,
        ).dumps()
    )

    offset = SEGMENT_HEADER_SIZE
    for idx, spec in enumerate(second_headers):
        payload = spec.encode()
        next_offset = offset + SECTION_DESCRIPTOR_SIZE + len(payload) if idx + 1 < len(second_headers) else done_offset
        second += _section(spec.kind, payload, next_offset)
        offset = next_offset

    second += _section("done", b"", done_offset)
    segments.append(bytes(second))

    return segments


def _metadata_conflict_headers() -> list[HeaderSpec]:
    corrupt_header2 = (
        "3\n"
        "main\n"
        "a\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc\n"
        "corrupt description\tCASE-2026-CORRUPT\tE-0\tMallory Example\t\t\t\tAcqTool\tLinux"
        "\t2026-02-03 00:00:00\t2026-02-03 00:00:00\t0\t\n"
    )

    healthy_header2 = (
        "3\n"
        "main\n"
        "a\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\tdc\tc\n"
        "Primary description\tCASE-2026-001\tE-1\tAlice Example\t\t\t\tAcqTool 1.2\tLinux"
        "\t2026-02-03 04:05:06\t2026-02-03 04:05:06\t0\t\tCASE-2026-777\n"
    )

    legacy_header = (
        "1\n"
        "main\n"
        "c\tn\ta\te\tav\tov\tm\tu\tp\n"
        "CASE-2026-999\tE-2\tLegacy description\tJosé Example\tAcqTool 1.0 ©\tWindows"
        "\t2026-02-03 05:05:06\t2026-02-03 05:05:06\t0\n"
    )

    return [
        HeaderSpec(
            "header2",
            corrupt_header2,
            encoding="utf-16-le",
            payload_prefix=b"\xff\xfe",
            corrupt_descriptor_checksum=True,
        ),
        HeaderSpec("header2", healthy_header2, encoding="utf-16-le", payload_prefix=b"\xff\xfe"),
        HeaderSpec("header", legacy_header, encoding="cp1252"),
    ]


def build_metadata_conflict_image() -> BuiltImage:
    """Build the sample image with conflicting declarations and missing fields.

    The declared MD5 equals the real content hash, which proves that a declaration is still not
    a verification: the parser reports what the image claims, not that the claim was checked.
    """
    chunk_data = bytes(range(256)) * 2
    return build_image(
        _metadata_conflict_headers(),
        chunk_data=chunk_data,
        declared_md5=hashlib.md5(chunk_data).hexdigest(),
    )


def write_sample(path: Path) -> None:
    """Write the metadata conflict sample to a path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_metadata_conflict_image().data)


if __name__ == "__main__":
    write_sample(Path(__file__).parents[2] / "_data" / "ewf" / "metadata-conflicts" / "image.E01")
