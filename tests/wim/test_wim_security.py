from __future__ import annotations

import io
import struct

import pytest

from dissect.archive.exception import InvalidSecurityBlockError, InvalidSecurityIdError
from dissect.archive.wim.wim import NO_SECURITY_ID, WIM

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_NORMAL = 0x80
RESHDR_FLAG_METADATA = 0x02

SD1_ROOT = b"SD1-ROOT-DESCRIPTOR!" + b"\x01" * 12  # 32 bytes
SD1_FILE = b"SD1-FILE-DESCRIPTOR!" + b"\x02" * 12  # 32 bytes
SD2_ROOT = b"SD2-ROOT-DESCRIPTOR!" + b"\x03" * 12  # 32 bytes
SD2_FILE = b"SD2-FILE-DESCRIPTOR!" + b"\x04" * 12  # 32 bytes


def _reshdr_short(size: int, flags: int, offset: int, original_size: int) -> bytes:
    return size.to_bytes(7, "little") + bytes([flags]) + struct.pack("<QQ", offset, original_size)


def _security_block(descriptors: list[bytes | None]) -> bytes:
    sizes = [len(descriptor) if descriptor else 0 for descriptor in descriptors]
    total_length = 8 + 8 * len(descriptors) + sum(sizes)
    return (
        struct.pack("<II", total_length, len(descriptors))
        + b"".join(struct.pack("<Q", size) for size in sizes)
        + b"".join(descriptor for descriptor in descriptors if descriptor)
    )


def _direntry(security_id: int, *, attributes: int = FILE_ATTRIBUTE_NORMAL, subdir_offset: int = 0, name: str = "") -> bytes:
    name_bytes = name.encode("utf-16-le")
    entry = struct.pack(
        "<QIIQQQQQQ20s4s8sHHH",
        0,  # Length, patched below
        attributes,
        security_id,
        subdir_offset,
        0,  # Unused1
        0,  # Unused2
        0,  # CreationTime
        0,  # LastAccessTime
        0,  # LastWriteTime
        b"\x00" * 20,  # Hash
        b"\x00" * 4,  # _Unknown
        b"\x00" * 8,  # ReparseTag / HardLink union
        0,  # Streams
        0,  # ShortNameLength
        len(name_bytes),
    )
    if name_bytes:
        entry += name_bytes + b"\x00\x00"
    return struct.pack("<Q", len(entry)) + entry[8:]


def _image_metadata(descriptors: list[bytes | None], root_security_id: int, children: list[tuple[str, int]]) -> bytes:
    security = _security_block(descriptors)
    security += b"\x00" * (-len(security) % 8)

    root = _direntry(root_security_id, attributes=FILE_ATTRIBUTE_DIRECTORY, subdir_offset=len(security) + 104)
    metadata = security + root + b"\x00" * (-(len(security) + len(root)) % 8)

    for name, security_id in children:
        entry = _direntry(security_id, name=name)
        metadata += entry + b"\x00" * (-len(entry) % 8)

    return metadata + b"\x00" * 8  # end of directory marker


def _wim(metadata_images: list[bytes]) -> bytes:
    offset = 208
    table = b""
    body = b""
    for metadata in metadata_images:
        table += _reshdr_short(len(metadata), RESHDR_FLAG_METADATA, offset, len(metadata))
        table += struct.pack("<HI20s", 1, 1, b"\x00" * 20)
        body += metadata
        offset += len(metadata)

    header = (
        b"MSWIM\x00\x00\x00"
        + struct.pack("<IIII", 208, 0x10D00, 0, 0x8000)
        + b"\x00" * 16  # WIMGuid
        + struct.pack("<HHI", 1, 1, len(metadata_images))
        + _reshdr_short(len(table), 0, offset, len(table))  # OffsetTable
        + b"\x00" * 24  # XmlData
        + b"\x00" * 24  # BootMetadata
        + struct.pack("<I", 0)  # BootIndex
        + b"\x00" * 24  # Integrity
        + b"\x00" * 60  # Unused
    )
    assert len(header) == 208
    return header + body + table


@pytest.fixture
def wim_two_images() -> WIM:
    image1 = _image_metadata(
        [SD1_ROOT, None, SD1_FILE],
        0,
        [("a.txt", 2), ("b.txt", 1), ("c.txt", NO_SECURITY_ID)],
    )
    image2 = _image_metadata(
        [SD2_ROOT, None, SD2_FILE],
        0,
        [("a.txt", 2), ("b.txt", 1), ("c.txt", NO_SECURITY_ID)],
    )
    return WIM(io.BytesIO(_wim([image1, image2])))


def test_security_block_preserves_index_space(wim_two_images: WIM) -> None:
    image1, _ = wim_two_images.images()

    # The empty middle entry must occupy its index, not shift later entries
    assert len(image1.security) == 3
    assert image1.security.descriptors == [SD1_ROOT, None, SD1_FILE]

    assert image1.root.security_id == 0
    assert image1.root.security_descriptor == SD1_ROOT

    # SecurityId 2 must resolve to the third descriptor, not the shifted second one
    entry = image1.get("a.txt")
    assert entry.security_id == 2
    assert entry.security_descriptor == SD1_FILE

    # SecurityId 1 is an empty placeholder: a valid index without a descriptor
    entry = image1.get("b.txt")
    assert entry.security_id == 1
    assert entry.security_descriptor is None

    # NO_SECURITY_ID means the entry has no descriptor at all
    entry = image1.get("c.txt")
    assert entry.security_id == NO_SECURITY_ID
    assert entry.security_descriptor is None


def test_security_tables_are_per_image(wim_two_images: WIM) -> None:
    image1, image2 = wim_two_images.images()

    assert image1.security is not image2.security

    # Both images use the same security IDs but must resolve to their own table's bytes
    assert image1.get("a.txt").security_id == image2.get("a.txt").security_id == 2
    assert image1.get("a.txt").security_descriptor == SD1_FILE
    assert image2.get("a.txt").security_descriptor == SD2_FILE
    assert image1.root.security_descriptor == SD1_ROOT
    assert image2.root.security_descriptor == SD2_ROOT


def test_security_id_out_of_range_raises() -> None:
    image = _image_metadata([SD1_ROOT, None, SD1_FILE], 0, [("evil.txt", 7)])
    wim = WIM(io.BytesIO(_wim([image])))
    entry = next(iter(wim.images())).get("evil.txt")

    assert entry.security_id == 7
    with pytest.raises(InvalidSecurityIdError):
        entry.security_descriptor


def _wim_with_security_block(security: bytes) -> WIM:
    security += b"\x00" * (-len(security) % 8)
    root = _direntry(0, attributes=FILE_ATTRIBUTE_DIRECTORY, subdir_offset=len(security) + 104)
    metadata = security + root + b"\x00" * 8
    wim = WIM(io.BytesIO(_wim([metadata])))
    next(iter(wim.images()))
    return wim


def test_security_block_total_length_mismatch_raises() -> None:
    security = bytearray(_security_block([SD1_ROOT, None, SD1_FILE]))
    struct.pack_into("<I", security, 0, struct.unpack_from("<I", security, 0)[0] + 8)
    with pytest.raises(InvalidSecurityBlockError):
        _wim_with_security_block(bytes(security))


def test_security_block_unaligned_entry_lengths_tile_exactly() -> None:
    # Real WIM files store exact descriptor lengths (e.g. 164, 152) packed contiguously,
    # so non-8-aligned lengths are valid as long as they tile the data region exactly
    sd_a = b"\x01" * 164
    sd_b = b"\x02" * 152
    wim = _wim_with_security_block(_security_block([sd_a, None, sd_b]))
    image = next(iter(wim.images()))

    assert image.security.descriptors == [sd_a, None, sd_b]
    assert image.security.get(0) == sd_a
    assert image.security.get(2) == sd_b


def test_security_block_gap_between_entries_raises() -> None:
    # Entry lengths sum to less than the declared data region: entries do not tile exactly
    security = struct.pack("<IIQQ", 8 + 16 + 40, 2, 32, 16) + SD1_ROOT + SD2_ROOT[:16]
    with pytest.raises(InvalidSecurityBlockError):
        _wim_with_security_block(security)


def test_security_block_truncated_descriptor_raises() -> None:
    # The metadata stream ends in the middle of the declared 32 byte descriptor
    metadata = struct.pack("<IIQ", 8 + 8 + 32, 1, 32) + SD1_ROOT[:16]
    wim = WIM(io.BytesIO(_wim([metadata])))
    with pytest.raises(InvalidSecurityBlockError):
        next(iter(wim.images()))
