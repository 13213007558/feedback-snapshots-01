from __future__ import annotations

import io
import random
from types import SimpleNamespace
from typing import BinaryIO

from dissect.vmfs.address import FileBlockAddr, LargeFileBlockAddr, SmallFileBlockAddr
from dissect.vmfs.c_vmfs import FS3_ZeroLevelAddrType
from dissect.vmfs.descriptor import BlockReadReason, FileDescriptor5, FileDescriptor6, ReadSegment

FILE_BLOCK_SHIFT = 20
FILE_BLOCK_SIZE = 1 << FILE_BLOCK_SHIFT
TBZ_GRANULARITY_SHIFT = 17
TBZ_GRANULARITY = 1 << TBZ_GRANULARITY_SHIFT
SFB_TO_LFB_SHIFT = 9
STALE_BYTE = 0xEE


def _vmfs6(disk: BinaryIO, resource: object | None = None) -> SimpleNamespace:
    """Build a minimal fake VMFS6 with the geometry relevant for TBZ handling."""
    return SimpleNamespace(
        is_vmfs5=False,
        is_vmfs6=True,
        fh=disk,
        _file_block_size_shift=FILE_BLOCK_SHIFT,
        _sub_block_size_shift=16,
        _sfb_size=512,
        descriptor=SimpleNamespace(sfbToLfbShift=SFB_TO_LFB_SHIFT),
        resources=SimpleNamespace(get=lambda type: resource),
    )


def _descriptor6(vmfs: SimpleNamespace, block_size: int, num_blocks: int) -> FileDescriptor6:
    descriptor = FileDescriptor6.__new__(FileDescriptor6)
    descriptor.vmfs = vmfs
    descriptor.metadata = SimpleNamespace(
        type=1,
        blockSize=block_size,
        fileLength=block_size * num_blocks,
        blockOffsetShift=FILE_BLOCK_SHIFT,
        tbzGranularityShift=TBZ_GRANULARITY_SHIFT,
        zeroLevelAddrType=FS3_ZeroLevelAddrType.FILE_BLOCK,
    )
    return descriptor


def _descriptor5(disk: BinaryIO, block_size: int, num_blocks: int) -> FileDescriptor5:
    descriptor = FileDescriptor5.__new__(FileDescriptor5)
    descriptor.vmfs = SimpleNamespace(
        is_vmfs5=True, is_vmfs6=False, fh=disk, resources=SimpleNamespace(get=lambda type: None)
    )
    descriptor.metadata = SimpleNamespace(
        type=1,
        blockSize=block_size,
        fileLength=block_size * num_blocks,
        blockOffsetShift=block_size.bit_length() - 1,
        tbzGranularityShift=block_size.bit_length() - 1,
        zeroLevelAddrType=FS3_ZeroLevelAddrType.FILE_BLOCK,
    )
    return descriptor


def _expected_sfb_block(content_byte: int, tbz: int) -> bytearray:
    """The logical contents of an SFB: on-disk bytes for data regions and zeros for TBZ regions."""
    block = bytearray(bytes([content_byte]) * FILE_BLOCK_SIZE)
    for region in range(8):
        if (tbz >> region) & 1:
            start = region * TBZ_GRANULARITY
            block[start : start + TBZ_GRANULARITY] = b"\x00" * TBZ_GRANULARITY
    return block


def test_sfb_partial_tbz_full_and_random_reads() -> None:
    """A partially TBZ marked SFB keeps its on-disk content outside the marked regions."""
    # A block where only some TBZ bits are set, surrounded by a normal and a fully marked block
    tbz_bitmaps = [0x00, (1 << 2) | (1 << 5), 0xFF, 0x00]
    expected_reasons = [
        BlockReadReason.DATA,
        BlockReadReason.DATA,
        BlockReadReason.TO_BE_ZEROED,
        BlockReadReason.DATA,
        BlockReadReason.DATA,
        BlockReadReason.TO_BE_ZEROED,
        BlockReadReason.DATA,
        BlockReadReason.DATA,
    ]
    num_blocks = len(tbz_bitmaps)
    addresses = [SmallFileBlockAddr.make(cluster=0, resource=i, tbz=tbz) for i, tbz in enumerate(tbz_bitmaps)]

    # Lay out a disk with distinct, non-zero content per block. The no-resource SFB path derives the disk offset as
    # ((cluster * sfb_size) + resource) << blockOffsetShift.
    offsets = []
    for address in addresses:
        cluster, resource = SmallFileBlockAddr.parse(address)
        offsets.append(((cluster * 512) + resource) << FILE_BLOCK_SHIFT)

    disk = bytearray(bytes([STALE_BYTE]) * (max(offsets) + FILE_BLOCK_SIZE))
    content_bytes = [0x11, 0x22, 0x33, 0x44]
    for offset, content_byte in zip(offsets, content_bytes):
        disk[offset : offset + FILE_BLOCK_SIZE] = bytes([content_byte]) * FILE_BLOCK_SIZE

    vmfs = _vmfs6(io.BytesIO(bytes(disk)))
    descriptor = _descriptor6(vmfs, FILE_BLOCK_SIZE, num_blocks)
    descriptor._offset_to_block_address = lambda offset: addresses[offset >> FILE_BLOCK_SHIFT]

    stream = descriptor.open()

    expected = b"".join(_expected_sfb_block(byte, tbz) for byte, tbz in zip(content_bytes, tbz_bitmaps))

    # Whole-file read
    assert stream.read() == expected

    # The non-TBZ regions of a marked block still return their original, non-zero content
    partial_block = stream.readoffset(FILE_BLOCK_SIZE, FILE_BLOCK_SIZE)
    assert partial_block[:TBZ_GRANULARITY] == bytes([content_bytes[1]]) * TBZ_GRANULARITY
    # And the marked regions are logical zeros even though the disk holds non-zero stale bytes
    assert partial_block[2 * TBZ_GRANULARITY : 3 * TBZ_GRANULARITY] == b"\x00" * TBZ_GRANULARITY
    assert partial_block[5 * TBZ_GRANULARITY : 6 * TBZ_GRANULARITY] == b"\x00" * TBZ_GRANULARITY

    # explain() attributes each region correctly, including that the zeros come from the TBZ marker
    segments = list(stream.explain(FILE_BLOCK_SIZE, FILE_BLOCK_SIZE))
    assert segments == [
        ReadSegment(FILE_BLOCK_SIZE + region * TBZ_GRANULARITY, TBZ_GRANULARITY, reason)
        for region, reason in enumerate(expected_reasons)
    ]

    # The zeros are explicitly attributable to the marker, not to the disk being zero originally
    zero_segments = list(stream.explain(FILE_BLOCK_SIZE + 2 * TBZ_GRANULARITY, TBZ_GRANULARITY))
    assert all(segment.reason == BlockReadReason.TO_BE_ZEROED for segment in zero_segments)
    assert disk[offsets[1] + 2 * TBZ_GRANULARITY] == content_bytes[1]

    # Random slices across block and TBZ boundaries
    rng = random.Random(0xC0FFEE)
    for _ in range(500):
        start = rng.randrange(len(expected))
        length = rng.randrange(1, len(expected) - start + 1)
        assert stream.readoffset(start, length) == expected[start : start + length]


def test_lfb_partial_tbz_does_not_leak_past_bitmap() -> None:
    """An LFB is larger than the 8 TBZ bitmap regions; bytes past the bitmap stay on-disk content."""
    block_size = FILE_BLOCK_SIZE << SFB_TO_LFB_SHIFT
    address = LargeFileBlockAddr.make(block=7, tbz=(1 << 0) | (1 << 7))
    base_offset = LargeFileBlockAddr.parse(address) << (FILE_BLOCK_SHIFT + SFB_TO_LFB_SHIFT)

    disk = bytearray(bytes([STALE_BYTE]) * (base_offset + block_size))
    disk[base_offset : base_offset + block_size] = b"\x77" * block_size

    resource = SimpleNamespace(resolve_address=lambda address: base_offset)
    vmfs = _vmfs6(io.BytesIO(bytes(disk)), resource=resource)
    descriptor = _descriptor6(vmfs, block_size, 1)
    descriptor._offset_to_block_address = lambda offset: address

    stream = descriptor.open()
    first_megabyte = stream.readoffset(0, FILE_BLOCK_SIZE)

    # Marked first and last bitmap regions are logical zero despite non-zero disk content
    assert first_megabyte[:TBZ_GRANULARITY] == b"\x00" * TBZ_GRANULARITY
    assert first_megabyte[7 * TBZ_GRANULARITY : 8 * TBZ_GRANULARITY] == b"\x00" * TBZ_GRANULARITY
    # The unmarked regions in between retain the original on-disk bytes
    assert first_megabyte[TBZ_GRANULARITY : 7 * TBZ_GRANULARITY] == b"\x77" * (6 * TBZ_GRANULARITY)

    # Everything beyond the 8 bitmap regions is plain data: no wrapped-around zeroing, no stale leak
    assert stream.readoffset(FILE_BLOCK_SIZE, TBZ_GRANULARITY) == b"\x77" * TBZ_GRANULARITY
    segments = list(stream.explain(0, FILE_BLOCK_SIZE))
    assert [segment.reason for segment in segments] == [
        BlockReadReason.TO_BE_ZEROED,
        *([BlockReadReason.DATA] * 6),
        BlockReadReason.TO_BE_ZEROED,
    ]


def test_vmfs5_single_tbz_bit_covers_whole_block() -> None:
    """On VMFS5 the single TBZ bit zeroes the whole block and sparse holes are a separate reason."""
    block_size = 1 << 16
    addresses = [FileBlockAddr.make(block=3, tbz=0), FileBlockAddr.make(block=4, tbz=1)]

    disk = bytearray(bytes([STALE_BYTE]) * (6 * block_size))
    disk[3 * block_size : 4 * block_size] = b"\x55" * block_size
    # The TBZ block holds stale bytes on disk; these must never be returned
    disk[4 * block_size : 5 * block_size] = b"\x66" * block_size

    descriptor = _descriptor5(io.BytesIO(bytes(disk)), block_size, 2)
    descriptor._offset_to_block_address = lambda offset: addresses[offset >> 16]

    stream = descriptor.open()
    assert stream.read() == b"\x55" * block_size + b"\x00" * block_size
    assert [segment.reason for segment in stream.explain(0, 2 * block_size)] == [
        BlockReadReason.DATA,
        BlockReadReason.TO_BE_ZEROED,
    ]

    # A zero pointer is an unallocated sparse hole, not a TBZ marker
    descriptor._offset_to_block_address = lambda offset: 0
    assert stream.readoffset(0, 16) == b"\x00" * 16
    assert list(stream.explain(0, 16)) == [ReadSegment(0, 16, BlockReadReason.UNALLOCATED)]


def test_vmfs6_unallocated_block_is_distinct_from_tbz() -> None:
    """A missing block address reads as zero but is explained as unallocated rather than TBZ."""
    vmfs = _vmfs6(io.BytesIO(bytes([STALE_BYTE]) * FILE_BLOCK_SIZE))
    descriptor = _descriptor6(vmfs, FILE_BLOCK_SIZE, 1)
    descriptor._offset_to_block_address = lambda offset: 0

    stream = descriptor.open()
    assert stream.read(TBZ_GRANULARITY) == b"\x00" * TBZ_GRANULARITY
    assert list(stream.explain(0, TBZ_GRANULARITY)) == [
        ReadSegment(0, TBZ_GRANULARITY, BlockReadReason.UNALLOCATED)
    ]
