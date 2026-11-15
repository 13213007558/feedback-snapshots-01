from __future__ import annotations

import gzip
import io
from collections.abc import Callable

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.address import FileBlockAddr, LargeFileBlockAddr, SmallFileBlockAddr
from dissect.vmfs.c_vmfs import FS3_AddrType
from dissect.vmfs.descriptor import BlockMapping
from tests.conftest import absolute_path

TBZ_SHIFT = 10
GRANULE_SIZE = 1 << TBZ_SHIFT
GRANULE_COUNT = 8
BLOCK_SIZE = GRANULE_SIZE * GRANULE_COUNT
# Only some of the TBZ bits are set: granules 1, 3 and 5 are pending zeroing.
PARTIAL_TBZ = 0b00101010


def _patterned_disk() -> bytes:
    return b"".join(bytes([0x40 + granule]) * GRANULE_SIZE for granule in range(GRANULE_COUNT))


def _load_vmfs6_with_tbz_block(address: int) -> tuple[vmfs.VMFS, vmfs.FileDescriptor]:
    """Open the VMFS6 test image and retarget a descriptor at an in-memory, partially TBZ marked block."""
    with gzip.open(absolute_path("_data/vmfs/vmfs6.bin.gz"), "rb") as fh:
        volume = io.BytesIO(fh.read())

    fs = vmfs.VMFS(lvm.LVM(volume).volumes[0].open())
    descriptor = fs.get("big")
    # Cache descriptor metadata from the real volume before retargeting the handle at the crafted block.
    _ = descriptor.metadata
    _ = descriptor.raw

    fs.fh = io.BytesIO(_patterned_disk())
    descriptor._offset_to_block_address = lambda offset: address
    descriptor.metadata.tbzGranularityShift = TBZ_SHIFT
    descriptor.metadata.blockSize = BLOCK_SIZE
    return fs, descriptor


def test_tbz_ranges_whole_block_vmfs5() -> None:
    """A VMFS5 style single TBZ bit always covers the whole block, regardless of the requested window."""
    mapping = BlockMapping(0, 0, 0, 0, FS3_AddrType.FILE_BLOCK, tbz=1)

    assert mapping.tbz_shift == 0
    assert list(mapping.tbz_ranges(0, GRANULE_SIZE)) == [(0, GRANULE_SIZE)]
    assert list(mapping.tbz_ranges(123, 456)) == [(0, 456)]


def test_tbz_ranges_granules_vmfs6() -> None:
    """Each set TBZ bit zeroes exactly one granule and partial windows are clipped to the requested region."""
    mapping = BlockMapping(0, 0, 0, 0, FS3_AddrType.LARGE_FILE_BLOCK, tbz=PARTIAL_TBZ, tbz_shift=TBZ_SHIFT)

    # A fully marked granule reports its whole window.
    assert list(mapping.tbz_ranges(GRANULE_SIZE, GRANULE_SIZE)) == [(0, GRANULE_SIZE)]
    # An unmarked granule reports nothing and keeps its on-disk contents.
    assert list(mapping.tbz_ranges(0, GRANULE_SIZE)) == []
    # A window crossing a granule boundary only reports the marked granule; the unmarked tail is left to disk.
    assert list(mapping.tbz_ranges(GRANULE_SIZE - 50, 200)) == [(50, 200)]


@pytest.mark.parametrize(
    ("address_factory", "addr_type"),
    [
        pytest.param(lambda tbz: LargeFileBlockAddr.make(block=0, tbz=tbz), FS3_AddrType.LARGE_FILE_BLOCK, id="lfb"),
        pytest.param(
            lambda tbz: SmallFileBlockAddr.make(cluster=0, resource=0, tbz=tbz),
            FS3_AddrType.SMALL_FILE_BLOCK,
            id="sfb",
        ),
    ],
)
def test_partial_tbz_full_read(address_factory: Callable[[int], int], addr_type: int) -> None:
    """A full block read keeps allocated data and only zeroes TBZ marked granules."""
    _, descriptor = _load_vmfs6_with_tbz_block(address_factory(PARTIAL_TBZ))
    disk = _patterned_disk()

    result = descriptor.open().read(BLOCK_SIZE)
    assert len(result) == BLOCK_SIZE

    for granule in range(GRANULE_COUNT):
        chunk = result[granule * GRANULE_SIZE : (granule + 1) * GRANULE_SIZE]
        disk_chunk = disk[granule * GRANULE_SIZE : (granule + 1) * GRANULE_SIZE]
        if granule in (1, 3, 5):
            # The disk still holds stale bytes here, but the TBZ marker forces logical zeros.
            assert disk_chunk != b"\x00" * GRANULE_SIZE
            assert chunk == b"\x00" * GRANULE_SIZE
        else:
            assert chunk == disk_chunk

    mapping = descriptor.mapping_at(GRANULE_SIZE)
    assert mapping.addr_type == addr_type
    assert mapping.tbz == PARTIAL_TBZ
    assert not mapping.sparse


@pytest.mark.parametrize(
    ("start", "length"),
    [
        (0, GRANULE_SIZE),
        (GRANULE_SIZE + 7, 257),
        (3 * GRANULE_SIZE - 50, 150),
        (5 * GRANULE_SIZE + 123, 777),
        (2 * GRANULE_SIZE + 10, 4 * GRANULE_SIZE),
        (BLOCK_SIZE - 333, 333),
    ],
)
def test_partial_tbz_random_slices(start: int, length: int) -> None:
    """Random and unaligned slices never leak stale bytes from a marked granule."""
    _, descriptor = _load_vmfs6_with_tbz_block(LargeFileBlockAddr.make(block=0, tbz=PARTIAL_TBZ))
    disk = _patterned_disk()

    stream = descriptor.open()
    stream.seek(start)
    result = stream.read(length)
    assert len(result) == length

    for offset in range(length):
        absolute = start + offset
        granule = absolute // GRANULE_SIZE
        expected = 0 if granule in (1, 3, 5) else disk[absolute]
        assert result[offset] == expected


def test_tbz_zero_is_distinguishable_from_disk_zero() -> None:
    """Marker-produced zeros are attributable to the TBZ bitmap, not to an actually zeroed disk region."""
    _, descriptor = _load_vmfs6_with_tbz_block(LargeFileBlockAddr.make(block=0, tbz=PARTIAL_TBZ))

    marked = descriptor.mapping_at(GRANULE_SIZE)
    assert not marked.sparse
    assert marked.tbz == PARTIAL_TBZ
    assert list(marked.tbz_ranges(marked.block_relative_offset, GRANULE_SIZE)) == [(0, GRANULE_SIZE)]

    unmarked = descriptor.mapping_at(0)
    assert unmarked.tbz == PARTIAL_TBZ
    assert list(unmarked.tbz_ranges(unmarked.block_relative_offset, GRANULE_SIZE)) == []


def test_sparse_hole_is_distinct_from_tbz_block() -> None:
    """A null pointer is a genuinely unallocated hole and must not be confused with an allocated TBZ block."""
    _, descriptor = _load_vmfs6_with_tbz_block(0)

    hole = descriptor.mapping_at(0)
    assert hole.sparse
    assert hole.address == 0
    assert hole.tbz == 0xFF
    assert descriptor.open().read(1024) == b"\x00" * 1024


def test_vmfs5_whole_block_tbz() -> None:
    """VMFS5 keeps its whole-block TBZ behaviour while ordinary blocks still read from disk."""
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        volume = io.BytesIO(fh.read())

    fs = vmfs.VMFS(lvm.LVM(volume).volumes[0].open())
    descriptor = fs.get("big")
    _ = descriptor.metadata
    _ = descriptor.raw

    block_size = fs.file_block_size
    fs.fh = io.BytesIO(b"\x7e" * block_size)
    descriptor._offset_to_block_address = lambda offset: FileBlockAddr.make(block=0, tbz=1)

    mapping = descriptor.mapping_at(12345)
    assert mapping.addr_type == FS3_AddrType.FILE_BLOCK
    assert mapping.tbz == 1
    assert mapping.tbz_shift == 0
    assert descriptor.open().read(block_size) == b"\x00" * block_size

    descriptor._offset_to_block_address = lambda offset: FileBlockAddr.make(block=0, tbz=0)
    assert descriptor.open().read(16) == b"\x7e" * 16
