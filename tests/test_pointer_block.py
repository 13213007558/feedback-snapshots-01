from __future__ import annotations

import io
import struct
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from dissect.vmfs.address import (
    FileBlockAddr,
    FileDescriptorAddr,
    JournalBlockAddr,
    PointerBlock2Addr,
    PointerBlock2Addr64,
    PointerBlockAddr,
    PointerBlockAddr64,
    SmallFileBlockAddr,
)
from dissect.vmfs.c_vmfs import FS3_DescriptorType, FS3_ResourceTypeID, FS3_ZeroLevelAddrType
from dissect.vmfs.descriptor import (
    FileDescriptor5,
    FileDescriptor6,
    _get_uint32_index,
    _get_uint64_index,
)
from dissect.vmfs.resource import (
    FileBlockResourceVMFS5,
    ResourceManager,
    SmallFileBlockResourceVMFS6,
)

if TYPE_CHECKING:
    from dissect.vmfs.descriptor import FileDescriptor

# Small block size to keep the test readable, the addressing logic is identical to larger block sizes
BLOCK_SIZE = 0x1000
BLOCK_SHIFT = 12

# VMFS5 pointer blocks hold 1024 uint32 entries, VMFS6 pointer blocks hold 8192 uint64 entries
VMFS5_PTR_BLOCK_NUM_SHIFT = 10
VMFS5_PTR_BLOCK_SIZE = 1024 * 4
VMFS6_PTR_BLOCK_NUM_SHIFT = 13
VMFS6_PTR_BLOCK_SIZE = 8192 * 8

VMFS6_SFB_PER_CLUSTER = 16

# A VMFS5 file block address with the highest bit of the 32-bit address set (block 0x2000000)
FB5_HIGH = FileBlockAddr.make(block=0x2000000)
FB5_HIGH_OFFSET = 0x2000000 * BLOCK_SIZE  # 128 GiB into the volume
assert FB5_HIGH == 0x80000001

# VMFS5 PB/PB2 addresses with the highest bit set (resource >= 0x8 sets bit 31)
PB5_HIGH = PointerBlockAddr.make(cluster=0x12345, resource=0x8)
PB25_HIGH = PointerBlock2Addr.make(cluster=0x23456, resource=0xF)
assert PB5_HIGH & 0x80000000 and PB25_HIGH & 0x80000000

# A VMFS6 small file block address with the highest bit of the 64-bit address set (resource >= 0x1000)
SFB6_HIGH = SmallFileBlockAddr.make(cluster=0x40000000, resource=0x1000)
SFB6_HIGH_OFFSET = ((0x40000000 * VMFS6_SFB_PER_CLUSTER) + 0x1000) << BLOCK_SHIFT  # ~4 PiB into the volume
assert SFB6_HIGH & 0x8000000000000000

# VMFS6 PB/PB2 addresses with the highest bit set (resource >= 0x80 sets bit 63)
PB6_HIGH = PointerBlockAddr64.make(cluster=0x123456789, resource=0x80)
PB26_HIGH = PointerBlock2Addr64.make(cluster=0xABCDEF123, resource=0xFF)
assert PB6_HIGH & 0x8000000000000000 and PB26_HIGH & 0x8000000000000000


class MappedStream:
    """A sparse file-like object that maps offsets to data.

    Lets us simulate a very large volume, with data at very high offsets, without actually
    allocating one. Negative seeks and reads from unmapped regions raise errors, so any
    incorrect address calculation is caught immediately instead of silently reading garbage.
    """

    def __init__(self, mapping: dict[int, bytes] | None = None) -> None:
        self.mapping = mapping or {}
        self.pos = 0
        self.seeks: list[int] = []

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence != io.SEEK_SET:
            raise NotImplementedError
        if offset < 0:
            raise ValueError(f"negative seek position {offset}")
        self.pos = offset
        self.seeks.append(offset)
        return offset

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise NotImplementedError

        buf = bytearray()
        offset = self.pos
        remaining = size
        while remaining > 0:
            for start, data in self.mapping.items():
                if start <= offset < start + len(data):
                    chunk = data[offset - start : offset - start + remaining]
                    break
            else:
                raise KeyError(f"read from unmapped offset {offset:#x}")
            buf += chunk
            offset += len(chunk)
            remaining -= len(chunk)

        self.pos = offset
        return bytes(buf)


class FakePointerBlockResource:
    """Serves pointer block contents from a mapping of address to bytes.

    Records every read address so tests can verify the traversed address hierarchy.
    """

    def __init__(self, mapping: dict[int, bytes], log: list[int]) -> None:
        self.mapping = mapping
        self.log = log

    def read(self, address: int) -> bytes:
        self.log.append(address)
        return self.mapping[address]


class FakeLeafResource:
    """Stand-in for a resource that should never be consulted for invalid address types."""

    def __init__(self, offset: int) -> None:
        self.offset = offset
        self.calls: list[int] = []

    def resolve_address(self, address: int) -> int:
        self.calls.append(address)
        return self.offset


def _make_pointer_block(entries: list[int], entry_size: int, total_size: int) -> bytes:
    fmt = "<I" if entry_size == 4 else "<Q"
    return b"".join(struct.pack(fmt, entry) for entry in entries).ljust(total_size, b"\x00")


def _make_vmfs5(volume: MappedStream, pointer_blocks: dict[int, bytes], resource_log: list[int]):
    vmfs = SimpleNamespace(
        is_vmfs5=True,
        is_vmfs6=False,
        fh=volume,
        _ptr_block_num_shift=VMFS5_PTR_BLOCK_NUM_SHIFT,
        _fd_data_addrs_offset=1024,
        _fd_data_addrs_size=1024,
        _fd_max_data_addrs=256,
    )
    vmfs.resources = ResourceManager(vmfs)

    fbb = object.__new__(FileBlockResourceVMFS5)
    fbb.fd = SimpleNamespace(block_size=BLOCK_SIZE)
    vmfs.resources.resources[FS3_ResourceTypeID.FILE_BLOCK.value] = fbb

    pb_resource = FakePointerBlockResource(pointer_blocks, resource_log)
    vmfs.resources.resources[FS3_ResourceTypeID.PTR_BLOCK.value] = pb_resource
    vmfs.resources.resources[FS3_ResourceTypeID.PTR2_BLOCK.value] = pb_resource

    return vmfs


def _make_vmfs6(volume: MappedStream, pointer_blocks: dict[int, bytes], resource_log: list[int]):
    vmfs = SimpleNamespace(
        is_vmfs5=False,
        is_vmfs6=True,
        fh=volume,
        _ptr_block_num_shift=VMFS6_PTR_BLOCK_NUM_SHIFT,
        _fd_data_addrs_offset=0x2000 - 2560,
        _fd_data_addrs_size=2560,
        _fd_max_data_addrs=320,
        _file_block_size_shift=BLOCK_SHIFT,
        _sub_block_size_shift=7,
        _sfb_size=VMFS6_SFB_PER_CLUSTER,
        descriptor=SimpleNamespace(sfbToLfbShift=3),
    )
    vmfs.resources = ResourceManager(vmfs)

    sfb = object.__new__(SmallFileBlockResourceVMFS6)
    sfb.vmfs = vmfs
    sfb.metadata = SimpleNamespace(resourcesPerCluster=VMFS6_SFB_PER_CLUSTER)
    vmfs.resources.resources[FS3_ResourceTypeID.SMALL_FILE_BLOCK.value] = sfb

    pb_resource = FakePointerBlockResource(pointer_blocks, resource_log)
    vmfs.resources.resources[FS3_ResourceTypeID.PTR_BLOCK.value] = pb_resource
    vmfs.resources.resources[FS3_ResourceTypeID.PTR2_BLOCK.value] = pb_resource

    return vmfs


def _make_fd(vmfs, cls: type[FileDescriptor], zla: FS3_ZeroLevelAddrType, blocks: list[int], size: int):
    fd = cls(vmfs, FileDescriptorAddr.make(0x40, 0))

    raw = bytearray(vmfs._fd_data_addrs_offset + vmfs._fd_data_addrs_size)
    fmt = "<I" if vmfs.is_vmfs5 else "<Q"
    for i, block in enumerate(blocks):
        struct.pack_into(fmt, raw, vmfs._fd_data_addrs_offset + (i * (4 if vmfs.is_vmfs5 else 8)), block)
    fd.__dict__["raw"] = memoryview(bytes(raw))
    fd.__dict__["metadata"] = SimpleNamespace(
        blockOffsetShift=BLOCK_SHIFT,
        blockSize=BLOCK_SIZE,
        fileLength=size,
        zeroLevelAddrType=zla,
        type=FS3_DescriptorType.REGFILE,
    )
    return fd


def _make_fd5(vmfs, zla: FS3_ZeroLevelAddrType, blocks: list[int], size: int) -> FileDescriptor5:
    return _make_fd(vmfs, FileDescriptor5, zla, blocks, size)


def _make_fd6(vmfs, zla: FS3_ZeroLevelAddrType, blocks: list[int], size: int) -> FileDescriptor6:
    return _make_fd(vmfs, FileDescriptor6, zla, blocks, size)


def test_get_uint32_index_unsigned() -> None:
    """Pointer block entries are unsigned 32-bit addresses, the highest bit may legitimately be set."""
    buf = struct.pack("<II", 0x80000001, 0xFFFFFFFF)
    assert _get_uint32_index(buf, 0) == 0x80000001
    assert _get_uint32_index(buf, 1) == 0xFFFFFFFF


def test_get_uint64_index() -> None:
    buf = struct.pack("<QQ", 0x8000000000000001, 0xFFFFFFFFFFFFFFFF)
    assert _get_uint64_index(buf, 0) == 0x8000000000000001
    assert _get_uint64_index(buf, 1) == 0xFFFFFFFFFFFFFFFF


def test_get_uint_index_truncated() -> None:
    """A truncated pointer array must raise a clear error instead of a bare struct.error."""
    with pytest.raises(ValueError, match="out of bounds"):
        _get_uint32_index(b"\x00" * 4, 1)

    with pytest.raises(ValueError, match="out of bounds"):
        _get_uint64_index(b"\x00" * 8, 1)


def test_vmfs5_direct_high_address() -> None:
    """VMFS5 direct file block with the highest address bit set resolves to the correct volume offset."""
    volume = MappedStream({FB5_HIGH_OFFSET: b"A" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs5(volume, {}, resource_log)

    fd = _make_fd5(vmfs, FS3_ZeroLevelAddrType.FILE_BLOCK, [FB5_HIGH, 0], 2 * BLOCK_SIZE)

    with fd.open() as fh:
        assert fh.read() == b"A" * BLOCK_SIZE + b"\x00" * BLOCK_SIZE

    # No indirection, the volume is sought directly to the high offset, the zero block is sparse
    assert resource_log == []
    assert volume.seeks == [FB5_HIGH_OFFSET]


def test_vmfs5_single_indirect_high_addresses() -> None:
    """VMFS5 single indirection through a PB with the highest bit set, containing a zero hole."""
    pointer_blocks = {PB5_HIGH: _make_pointer_block([FB5_HIGH, 0, 0], 4, VMFS5_PTR_BLOCK_SIZE)}
    volume = MappedStream({FB5_HIGH_OFFSET: b"B" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs5(volume, pointer_blocks, resource_log)

    fd = _make_fd5(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [PB5_HIGH], 3 * BLOCK_SIZE)

    with fd.open() as fh:
        assert fh.read() == b"B" * BLOCK_SIZE + b"\x00" * BLOCK_SIZE * 2

    # The PB was consulted once per file block, the volume was only sought for the non-sparse block
    assert resource_log == [PB5_HIGH] * 3
    assert volume.seeks == [FB5_HIGH_OFFSET]


def test_vmfs5_double_indirect_high_addresses() -> None:
    """VMFS5 double indirection FD -> PB2 -> PB -> FB, all with the highest address bit set."""
    pointer_blocks = {
        PB25_HIGH: _make_pointer_block([PB5_HIGH, 0], 4, VMFS5_PTR_BLOCK_SIZE),
        PB5_HIGH: _make_pointer_block([FB5_HIGH, 0], 4, VMFS5_PTR_BLOCK_SIZE),
    }
    volume = MappedStream({FB5_HIGH_OFFSET: b"C" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs5(volume, pointer_blocks, resource_log)

    fd = _make_fd5(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE, [PB25_HIGH], 1025 * BLOCK_SIZE)

    with fd.open() as fh:
        # Block 0 goes through the full FD -> PB2 -> PB -> FB chain
        fh.seek(0)
        assert fh.read(BLOCK_SIZE) == b"C" * BLOCK_SIZE
        assert resource_log == [PB25_HIGH, PB5_HIGH]
        assert volume.seeks == [FB5_HIGH_OFFSET]

        # Block 1 is a zero hole in the PB
        fh.seek(BLOCK_SIZE)
        assert fh.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
        assert resource_log == [PB25_HIGH, PB5_HIGH] * 2
        assert volume.seeks == [FB5_HIGH_OFFSET]

        # Block 1024 is a zero hole in the PB2, the PB is not even consulted
        fh.seek(1024 * BLOCK_SIZE)
        assert fh.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
        assert resource_log == [PB25_HIGH, PB5_HIGH] * 2 + [PB25_HIGH]
        assert volume.seeks == [FB5_HIGH_OFFSET]

    # Show the traversed address hierarchy for the first block
    print(
        "VMFS5 double indirection:",
        f"FD {FileDescriptorAddr(fd.address)!r}",
        f"-> {PointerBlock2Addr(PB25_HIGH)!r}",
        f"-> {PointerBlockAddr(PB5_HIGH)!r}",
        f"-> {FileBlockAddr(FB5_HIGH)!r}",
        f"-> volume offset {FB5_HIGH_OFFSET:#x}",
    )


def test_vmfs6_direct_high_address() -> None:
    """VMFS6 direct small file block with the highest address bit set resolves to the correct volume offset."""
    volume = MappedStream({SFB6_HIGH_OFFSET: b"D" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs6(volume, {}, resource_log)

    fd = _make_fd6(vmfs, FS3_ZeroLevelAddrType.FILE_BLOCK, [SFB6_HIGH, 0], 2 * BLOCK_SIZE)

    with fd.open() as fh:
        assert fh.read() == b"D" * BLOCK_SIZE + b"\x00" * BLOCK_SIZE

    assert resource_log == []
    assert volume.seeks == [SFB6_HIGH_OFFSET]


def test_vmfs6_single_indirect_high_addresses() -> None:
    """VMFS6 single indirection through a 64-bit PB with the highest bit set, containing a zero hole."""
    pointer_blocks = {PB6_HIGH: _make_pointer_block([SFB6_HIGH, 0, 0], 8, VMFS6_PTR_BLOCK_SIZE)}
    volume = MappedStream({SFB6_HIGH_OFFSET: b"E" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs6(volume, pointer_blocks, resource_log)

    fd = _make_fd6(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [PB6_HIGH], 3 * BLOCK_SIZE)

    with fd.open() as fh:
        assert fh.read() == b"E" * BLOCK_SIZE + b"\x00" * BLOCK_SIZE * 2

    assert resource_log == [PB6_HIGH] * 3
    assert volume.seeks == [SFB6_HIGH_OFFSET]


def test_vmfs6_double_indirect_high_addresses() -> None:
    """VMFS6 double indirection FD -> PB2 -> PB -> SFB, all with the highest address bit set."""
    pointer_blocks = {
        PB26_HIGH: _make_pointer_block([PB6_HIGH, 0], 8, VMFS6_PTR_BLOCK_SIZE),
        PB6_HIGH: _make_pointer_block([SFB6_HIGH, 0], 8, VMFS6_PTR_BLOCK_SIZE),
    }
    volume = MappedStream({SFB6_HIGH_OFFSET: b"F" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs6(volume, pointer_blocks, resource_log)

    fd = _make_fd6(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE, [PB26_HIGH], 8193 * BLOCK_SIZE)

    with fd.open() as fh:
        # Block 0 goes through the full FD -> PB2 -> PB -> SFB chain
        fh.seek(0)
        assert fh.read(BLOCK_SIZE) == b"F" * BLOCK_SIZE
        assert resource_log == [PB26_HIGH, PB6_HIGH]
        assert volume.seeks == [SFB6_HIGH_OFFSET]

        # Block 1 is a zero hole in the PB
        fh.seek(BLOCK_SIZE)
        assert fh.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
        assert resource_log == [PB26_HIGH, PB6_HIGH] * 2
        assert volume.seeks == [SFB6_HIGH_OFFSET]

        # Block 8192 is a zero hole in the PB2, the PB is not even consulted
        fh.seek(8192 * BLOCK_SIZE)
        assert fh.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
        assert resource_log == [PB26_HIGH, PB6_HIGH] * 2 + [PB26_HIGH]
        assert volume.seeks == [SFB6_HIGH_OFFSET]

    # Show the traversed address hierarchy for the first block
    print(
        "VMFS6 double indirection:",
        f"FD {FileDescriptorAddr(fd.address)!r}",
        f"-> {PointerBlock2Addr64(PB26_HIGH)!r}",
        f"-> {PointerBlockAddr64(PB6_HIGH)!r}",
        f"-> {SmallFileBlockAddr(SFB6_HIGH)!r}",
        f"-> volume offset {SFB6_HIGH_OFFSET:#x}",
    )


def test_vmfs5_invalid_leaf_type() -> None:
    """A leaf address that is not a data block must raise, not resolve through some other resource."""
    decoy_offset = 0x100000
    pointer_blocks = {PB5_HIGH: _make_pointer_block([FileDescriptorAddr.make(1, 1)], 4, VMFS5_PTR_BLOCK_SIZE)}
    volume = MappedStream({decoy_offset: b"X" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs5(volume, pointer_blocks, resource_log)

    # Register a resource for the (invalid) leaf address type, which previously would have been
    # silently resolved and returned as file data
    decoy = FakeLeafResource(decoy_offset)
    vmfs.resources.resources[FS3_ResourceTypeID.FILE_DESC.value] = decoy

    fd = _make_fd5(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [PB5_HIGH], BLOCK_SIZE)

    with pytest.raises(TypeError, match="Invalid block"), fd.open() as fh:
        fh.read()

    assert decoy.calls == []


def test_vmfs6_invalid_leaf_type() -> None:
    """A leaf address that is not a data block must raise, not resolve through some other resource."""
    decoy_offset = 0x100000
    pointer_blocks = {PB6_HIGH: _make_pointer_block([FileDescriptorAddr.make(1, 1)], 8, VMFS6_PTR_BLOCK_SIZE)}
    volume = MappedStream({decoy_offset: b"X" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs6(volume, pointer_blocks, resource_log)

    decoy = FakeLeafResource(decoy_offset)
    vmfs.resources.resources[FS3_ResourceTypeID.FILE_DESC.value] = decoy

    fd = _make_fd6(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [PB6_HIGH], BLOCK_SIZE)

    with pytest.raises(TypeError, match="Invalid block"), fd.open() as fh:
        fh.read()

    assert decoy.calls == []


def test_vmfs5_invalid_pointer_block_type() -> None:
    """An indirect address that is not a pointer block must raise a clear error."""
    volume = MappedStream({FB5_HIGH_OFFSET: b"A" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs5(volume, {}, resource_log)

    # ZLA says POINTER_BLOCK, but the address in the pointer array is a file block
    fd = _make_fd5(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [FB5_HIGH], BLOCK_SIZE)

    with pytest.raises(TypeError, match="Invalid pointer block address"), fd.open() as fh:
        fh.read()


def test_vmfs6_invalid_pointer_block_type() -> None:
    """An indirect address that is not a pointer block must raise a clear error."""
    volume = MappedStream()
    resource_log = []
    vmfs = _make_vmfs6(volume, {}, resource_log)

    # ZLA says POINTER_BLOCK, but the address in the pointer array is a file descriptor
    fd = _make_fd6(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [FileDescriptorAddr.make(1, 1)], BLOCK_SIZE)

    with pytest.raises(TypeError, match="Invalid pointer block address"), fd.open() as fh:
        fh.read()


def test_vmfs5_truncated_pointer_block() -> None:
    """A truncated pointer block must raise a clear error instead of reading out of bounds."""
    pointer_blocks = {PB5_HIGH: struct.pack("<I", FB5_HIGH)}  # Only a single entry
    volume = MappedStream({FB5_HIGH_OFFSET: b"A" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs5(volume, pointer_blocks, resource_log)

    fd = _make_fd5(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [PB5_HIGH], 2 * BLOCK_SIZE)

    with pytest.raises(ValueError, match="out of bounds"), fd.open() as fh:
        fh.read()


def test_vmfs6_truncated_pointer_block() -> None:
    """A truncated pointer block must raise a clear error instead of reading out of bounds."""
    pointer_blocks = {PB6_HIGH: struct.pack("<Q", SFB6_HIGH)}  # Only a single entry
    volume = MappedStream({SFB6_HIGH_OFFSET: b"D" * BLOCK_SIZE})
    resource_log = []
    vmfs = _make_vmfs6(volume, pointer_blocks, resource_log)

    fd = _make_fd6(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [PB6_HIGH], 2 * BLOCK_SIZE)

    with pytest.raises(ValueError, match="out of bounds"), fd.open() as fh:
        fh.read()


def test_resource_manager_read_unopened_type() -> None:
    """Reading an address for a resource type that is not opened must raise a clear error."""
    vmfs = _make_vmfs5(MappedStream(), {}, [])

    with pytest.raises(ValueError, match="No resource opened"):
        vmfs.resources.read(JournalBlockAddr.make(1, 1))
