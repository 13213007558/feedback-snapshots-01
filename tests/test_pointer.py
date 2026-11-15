"""Tests for pointer block (PB/PB2) address decoding and indirection.

These tests deliberately avoid large disk images. Instead they use a tiny in-memory "mapped" volume where only the
offsets that are actually read exist, so we can place blocks at very high addresses (including addresses whose top
bit is set) without allocating the backing storage.

They cover:
  - VMFS5 32-bit and VMFS6 64-bit pointers
  - direct, single-indirection and double-indirection modes
  - legal addresses with the top bit set
  - sparse zero holes at every indirection layer
  - explicit errors on illegal address types and truncated pointer arrays
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from dissect.vmfs.address import (
    FileBlockAddr,
    LargeFileBlockAddr,
    PointerBlock2Addr,
    PointerBlock2Addr64,
    PointerBlockAddr,
    PointerBlockAddr64,
    SmallFileBlockAddr,
    SubBlockAddr,
    SubBlockAddr64,
)
from dissect.vmfs.c_vmfs import FS3_AddrType, FS3_ZeroLevelAddrType
from dissect.vmfs.descriptor import (
    BlockStream,
    FileDescriptor5,
    FileDescriptor6,
    _get_uint32_index,
    _get_uint64_index,
)
from dissect.vmfs.exception import InvalidPointerBlockError

BLOCK_SIZE = 1024
# A payload byte that is distinct from the sparse-zero fill so misreads are obvious.
PAYLOAD = 0x5A


class MappedVolume:
    """A seekable in-memory volume backed by a sparse offset -> bytes mapping.

    Only explicitly written offsets occupy memory, so blocks can live at arbitrarily high (even 2**63-ish) offsets.
    A negative seek is rejected, mirroring a real file object and guarding against sign-extension bugs.
    """

    def __init__(self) -> None:
        self.blocks: dict[int, bytes] = {}
        self.pos = 0
        # Records the volume offsets actually read, in order. Used to assert the address hierarchy that was traversed.
        self.read_log: list[int] = []

    def write(self, offset: int, data: bytes) -> None:
        if offset < 0:
            raise ValueError(f"negative write offset {offset}")
        self.blocks[offset] = data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence != 0:
            raise ValueError("only SEEK_SET is supported")
        if offset < 0:
            raise ValueError(f"negative seek position {offset}")
        self.pos = offset
        return offset

    def tell(self) -> int:
        return self.pos

    def read(self, size: int = -1) -> bytes:
        self.read_log.append(self.pos)
        data = self.blocks.get(self.pos)
        if data is None:
            # Reading an unmapped high offset yields zeros, like an untouched block on disk.
            return b"\x00" * size if size not in (-1, None) else b""
        return data if size in (-1, None) else data[:size]


class FakeResource:
    """Minimal stand-in for a resource file that resolves addresses via a callback."""

    def __init__(self, resolve):
        self._resolve = resolve

    def resolve_address(self, address: int) -> int:
        return self._resolve(address)

    def read(self, address: int) -> bytes:
        # Mirror ResourceFile.read: resolve to a volume offset, then read the backing volume.
        offset = self.resolve_address(address)
        self._volume.seek(offset)
        return self._volume.read(self._resource_size)

    def bind(self, volume: MappedVolume, resource_size: int) -> FakeResource:
        self._volume = volume
        self._resource_size = resource_size
        return self


class FakeResourceManager:
    """ResourceManager double: routes by address type and fails explicitly on an unmappable type."""

    def __init__(self, resources: dict[int, FakeResource]):
        self._resources = resources

    def get(self, addr_type: int) -> FakeResource | None:
        return self._resources.get(addr_type)

    def read(self, address: int) -> bytes:
        resource = self._resources.get(address & 0b111)
        if resource is None:
            raise InvalidPointerBlockError(f"No resource available for address {address:#x}")
        return resource.read(address)


def _fake_vmfs(is_vmfs5: bool, volume: MappedVolume, resources: dict[int, FakeResource]) -> SimpleNamespace:
    """Build the small slice of a VMFS instance that the descriptor/stream code paths touch."""
    vmfs = SimpleNamespace()
    vmfs.fh = volume
    vmfs.is_vmfs5 = is_vmfs5
    vmfs.is_vmfs6 = not is_vmfs5
    vmfs.file_block_size = BLOCK_SIZE
    vmfs.sub_block_size = BLOCK_SIZE
    vmfs._file_block_size_shift = 10
    vmfs._sub_block_size_shift = 10
    vmfs.resources = FakeResourceManager(resources)

    if is_vmfs5:
        # Matches VMFS.__init__ for VMFS5.
        vmfs._fd_size = 2048
        vmfs._fd_data_size = 1024
        vmfs._fd_data_addrs_size = 1024
        vmfs._fd_meta_offset = 512
        vmfs._fd_data_offset = 1024
        vmfs._fd_data_addrs_offset = 1024
        vmfs._fd_max_data_addrs = 256
        vmfs._ptr_block_num_ptrs = 1024
        vmfs._ptr_block_num_shift = 10
        vmfs._sfb_size = 0
        vmfs.descriptor = SimpleNamespace(sfbToLfbShift=0)
    else:
        # Matches VMFS.__init__ for VMFS6 with mdAlignment 0x1000.
        vmfs.md_alignment = 0x1000
        vmfs._fd_size = 0x2000
        vmfs._fd_data_size = 0x1000 - 512
        vmfs._fd_data_addrs_size = 2560
        vmfs._fd_meta_offset = 0x1000
        vmfs._fd_data_offset = vmfs._fd_size - vmfs._fd_data_size
        vmfs._fd_data_addrs_offset = vmfs._fd_size - vmfs._fd_data_addrs_size
        vmfs._fd_max_data_addrs = 320
        vmfs._ptr_block_num_ptrs = 8192
        vmfs._ptr_block_num_shift = 13
        vmfs._sfb_size = min(0x2000, 0x20000000 // BLOCK_SIZE)
        vmfs.descriptor = SimpleNamespace(sfbToLfbShift=0)

    return vmfs


def _make_descriptor(
    vmfs: SimpleNamespace,
    zla: FS3_ZeroLevelAddrType,
    pointers: list[int],
    *,
    is_vmfs5: bool,
) -> FileDescriptor5 | FileDescriptor6:
    """Create a file descriptor whose block pointer array contains ``pointers``."""
    cls = FileDescriptor5 if is_vmfs5 else FileDescriptor6
    descriptor = cls.__new__(cls)
    descriptor.vmfs = vmfs
    descriptor.address = 0x400044

    width = 4 if is_vmfs5 else 8
    addrs = b"".join(pointer.to_bytes(width, "little", signed=False) for pointer in pointers)
    raw = bytearray(vmfs._fd_size)
    start = vmfs._fd_data_addrs_offset
    raw[start : start + len(addrs)] = addrs
    descriptor.raw = memoryview(raw)

    descriptor.metadata = SimpleNamespace(
        blockOffsetShift=10,
        blockSize=BLOCK_SIZE,
        zeroLevelAddrType=int(zla),
        fileLength=BLOCK_SIZE,
    )
    return descriptor


def _leaf_address(is_vmfs5: bool) -> tuple[int, int, str]:
    """Return a top-bit-set data-block address and the volume offset it resolves to."""
    if is_vmfs5:
        # Maximum 26-bit block number, which sets bit 31 of the uint32 address.
        block_num = 0x3FFFFFF
        address = FileBlockAddr.make(block_num)
        offset = block_num << 10
        return address, offset, f"FB block={block_num}"
    # Maximum 31-bit SFB cluster + max 13-bit resource: sets bit 63 of the uint64 address.
    cluster, resource = 0x7FFFFFFF, 0x1FFF
    address = SmallFileBlockAddr.make(cluster, resource)
    offset = ((cluster * 8192) + resource) << 10
    return address, offset, f"SFB cluster={cluster} resource={resource}"


def _pointer_address(is_vmfs5: bool) -> int:
    if is_vmfs5:
        # Max 22-bit cluster and max 4-bit resource -> bit 31 set.
        return PointerBlockAddr.make(0x3FFFFF, 0xF)
    # Max 36-bit cluster and max 8-bit resource -> bit 63 set.
    return PointerBlockAddr64.make(0xFFFFFFFFF, 0xFF)


def _pointer2_address(is_vmfs5: bool) -> int:
    if is_vmfs5:
        return PointerBlock2Addr.make(0x3FFFFF, 0xF)
    return PointerBlock2Addr64.make(0xFFFFFFFFF, 0xFF)


def _pointer_buffer(is_vmfs5: bool, entries: dict[int, int]) -> bytes:
    """Serialize a sparse index -> pointer mapping into a pointer block buffer."""
    width = 4 if is_vmfs5 else 8
    highest = max(entries)
    buf = bytearray((highest + 1) * width)
    for index, pointer in entries.items():
        buf[index * width : (index + 1) * width] = pointer.to_bytes(width, "little", signed=False)
    return bytes(buf)


def _resource_map(is_vmfs5: bool, sfb_size: int, volume: MappedVolume, pb_buffers: dict[int, bytes]):
    """Build the resource routing table, resolving pointer blocks from ``pb_buffers`` and data blocks via the volume."""

    def pb_resolve(address: int) -> int:
        # The pointer block "resource" is itself a file block; store its backing buffer in the volume at a high offset.
        target = address | 0x40000000_00000000  # deterministic, distinct high offset
        if address not in pb_buffers:
            raise KeyError(f"no pointer block buffer for {address:#x}")
        volume.write(target, pb_buffers[address])
        return target

    def data_resolve(address: int) -> int:
        if is_vmfs5:
            return FileBlockAddr.parse(address) << 10
        cluster, resource = SmallFileBlockAddr.parse(address)
        return ((cluster * sfb_size) + resource) << 10

    ptr_type = FS3_AddrType.POINTER_BLOCK.value
    ptr2_type = FS3_AddrType.POINTER2_BLOCK.value
    pb_size = 0x10000
    resources = {
        ptr_type: FakeResource(pb_resolve).bind(volume, pb_size),
        ptr2_type: FakeResource(pb_resolve).bind(volume, pb_size),
    }
    data_type = FS3_AddrType.FILE_BLOCK.value if is_vmfs5 else FS3_AddrType.SMALL_FILE_BLOCK.value
    resources[data_type] = FakeResource(data_resolve).bind(volume, BLOCK_SIZE)
    return resources


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
def test_high_bit_direct_pointer(is_vmfs5: bool) -> None:
    """A top-bit-set data block in the direct (zero-level) array resolves to the right high offset."""
    volume = MappedVolume()
    vmfs = _fake_vmfs(is_vmfs5, volume, {})
    leaf, leaf_offset, label = _leaf_address(is_vmfs5)
    volume.write(leaf_offset, bytes([PAYLOAD]) * BLOCK_SIZE)

    descriptor = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.FILE_BLOCK, [leaf], is_vmfs5=is_vmfs5)

    assert BlockStream(descriptor).read(BLOCK_SIZE) == bytes([PAYLOAD]) * BLOCK_SIZE
    assert volume.read_log == [leaf_offset], f"{label} must be read at its high volume offset"
    assert all(offset >= 0 for offset in volume.read_log), "no negative seek may occur"


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
@pytest.mark.parametrize(
    ("zla", "ptr_builder"),
    [
        (FS3_ZeroLevelAddrType.POINTER_BLOCK, _pointer_address),
        (FS3_ZeroLevelAddrType.POINTER2_BLOCK, _pointer2_address),
    ],
    ids=["PB", "PB2"],
)
def test_high_bit_single_indirection(is_vmfs5: bool, zla: FS3_ZeroLevelAddrType, ptr_builder) -> None:
    """A high PB/PB2 pointer followed by a high data-block pointer traverses both layers correctly."""
    volume = MappedVolume()
    pb_buffers: dict[int, bytes] = {}

    pb = ptr_builder(is_vmfs5)
    leaf, leaf_offset, _ = _leaf_address(is_vmfs5)
    pb_buffers[pb] = _pointer_buffer(is_vmfs5, {0: leaf})
    volume.write(leaf_offset, bytes([PAYLOAD]) * BLOCK_SIZE)

    vmfs = _fake_vmfs(is_vmfs5, volume, {})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)
    descriptor = _make_descriptor(vmfs, zla, [pb], is_vmfs5=is_vmfs5)

    assert BlockStream(descriptor).read(BLOCK_SIZE) == bytes([PAYLOAD]) * BLOCK_SIZE
    # First the high pointer block is read, then the high data block: full hierarchy observed.
    assert len(volume.read_log) == 2
    assert volume.read_log[-1] == leaf_offset
    assert all(offset >= 0 for offset in volume.read_log)


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
def test_high_bit_double_indirection(is_vmfs5: bool) -> None:
    """Two levels of high pointer blocks plus a high data block resolve end to end."""
    volume = MappedVolume()
    pb_buffers: dict[int, bytes] = {}

    primary = _pointer_address(is_vmfs5)
    secondary = _pointer2_address(is_vmfs5)
    leaf, leaf_offset, _ = _leaf_address(is_vmfs5)
    pb_buffers[primary] = _pointer_buffer(is_vmfs5, {0: secondary})
    pb_buffers[secondary] = _pointer_buffer(is_vmfs5, {0: leaf})
    volume.write(leaf_offset, bytes([PAYLOAD]) * BLOCK_SIZE)

    vmfs = _fake_vmfs(is_vmfs5, volume, {})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)
    descriptor = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE, [primary], is_vmfs5=is_vmfs5)

    assert BlockStream(descriptor).read(BLOCK_SIZE) == bytes([PAYLOAD]) * BLOCK_SIZE
    # Hierarchy: primary PB -> secondary PB2 -> data block.
    assert len(volume.read_log) == 3
    assert volume.read_log[-1] == leaf_offset
    assert all(offset >= 0 for offset in volume.read_log)


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
def test_zero_holes_are_sparse(is_vmfs5: bool) -> None:
    """Zero pointers at the direct, primary and secondary layers read as zeros without touching the volume."""
    volume = MappedVolume()
    vmfs = _fake_vmfs(is_vmfs5, volume, {})

    # Direct zero pointer.
    direct = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.FILE_BLOCK, [0], is_vmfs5=is_vmfs5)
    assert BlockStream(direct).read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
    assert volume.read_log == []

    # Primary-layer zero pointer (single indirection).
    single = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [0], is_vmfs5=is_vmfs5)
    assert BlockStream(single).read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
    assert volume.read_log == []

    # Secondary-layer zero pointer (double indirection): primary is real, inner entry is zero.
    pb_buffers: dict[int, bytes] = {}
    primary = _pointer_address(is_vmfs5)
    pb_buffers[primary] = _pointer_buffer(is_vmfs5, {0: 0})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)
    double = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE, [primary], is_vmfs5=is_vmfs5)
    assert BlockStream(double).read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
    # Only the primary pointer block is read; the zero inner entry must short-circuit.
    assert len(volume.read_log) == 1


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
def test_illegal_pointer_type_rejected(is_vmfs5: bool) -> None:
    """A pointer block entry with an illegal address type raises instead of resolving to another resource."""
    volume = MappedVolume()

    # A file descriptor address (type 4) is never a legal pointer block or data block entry.
    illegal = 0x80000004 if is_vmfs5 else 0x80000000_00000004

    # Illegal type at the primary (zero-level) pointer slot.
    pb_buffers: dict[int, bytes] = {}
    vmfs = _fake_vmfs(is_vmfs5, volume, {})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)
    bad_primary = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [illegal], is_vmfs5=is_vmfs5)
    with pytest.raises(InvalidPointerBlockError):
        BlockStream(bad_primary).read(BLOCK_SIZE)

    # Illegal type as a leaf reached through a valid high pointer block.
    primary = _pointer_address(is_vmfs5)
    pb_buffers[primary] = _pointer_buffer(is_vmfs5, {0: illegal})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)
    bad_leaf = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [primary], is_vmfs5=is_vmfs5)
    with pytest.raises(InvalidPointerBlockError):
        BlockStream(bad_leaf).read(BLOCK_SIZE)

    # Illegal type at the secondary layer of a double-indirection chain must also fail explicitly.
    pb_buffers.clear()
    first = _pointer_address(is_vmfs5)
    pb_buffers[first] = _pointer_buffer(is_vmfs5, {0: illegal})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)
    bad_double = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE, [first], is_vmfs5=is_vmfs5)
    with pytest.raises(InvalidPointerBlockError):
        BlockStream(bad_double).read(BLOCK_SIZE)


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
def test_truncated_pointer_block_on_disk_rejected(is_vmfs5: bool) -> None:
    """A pointer block on the (mapped) volume that is too short surfaces an explicit error via the stream."""
    volume = MappedVolume()
    primary = _pointer_address(is_vmfs5)

    # The backing pointer block holds only a couple of bytes, far less than one pointer entry.
    pb_buffers = {primary: b"\x01\x02"}
    vmfs = _fake_vmfs(is_vmfs5, volume, {})
    resources = _resource_map(is_vmfs5, vmfs._sfb_size, volume, pb_buffers)
    vmfs.resources = FakeResourceManager(resources)

    descriptor = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.POINTER_BLOCK, [primary], is_vmfs5=is_vmfs5)
    with pytest.raises(InvalidPointerBlockError):
        BlockStream(descriptor).read(BLOCK_SIZE)


@pytest.mark.parametrize("is_vmfs5", [True, False], ids=["vmfs5-uint32", "vmfs6-uint64"])
def test_truncated_pointer_array_rejected(is_vmfs5: bool) -> None:
    """A pointer block buffer too short for the requested index raises an explicit error."""
    width = 4 if is_vmfs5 else 8
    getter = _get_uint32_index if is_vmfs5 else _get_uint64_index

    # A full first entry but nothing for the second index.
    buf = (0).to_bytes(width, "little")
    with pytest.raises(InvalidPointerBlockError):
        getter(buf, 1)

    # A buffer shorter than even a single entry.
    with pytest.raises(InvalidPointerBlockError):
        getter(buf[: width - 1], 0)


def test_uint32_decode_is_unsigned() -> None:
    """The 32-bit pointer decoder must return an unsigned high address, never a negative number."""
    raw = (0xFFFFFFC3).to_bytes(4, "little")
    assert _get_uint32_index(raw, 0) == 0xFFFFFFC3
    assert _get_uint32_index(raw, 0) > 0


def test_uint64_decode_high_address() -> None:
    """The 64-bit pointer decoder preserves addresses with the top bit set."""
    raw = (0xFF0003FFFFFFFFC3).to_bytes(8, "little")
    assert _get_uint64_index(raw, 0) == 0xFF0003FFFFFFFFC3
    assert _get_uint64_index(raw, 0) > 0


def test_vmfs6_lfb_high_bit_leaf() -> None:
    """VMFS6 LFB leaves with the top bit set resolve through the LFB resource math."""
    volume = MappedVolume()
    vmfs = _fake_vmfs(False, volume, {})

    block_num = 0x7FFFFFFF
    leaf = LargeFileBlockAddr.make(block_num)
    leaf_offset = block_num << 10  # sfbToLfbShift == 0 in the fake
    volume.write(leaf_offset, bytes([PAYLOAD]) * BLOCK_SIZE)

    resources = {FS3_AddrType.LARGE_FILE_BLOCK.value: FakeResource(lambda addr: LargeFileBlockAddr.parse(addr) << 10)}
    vmfs.resources = FakeResourceManager(resources)

    descriptor = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.FILE_BLOCK, [leaf], is_vmfs5=False)
    assert BlockStream(descriptor).read(BLOCK_SIZE) == bytes([PAYLOAD]) * BLOCK_SIZE
    assert volume.read_log == [leaf_offset]


def test_vmfs5_subblock_pointer_semantics() -> None:
    """VMFS5 sub-block leaves (type 2) remain a valid data target with high addresses."""
    volume = MappedVolume()
    vmfs = _fake_vmfs(True, volume, {})

    # High cluster in the 22-bit SB cluster field.
    leaf = SubBlockAddr.make(0x3FFFFF, 0xF)
    leaf_offset = 0x7E57_0000
    volume.write(leaf_offset, bytes([PAYLOAD]) * BLOCK_SIZE)
    vmfs.resources = FakeResourceManager({FS3_AddrType.SUB_BLOCK.value: FakeResource(lambda addr: leaf_offset)})

    descriptor = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.SUB_BLOCK, [leaf], is_vmfs5=True)
    assert BlockStream(descriptor).read(BLOCK_SIZE) == bytes([PAYLOAD]) * BLOCK_SIZE
    assert volume.read_log == [leaf_offset]


def test_vmfs6_subblock64_pointer_semantics() -> None:
    """VMFS6 64-bit sub-block leaves with the top bit set remain a valid data target."""
    volume = MappedVolume()
    vmfs = _fake_vmfs(False, volume, {})

    leaf = SubBlockAddr64.make(0xFFFFFFFFF, 0xFF)
    assert leaf & (1 << 63)
    leaf_offset = 0x7E57_0000
    volume.write(leaf_offset, bytes([PAYLOAD]) * BLOCK_SIZE)
    vmfs.resources = FakeResourceManager({FS3_AddrType.SUB_BLOCK.value: FakeResource(lambda addr: leaf_offset)})

    descriptor = _make_descriptor(vmfs, FS3_ZeroLevelAddrType.SUB_BLOCK, [leaf], is_vmfs5=False)
    assert BlockStream(descriptor).read(BLOCK_SIZE) == bytes([PAYLOAD]) * BLOCK_SIZE
    assert volume.read_log == [leaf_offset]
