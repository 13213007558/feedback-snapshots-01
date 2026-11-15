from __future__ import annotations

import gzip
import io

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.exception import NotAnRDMFileError, RDMCapacityError, RDMDeviceMismatchError
from dissect.vmfs.rdm import RDM
from tests.conftest import absolute_path

RDM_DEVICE_ID = b"QM00015             QEMU H"
RDM_CAPACITY = 6969 * 1024 * 1024 * 1024


class FakeDisk(io.RawIOBase):
    """A sparse fake evidence disk, no real block device involved.

    Every byte at offset ``pos`` reads as ``(pos // 512) & 0xff``, so reads
    can be verified against a deterministic pattern.
    """

    def __init__(self, size: int) -> None:
        self._size = size
        self._pos = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._size + offset
        return self._pos

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._size - self._pos
        size = max(0, min(size, self._size - self._pos))
        start = self._pos
        self._pos += size
        return bytes((pos // 512) & 0xFF for pos in range(start, start + size))


class FakeFileDescriptor:
    """A duck-typed RDM file descriptor with a controllable file length."""

    def __init__(self, mapping: bytes, size: int) -> None:
        self._mapping = mapping
        self._size = size

    def is_rdm(self) -> bool:
        return True

    @property
    def rdm_mapping(self) -> c_vmfs.FS3_RawDiskMap:
        return c_vmfs.FS3_RawDiskMap(self._mapping)

    @property
    def size(self) -> int:
        return self._size


@pytest.fixture
def fs() -> vmfs.VMFS:
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        vs = lvm.LVM(fh)
        yield vmfs.VMFS(vs.volumes[0].open())


@pytest.fixture
def rdm(fs: vmfs.VMFS) -> RDM:
    return RDM(fs.get("rdm-rdm.vmdk"))


def test_rdm_parse(rdm: RDM) -> None:
    """The mapping metadata is parsed from the RDM file descriptor."""
    assert rdm.device_id == RDM_DEVICE_ID
    assert rdm.size == RDM_CAPACITY
    assert rdm.mode is None
    assert rdm.mapping.diskId.type == 1


def test_rdm_file_descriptor_entry(fs: vmfs.VMFS) -> None:
    """The RDM mapping is reachable through the file descriptor."""
    fd = fs.get("rdm-rdm.vmdk")
    assert isinstance(fd.rdm, RDM)
    assert fd.rdm.device_id == RDM_DEVICE_ID


def test_rdm_describe_without_image(rdm: RDM) -> None:
    """The mapping can be described without any evidence image, missing metadata is stated."""
    description = rdm.describe()
    assert "QM00015" in description
    assert f"Capacity: {RDM_CAPACITY} bytes" in description
    assert "Device mode: not recorded" in description


def test_rdm_bind_success(rdm: RDM) -> None:
    """A correctly bound evidence image yields the mapped disk bytes."""
    stream = rdm.bind(FakeDisk(RDM_CAPACITY), device_id=RDM_DEVICE_ID)
    assert stream.size == RDM_CAPACITY

    offset = 42 * 1024 * 1024
    stream.seek(offset)
    assert stream.read(512) == bytes([(offset // 512) & 0xFF]) * 512

    # The readable range is limited to the mapped capacity
    stream.seek(RDM_CAPACITY)
    assert stream.read(512) == b""


def test_rdm_bind_device_identity_mismatch(rdm: RDM) -> None:
    """An evidence image for the same path but a different device identity is rejected."""
    with pytest.raises(RDMDeviceMismatchError, match="Device identity mismatch") as excinfo:
        rdm.bind(FakeDisk(RDM_CAPACITY), device_id=b"QM99999             QEMU H")

    assert "QM00015" in str(excinfo.value)
    assert "QM99999" in str(excinfo.value)


def test_rdm_bind_capacity_insufficient(rdm: RDM) -> None:
    """An evidence image that is too small for the mapped capacity is rejected."""
    with pytest.raises(RDMCapacityError, match="too small") as excinfo:
        rdm.bind(FakeDisk(RDM_CAPACITY - 512), device_id=RDM_DEVICE_ID)

    assert str(RDM_CAPACITY) in str(excinfo.value)
    assert str(RDM_CAPACITY - 512) in str(excinfo.value)


def test_rdm_missing_capacity_basis(rdm: RDM) -> None:
    """A mapping without a recorded capacity states so and refuses to bind."""
    mapping_bytes = bytes(rdm.fd.data[: len(c_vmfs.FS3_RawDiskMap)])
    fake_rdm = RDM(FakeFileDescriptor(mapping_bytes, 0))

    assert fake_rdm.size is None
    assert "Capacity: not recorded" in fake_rdm.describe()

    with pytest.raises(RDMCapacityError, match="no capacity"):
        fake_rdm.bind(FakeDisk(RDM_CAPACITY), device_id=RDM_DEVICE_ID)


def test_rdm_open_does_not_return_descriptor(fs: vmfs.VMFS) -> None:
    """Opening an RDM file never returns the descriptor itself as disk content."""
    fd = fs.get("rdm-rdm.vmdk")
    with pytest.raises(NotImplementedError, match="RDM.bind"):
        fd.open()


def test_rdm_requires_rdm_file(fs: vmfs.VMFS) -> None:
    """Only RDM file descriptors can be parsed as a mapping."""
    with pytest.raises(NotAnRDMFileError):
        RDM(fs.get("small"))


def test_rdm_bind_unseekable_evidence(rdm: RDM) -> None:
    """An evidence image whose capacity cannot be determined is rejected."""

    class Unseekable(io.RawIOBase):
        def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
            raise OSError("not seekable")

    with pytest.raises(RDMCapacityError, match="not seekable"):
        rdm.bind(Unseekable(), device_id=RDM_DEVICE_ID)
