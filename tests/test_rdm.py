from __future__ import annotations

import contextlib
import gzip
import io

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.exception import NotAnRDMFileError, RDMNotBoundError, RDMReadError, RDMValidationError
from dissect.vmfs.rdm import (
    RDMDeviceIdentity,
    RDMDeviceMode,
    RDMImage,
    RDMValidationIssue,
    bind_rdm,
    check_rdm,
)
from tests.conftest import absolute_path

SECTOR = 512


class SparseImage(io.RawIOBase):
    """A small seekable evidence stream with a deterministic byte pattern.

    Bytes are generated on demand, so tests do not need a real block device or
    a large backing file. The byte at offset ``i`` is ``i % 251``.

    ``readable_size`` can be lowered at any time to simulate evidence that stops
    being readable.
    """

    def __init__(self, size: int):
        super().__init__()
        self.size = size
        self.readable_size = size
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
            self._pos = self.size + offset
        else:
            raise ValueError(f"invalid whence value {whence}")
        if self._pos < 0:
            raise ValueError("negative seek position")
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = max(0, self.readable_size - self._pos)
        n = max(0, min(n, self.readable_size - self._pos))
        if n <= 0:
            return b""
        data = bytes((self._pos + i) % 251 for i in range(n))
        self._pos += n
        return data




@contextlib.contextmanager
def open_rdm_fixture(path: str):
    """Open the real VMFS fixture and yield ``(fs, rdm_fd)``."""
    with gzip.open(absolute_path(f"_data/vmfs/{path}"), "rb") as fh:
        fs = vmfs.VMFS(lvm.LVM(fh).volumes[0].open())
        yield fs, fs.get("rdm-rdm.vmdk")


def _image(
    fd: vmfs.FileDescriptor,
    size: int | None = None,
    *,
    identity: RDMDeviceIdentity | None = None,
    mode: RDMDeviceMode | str | None = RDMDeviceMode.PHYSICAL,
    path: str | None = None,
) -> RDMImage:
    """Create an evidence image that describes the fixture RDM device."""
    if size is None:
        size = fd.size
    if identity is None:
        identity = fd.rdm_mapping.device_id
    return RDMImage(SparseImage(size), identity, mode=mode, path=path)


@pytest.mark.parametrize("path", ["vmfs5.bin.gz", "vmfs6.bin.gz"])
def test_rdm_mapping_describes_external_device(path: str) -> None:
    """RDM metadata is inspectable and is never the disk content."""
    with open_rdm_fixture(path) as (_, fd):
        mapping = fd.rdm_mapping

        assert fd.is_rdm()
        assert mapping.descriptor is not None
        assert mapping.device_id.id == b"QM00015             QEMU H"
        assert mapping.device_id.type == 1
        assert mapping.capacity == fd.size == 6969 * 1024 * 1024 * 1024

        description = mapping.describe()
        assert "QM00015" in description
        assert "RDM mapping" in description
        assert mapping.as_dict()["capacity"] == fd.size

        # The descriptor data is mapping metadata, not disk content.
        descriptor_bytes = bytes(fd.data)
        assert descriptor_bytes.startswith(b"\x01\x1a")
        assert len(descriptor_bytes) != fd.size

        # Even the first bytes of a correct binding are evidence, not metadata.
        binding = fd.bind_rdm(_image(fd))
        assert binding.read(len(descriptor_bytes)) != descriptor_bytes


@pytest.mark.parametrize("path", ["vmfs5.bin.gz", "vmfs6.bin.gz"])
def test_rdm_correct_binding_reads_external_bytes(path: str) -> None:
    """A correct identity, mode and capacity binding reads the evidence bytes."""
    with open_rdm_fixture(path) as (_, fd):
        image = _image(fd, path="/evidence/rdm-rdm.vmdk")
        binding = fd.bind_rdm(image)

        assert binding.size == fd.size
        assert binding.tell() == 0
        assert binding.read(SECTOR) == bytes(i % 251 for i in range(SECTOR))

        # The evidence path is descriptive only; it was never opened.
        assert image.path == "/evidence/rdm-rdm.vmdk"
        assert image.identity.id == fd.rdm_mapping.device_id.id

        # Pointing the descriptive path at a real, readable file does not make
        # the binding read that file. It must keep reading the supplied stream.
        local = RDMImage(SparseImage(fd.size), fd.rdm_mapping.device_id, mode="physical", path=__file__)
        local_binding = fd.bind_rdm(local)
        expected = bytes(i % 251 for i in range(16))
        assert local_binding.read(16) == expected
        with open(__file__, "rb") as fh:
            assert expected != fh.read(16)

        offset = 1234 * SECTOR
        assert binding.read_range(offset, SECTOR) == bytes((offset + i) % 251 for i in range(SECTOR))

        binding.seek(-SECTOR, io.SEEK_END)
        assert binding.tell() == fd.size - SECTOR
        assert binding.read(SECTOR) == bytes((fd.size - SECTOR + i) % 251 for i in range(SECTOR))
        assert binding.read(1) == b""

        # Closing the binding must not close the caller-owned evidence.
        binding.close()
        assert not image.fh.closed
        with pytest.raises(ValueError, match="closed"):
            binding.read(1)


@pytest.mark.parametrize("path", ["vmfs5.bin.gz", "vmfs6.bin.gz"])
def test_rdm_same_path_different_identity(path: str) -> None:
    """A same-named image with a different device identity is rejected."""
    with open_rdm_fixture(path) as (_, fd):
        image = RDMImage(
            SparseImage(fd.size),
            RDMDeviceIdentity(type=1, id=b"QM00016             QEMU H"),
            mode=RDMDeviceMode.PHYSICAL,
            path="/evidence/rdm-rdm.vmdk",
        )

        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm(image)

        error = exc_info.value
        assert error.codes == ("device_identity_mismatch",)
        assert error.issues[0].image == "/evidence/rdm-rdm.vmdk"
        assert "id" in str(error.issues[0])
        assert error.mapping is fd.rdm_mapping
        assert "QM00015" in error.mapping.describe()


@pytest.mark.parametrize("path", ["vmfs5.bin.gz", "vmfs6.bin.gz"])
def test_rdm_capacity_insufficient(path: str) -> None:
    """Evidence smaller than the mapped capacity is rejected with the shortfall."""
    with open_rdm_fixture(path) as (_, fd):
        image = _image(fd, size=fd.size - SECTOR)

        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm(image)

        error = exc_info.value
        assert error.codes == ("image_capacity_insufficient",)
        issue = error.issues[0]
        assert issue.code == "image_capacity_insufficient"
        assert str(fd.size) in issue.message
        assert str(fd.size - SECTOR) in issue.message


@pytest.mark.parametrize("path", ["vmfs5.bin.gz", "vmfs6.bin.gz"])
def test_rdm_declared_capacity_must_match_stream(path: str) -> None:
    """A declared capacity that the stream cannot prove is reported."""
    with open_rdm_fixture(path) as (_, fd):
        image = RDMImage(
            SparseImage(fd.size - SECTOR),
            fd.rdm_mapping.device_id,
            mode=RDMDeviceMode.PHYSICAL,
            size=fd.size,
        )

        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm(image)

        assert "image_capacity_mismatch" in exc_info.value.codes


def test_rdm_missing_device_mode() -> None:
    """A missing device mode is reported instead of being guessed."""
    with open_rdm_fixture("vmfs6.bin.gz") as (_, fd):
        image = RDMImage(SparseImage(fd.size), fd.rdm_mapping.device_id)
        assert image.mode is None

        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm(image)

        assert exc_info.value.codes == ("missing_device_mode",)
        assert "mode" in str(exc_info.value.issues[0])

        # Supplying the missing mode explicitly also works.
        binding = fd.bind_rdm(image, mode="physical")
        assert binding.read(4) == bytes([0, 1, 2, 3])

        # A conflicting declared mode is reported, not silently overridden.
        virtual = RDMImage(SparseImage(fd.size), fd.rdm_mapping.device_id, mode="virtual")
        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm(virtual, mode="physical")

        assert exc_info.value.codes == ("device_mode_mismatch",)


def test_rdm_unbound_open_does_not_return_descriptor() -> None:
    """Opening an RDM without evidence fails instead of returning descriptor bytes."""
    with open_rdm_fixture("vmfs6.bin.gz") as (_, fd):
        with pytest.raises(RDMNotBoundError) as exc_info:
            fd.open()

        error = exc_info.value
        assert error.codes == ("missing_evidence",)
        assert error.mapping is fd.rdm_mapping
        assert error.mapping.describe()

        # An empty evidence inventory is also a concrete failure.
        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm([])
        assert exc_info.value.codes == ("no_evidence_image",)


def test_rdm_read_limits_are_explicit() -> None:
    """Reads beyond the binding or a short stream name the missing range."""
    with open_rdm_fixture("vmfs6.bin.gz") as (_, fd):
        image = _image(fd)
        binding = fd.bind_rdm(image)

        with pytest.raises(RDMReadError) as exc_info:
            binding.read_range(fd.size - 4, 8)

        error = exc_info.value
        assert error.code == "range_exceeds_capacity"
        assert error.requested_range == (fd.size - 4, 8)
        assert error.missing_ranges == ((fd.size, 4),)

        # Bind first, then let the evidence suddenly become unreadable. The
        # binding must report the exact missing range instead of returning a
        # short buffer as if it were the disk content.
        short = _image(fd)
        binding = fd.bind_rdm(short)
        short.fh.readable_size = SECTOR

        with pytest.raises(RDMReadError) as exc_info:
            binding.read(SECTOR * 2)

        assert exc_info.value.code == "short_read"
        assert exc_info.value.missing_ranges == ((SECTOR, SECTOR),)


def test_rdm_check_reports_issues_without_opening() -> None:
    """The validation-only entry point reports the same concrete issues."""
    with open_rdm_fixture("vmfs6.bin.gz") as (_, fd):
        good = _image(fd)
        assert check_rdm(fd, good) == []

        short = _image(fd, size=fd.size - SECTOR)
        issues = check_rdm(fd, short)
        assert [issue.code for issue in issues] == ["image_capacity_insufficient"]

        # Checking never hands out a binding, so a partial image cannot be read.
        assert fd.rdm_mapping.describe()


def test_rdm_binding_rejects_unreadable_range() -> None:
    """A capacity claim alone is not enough; the mapped range must be readable."""
    with open_rdm_fixture("vmfs6.bin.gz") as (_, fd):
        # The stream reports the full size but cannot serve the last byte.
        incomplete = SparseImage(fd.size)
        incomplete.readable_size = SECTOR
        image = RDMImage(
            incomplete,
            fd.rdm_mapping.device_id,
            mode=RDMDeviceMode.PHYSICAL,
            size=fd.size,
        )

        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm(image)

        assert "image_not_readable" in exc_info.value.codes
        assert any(issue.field == "range" for issue in exc_info.value.issues)


def test_rdm_selection_and_non_rdm_guard() -> None:
    """Matching is by explicit identity, and non-RDM files reject evidence."""
    with open_rdm_fixture("vmfs6.bin.gz") as (fs, fd):
        other = RDMImage(
            SparseImage(fd.size),
            RDMDeviceIdentity(type=1, id=b"UNRELATED"),
            mode=RDMDeviceMode.PHYSICAL,
            path="/evidence/unrelated.img",
        )
        good = _image(fd, path="/evidence/good.img")

        binding = fd.bind_rdm([other, good])
        assert binding.image is good

        # The VMFS-level convenience entry points behave the same way.
        assert fs.bind_rdm("rdm-rdm.vmdk", good).size == fd.size
        assert fs.open_rdm("rdm-rdm.vmdk", good).read(2) == bytes([0, 1])
        assert fs.check_rdm("rdm-rdm.vmdk", good) == []

        with pytest.raises(RDMValidationError) as exc_info:
            fd.bind_rdm([good, _image(fd, path="/evidence/copy.img")])
        assert exc_info.value.codes == ("ambiguous_image",)

        with pytest.raises(NotAnRDMFileError):
            bind_rdm(fs.get("normal-flat.vmdk"), good)

        with pytest.raises(NotAnRDMFileError):
            _ = fs.get("normal-flat.vmdk").rdm_mapping

        with pytest.raises(ValueError, match="not an RDM"):
            fs.get("normal-flat.vmdk").open(good)


def test_rdm_metadata_issue_is_reported_without_evidence() -> None:
    """Missing mapping evidence is a concrete issue, not a name guess."""
    issue = RDMValidationIssue("missing_mapping_identity", "no usable SCSI id", field="diskId.id")
    assert issue.code == "missing_mapping_identity"
    assert "diskId.id" in str(issue)

    with open_rdm_fixture("vmfs6.bin.gz") as (_, fd):
        mapping = fd.rdm_mapping
        assert mapping.validate_metadata() == ()
        assert mapping.raw.diskId.id[:7] == b"QM00015"

        # A mapping without a usable identity cannot be bound by name.
        mapping.device_id = RDMDeviceIdentity(type=1, id=b"")
        image = RDMImage(SparseImage(fd.size), RDMDeviceIdentity(type=1, id=b"some other id"), mode="physical")
        with pytest.raises(RDMValidationError) as exc_info:
            mapping.bind(image)

        assert "missing_mapping_identity" in exc_info.value.codes
