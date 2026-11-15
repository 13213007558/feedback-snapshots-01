from __future__ import annotations

import contextlib
import gzip
import io
import stat

import pytest

from dissect.vmfs import lvm, vmfs
from dissect.vmfs.c_vmfs import FS3_Config, FS3_ZeroLevelAddrType, FS6_DirBlockType, c_vmfs
from dissect.vmfs.descriptor import _dir_hash_get_location, _dir_name_hash
from dissect.vmfs.exception import VolumeNotAvailableError
from tests.conftest import absolute_path


@pytest.mark.parametrize(
    ("path", "type"),
    [
        pytest.param("vmfs/vmfs5.bin.gz", "vmfs5", id="vmfs5"),
        pytest.param("vmfs/vmfs5l.bin.gz", "vmfs5l", id="vmfs5l"),
        pytest.param("vmfs/vmfs5d.bin.gz", "vmfs5d", id="vmfs5d"),
        pytest.param("vmfs/vmfs5ld.bin.gz", "vmfs5ld", id="vmfs5ld"),
        pytest.param("vmfs/vmfs6.bin.gz", "vmfs6", id="vmfs6"),
        pytest.param("vmfs/vmfs6l.bin.gz", "vmfs6l", id="vmfs6l"),
        pytest.param("vmfs/vmfs6d.bin.gz", "vmfs6d", id="vmfs6d"),
        pytest.param("vmfs/vmfs6ld.bin.gz", "vmfs6ld", id="vmfs6ld"),
        pytest.param("vmfs/vmfs5-resource-optimized.bin.gz", "vmfs5", id="vmfs5-resource-optimized"),
        pytest.param("vmfs/vmfs6-resource-optimized.bin.gz", "vmfs6", id="vmfs6-resource-optimized"),
        pytest.param("vmfs/vmfs5-no-dense-sbpc.bin.gz", "vmfs5", id="vmfs5-no-dense-sbpc"),
        pytest.param(["vmfs/span/vmfs5-span-0.bin.gz", "vmfs/span/vmfs5-span-1.bin.gz"], "vmfs5", id="vmfs5-span"),
        pytest.param(["vmfs/span/vmfs6-span-0.bin.gz", "vmfs/span/vmfs6-span-1.bin.gz"], "vmfs6", id="vmfs6-span"),
    ],
)
def test_vmfs_basic(path: str | list[str], type: str, request: pytest.FixtureRequest) -> None:
    """Test basic VMFS functionality and properties."""
    with contextlib.ExitStack() as stack:
        vs = None
        volume = None

        if not isinstance(path, list):
            path = [path]

        fhs = [stack.enter_context(gzip.open(absolute_path(f"_data/{p}"), "rb")) for p in path]

        if type in ("vmfs5d", "vmfs5ld", "vmfs6d", "vmfs6ld"):
            assert len(fhs) == 1
            volume = fhs[0]
        else:
            vs = lvm.LVM(fhs)
            assert len(vs.devices) == len(path)

        if vs is not None:
            assert len(vs.volumes) == 1
            volume = vs.volumes[0].open()

        fs = vmfs.VMFS(volume)

        if type.startswith("vmfs5"):
            assert fs.is_vmfs5
            assert not fs.is_vmfs6
        else:
            assert not fs.is_vmfs5
            assert fs.is_vmfs6

        if type in ("vmfs5l", "vmfs5ld", "vmfs6l", "vmfs6ld"):
            assert fs.is_local
        else:
            assert not fs.is_local

        assert fs.label == request.node.callspec.id
        if "no-dense-sbpc" in request.node.callspec.id:
            assert FS3_Config.DENSE_SBPC not in fs.descriptor.config
        else:
            assert FS3_Config.DENSE_SBPC in fs.descriptor.config

        root_dir = fs.get("/").listdir()
        for name in (".vh.sf", ".pb2.sf", ".pbc.sf", ".fbb.sf", ".fdc.sf", ".sbc.sf", ".sdd.sf") + (
            (".jbc.sf",) if fs.is_vmfs6 else ()
        ):
            assert name in root_dir, f"Expected {name} in root directory"

            fd = root_dir[name].fd
            assert fd.is_system(), f"{name} should be a system file"

            if name == ".sdd.sf":
                assert fd.is_dir(), f"{name} should be a directory"
                assert stat.S_ISDIR(fd.mode), f"{name} should be a directory"
            else:
                assert fd.is_file(), f"{name} should be a regular file"
                assert stat.S_ISREG(fd.mode), f"{name} should be a regular file"


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("vmfs/vmfs5.bin.gz", id="vmfs5"),
        pytest.param("vmfs/vmfs6.bin.gz", id="vmfs6"),
    ],
)
def test_vmfs_content(path: str) -> None:
    """Test reading content from VMFS."""
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)
        fs = vmfs.VMFS(vs.volumes[0].open())

        # Test root
        fd = fs.get("/")
        assert fd.is_dir()
        assert stat.S_ISDIR(fd.mode)

        # Test a small file
        fd = fs.get("small")
        _assert_is_file(fd, 5, FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT)
        assert fd.open().read() == b"tiny\n"

        # Test a big file
        fd = fs.get("big")
        _assert_is_file(fd, (1024 * 64 * 16) + 1, FS3_ZeroLevelAddrType.FILE_BLOCK)
        assert fd.open().read() == (b"Kusjes van SRT<3" * (1024 * 64)) + b"\n"

        # Test a bigger file
        fd = fs.get("bigger")
        _assert_is_file(fd, (1024 * 1024 * 128), FS3_ZeroLevelAddrType.FILE_BLOCK)
        assert fd.open().read() == b"".join((bytes([i % 256]) * 1024 * 1024) for i in range(128))

        # Test a symlink
        fd = fs.get("symlink")
        assert fd.is_symlink()
        assert stat.S_ISLNK(fd.mode)
        assert fd.link == f"/vmfs/volumes/{fs.label}/small"

        # Test a directory
        fd = fs.get("directory")
        assert fd.is_dir()
        assert stat.S_ISDIR(fd.mode)
        contents = fd.listdir()

        assert set(contents.keys()) == {f"file{i}" for i in range(1, 101)} | {".", ".."}, (
            "Expected 100 files in the directory"
        )

        for entry in contents.values():
            if entry.name in (".", ".."):
                continue
            content = f"File {entry.name[4:]}\n".encode()
            _assert_is_file(entry.fd, len(content), FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT)
            assert entry.fd.open().read() == content

        # Test a small VMDK file
        fd = fs.get("normal-flat.vmdk")
        _assert_is_file(fd, 69 * 1024 * 1024 * 1024, FS3_ZeroLevelAddrType.POINTER_BLOCK)
        fh = fd.open()
        fh.seek(42 * 1024 * 1024 * 1024)
        assert fh.read(512) == b"\x42" * 512

        # Test a large VMDK file
        fd = fs.get("large-flat.vmdk")
        _assert_is_file(fd, 42 * 1024 * 1024 * 1024 * 1024, FS3_ZeroLevelAddrType.POINTER_BLOCK_DOUBLE)
        fh = fd.open()
        fh.seek(117 * 1024 * 1024 * 1024)
        assert fh.read(512) == b"\x42" * 512

        # Test a RDM file
        fd = fs.get("rdm-rdm.vmdk")
        assert fd.is_rdm()
        assert fd.size == 6969 * 1024 * 1024 * 1024
        assert fd.rdm_mapping.diskId.type == 1
        assert fd.rdm_mapping.diskId.len == 26
        assert fd.rdm_mapping.diskId.id[:26] == b"QM00015             QEMU H"

        # Test a directory with hash collisions (VMFS6 only, on VMFS5 this just iterates over the entries)
        fd = fs.get("collision")
        assert fd.is_dir()

        fh = fd.open()
        contents = fd.listdir()
        for name in contents:
            if fs.is_vmfs6 and name not in (".", ".."):
                # Manually verify that all the names are a hash collision
                assert _dir_name_hash(name, False)[1] == 0x26F7, name
                type, block, slot = _dir_hash_get_location(fh, 0x26F7)
                assert type == FS6_DirBlockType.LINK

                # And that we have enough hash collisions to fill a link group
                offset = (
                    # Block offset
                    c_vmfs.FS6_DIR_HEADER_BLOCK_SIZE
                    + (block * fs.md_alignment)
                    # Block header size
                    + len(c_vmfs.FS6_DirBlockHeader)
                    # Slot offset
                    + (slot * len(c_vmfs.FS6_DirLinkGroup))
                )
                fh.seek(offset)
                link_group = c_vmfs.FS6_DirLinkGroup(fh)
                assert link_group.nextGroup

            # Check that we can correctly retrieve the entry by name, following the link chain
            assert fd.get(name).name == name


def _jbosf(donor: vmfs.VMFS, sbc: io.BytesIO | None = None) -> vmfs.VMFS:
    """Create a JBOSF (Just a Bunch Of System Files) VMFS from a full volume donor VMFS."""
    kwargs = {}
    if donor.is_vmfs6:
        kwargs["jbc"] = donor.get(".jbc.sf").open()
    return vmfs.VMFS(
        vh=donor.get(".vh.sf").open(),
        fdc=donor.get(".fdc.sf").open(),
        fbb=donor.get(".fbb.sf").open(),
        sbc=sbc if sbc is not None else donor.get(".sbc.sf").open(),
        pbc=donor.get(".pbc.sf").open(),
        pb2=donor.get(".pb2.sf").open(),
        **kwargs,
    )


def _read_ranges(size: int, block_size: int) -> list[tuple[int, int]]:
    """Generate interesting (offset, length) read ranges for a file of the given size."""
    ranges = [(0, 1), (0, size)]
    offsets = {1, size // 2, size - 1, block_size - 1, block_size, block_size + 1, (2 * block_size) - 1}
    for offset in sorted(offsets):
        if 0 <= offset < size:
            for length in (1, 100, block_size, size):
                ranges.append((offset, length))
    return ranges


def test_vmfs_jbosf() -> None:
    """Test reading a VMFS with JBOSF (Just a Bunch Of System Files)."""
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())

        fs = _jbosf(donor)

        assert fs.is_vmfs5

        with pytest.raises(VolumeNotAvailableError):
            fs.get("small")

        fd = fs.get(donor.get("small").address)
        assert fd.open().read() == b"tiny\n"


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("vmfs/vmfs5.bin.gz", id="vmfs5"),
        pytest.param("vmfs/vmfs6.bin.gz", id="vmfs6"),
    ],
)
def test_vmfs_jbosf_file_content(path: str) -> None:
    """Test that file content read from system files matches the full volume on every visible range."""
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())
        fs = _jbosf(donor)

        readable_zla = (FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT, FS3_ZeroLevelAddrType.SUB_BLOCK)
        checked = 0
        for name, entry in donor.get("/").listdir().items():
            if name in (".", ".."):
                continue

            dfd = entry.fd
            if dfd.is_rdm() or dfd.zla not in readable_zla:
                continue

            ffd = fs.get(dfd.address)
            expected = dfd.open().read()

            # A full read must return the exact same content
            assert ffd.open().read() == expected

            # Every range that is visible from the system files must match the volume
            for offset, length in _read_ranges(dfd.size, dfd.block_size):
                with dfd.open() as dfh, ffd.open() as jfh:
                    dfh.seek(offset)
                    jfh.seek(offset)
                    assert jfh.read(length) == dfh.read(length), f"{name} mismatch at {offset:#x}+{length:#x}"

            checked += 1

        assert checked, "expected to compare at least one file"


def test_vmfs_jbosf_read_past_end() -> None:
    """Test that JBOSF reads are limited by the actual file length and don't repeat or pad data."""
    with gzip.open(absolute_path("_data/vmfs/vmfs6.bin.gz"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())
        fs = _jbosf(donor)

        # The "directory" file spans multiple readable sub-blocks
        dfd = donor.get("directory")
        assert dfd.zla == FS3_ZeroLevelAddrType.SUB_BLOCK
        assert dfd.size > dfd.block_size

        ffd = fs.get(dfd.address)
        expected = dfd.open().read()

        # A read spanning multiple sub-blocks must not return whole blocks or a repeated tail
        assert ffd.open()._read(0, 2 * ffd.block_size) == expected

        # A short read across the sub-block boundary must return exactly the requested range
        offset = dfd.block_size - 50
        with dfd.open() as dfh, ffd.open() as jfh:
            dfh.seek(offset)
            jfh.seek(offset)
            assert jfh.read(100) == dfh.read(100)

        # A resident file must not return data beyond its actual file length
        dfd = donor.get("small")
        assert dfd.zla == FS3_ZeroLevelAddrType.FILE_DESCRIPTOR_RESIDENT

        ffd = fs.get(dfd.address)
        assert ffd.open()._read(0, ffd.block_size) == dfd.open().read()


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("vmfs/vmfs5.bin.gz", id="vmfs5"),
        pytest.param("vmfs/vmfs6.bin.gz", id="vmfs6"),
    ],
)
def test_vmfs_jbosf_missing_volume(path: str) -> None:
    """Test that ranges requiring the volume raise a clear error instead of returning fabricated data."""
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())
        fs = _jbosf(donor)

        # "big" is fully backed by file blocks on the volume
        ffd = fs.get(donor.get("big").address)

        with pytest.raises(VolumeNotAvailableError):
            ffd.open().read(1)

        with pytest.raises(VolumeNotAvailableError):
            ffd.open().read()

        fh = ffd.open()
        fh.seek(1024 * 1024)
        with pytest.raises(VolumeNotAvailableError):
            fh.read(512)

        # "normal-flat.vmdk" is a large sparse file backed by pointer blocks
        # The allocated regions require the volume, the sparse regions are genuine zeroes
        dfd = donor.get("normal-flat.vmdk")
        ffd = fs.get(dfd.address)

        fh = ffd.open()
        fh.seek(42 * 1024 * 1024 * 1024)
        with pytest.raises(VolumeNotAvailableError):
            fh.read(512)

        with dfd.open() as dfh, ffd.open() as jfh:
            assert jfh.read(512) == dfh.read(512) == b"\x00" * 512


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("vmfs/zero5.bin.gz", id="vmfs5"),
        pytest.param("vmfs/zero6.bin.gz", id="vmfs6"),
    ],
)
def test_vmfs_jbosf_sparse(path: str) -> None:
    """Test that sparse (zero) blocks read as zeroes from system files, matching the full volume."""
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())
        fs = _jbosf(donor)

        dfd = donor.get("empty-flat.vmdk")
        ffd = fs.get(dfd.address)

        for offset in (0, 512, 1024 * 1024, 42 * 1024 * 1024 * 1024):
            with dfd.open() as dfh, ffd.open() as jfh:
                dfh.seek(offset)
                jfh.seek(offset)
                assert jfh.read(4096) == dfh.read(4096) == b"\x00" * 4096


def test_vmfs_jbosf_truncated_system_file() -> None:
    """Test that a truncated system file raises a clear error instead of looking like a normal EOF."""
    with gzip.open(absolute_path("_data/vmfs/vmfs5.bin.gz"), "rb") as fh:
        vs = lvm.LVM(fh)
        donor = vmfs.VMFS(vs.volumes[0].open())

        # Truncate .sbc.sf to just the resource metadata, so the sub-block data is missing
        sbc = io.BytesIO(donor.get(".sbc.sf").open().read(0x10000))
        fs = _jbosf(donor, sbc=sbc)

        fd = fs.get(donor.get("symlink").address)
        assert fd.zla == FS3_ZeroLevelAddrType.SUB_BLOCK

        with pytest.raises(VolumeNotAvailableError):
            fd.open().read()


def _assert_is_file(fd: vmfs.FileDescriptor, size: int, zla: FS3_ZeroLevelAddrType) -> None:
    """Assert that the file descriptor is a file with the given size and ZLA."""
    assert not fd.is_dir()
    assert fd.is_file()
    assert not fd.is_symlink()
    assert not fd.is_rdm()
    assert not fd.is_system()
    assert stat.S_ISREG(fd.mode)
    assert fd.size == size
    assert fd.zla == zla


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("vmfs/zero5.bin.gz", id="vmfs5"),
        pytest.param("vmfs/zero6.bin.gz", id="vmfs6"),
    ],
)
def test_sparse(path: str) -> None:
    """Test that an empty disk but with a valid ZLA is correctly interpreted as sparse."""
    with gzip.open(absolute_path(f"_data/{path}"), "rb") as fh:
        vs = lvm.LVM(fh)
        fs = vmfs.VMFS(vs.volumes[0].open())

        fd = fs.get("empty-flat.vmdk")
        assert fd.zla == FS3_ZeroLevelAddrType.POINTER_BLOCK
        assert fd.open().read(512) == b"\x00" * 512
