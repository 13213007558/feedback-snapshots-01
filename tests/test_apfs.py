from __future__ import annotations

import gzip
import hashlib
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from dissect.util.stream import BufferedStream

from dissect.apfs.apfs import APFS, fusion_tier2_device_mask, log
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.cursor import Cursor
from dissect.apfs.exception import Error
from dissect.apfs.util import parse_fs_object_key
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from dissect.apfs.objects.fs import FS


def _assert_apfs_content(volume: FS, beta: bool) -> None:
    # Root directory
    node = volume.get("/")
    assert node.name == "root"
    assert node.path == "/root"
    assert node.is_dir()
    assert all(
        name in sorted(node.listdir())
        for name in [
            ".fseventsd",
            "case_folding_µ",
            "dir",
            "empty",
            "hardlink",
            "nfd_téstfilè",
            "nfd_¾",
            "nfkd_3⁄4",  # noqa: RUF001
            "symlink-dir",
            "symlink-file",
        ]
    )

    # Test direntry parsing
    assert node.listdir()["dir"].is_dir()
    assert node.listdir()["hardlink"].is_file()
    assert node.listdir()["symlink-dir"].is_symlink()

    # Empty file
    node = volume.get("empty")
    assert node.name == "empty"
    assert node.path == "/root/empty"
    assert node.is_file()
    assert node.open().read() == b""

    # Test case sensitivity
    if volume.is_case_insensitive:
        node = volume.get("EMPTY")
        assert node.name == "empty"
        assert node.path == "/root/empty"
        assert node.is_file()
        assert node.open().read() == b""
    else:
        with pytest.raises(FileNotFoundError):
            volume.get("EMPTY")

    # Directory
    node = volume.get("dir")
    assert node.name == "dir"
    assert node.path == "/root/dir"
    assert node.is_dir()
    assert all(
        name in sorted(node.listdir())
        for name in (
            [
                "compressed-zlib-fork",
                "compressed-zlib-xattr",
                "fifo",
                "file",
                "resourcefork",
                "xattr-dir",
                "xattr-large",
                "xattr-small",
            ]
            if beta
            else [
                "compressed-lzfse-fork",
                "compressed-lzfse-xattr",
                "compressed-lzvn-fork",
                "compressed-lzvn-xattr",
                "compressed-zlib-fork",
                "compressed-zlib-xattr",
                "fifo",
                "file",
                "resourcefork",
                "xattr-dir",
                "xattr-large",
                "xattr-small",
            ]
        )
    )

    # Regular file
    node = volume.get("dir/file")
    assert node.name == "file"
    assert node.path == "/root/dir/file"
    assert sorted(node.names) == ["file", "hardlink"]
    assert sorted(node.paths) == ["/root/dir/file", "/root/hardlink"]
    assert node.is_file()
    assert node.open().read().decode() == " File System\n"

    # Hard link
    node = volume.get("hardlink")
    assert node.oid == volume.get("dir/file").oid
    assert node.sibling_id == volume.get("dir/file").sibling_id + 1
    assert node.name == "hardlink"
    assert node.path == "/root/hardlink"
    assert sorted(node.names) == ["file", "hardlink"]
    assert sorted(node.paths) == ["/root/dir/file", "/root/hardlink"]
    assert node.is_file()
    assert node.inode == volume.get("dir/file").inode

    # Symbolic link to file
    node = volume.get("symlink-file")
    assert node.name == "symlink-file"
    assert node.path == "/root/symlink-file"
    assert node.is_symlink()
    assert node.readlink() == "dir/file"

    # Symbolic link to directory
    node = volume.get("symlink-dir")
    assert node.name == "symlink-dir"
    assert node.path == "/root/symlink-dir"
    assert node.is_symlink()
    assert node.readlink() == "dir"

    if ".HFS+ Private Directory Data\r" not in volume.get("/").listdir():
        # File with NFC encoded name
        node = volume.get("nfc_téstfilè")
        assert node.name == "nfc_téstfilè"

    # File with NFD encoded name
    node = volume.get("nfd_téstfilè")
    assert node.name == "nfd_téstfilè"
    assert node.name != "nfd_téstfilè"  # Not normalized

    # File with NFD encoded name
    node = volume.get("nfd_¾")
    assert node.name == "nfd_¾"
    assert node.name != "nfd_3⁄4"  # Not normalized  # noqa: RUF001

    # File with NFKD encoded name
    node = volume.get("nfkd_3⁄4")  # noqa: RUF001
    assert node.name == "nfkd_3⁄4"  # noqa: RUF001
    assert node.name != "nfkd_¾"  # Not normalized

    # File with case folding
    node = volume.get("case_folding_µ")
    assert node.name == "case_folding_µ"

    # Resource fork
    node = volume.get("dir/resourcefork")
    assert node.name == "resourcefork"
    assert node.is_file()
    assert node.xattr["com.apple.ResourceFork"].open().read() == b"Resource fork data\n"

    # Small xattr
    node = volume.get("dir/xattr-small")
    assert node.name == "xattr-small"
    assert node.is_file()
    assert node.xattr["xattr-small"].open().read() == b"Small xattr data"

    # Directory with xattr
    node = volume.get("dir/xattr-dir")
    assert node.name == "xattr-dir"
    assert node.is_dir()
    assert node.xattr["xattr-dir"].open().read() == b"xattr data on directory"

    # Large xattr
    node = volume.get("dir/xattr-large")
    assert node.name == "xattr-large"
    assert node.is_file()
    assert (
        hashlib.sha256(node.xattr["xattr-large"].open().read()).hexdigest()
        == "dd4e6730520932767ec0a9e33fe19c4ce24399d6eba4ff62f13013c9ed30ef87"
        if beta
        else "a11c957142c3fd8ebf2bee1ed0cf184a246033a3874d060acd28c319b323466e"
    )

    # Compressed file method 3 (ZLIB-XATTR)
    node = volume.get("dir/compressed-zlib-xattr")
    assert node.name == "compressed-zlib-xattr"
    assert node.is_file()
    assert node.is_compressed()
    assert (
        node.open().read()
        == b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # noqa: E501
    )

    # Compressed file method 4 (ZLIB-FORK)
    node = volume.get("dir/compressed-zlib-fork")
    assert node.name == "compressed-zlib-fork"
    assert node.is_file()
    assert node.is_compressed()
    assert (
        hashlib.sha256(node.open().read()).hexdigest()
        == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
    )

    if not beta:
        # Compressed file method 7 (LZVN-XATTR)
        node = volume.get("dir/compressed-lzvn-xattr")
        assert node.name == "compressed-lzvn-xattr"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            node.open().read()
            == b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # noqa: E501
        )

        # Compressed file method 8 (LZVN-FORK)
        node = volume.get("dir/compressed-lzvn-fork")
        assert node.name == "compressed-lzvn-fork"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            hashlib.sha256(node.open().read()).hexdigest()
            == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
        )

        # Compressed file method 11 (LZFSE-XATTR)
        node = volume.get("dir/compressed-lzfse-xattr")
        assert node.name == "compressed-lzfse-xattr"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            node.open().read()
            == b"Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"  # noqa: E501
        )

        # Compressed file method 12 (LZFSE-FORK)
        node = volume.get("dir/compressed-lzfse-fork")
        assert node.name == "compressed-lzfse-fork"
        assert node.is_file()
        assert node.is_compressed()
        assert (
            hashlib.sha256(node.open().read()).hexdigest()
            == "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f"
        )

    if ".HFS+ Private Directory Data\r" not in volume.get("/").listdir() and not beta:
        # Special files
        dirents = volume.get("dir").listdir()
        assert dirents["blockdev"].is_block_device()

        node = volume.get("dir/blockdev")
        assert node.name == "blockdev"
        assert node.is_block_device()

        for name in [
            "chardev",
            "chardev-386bsd",
            "chardev-4bsd",
            "chardev-bsdos",
            "chardev-bsdos2",
            "chardev-freebsd",
            "chardev-hpux",
            "chardev-isc",
            "chardev-linux",
            "chardev-netbsd",
            "chardev-osf1",
            "chardev-sco",
            "chardev-solaris",
            "chardev-sunos",
            "chardev-svr3",
            "chardev-svr4",
            "chardev-ultrix",
        ]:
            assert dirents[name].is_character_device()

            node = volume.get(f"dir/{name}")
            assert node.name == name
            assert node.is_character_device()

    node = volume.get("dir/fifo")
    assert node.name == "fifo"
    assert node.is_fifo()


@pytest.mark.parametrize(
    ("path", "name", "features", "password"),
    [
        pytest.param(
            "_data/case_insensitive.bin.gz",
            "Case Insensitive",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            None,
            id="case-insensitive",
        ),
        pytest.param(
            "_data/case_sensitive.bin.gz",
            "Case Sensitive",
            c_apfs.APFS_INCOMPAT.NORMALIZATION_INSENSITIVE,
            None,
            id="case-sensitive",
        ),
        pytest.param(
            "_data/jhfs_converted.bin.gz",
            "JHFS+ Converted",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            None,
            id="jhfs-converted",
        ),
        pytest.param(
            "_data/encrypted.bin.gz",
            "Encrypted",
            c_apfs.APFS_INCOMPAT.ENC_ROLLED | c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            "password",
            id="encrypted",
        ),
        pytest.param(
            "_data/jhfs_encrypted.bin.gz",
            "JHFS+ Encrypted Converted",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            "password",
            id="jfs-encrypted",
        ),
        pytest.param(
            "_data/case_insensitive_beta.bin.gz",
            "Case Insensitive (beta)",
            c_apfs.APFS_INCOMPAT.CASE_INSENSITIVE,
            None,
            id="case-insensitive-beta",
        ),
        pytest.param(
            "_data/case_sensitive_beta.bin.gz",
            "Case Sensitive (beta)",
            c_apfs.APFS_INCOMPAT(0),
            None,
            id="case-sensitive-beta",
        ),
    ],
)
def test_apfs(path: str, name: str, features: c_apfs.APFS_INCOMPAT, password: str | None) -> None:
    """Test APFS volumes."""
    with gzip.open(absolute_path(path), "rb") as fh:
        container = APFS(fh)
        assert len(container.volumes) == 1

        volume = container.volumes[0]
        assert volume.name == name
        assert volume.incompatible_features == features

        if password:
            assert volume.is_encrypted
            volume.unlock(password)

        _assert_apfs_content(volume, "(beta)" in name)


def test_snapshots() -> None:
    """Test APFS snapshots."""
    with gzip.open(absolute_path("_data/snapshot.bin.gz"), "rb") as fh:
        container = APFS(fh)
        assert len(container.volumes) == 1

        volume = container.volumes[0]
        assert volume.name == "Snapshots"

        assert "file" not in volume.get("/").listdir()

        for i, snapshot in enumerate(volume.snapshots):
            assert snapshot.name == f"Snapshot {i}"
            assert snapshot.open().get("file").open().read() == f"Snapshot {i}\n".encode()


def test_corrupt_checkpoints(caplog: pytest.LogCaptureFixture) -> None:
    """Test APFS volumes with corrupt checkpoints."""
    with gzip.open(absolute_path("_data/corrupt.bin.gz"), "rb") as fh, caplog.at_level("DEBUG", log.name):
        container = APFS(fh)

        assert container.sb.xid == 302
        assert len(container.volumes) == 1

    assert caplog.messages[0] == "Skipping superblock xid=304: invalid OMAP"
    assert caplog.messages[1] == "Skipping superblock xid=303: Invalid nx_superblock checksum"


def test_large_extents() -> None:
    """Test APFS volumes with large extents."""
    with gzip.open(absolute_path("_data/large.bin.gz"), "rb") as fh:
        container = APFS(fh)
        assert len(container.volumes) == 1

        volume = container.volumes[0]
        assert volume.name == "Large"

        node = volume.get("yomomma.bin")
        assert node.size == 512 * 1024 * 1024

        fh = node.open()

        # First extent is 128MiB
        assert fh._lookup(0) == (0, 1070, 128 * 1024 * 1024, 0)

        with patch.object(volume.container, "_read_block", wraps=volume.container._read_block) as mock_read_block:
            assert fh.read(512) == b"\x67" * 512

            # Check that we only read one block, not the entire 128MiB extent
            mock_read_block.assert_called_once_with(1070, 1)


FUSION_TIER2_BLOCK_MASK = c_apfs.FUSION_TIER2_DEVICE_BYTE_ADDR >> 12


def _block(buf: bytearray, address: int) -> bytes:
    return bytes(buf[address * 4096 : (address + 1) * 4096])


def _set_block(buf: bytearray, address: int, data: bytes) -> None:
    buf[address * 4096 : (address + 1) * 4096] = data


def _patch_block_value(buf: bytearray, node: c_apfs.btree_node_phys, index: int, offset: int, data: bytes) -> None:
    """Patch bytes inside a B-tree value, using the same reverse value area as the parser."""
    toc = node.toc[index]
    value_offset = toc.v if node._has_fixed_kv_size else toc.v.off
    value_end = node.address * 4096 + 4096 - (len(c_apfs.btree_info) if node.is_root else 0)
    start = value_end - value_offset + offset
    buf[start : start + len(data)] = data


def _find_record(node: c_apfs.btree_node_phys, btree: c_apfs.btree, oid: int, type: c_apfs.APFS_TYPE) -> int:
    for i in range(node.nkeys):
        record_oid, record_type = parse_fs_object_key(btree._read_key(node, i))
        if record_oid == oid and record_type == type:
            return i
    raise KeyError((oid, type))


def _fusion_streams(marker: bytes) -> tuple[bytearray, bytearray]:
    """Build two small mapping streams from the beta image.

    The directory leaf and the file extent are moved to the tier-2 stream at the same
    addresses as the tier-1 stream holds marker bytes, so a wrong source is detectable.
    """
    raw = bytearray(gzip.decompress(absolute_path("_data/case_insensitive_beta.bin.gz").read_bytes()))
    container = APFS(BytesIO(bytes(raw)))
    volume = container.volumes[0]
    inode = volume.get("dir/file")

    cursor = Cursor(volume.root_tree, volume.omap, volume.object.apfs_root_tree_oid, volume.xid)
    cursor.first()
    leaf = cursor._node

    extent_index = _find_record(leaf, volume.root_tree, inode.private_id, c_apfs.APFS_TYPE.FILE_EXTENT)
    extent = c_apfs.j_file_extent_val(volume.root_tree._read_value(leaf, extent_index))
    file_block = extent.phys_block_num

    omap_node = volume.omap.btree.root
    for omap_index in range(omap_node.nkeys):
        key = c_apfs.omap_key(volume.omap.btree._read_key(omap_node, omap_index))
        if key.ok_oid == leaf.oid:
            break
    else:
        raise AssertionError("Could not find the directory leaf in the volume object map")

    # Point the file extent at the same block address on the tier-2 device.
    _patch_block_value(raw, leaf, extent_index, 8, (FUSION_TIER2_BLOCK_MASK | file_block).to_bytes(8, "little"))

    tier1 = bytearray(raw)
    tier2 = bytearray(len(raw))

    # Point the volume object map at the directory leaf on the tier-2 device.
    _patch_block_value(tier1, omap_node, omap_index, 8, (FUSION_TIER2_BLOCK_MASK | leaf.address).to_bytes(8, "little"))

    # Both streams hold different bytes at the same block offsets.
    _set_block(tier2, leaf.address, _block(raw, leaf.address))
    _set_block(tier2, file_block, b"Fusion tier-2 dat".ljust(4096, b"!"))

    _set_block(tier1, leaf.address, marker.ljust(4096, b"#"))
    _set_block(tier1, file_block, b"Fusion tier-1 dat".ljust(4096, b"@"))

    return tier1, tier2


def test_fusion_tier2_routing() -> None:
    """Test that Fusion tier-2 addresses route metadata and file extents to the second device."""
    tier1, tier2 = _fusion_streams(b"tier2-marker")

    with (
        BufferedStream(BytesIO(tier1), size=len(tier1)) as fh,
        BufferedStream(BytesIO(tier2), size=len(tier2)) as tier2_fh,
    ):
        container = APFS(fh, tier2_fh)
        assert container.block_size == 4096
        assert container.tier2_block_mask == FUSION_TIER2_BLOCK_MASK
        assert container.device_block_address(FUSION_TIER2_BLOCK_MASK | 0x5D) == 0x5D

        # The selection bit is defined as a byte address, so it converts by block size.
        assert fusion_tier2_device_mask(512) == c_apfs.FUSION_TIER2_DEVICE_BYTE_ADDR >> 9
        assert fusion_tier2_device_mask(4096) != fusion_tier2_device_mask(512)
        with pytest.raises(ValueError, match="Invalid block size"):
            fusion_tier2_device_mask(3000)

        volume = container.volumes[0]

        # Directory objects come from the tier-2 leaf that replaced the tier-1 marker block.
        assert "dir" in volume.get("/").listdir()
        assert volume.get("dir/file").open().read() == b"Fusion tier-2 da"

        block, device = container.read_block_with_device(FUSION_TIER2_BLOCK_MASK | 0x5D)
        assert device == "tier2"
        assert block.startswith(b"Fusion tier-2 ")


def test_fusion_marks_same_offset_differently() -> None:
    """Test that both streams use the same offsets with different marker bytes."""
    tier1, tier2 = _fusion_streams(b"tier2-marker")

    with (
        BufferedStream(BytesIO(tier1), size=len(tier1)) as fh,
        BufferedStream(BytesIO(tier2), size=len(tier2)) as tier2_fh,
    ):
        fusion = APFS(fh, tier2_fh)

        # The same block offset resolves to different bytes on each device.
        tier1_block, tier1_device = fusion.read_block_with_device(0x5D)
        tier2_block, tier2_device = fusion.read_block_with_device(FUSION_TIER2_BLOCK_MASK | 0x5D)
        assert tier1_device == "tier1"
        assert tier2_device == "tier2"
        assert tier1_block.startswith(b"Fusion tier-1 ")
        assert tier2_block.startswith(b"Fusion tier-2 ")

        # The directory listing and the file content both use the tier-2 leaf.
        assert "dir" in fusion.volumes[0].get("/").listdir()
        assert fusion.volumes[0].get("dir/file").open().read() == b"Fusion tier-2 da"


def test_fusion_missing_tier2_device() -> None:
    """Test that a tier-2 address without a second device fails explicitly."""
    tier1, _ = _fusion_streams(b"tier2-marker")

    with BufferedStream(BytesIO(tier1), size=len(tier1)) as fh:
        container = APFS(fh)
        assert not container.is_fusion

        with pytest.raises(Error, match="no tier-2 device was provided"):
            container.read_block(FUSION_TIER2_BLOCK_MASK | 0x5D)

        with pytest.raises(Error, match="no tier-2 device was provided"):
            container.volumes[0].get("dir/file")


def test_fusion_short_tier2_device() -> None:
    """Test that a tier-2 device that is too small fails explicitly."""
    tier1, tier2 = _fusion_streams(b"tier2-marker")

    with BufferedStream(BytesIO(tier1), size=len(tier1)) as fh, BytesIO(bytes(tier2[: 0x5D * 4096])) as tier2_fh:
        container = APFS(fh, tier2_fh)

        with pytest.raises(Error, match="beyond the capacity"):
            container.read_block(FUSION_TIER2_BLOCK_MASK | 0x5D)


def test_fusion_crossing_device_boundary() -> None:
    """Test that a read spanning the Fusion device selection boundary is rejected."""
    tier1, tier2 = _fusion_streams(b"tier2-marker")

    with (
        BufferedStream(BytesIO(tier1), size=len(tier1)) as fh,
        BufferedStream(BytesIO(tier2), size=len(tier2)) as tier2_fh,
    ):
        container = APFS(fh, tier2_fh)

        with pytest.raises(Error, match="crosses the Fusion device selection boundary"):
            container.read_block(FUSION_TIER2_BLOCK_MASK - 1, count=2)

        with pytest.raises(Error, match="crosses the Fusion device selection boundary"):
            container.read_block(0x5D, count=FUSION_TIER2_BLOCK_MASK)


def test_single_device_reads_unchanged() -> None:
    """Test that single-device use keeps reading the first stream only."""
    with gzip.open(absolute_path("_data/case_insensitive_beta.bin.gz"), "rb") as fh:
        container = APFS(fh)
        assert not container.is_fusion
        assert container.tier2_fh is None

        volume = container.volumes[0]
        assert volume.get("dir/file").open().read() == b"\xef\xa3\xbf File System\n"
