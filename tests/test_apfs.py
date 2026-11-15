from __future__ import annotations

import gzip
import hashlib
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.apfs.apfs import APFS, log
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import (
    EncryptionError,
    UnsupportedKeyGenerationError,
    VolumeLockedError,
    VolumeMismatchError,
)
from dissect.apfs.objects.fs import VolumeKeyContext
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
            snapshot_fs = snapshot.open()
            assert snapshot_fs.tree_xid == snapshot.xid
            assert snapshot_fs.get("file").open().read() == f"Snapshot {i}\n".encode()


def test_encrypted_snapshots() -> None:
    """Test opening snapshots of an encrypted volume.

    The current volume and the snapshot have the same file path with different content, and both
    must be read at their own transaction with their own content.
    """
    with gzip.open(absolute_path("_data/encrypted_snapshot.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]

        assert volume.is_encrypted
        assert len(volume.snapshots) == 2

        locked, unsupported = volume.snapshots

        # Without unlocking the volume, no snapshot may be opened and no directory may leak out.
        with pytest.raises(VolumeLockedError):
            locked.open()
        with pytest.raises(VolumeLockedError):
            volume.get("dir/file")

        volume.unlock("password")

        current = volume.get("dir/file")
        assert current.open().read() == b"\xef\xa3\xbf File System\n"

        snapshot_fs = locked.open()
        assert snapshot_fs.uuid == volume.uuid
        assert snapshot_fs.tree_xid == locked.xid
        assert snapshot_fs.key_context is volume.key_context
        # The snapshot shares the volume object map, but resolves its own transaction.
        assert snapshot_fs.omap is volume.omap
        assert snapshot_fs.root_tree.address != volume.root_tree.address

        snapshot_file = snapshot_fs.get("dir/file")
        assert snapshot_file.oid == current.oid
        assert snapshot_file.open().read() == b"Snapshot file content\n"

        # Reading the live volume after opening the snapshot still returns the live content.
        assert volume.get("dir/file").open().read() == b"\xef\xa3\xbf File System\n"

        # A snapshot that requires a different key generation must fail instead of being opened.
        with pytest.raises(UnsupportedKeyGenerationError):
            unsupported.open()


def test_snapshot_key_context_volume_mismatch() -> None:
    """Test that a key context can only be used for the volume it was derived for."""
    with gzip.open(absolute_path("_data/encrypted_snapshot.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]
        volume.unlock("password")

        with gzip.open(absolute_path("_data/jhfs_encrypted.bin.gz"), "rb") as other_fh:
            other_volume = APFS(other_fh).volumes[0]
            other_volume.unlock("password")
            other_context = other_volume.key_context
            other_content = other_volume.get("dir/file").open().read()

        snapshot = volume.snapshots[0]
        with pytest.raises(VolumeMismatchError):
            snapshot.open(key_context=other_context)

        # A context for another volume must not have been applied to the snapshot or its parent.
        assert volume.get("dir/file").open().read() == b"\xef\xa3\xbf File System\n"
        assert other_content == b"\xef\xa3\xbf File System\n"

        # A well-bound context with the wrong key fails eagerly, before any directory is returned.
        wrong_key = VolumeKeyContext(volume.uuid, b"\x01" * 32, volume.crypto_state, container_uuid=container.uuid)
        with pytest.raises(EncryptionError):
            snapshot.open(key_context=wrong_key)

        # The correct context still works.
        assert snapshot.open().get("dir/file").open().read() == b"Snapshot file content\n"

        # An explicit context is not silently applied to a parent that was never unlocked: the
        # snapshot uses it, but the live volume still requires its own unlock.
        with gzip.open(absolute_path("_data/encrypted_snapshot.bin.gz"), "rb") as fresh_fh:
            fresh_volume = APFS(fresh_fh).volumes[0]
            explicit = fresh_volume.snapshots[0].open(key_context=volume.key_context)
            assert explicit.get("dir/file").open().read() == b"Snapshot file content\n"
            with pytest.raises(VolumeLockedError):
                fresh_volume.get("dir/file")


def test_snapshot_key_context_unsupported_mode() -> None:
    """Test that unsupported encryption states fail explicitly instead of partially opening."""
    with gzip.open(absolute_path("_data/encrypted_snapshot.bin.gz"), "rb") as fh:
        container = APFS(fh)
        volume = container.volumes[0]
        volume.unlock("password")

        snapshot = volume.snapshots[0]
        snapshot_fs = snapshot.open()

        # Mutating the snapshot's crypto state out from under the context must be rejected when a
        # new context is applied.
        snapshot_fs._crypto_state = None
        snapshot_fs.object.apfs_meta_crypto.key_revision = 2
        with pytest.raises(UnsupportedKeyGenerationError):
            snapshot_fs.apply_key_context(volume.key_context)

        # An unencrypted volume refuses an encryption context instead of silently ignoring it.
        with gzip.open(absolute_path("_data/snapshot.bin.gz"), "rb") as plain_fh:
            plain_volume = APFS(plain_fh).volumes[0]
            with pytest.raises(VolumeMismatchError):
                plain_volume.apply_key_context(volume.key_context)


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
