from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import XattrError
from dissect.squashfs.squashfs import SquashFS
from dissect.squashfs.xattr import XattrSource, decode_xattr_entry

if TYPE_CHECKING:
    from typing import BinaryIO


def test_existing_fixture_xattrs(gzip_sqfs: BinaryIO) -> None:
    fs = SquashFS(gzip_sqfs)
    assert fs.xattr_ids == 1
    assert len(fs.xattr_id_table) == 1

    inode = fs.get("file-with-xattr")
    assert inode.xattr_id == 0
    assert len(inode.xattrs) == 1

    attribute = inode.xattrs[0]
    assert attribute.name == "security.selinux"
    assert attribute.prefix == c_squashfs.SQUASHFS_XATTR_SECURITY
    assert attribute.suffix == "selinux"
    assert attribute.value.endswith(b"\x00")
    assert attribute.out_of_line is False
    assert attribute.source.xattr_id == 0
    assert attribute.value_source is attribute.source

    assert inode.getxattr("security.selinux") is attribute
    assert inode.get_xattr("security.selinux") is attribute
    assert inode.getxattr("security.capability") is None


def test_long_symlink_xattr(gzip_sqfs: BinaryIO) -> None:
    fs = SquashFS(gzip_sqfs)
    inode = fs.get("symlink-with-xattr")
    assert inode.is_symlink()
    assert inode.link == "file-with-xattr"
    assert inode.xattr_id == 0
    assert [attribute.name for attribute in inode.xattrs] == ["security.selinux"]


def test_inode_with_shared_xattr(gzip_sqfs: BinaryIO) -> None:
    # The fixture deduplicates this SELinux attribute into a single xattr ID.
    fs = SquashFS(gzip_sqfs)
    inode = fs.get("dir/file_69")
    assert inode.xattr_id == 0
    assert [attribute.name for attribute in inode.xattrs] == ["security.selinux"]


def test_xattr_id_out_of_bounds(gzip_sqfs: BinaryIO) -> None:
    fs = SquashFS(gzip_sqfs)
    with pytest.raises(IndexError):
        fs.xattrs(1)
    with pytest.raises(IndexError):
        fs.xattr(-1)


def test_decode_xattr_unknown_prefix() -> None:
    attribute = decode_xattr_entry(0x42, b"name", b"value")
    assert attribute.prefix == 0x42
    assert attribute.name == "<prefix:66>.name"
    assert attribute.value == b"value"
    assert attribute.source.out_of_line is False


def test_xattr_source_defaults() -> None:
    source = XattrSource()
    assert source.xattr_id is None
    assert source.out_of_line is False
    assert source.ool_ref is None


def test_xattr_error_is_value_error() -> None:
    assert issubclass(XattrError, ValueError)


def test_xattr_error_is_exported() -> None:
    import dissect.squashfs

    assert dissect.squashfs.XattrError is XattrError
