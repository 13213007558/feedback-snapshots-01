from __future__ import annotations

from io import BytesIO

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import (
    NotADirectoryError,
    NotAFileError,
    NotASymlinkError,
)
from dissect.squashfs.squashfs import SquashFS


def _verify_filesystem(sqfs: SquashFS) -> None:
    assert sqfs.root.is_dir()
    assert sorted(sqfs.root.listdir().keys()) == [
        "dir",
        "file-with-xattr",
        "large-file",
        "small-file",
        "symlink-1",
        "symlink-2",
        "symlink-with-xattr",
    ]

    f1 = sqfs.get("small-file")
    assert f1.is_file()
    assert f1.size == 9
    assert str(f1.mtime) == "2022-12-05 18:53:05+00:00"
    assert f1.open().read() == b"contents\n"
    f2 = sqfs.get("large-file")
    assert f2.is_file()
    assert f2.size == 4177920
    assert f2.open().read() == b"".join([bytes([i] * 4096) for i in range(255)]) * 4

    s1 = sqfs.get("symlink-1")
    assert s1.is_symlink()
    assert s1.link == "small-file"
    s2 = sqfs.get("symlink-2")
    assert s2.is_symlink()
    assert s2.link == "dir/file_69"

    d1 = sqfs.get("dir")
    assert d1.is_dir()
    assert d1.size == 1507
    assert len(list(d1.iterdir())) == 100

    assert sqfs.get("dir/file_69").inode_number == s2.link_inode.inode_number

    with pytest.raises(NotAFileError):
        sqfs.get("dir").open()

    with pytest.raises(NotADirectoryError):
        sqfs.get("small-file").listdir()

    with pytest.raises(NotASymlinkError):
        assert sqfs.get("large-file").link


@pytest.mark.parametrize(
    ("sqfs", "compression_id"),
    [
        ("gzip_sqfs", c_squashfs.ZLIB_COMPRESSION),
        ("gzip_opts_sqfs", c_squashfs.ZLIB_COMPRESSION),
        ("lz4_sqfs", c_squashfs.LZ4_COMPRESSION),
        # Whether LZMA works seems to depend on if your machine has been blessed by the compression gods
        # Include the test data for reference material, but don't test against it
        # ("lzma_sqfs", c_squashfs.LZMA_COMPRESSION),
        ("lzo_sqfs", c_squashfs.LZO_COMPRESSION),
        ("xz_sqfs", c_squashfs.XZ_COMPRESSION),
        ("zstd_sqfs", c_squashfs.ZSTD_COMPRESSION),
    ],
)
def test_squashfs(sqfs: str, compression_id: int, request: pytest.FixtureRequest) -> None:
    sqfs = SquashFS(request.getfixturevalue(sqfs))
    assert sqfs.sb.compression == compression_id
    _verify_filesystem(sqfs)


def test_squashfs_unsupported_bigendian_3_0() -> None:
    """Test if we correctly detect a SquashFS 3.0 big-endian filesystem."""
    # Random SquashFS version 3.0 big-endian header found on binwalk GitHub issue tracker.
    buf = bytes.fromhex(
        "73717368000000b60000002042010d364200bc844200339440016800000300006b0400104003004ae64f330000000000"
        "001623000100000000001177ff8e0800000000000e303100000000000e3025000000000000000000000000000e234c00"
    )

    sb = c_squashfs.squashfs_super_block(buf)
    assert sb.s_magic == c_squashfs.SQUASHFS_MAGIC_SWAP
    assert sb.s_major == 0x300

    with pytest.raises(NotImplementedError, match=r"Unsupported squashfs pre-4.0 big-endian filesystem"):
        SquashFS(BytesIO(buf))


def _metadata_block(data: bytes) -> bytes:
    import struct

    # Uncompressed metadata block: high bit set, followed by its payload length.
    return struct.pack("<H", len(data) | 0x8000) + data


def _inode_payload(entry: dict[str, object], inode_number: int) -> bytes:
    kind = str(entry["kind"])
    header_type = (
        int(entry.get("header_type", 0))
        or {
            "file": c_squashfs.SQUASHFS_LREG_TYPE,
            "dir": c_squashfs.SQUASHFS_LDIR_TYPE,
            "symlink": c_squashfs.SQUASHFS_LSYMLINK_TYPE,
        }[kind]
    )
    nlink = int(entry.get("nlink", 2 if kind == "dir" else 1))

    if kind == "file":
        # This fixture only exercises inode identity and type metadata. Files are empty so no
        # data block is implied.
        header = c_squashfs.squashfs_lreg_inode_header(
            inode_type=header_type,
            mode=0o0644,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=inode_number,
            start_block=0,
            file_size=0,
            sparse=0,
            nlink=nlink,
            fragment=c_squashfs.SQUASHFS_INVALID_FRAG,
            offset=0,
            xattr=c_squashfs.SQUASHFS_INVALID_XATTR,
        )
        return bytes(header)
    if kind == "symlink":
        target = bytes(entry.get("target", b""))
        header = c_squashfs.squashfs_symlink_inode_header(
            inode_type=header_type,
            mode=0o0777,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=inode_number,
            nlink=nlink,
            symlink_size=len(target),
        )
        return bytes(header) + target
    if kind == "dir":
        header = c_squashfs.squashfs_ldir_inode_header(
            inode_type=header_type,
            mode=0o0755,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=inode_number,
            nlink=nlink,
            file_size=0,
            start_block=0,
            parent_inode=0,
            i_count=0,
            offset=0,
            xattr=c_squashfs.SQUASHFS_INVALID_XATTR,
        )
        return bytes(header)
    raise ValueError(f"Unsupported kind: {kind}")


def _squashfs_image(
    entries: list[dict[str, object]],
    *,
    lookup: bool = True,
    lookup_overrides: dict[int, int] | None = None,
    invalid_lookup_block: bool = False,
    dir_inode_number_overrides: dict[str, int] | None = None,
) -> BytesIO:
    """Build a tiny uncompressed SquashFS 4 image containing the given root entries.

    ``entries`` are dictionaries with ``path``, ``kind`` and optionally ``key`` (to share an inode
    between paths), ``dir_type`` (the type declared by the directory entry), ``header_type`` and
    ``target`` for symlinks. The directory header base inode number is deliberately offset from the
    first declared inode number so signed negative deltas are exercised.
    """
    import struct

    numbers: dict[str, int] = {}
    representatives: dict[str, dict[str, object]] = {}
    for entry in entries:
        key = str(entry.get("key", entry["path"]))
        if key not in numbers:
            numbers[key] = len(numbers) + 1
            representatives[key] = entry
    root_number = len(numbers) + 1

    inode_offsets: dict[str, int] = {}
    inode_data = bytearray()
    for key, entry in representatives.items():
        inode_offsets[key] = len(inode_data)
        inode_data += _inode_payload(entry, numbers[key])
    root_offset = len(inode_data)

    if entries:
        base_inode_number = numbers[str(entries[0].get("key", entries[0]["path"]))] + 3
        dir_data = bytearray(struct.pack("<III", len(entries) - 1, 0, base_inode_number))
        for entry in entries:
            key = str(entry.get("key", entry["path"]))
            name = str(entry["path"]).rsplit("/", 1)[-1].encode()
            declared_type = (
                int(entry.get("dir_type", 0))
                or {
                    "file": c_squashfs.SQUASHFS_FILE_TYPE,
                    "dir": c_squashfs.SQUASHFS_DIR_TYPE,
                    "symlink": c_squashfs.SQUASHFS_SYMLINK_TYPE,
                }[str(entry["kind"])]
            )
            delta = (dir_inode_number_overrides or {}).get(str(entry["path"]), numbers[key]) - base_inode_number
            dir_data += struct.pack("<HhHH", inode_offsets[key], delta, declared_type, len(name) - 1)
            dir_data += name
    else:
        dir_data = bytearray()

    root_header = c_squashfs.squashfs_ldir_inode_header(
        inode_type=c_squashfs.SQUASHFS_LDIR_TYPE,
        mode=0o0755,
        uid=0,
        guid=0,
        mtime=0,
        inode_number=root_number,
        nlink=2,
        file_size=len(dir_data) + 3,
        start_block=0,
        parent_inode=0,
        i_count=0,
        offset=0,
        xattr=c_squashfs.SQUASHFS_INVALID_XATTR,
    )
    inode_data += bytes(root_header)

    image = bytearray(bytes(96))  # Aligned superblock placeholder.
    inode_table_start = len(image)
    image += _metadata_block(bytes(inode_data))
    directory_table_start = len(image)
    image += _metadata_block(bytes(dir_data))

    if lookup:
        refs = bytearray()
        for key in sorted(numbers, key=numbers.get):
            refs += struct.pack("<Q", inode_offsets[key])
        refs += struct.pack("<Q", root_offset)
        for inode_number, reference in (lookup_overrides or {}).items():
            refs[(inode_number - 1) * 8 : inode_number * 8] = struct.pack("<Q", reference)

        lookup_metadata_offset = len(image)
        image += _metadata_block(bytes(refs))
        lookup_table_start = len(image)
        image += struct.pack("<q", c_squashfs.SQUASHFS_INVALID_BLK if invalid_lookup_block else lookup_metadata_offset)
        flags = 1 << c_squashfs.SQUASHFS_EXPORT
    else:
        lookup_table_start = c_squashfs.SQUASHFS_INVALID_BLK
        flags = 1 << c_squashfs.SQUASHFS_NOI

    sb = c_squashfs.squashfs_super_block(
        s_magic=c_squashfs.SQUASHFS_MAGIC,
        inodes=len(numbers) + 1,
        mkfs_time=0,
        block_size=4096,
        fragments=0,
        compression=c_squashfs.ZLIB_COMPRESSION,
        block_log=12,
        flags=flags,
        no_ids=0,
        s_major=4,
        s_minor=0,
        root_inode=(0 << 16) | root_offset,
        bytes_used=len(image),
        id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        xattr_id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        inode_table_start=inode_table_start,
        directory_table_start=directory_table_start,
        fragment_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        lookup_table_start=lookup_table_start,
    )
    image[:96] = bytes(sb)
    return BytesIO(bytes(image))


def test_inode_consistency_hardlink_and_signed_delta() -> None:
    """A shared inode is a legitimate hardlink, not a consistency conflict."""
    entries = [
        {"path": "/hardlink-b", "kind": "file", "key": "shared", "nlink": 2},
        {"path": "/hardlink-a", "kind": "file", "key": "shared", "nlink": 2},
        {"path": "/plain", "kind": "file"},
    ]
    sqfs = SquashFS(_squashfs_image(entries))
    report = sqfs.check_consistency()

    assert report.lookup is not None
    assert report.lookup.status == "available"
    assert report.is_consistent
    assert not report.conflicts
    assert not report.errors

    by_name = {entry.name: entry for entry in report}
    a, b = by_name["hardlink-a"], by_name["hardlink-b"]
    assert a.directory.declared_inode_number == b.directory.declared_inode_number
    assert a.directory.inode_record_address == b.directory.inode_record_address
    assert a.inode.inode_number == b.inode.inode_number
    assert a.lookup_match is True
    assert b.lookup_match is True
    assert a.shared_inode
    assert b.shared_inode
    assert report.shared_inodes[(a.directory.inode_block, a.directory.inode_offset)] == [
        "/hardlink-b",
        "/hardlink-a",
    ]

    # The directory header base is offset, so the raw signed deltas are negative and retained.
    assert a.directory.inode_number_delta < 0
    assert a.directory.declared_inode_number == a.directory.dir_header_inode_number + a.directory.inode_number_delta
    assert a.directory.inode_record_address == sqfs.sb.inode_table_start + a.directory.inode_block

    # Normal traversal follows the inode header, while the directory declaration stays available.
    node = sqfs.get("hardlink-a")
    assert node.is_file()
    assert node.inode_number == a.inode.inode_number
    assert node.directory_type == c_squashfs.SQUASHFS_FILE_TYPE


def test_inode_consistency_reports_type_mismatch() -> None:
    """A directory entry that declares a regular file but points at a symlink must be reported."""
    entries = [
        {"path": "/disguised", "kind": "symlink", "target": b"target", "dir_type": c_squashfs.SQUASHFS_FILE_TYPE},
    ]
    sqfs = SquashFS(_squashfs_image(entries))
    report = sqfs.check_consistency()

    assert not report.is_consistent
    assert len(report.conflicts) == 1
    entry = report.conflicts[0]
    assert entry.name == "disguised"
    assert entry.inode_number_match is True
    assert entry.type_match is False
    assert entry.lookup_match is True
    assert [issue.code for issue in entry.issues] == ["type_mismatch"]

    # Raw values from both sources remain visible, with their trust boundaries.
    assert entry.directory.declared_type == c_squashfs.SQUASHFS_FILE_TYPE
    assert entry.directory.type_name == "file"
    assert entry.inode.inode_type == c_squashfs.SQUASHFS_LSYMLINK_TYPE
    assert entry.inode.type_name == "long-symlink"
    assert entry.directory.inode_record_address == sqfs.sb.inode_table_start + entry.directory.inode_block
    assert set(entry.trust_boundaries) == {"directory", "inode_header", "lookup_table"}

    # Ordinary traversal exposes the real inode type rather than the misleading declaration.
    node = sqfs.get("disguised")
    assert node.is_symlink()
    assert not node.is_file()
    assert node.directory_type == c_squashfs.SQUASHFS_FILE_TYPE


def test_inode_consistency_without_lookup_table() -> None:
    """Without a lookup table the two available sources are still compared."""
    sqfs = SquashFS(_squashfs_image([{"path": "/file", "kind": "file"}], lookup=False))
    report = sqfs.check_consistency()

    assert report.lookup is not None
    assert report.lookup.available is False
    assert report.lookup.status == "unavailable"
    assert report.is_consistent

    entry = report.entries[0]
    assert entry.inode_number_match is True
    assert entry.type_match is True
    assert entry.lookup_match is None
    assert entry.lookup.available is False
    assert entry.lookup.error is not None


def test_inode_consistency_corrupt_lookup_entry() -> None:
    """A broken lookup entry is reported separately and cannot be treated as agreement."""
    entries = [{"path": "/file", "kind": "file"}]
    sqfs = SquashFS(_squashfs_image(entries, lookup_overrides={1: 0xFFFFFFFFFFFFFFFF}))
    report = sqfs.check_consistency()

    assert report.lookup is not None
    assert report.lookup.status == "corrupt"
    assert not report.is_consistent

    entry = report.entries[0]
    assert entry.inode_number_match is True
    assert entry.type_match is True
    assert entry.lookup_match is None
    assert [issue.code for issue in entry.issues] == ["lookup_entry_invalid"]
    assert entry.lookup.error is not None


def test_inode_consistency_corrupt_lookup_table() -> None:
    """A declared but unreadable lookup table is a lookup failure, not a two-way pass."""
    sqfs = SquashFS(_squashfs_image([{"path": "/file", "kind": "file"}], invalid_lookup_block=True))
    report = sqfs.check_consistency()

    assert report.lookup is not None
    assert report.lookup.status == "corrupt"
    assert report.lookup.present
    assert not report.is_consistent
    assert report.entries[0].lookup_match is None
    assert "lookup_table_invalid" in [issue.code for issue in report.entries[0].issues]


def test_inode_consistency_reports_inode_number_mismatch() -> None:
    """A directory entry can point at a real inode whose header number disagrees with the declaration."""
    entries = [{"path": "/wrong-number", "kind": "file"}]
    sqfs = SquashFS(_squashfs_image(entries, dir_inode_number_overrides={"/wrong-number": 2}))
    report = sqfs.check_consistency()

    assert not report.is_consistent
    entry = report.entries[0]
    assert entry.inode_number_match is False
    assert entry.type_match is True
    assert entry.lookup_match is False
    assert entry.lookup.error is None
    assert "inode_number_mismatch" in [issue.code for issue in entry.issues]
    assert "lookup_address_mismatch" in [issue.code for issue in entry.issues]
    assert entry.directory.declared_inode_number == 2
    assert entry.inode.inode_number == 1


def test_inode_consistency_start_and_max_depth() -> None:
    """The checker can be scoped to a directory without changing normal traversal."""
    sqfs = SquashFS(
        _squashfs_image(
            [
                {"path": "/file", "kind": "file"},
                {"path": "/sub", "kind": "dir"},
            ]
        )
    )

    report = sqfs.check_consistency()
    assert [entry.path for entry in report] == ["/file", "/sub"]

    root_only = sqfs.check_consistency(max_depth=0)
    assert [entry.path for entry in root_only] == ["/file", "/sub"]
    assert root_only.is_consistent

    sub = sqfs.get("sub")
    scoped = sqfs.check_consistency(start=sub)
    assert scoped.entries == []


def test_lookup_inode_carries_reference() -> None:
    """Normal inode lookup still resolves through the export table and retains its raw reference."""
    sqfs = SquashFS(_squashfs_image([{"path": "/file", "kind": "file"}]))
    node = sqfs._lookup_inode(1)

    assert node.inode_number == 1
    assert node.inode_record == 0
    assert node.is_file()


def test_lookup_inode_entry_reports_corruption() -> None:
    """Direct lookup evidence distinguishes an absent table from a declared but broken one."""
    sqfs = SquashFS(_squashfs_image([{"path": "/file", "kind": "file"}], lookup=False))
    absent = sqfs.lookup_inode_entry(1)
    assert absent.available is False
    assert absent.error is not None
    assert sqfs.lookup_table_status().status == "unavailable"

    broken = SquashFS(_squashfs_image([{"path": "/file", "kind": "file"}], invalid_lookup_block=True))
    evidence = broken.lookup_inode_entry(1)
    assert evidence.available is True
    assert evidence.error is not None
    assert evidence.present is True
    assert broken.lookup_table_status().status == "corrupt"
