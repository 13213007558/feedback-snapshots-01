from __future__ import annotations

import stat
import struct
from io import BytesIO

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.consistency import (
    INODE_NUMBER_MISMATCH,
    LOOKUP_ENTRY_CORRUPT,
    TYPE_MISMATCH,
    check_consistency,
)
from dissect.squashfs.squashfs import SquashFS


def _metadata_block(data: bytes) -> bytes:
    assert len(data) <= c_squashfs.SQUASHFS_METADATA_SIZE
    return struct.pack("<H", len(data) | c_squashfs.SQUASHFS_COMPRESSED_BIT) + data


def _dir_inode(inode_number: int, file_size: int) -> bytes:
    return bytes(
        c_squashfs.squashfs_dir_inode_header(
            inode_type=c_squashfs.SQUASHFS_DIR_TYPE,
            mode=0o755,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=inode_number,
            start_block=0,
            nlink=2,
            file_size=file_size,
            offset=0,
            parent_inode=inode_number,
        )
    )


def _reg_inode(inode_number: int) -> bytes:
    return bytes(
        c_squashfs.squashfs_reg_inode_header(
            inode_type=c_squashfs.SQUASHFS_FILE_TYPE,
            mode=0o644,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=inode_number,
            start_block=0,
            fragment=c_squashfs.SQUASHFS_INVALID_FRAG,
            offset=0,
            file_size=0,
        )
    )


def _fifo_inode(inode_number: int) -> bytes:
    return bytes(
        c_squashfs.squashfs_base_inode_header(
            inode_type=c_squashfs.SQUASHFS_FIFO_TYPE,
            mode=0o644,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=inode_number,
        )
    )


def _build_image(
    entries: list[tuple[str, int, int, int]],
    inodes: list[tuple[int, bytes]],
    *,
    base_inode: int,
    lookup: bool = True,
    corrupt_lookup: dict[int, int] | None = None,
    lookup_block: int | None = None,
    entry_offsets: dict[int, int] | None = None,
) -> bytes:
    """Build a minimal SquashFS 4 image with uncompressed metadata.

    ``entries`` contains ``(name, inode_number, declared_type, signed_delta)``.
    Inodes are laid out in the given order; the first one must be the root directory
    inode with number 1.
    """
    # Lay out non-root inodes first so we know their offsets relative to the inode table.
    inode_offsets: dict[int, int] = {}
    offset = len(_dir_inode(1, 0))
    other_inodes = []
    for inode_number, data in inodes[1:]:
        inode_offsets[inode_number] = offset
        other_inodes.append(data)
        offset += len(data)

    directory_data = bytes(
        c_squashfs.squashfs_dir_header(
            count=len(entries) - 1,
            start_block=0,
            inode_number=base_inode,
        )
    )
    entry_offsets = entry_offsets or {}
    for name, inode_number, declared_type, delta in entries:
        assert inode_number == base_inode + delta
        directory_data += bytes(
            c_squashfs.squashfs_dir_entry(
                offset=entry_offsets.get(inode_number, inode_offsets[inode_number]),
                inode_number=delta,
                type=declared_type,
                size=len(name) - 1,
            )
        )
        directory_data += name.encode()

    root_inode = _dir_inode(1, len(directory_data) + 3)
    inode_table_data = _metadata_block(root_inode + b"".join(other_inodes))
    directory_table_data = _metadata_block(directory_data)

    inode_table_start = len(c_squashfs.squashfs_super_block)
    position = inode_table_start + len(inode_table_data)
    directory_table_start = position
    position += len(directory_table_data)

    id_metadata_address = position
    id_metadata = _metadata_block(struct.pack("<I", 0))
    position += len(id_metadata)
    id_table_start = position
    position += 8

    lookup_metadata_address = None
    lookup_table_start = c_squashfs.SQUASHFS_INVALID_BLK
    if lookup:
        corrupt_lookup = corrupt_lookup or {}
        lookup_entries = []
        for inode_number, _ in inodes:
            if inode_number in corrupt_lookup:
                lookup_entries.append(corrupt_lookup[inode_number])
            else:
                lookup_entries.append(inode_offsets.get(inode_number, 0))

        lookup_metadata = _metadata_block(b"".join(struct.pack("<Q", value) for value in lookup_entries))
        lookup_metadata_address = position
        position += len(lookup_metadata)
        lookup_table_start = lookup_block if lookup_block is not None else position
        position += 8

    superblock = bytes(
        c_squashfs.squashfs_super_block(
            s_magic=c_squashfs.SQUASHFS_MAGIC,
            inodes=len(inodes),
            mkfs_time=0,
            block_size=131072,
            fragments=0,
            compression=c_squashfs.ZLIB_COMPRESSION,
            block_log=17,
            flags=0x80 if lookup else 0,
            no_ids=1,
            s_major=4,
            s_minor=0,
            root_inode=0,
            bytes_used=position,
            id_table_start=id_table_start,
            xattr_id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
            inode_table_start=inode_table_start,
            directory_table_start=directory_table_start,
            fragment_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
            lookup_table_start=lookup_table_start,
        )
    )

    image = bytearray(superblock)
    image += inode_table_data
    image += directory_table_data
    image += id_metadata
    image += struct.pack("<Q", id_metadata_address)

    if lookup:
        image += lookup_metadata
        image += struct.pack("<Q", lookup_metadata_address)

    assert len(image) == position
    return bytes(image)


def _nested_image() -> bytes:
    root_data = (
        bytes(c_squashfs.squashfs_dir_header(count=0, start_block=0, inode_number=2))
        + bytes(c_squashfs.squashfs_dir_entry(offset=32, inode_number=0, type=c_squashfs.SQUASHFS_DIR_TYPE, size=2))
        + b"dir"
    )
    nested_data = (
        bytes(c_squashfs.squashfs_dir_header(count=0, start_block=0, inode_number=3))
        + bytes(c_squashfs.squashfs_dir_entry(offset=64, inode_number=0, type=c_squashfs.SQUASHFS_FILE_TYPE, size=5))
        + b"nested"
    )
    directory_data = root_data + nested_data

    dir_inode = bytes(
        c_squashfs.squashfs_dir_inode_header(
            inode_type=c_squashfs.SQUASHFS_DIR_TYPE,
            mode=0o755,
            uid=0,
            guid=0,
            mtime=0,
            inode_number=2,
            start_block=0,
            nlink=2,
            file_size=len(nested_data) + 3,
            offset=len(root_data),
            parent_inode=1,
        )
    )
    inode_data = _dir_inode(1, len(root_data) + 3) + dir_inode + _reg_inode(3)

    inode_table_start = len(c_squashfs.squashfs_super_block)
    inode_table_data = _metadata_block(inode_data)
    position = inode_table_start + len(inode_table_data)
    directory_table_start = position
    directory_table_data = _metadata_block(directory_data)
    position += len(directory_table_data)

    id_metadata_address = position
    id_metadata = _metadata_block(struct.pack("<I", 0))
    position += len(id_metadata)
    id_table_start = position
    position += 8

    lookup_metadata_address = position
    lookup_metadata = _metadata_block(struct.pack("<Q", 0) + struct.pack("<Q", 32) + struct.pack("<Q", 64))
    position += len(lookup_metadata)
    lookup_table_start = position
    position += 8

    superblock = bytes(
        c_squashfs.squashfs_super_block(
            s_magic=c_squashfs.SQUASHFS_MAGIC,
            inodes=3,
            mkfs_time=0,
            block_size=131072,
            fragments=0,
            compression=c_squashfs.ZLIB_COMPRESSION,
            block_log=17,
            flags=0x80,
            no_ids=1,
            s_major=4,
            s_minor=0,
            root_inode=0,
            bytes_used=position,
            id_table_start=id_table_start,
            xattr_id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
            inode_table_start=inode_table_start,
            directory_table_start=directory_table_start,
            fragment_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
            lookup_table_start=lookup_table_start,
        )
    )

    image = superblock + inode_table_data + directory_table_data + id_metadata + struct.pack("<Q", id_metadata_address)
    image += lookup_metadata + struct.pack("<Q", lookup_metadata_address)
    assert len(image) == position
    return image


def _hardlink_image(*, lookup: bool = True, corrupt_lookup: dict[int, int] | None = None) -> bytes:
    return _build_image(
        [
            ("hardlink-a", 2, c_squashfs.SQUASHFS_FILE_TYPE, 0),
            ("hardlink-b", 2, c_squashfs.SQUASHFS_FILE_TYPE, 0),
        ],
        [(1, b""), (2, _reg_inode(2))],
        base_inode=2,
        lookup=lookup,
        corrupt_lookup=corrupt_lookup,
    )


def _type_mismatch_image(*, lookup: bool = True) -> bytes:
    # The directory entry declares a regular file and uses a signed delta to reach
    # inode 2, whose actual inode header describes a FIFO.
    return _build_image(
        [("regular-looking", 2, c_squashfs.SQUASHFS_FILE_TYPE, -3)],
        [(1, b""), (2, _fifo_inode(2))],
        base_inode=5,
        lookup=lookup,
    )


def test_hardlink_shared_inode_is_not_a_conflict() -> None:
    fs = SquashFS(BytesIO(_hardlink_image()))
    report = fs.check_consistency()

    assert report.consistent
    assert report.lookup_table is not None
    assert report.lookup_table.status == "ok"
    assert len(report.entries) == 2
    assert all(entry.consistent for entry in report.entries)

    first, second = report.entries
    assert first.directory.inode_record_address == second.directory.inode_record_address == (0, 32)
    assert first.directory.directory_record_address != second.directory.directory_record_address
    assert first.lookup.address == second.lookup.address == (0, 32)

    node_a = fs.get("hardlink-a")
    node_b = fs.get("hardlink-b")
    assert node_a.inode_number == node_b.inode_number == 2
    assert node_a.is_file()
    assert node_b.is_file()
    assert node_a.directory_entry.record_offset != node_b.directory_entry.record_offset


def test_directory_type_conflict_is_reported_and_traversal_uses_inode_header() -> None:
    fs = SquashFS(BytesIO(_type_mismatch_image()))
    report = fs.check_consistency()

    assert not report.consistent
    assert report.lookup_table is not None
    assert report.lookup_table.status == "ok"

    entry = report.for_path("/regular-looking")
    assert entry is not None
    assert not entry.consistent

    claim = entry.directory
    assert claim.inode_number == 2
    assert claim.inode_number_base == 5
    assert claim.inode_number_delta == -3
    assert claim.inode_type == c_squashfs.SQUASHFS_FILE_TYPE
    assert claim.inode_record_address == (0, 32)
    assert claim.directory_record_address[0] > 0
    assert entry.inode_header.inode_type == c_squashfs.SQUASHFS_FIFO_TYPE
    assert entry.inode_header.inode_number == 2
    assert entry.lookup.matches is True

    issue_kinds = [issue.kind for issue in entry.issues]
    assert TYPE_MISMATCH in issue_kinds

    node = fs.get("regular-looking")
    assert node.type == stat.S_IFIFO
    assert not node.is_file()
    assert node.declared_type == stat.S_IFREG
    assert node.declared_inode_number == 2
    assert node.inode_number == 2


def test_without_lookup_table_two_way_comparison_still_works() -> None:
    hardlink_report = SquashFS(BytesIO(_hardlink_image(lookup=False))).check_consistency()
    assert hardlink_report.consistent
    assert hardlink_report.lookup_table is not None
    assert hardlink_report.lookup_table.status == "absent"
    assert hardlink_report.lookup_table.entries == []
    assert all(not entry.lookup.available for entry in hardlink_report.entries)
    assert all(entry.lookup.raw is None for entry in hardlink_report.entries)

    mismatch_report = SquashFS(BytesIO(_type_mismatch_image(lookup=False))).check_consistency()
    assert not mismatch_report.consistent
    assert mismatch_report.lookup_table is not None
    assert mismatch_report.lookup_table.status == "absent"
    entry = mismatch_report.for_path("/regular-looking")
    assert entry is not None
    assert entry.lookup.available is False
    assert TYPE_MISMATCH in [issue.kind for issue in entry.issues]


def test_corrupt_lookup_entry_fails_even_when_directory_and_inode_agree() -> None:
    fs = SquashFS(BytesIO(_hardlink_image(corrupt_lookup={2: 0})))
    report = fs.check_consistency()

    assert not report.consistent
    assert report.lookup_table is not None
    assert report.lookup_table.status == "corrupt"
    assert report.lookup_table.issues
    assert LOOKUP_ENTRY_CORRUPT in [issue.kind for issue in report.all_issues]

    entry = report.for_path("/hardlink-a")
    assert entry is not None
    assert entry.directory.inode_number == entry.inode_header.inode_number == 2
    assert entry.directory.inode_record_address == entry.inode_header.address == (0, 32)
    assert entry.lookup.available is True
    assert entry.lookup.matches is None
    assert entry.lookup.error is not None
    assert LOOKUP_ENTRY_CORRUPT in [issue.kind for issue in entry.issues]


def test_corrupt_unreferenced_lookup_entry_is_still_reported() -> None:
    image = _build_image(
        [("hardlink-a", 2, c_squashfs.SQUASHFS_FILE_TYPE, 0)],
        [(1, b""), (2, _reg_inode(2)), (3, _reg_inode(3))],
        base_inode=2,
        corrupt_lookup={3: 0},
    )
    report = SquashFS(BytesIO(image)).check_consistency()

    assert not report.consistent
    assert report.lookup_table is not None
    assert report.lookup_table.status == "corrupt"
    assert any(issue.inode_number == 3 for issue in report.lookup_table.issues)


def test_lookup_entry_pointing_at_wrong_inode_is_corrupt() -> None:
    # The directory and inode header both agree on inode 2, but the independent lookup
    # entry for inode 2 points at inode 3's record. This must fail the third path even
    # though the two-way comparison still looks fine.
    wrong_target = 32 + len(_reg_inode(2))
    image = _build_image(
        [("hardlink-a", 2, c_squashfs.SQUASHFS_FILE_TYPE, 0)],
        [(1, b""), (2, _reg_inode(2)), (3, _reg_inode(3))],
        base_inode=2,
        corrupt_lookup={2: wrong_target},
    )
    report = SquashFS(BytesIO(image)).check_consistency()

    assert not report.consistent
    assert report.lookup_table is not None
    assert report.lookup_table.status == "corrupt"
    assert any(issue.inode_number == 2 for issue in report.lookup_table.issues)
    assert LOOKUP_ENTRY_CORRUPT in [issue.kind for issue in report.all_issues]

    entry = report.for_path("/hardlink-a")
    assert entry is not None
    assert entry.directory.inode_record_address == entry.inode_header.address == (0, 32)
    assert entry.lookup.address == (0, wrong_target)
    assert entry.lookup.matches is None


def test_inode_number_conflict_between_directory_and_header() -> None:
    inode_2 = _reg_inode(2)
    image = _build_image(
        [("hardlink-a", 2, c_squashfs.SQUASHFS_FILE_TYPE, 0)],
        [(1, b""), (2, inode_2), (3, _reg_inode(3))],
        base_inode=2,
        lookup=False,
        entry_offsets={2: 32 + len(inode_2)},
    )
    report = SquashFS(BytesIO(image)).check_consistency()

    assert not report.consistent
    entry = report.for_path("/hardlink-a")
    assert entry is not None
    assert entry.directory.inode_number == 2
    assert entry.inode_header.inode_number == 3
    assert INODE_NUMBER_MISMATCH in [issue.kind for issue in entry.issues]


def test_report_exposes_raw_values_and_trust_boundaries() -> None:
    fs = SquashFS(BytesIO(_type_mismatch_image()))
    report = fs.check_consistency()
    rendered = report.describe()

    assert "directory: inode_number=2 (base=5 delta=-3)" in rendered
    assert "type=2" in rendered
    assert "inode_header:" in rendered
    assert "type=6" in rendered
    assert "lookup:" in rendered
    assert "trust_boundary:" in rendered

    data = report.as_dict()
    entry = data["entries"][0]
    assert entry["directory"]["inode_number_delta"] == -3
    assert entry["directory"]["inode_number_base"] == 5
    assert entry["directory"]["inode_record_address"] == [0, 32]
    assert entry["directory"]["trusted"] is False
    assert entry["directory"]["trust_boundary"]
    assert entry["inode_header"]["inode_type"] == c_squashfs.SQUASHFS_FIFO_TYPE
    assert entry["inode_header"]["trusted"] is True
    assert entry["lookup"]["raw"] == 32
    assert entry["lookup"]["matches"] is True
    assert data["lookup_table"]["status"] == "ok"
    assert data["lookup_table"]["trusted"] is True
    assert data["consistent"] is False


def test_module_level_check_consistency() -> None:
    fs = SquashFS(BytesIO(_hardlink_image()))
    assert check_consistency(fs).consistent


def test_nested_directory_reports_nested_paths() -> None:
    image = _nested_image()
    report = SquashFS(BytesIO(image)).check_consistency()

    assert report.consistent
    assert {entry.path for entry in report.entries} == {"/dir", "/dir/nested"}


def test_unreadable_inode_type_is_unknown_not_pass() -> None:
    image = bytearray(_hardlink_image())
    fs = SquashFS(BytesIO(image))

    # Change the shared inode's type to an unknown value. Its identity is still
    # readable, but the type evidence cannot be trusted, so this must not pass.
    image[fs.sb.inode_table_start + 2 + 32 : fs.sb.inode_table_start + 2 + 32 + 2] = b"\xff\x00"
    report = SquashFS(BytesIO(bytes(image))).check_consistency()

    assert not report.consistent
    entry = report.for_path("/hardlink-a")
    assert entry is not None
    assert entry.inode_header.inode_number == 2
    assert entry.inode_header.inode_type == 0xFF
    assert entry.inode_header.trusted is False


@pytest.mark.parametrize(
    "fixture_name",
    ["gzip_sqfs", "gzip_opts_sqfs", "lz4_sqfs", "lzo_sqfs", "xz_sqfs", "zstd_sqfs"],
)
def test_bundled_images_are_consistent(fixture_name: str, request: pytest.FixtureRequest) -> None:
    fs = SquashFS(request.getfixturevalue(fixture_name))
    report = fs.check_consistency()

    assert report.consistent
    assert report.lookup_table is not None
    assert report.lookup_table.status == "ok"
    assert report.lookup_table.trusted
    assert len(report.entries) > 100
    assert all(entry.consistent for entry in report.entries)
