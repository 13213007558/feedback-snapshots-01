from __future__ import annotations

import io
import struct
import uuid

import pytest

from dissect.archive.tibx.c_tibx import c_tibx
from dissect.archive.tibx.exception import InvalidArchiveError
from dissect.archive.tibx.tibx import TIBX
from tests._tools.tibx._synth import (
    PAGE,
    Cell,
    ExtentSpec,
    ImapItem,
    build_lsm_archive,
    imap,
    lsb,
    lsm_page,
    slice_record,
)

# A chain lives in one archive: each backup writes its extents under its own slice id, and
# the slices tree (TLV[5]) records the backups. Slice ids are not contiguous in the wild --
# a real differential chain numbered its two backups 2 and 4 -- so this uses 2, 3, 5.
SLICES = [2, 3, 5]


def _chain() -> TIBX:
    archive = build_lsm_archive(
        [
            ExtentSpec(10, 0, b"base state" + b"\x00" * 54, slice_id=2),
            ExtentSpec(10, 0, b"after first backup" + b"\x00" * 46, slice_id=3),
            ExtentSpec(10, 0, b"after second backup" + b"\x00" * 45, slice_id=5),
        ],
        slices=SLICES,
    )
    return TIBX(io.BytesIO(archive))


def test_slice_record_size() -> None:
    # Ensure that the slice_record struct remains correct size
    assert len(c_tibx.slice_record) == 0x84


def test_recovery_points_are_backups_not_commit_roots() -> None:
    # Acronis writes a varying number of ARCH commit roots per backup, so counting roots
    # invents recovery points that were never taken. The slices tree is the archive's own
    # record of its backups, and matches what "acrocmd list backups" lists.
    tibx = _chain()
    points = tibx.recovery_points()

    assert len(points) == 3
    assert [p.index for p in points] == [0, 1, 2]
    assert [p.slice_id for p in points] == SLICES


def test_recovery_point_carries_guid_and_times() -> None:
    point = _chain().recovery_points()[1]

    assert point.guid == uuid.UUID(bytes_le=bytes([3]) * 16)
    assert point.created.timestamp() == pytest.approx(3.0)
    assert point.finished.timestamp() == pytest.approx(3.01)


def test_latest_is_default() -> None:
    tibx = _chain()
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_select_by_index() -> None:
    tibx = _chain()
    tibx.use_recovery_point(0)
    assert tibx.streams()[0].read(0, 10) == b"base state"

    tibx.use_recovery_point(1)
    assert tibx.streams()[0].read(0, 18) == b"after first backup"

    tibx.use_recovery_point(2)
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_selection_is_by_slice_not_position() -> None:
    # Selecting a point takes every extent up to and including its slice id. Picking the
    # middle backup of a chain whose ids are 2, 3, 5 must not be read as "slice <= 1".
    tibx = _chain()
    tibx.use_recovery_point(1)

    assert {extent.slice_id for extent in tibx.extents} == {2, 3}


def test_select_oldest_and_latest() -> None:
    tibx = _chain()
    tibx.use_recovery_point("oldest")
    assert tibx.streams()[0].read(0, 10) == b"base state"
    tibx.use_recovery_point("latest")
    assert tibx.streams()[0].read(0, 19) == b"after second backup"


def test_index_out_of_range() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="out of range"):
        tibx.use_recovery_point(5)


def test_select_by_recovery_point_object() -> None:
    tibx = _chain()
    point = tibx.recovery_points()[1]
    tibx.use_recovery_point(point)

    assert tibx.view.slice_id == 3
    assert tibx.streams()[0].read(0, 18) == b"after first backup"
    assert tibx.view_at(point).slice_id == 3

    with pytest.raises(InvalidArchiveError, match="not one of this archive"):
        other = _chain().recovery_points()[1]
        other._record = c_tibx.slice_record(bytes([9]) * 16, 3000, 3010)
        other.guid = uuid.UUID(bytes_le=bytes([9]) * 16)
        tibx.use_recovery_point(other)


def test_invalid_selector() -> None:
    tibx = _chain()
    with pytest.raises(InvalidArchiveError, match="invalid recovery point"):
        tibx.use_recovery_point("bogus")


def test_archive_without_slices_reports_no_recovery_points() -> None:
    # An archive whose slices tree is absent records no backups. Reporting none is right;
    # the previous behaviour counted commit roots and reported points that never existed.
    archive = build_lsm_archive([ExtentSpec(10, 0, b"x" * 64)])
    tibx = TIBX(io.BytesIO(archive))

    assert tibx.recovery_points() == []
    with pytest.raises(InvalidArchiveError, match="records no backups"):
        tibx.use_recovery_point(0)


def test_recovery_points_from_memtree_and_ctrees() -> None:
    # As the slices tree grows its records move from the mem-tree into on-disk ctrees, like
    # those of every LSM tree. Across them the newest record of a slice wins.
    extents = [ExtentSpec(10, 0, b"x" * 64, slice_id=slice_id) for slice_id in SLICES]

    def cell(slice_id: int, marker: int) -> Cell:
        key = c_tibx.slice_key(slice_id=slice_id).dumps()
        return Cell(key, slice_record(bytes([marker]) * 16, 1000 * slice_id, 1000 * slice_id + 10))

    leaf_page = len(build_lsm_archive(extents)) // PAGE
    slices = lsb(
        4,
        len(c_tibx.slice_record),
        memtree_cells=[cell(3, 0x33)],  # newer than the ctree's record of slice 3
        ctrees=[(leaf_page * PAGE, 3)],
    )
    leaf = lsm_page(c_tibx.PageType.LEAF, b"LEAF", [cell(2, 2), cell(3, 3), cell(5, 5)], key_length=4, compact=True)
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, extra_slots={5: slices}) + leaf))

    points = tibx.recovery_points()
    assert [point.slice_id for point in points] == SLICES
    assert [point.guid.bytes_le[0] for point in points] == [2, 0x33, 5]

    tibx.use_recovery_point(2)
    assert tibx.extents


def _ntfs_boot(total_sectors: int) -> bytes:
    """A boot sector just complete enough to parse a volume size from."""
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, 512)
    struct.pack_into("<Q", boot, 0x28, total_sectors)
    return bytes(boot)


def _rotating_streams() -> TIBX:
    # Two backups of one logical partition. The same name, disk1/part1, is stored under a new
    # data_map stream in the second differential backup (4 then 6), while one segment holds
    # the unchanged boot sector of both. Slice ids stay non-contiguous (2, 4, 7); a third
    # backup (7) deletes the partition without writing new content for it.
    boot = _ntfs_boot(0x18000)
    items = [
        ImapItem(2, b"disk1/part1", 4, 0x18000),
        ImapItem(4, b"disk1/part1", 6, 0x18000),
        ImapItem(4, b"meta", 9, 64),
        ImapItem(7, b"disk1/part1", 0, 0, flags=c_tibx.ItemFlags.DELETED),
        ImapItem(7, b"meta", 9, 64),
    ]
    return TIBX(
        io.BytesIO(
            build_lsm_archive(
                [
                    ExtentSpec(4, 0, boot, slice_id=2, segment_group=1),
                    ExtentSpec(4, 0x10000, b"first generation".ljust(512, b"\x00"), slice_id=2),
                    ExtentSpec(6, 0, boot, slice_id=4, segment_group=1),
                    ExtentSpec(6, 0x10000, b"second generation".ljust(512, b"\x00"), slice_id=4),
                    ExtentSpec(9, 0, b'\xef\xbb\xbf<?xml version="1.0"?><metainfo/>', slice_id=4),
                ],
                slices=[2, 4, 7],
                extra_slots={0: imap(items)},
            )
        )
    )


def test_views_of_several_points_can_be_read_interleaved() -> None:
    # Two views of the same logical partition, stored under different data_map streams.
    # Reading one must never disturb the other, and switching the archive back and forth
    # must not change either.
    tibx = _rotating_streams()
    first = tibx.view_at(0)
    second = tibx.view_at(1)

    assert [volume.volume_id for volume in first.volumes()] == [4]
    assert [volume.volume_id for volume in second.volumes()] == [6]
    first_volume = first.volumes()[0]
    second_volume = second.volumes()[0]
    assert first_volume.view is first
    assert second_volume.view is second
    assert (first_volume.slice_id, second_volume.slice_id) == (2, 4)

    assert first_volume.read(0x10000, 16) == b"first generation"
    assert second_volume.read(0x10000, 17) == b"second generation"

    tibx.use_recovery_point(2)
    assert [volume.volume_id for volume in tibx.volumes()] == []
    assert first_volume.read(0x10000, 16) == b"first generation"
    assert second_volume.read(0x10000, 17) == b"second generation"

    # A selected view reflects the archived selection, including switching back
    tibx.use_recovery_point(0)
    assert [volume.volume_id for volume in tibx.volumes()] == [4]
    assert tibx.volumes()[0].read(0x10000, 16) == b"first generation"
    assert second_volume.read(0x10000, 17) == b"second generation"


def test_volume_size_is_bound_to_its_view() -> None:
    # The imap records the partition's size per version: the first view's volume must keep
    # the size it was published with even after the archive selects another point.
    tibx = _rotating_streams()
    first = tibx.view_at(0).volumes()[0]
    assert first.size == 0x18000

    tibx.use_recovery_point(1)
    assert tibx.volumes()[0].size == 0x18000
    tibx.use_recovery_point(2)
    assert first.size == 0x18000


def test_deleted_partition_does_not_resurrect_an_older_stream() -> None:
    # The last backup records the partition as deleted. Its streams -- and the one before --
    # are in the data_map, but neither may be reported as a volume, neither by name nor by
    # falling back to content classification of the old generation.
    tibx = _rotating_streams()
    tibx.use_recovery_point(2)

    assert tibx.volumes() == []
    assert {stream.volume_id for stream in tibx.streams()} == {4, 6, 9}

    # The older views still have their partition; a new view of the same point stays empty.
    assert [volume.volume_id for volume in tibx.view_at(0).volumes()] == [4]
    assert [volume.volume_id for volume in tibx.view_at(1).volumes()] == [6]
    assert tibx.view_at(2).volumes() == []


def test_segment_cache_is_shared_between_views() -> None:
    # Views share the archive's immutable segment plaintext; they do not copy the cache.
    tibx = _rotating_streams()
    first = tibx.view_at(0)
    second = tibx.view_at(1)

    # The boot sector is one segment, shared by the two generations. Reading it through
    # both views compresses and caches it once.
    assert first.volumes()[0].read(3, 8) == second.volumes()[0].read(3, 8) == b"NTFS    "
    assert len(tibx._segment_cache) == 1
    assert first.tibx is second.tibx

    # The changing tails are separate segments, and reading them leaves the shared one in
    # place for either view.
    first.volumes()[0].read(0x10000, 4)
    second.volumes()[0].read(0x10000, 4)
    assert len(tibx._segment_cache) == 3
    assert first.volumes()[0].read(3, 8) == second.volumes()[0].read(3, 8) == b"NTFS    "


def test_view_after_switching_back_uses_the_selected_point() -> None:
    # The acceptance criterion in reverse: a *new* view must reflect the selection at the
    # time it is made, not the first point ever looked at or the order views were created.
    tibx = _rotating_streams()
    first = tibx.view_at(0)
    tibx.use_recovery_point(1)
    second = tibx.view_at(1)

    assert [v.volume_id for v in first.volumes()] == [4]
    assert [v.volume_id for v in second.volumes()] == [6]
    assert [v.volume_id for v in tibx.view.volumes()] == [6]

    tibx.use_recovery_point(0)
    assert [v.volume_id for v in tibx.view.volumes()] == [4]
    assert [v.volume_id for v in second.volumes()] == [6]


def test_an_incomplete_partition_version_is_not_a_volume() -> None:
    # An unfinished backup's partition is recorded without COMPLETE. It is not a deletion,
    # so content classification still sees the stream. A completed later version does exist
    # in the archive but must not leak into the earlier view.
    boot = _ntfs_boot(0x18000)
    items = [
        ImapItem(2, b"disk1/part1", 4, 0x18000, flags=c_tibx.ItemFlags(0)),
        ImapItem(4, b"disk1/part1", 6, 0x18000),
    ]
    tibx = TIBX(
        io.BytesIO(
            build_lsm_archive(
                [
                    ExtentSpec(4, 0, boot, slice_id=2),
                    ExtentSpec(6, 0, boot, slice_id=4),
                ],
                slices=[2, 4],
                extra_slots={0: imap(items)},
            )
        )
    )

    tibx.use_recovery_point(0)
    assert [volume.volume_id for volume in tibx.volumes()] == [4]
    tibx.use_recovery_point(1)
    assert [volume.volume_id for volume in tibx.volumes()] == [6]


def test_deleted_partition_still_reports_its_previous_size_to_an_older_view() -> None:
    # Both the size and the extents of an open view stay put. A deletion recorded later
    # (with a zero stream id) must not change what the partition was at that point.
    boot = _ntfs_boot(0x18000)
    items = [
        ImapItem(2, b"disk1/part1", 4, 0x18000),
        ImapItem(7, b"disk1/part1", 0, 0, flags=c_tibx.ItemFlags.DELETED),
    ]
    tibx = TIBX(
        io.BytesIO(
            build_lsm_archive(
                [ExtentSpec(4, 0, boot, slice_id=2)],
                slices=[2, 7],
                extra_slots={0: imap(items)},
            )
        )
    )

    old = tibx.view_at(0).volumes()[0]
    assert (old.volume_id, old.slice_id, old.size) == (4, 2, 0x18000)
    tibx.use_recovery_point(1)
    assert tibx.volumes() == []
    assert (old.slice_id, old.size) == (2, 0x18000)
    assert old.read(3, 4) == b"NTFS"
