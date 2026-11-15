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


def _ntfs_boot(total_sectors: int, sector_size: int = 512) -> bytes:
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, sector_size)
    struct.pack_into("<Q", boot, 0x28, total_sectors)
    return bytes(boot)


def _two_partition_chain() -> TIBX:
    """Three backups (slice ids 2, 3, 5) where one partition moves to a new stream each time.

    ``disk1/part1`` is written to stream 4 by slice 2, to stream 8 by slice 3, and to
    stream 12 by slice 5. ``disk1/part2`` is on stream 9 in slice 2 and 3, then deleted by
    slice 5. The first partition's two generations also share one *immutable* segment for
    their unchanged tail, as an incremental would: stream 4 and stream 8 both map it.
    """
    boot = _ntfs_boot(0x20)
    extents = [
        ExtentSpec(4, 0, boot, slice_id=2, extent_id=1),
        ExtentSpec(4, 0x1000, b"first content", slice_id=2, extent_id=2),
        ExtentSpec(4, 0x1100, b"shared tail", slice_id=2, extent_id=3, segment_group=1),
        ExtentSpec(8, 0, boot, slice_id=3, extent_id=1),
        ExtentSpec(8, 0x1000, b"second content", slice_id=3, extent_id=2),
        ExtentSpec(8, 0x1100, b"shared tail", slice_id=3, extent_id=4, segment_group=1),
        ExtentSpec(12, 0, boot, slice_id=5, extent_id=1),
        ExtentSpec(12, 0x1000, b"third content", slice_id=5, extent_id=2),
        ExtentSpec(9, 0, boot, slice_id=2, extent_id=1),
        ExtentSpec(9, 0x1000, b"doomed", slice_id=2, extent_id=2),
    ]
    # Each generation reports a distinct imap size, so a size read through the wrong
    # recovery point is visible rather than coincidentally equal
    items = [
        ImapItem(2, b"disk1/part1", 4, 0x2000),
        ImapItem(2, b"disk1/part2", 9, 0x2000),
        ImapItem(3, b"disk1/part1", 8, 0x3000),
        ImapItem(3, b"disk1/part2", 9, 0x2000),
        ImapItem(5, b"disk1/part1", 12, 0x4000),
        ImapItem(
            5,
            b"disk1/part2",
            0,
            0,
            flags=c_tibx.ItemFlags.COMPLETE | c_tibx.ItemFlags.DELETED,
        ),
    ]
    return TIBX(io.BytesIO(build_lsm_archive(extents, slices=SLICES, extra_slots={0: imap(items)})))


def test_views_read_interleaved_recovery_points_without_drift() -> None:
    # Two views of the same logical partition, read alternately while the archive itself
    # switches selection underneath them. Every view keeps its own bytes, size and source
    # stream, no matter which point the archive currently reflects.
    tibx = _two_partition_chain()
    old, new = tibx.view(0), tibx.view(1)
    old_part = next(volume for volume in old.volumes() if volume.volume_id == 4)
    new_part = next(volume for volume in new.volumes() if volume.volume_id == 8)

    assert (old_part.volume_id, new_part.volume_id) == (4, 8)
    assert old_part.read(0x1000, 13) == b"first content"
    assert new_part.read(0x1000, 14) == b"second content"

    tibx.use_recovery_point(2)
    assert old_part.read(0x1000, 13) == b"first content"
    assert new_part.read(0x1000, 14) == b"second content"
    # Sizes are first touched only now, after the archive moved on: each must still come
    # from the imap snapshot of the view its volume was opened for.
    assert old_part.size == 0x2000
    assert new_part.size == 0x3000

    # A view created after the switch follows the selection, with a stream of its own
    latest_part = next(volume for volume in tibx.volumes() if volume.volume_id == 12)
    assert latest_part.read(0x1000, 13) == b"third content"
    assert latest_part.size == 0x4000


def test_switching_back_does_not_change_a_previously_opened_view() -> None:
    tibx = _two_partition_chain()
    old_view = tibx.view(0)
    old_part = next(volume for volume in old_view.volumes() if volume.volume_id == 4)

    tibx.use_recovery_point(1)
    assert old_part.read(0x1000, 6) == b"first "

    # Switch back through the archive: the new view is byte-identical to the first one,
    # and the old volume still reads from the stream it was opened for.
    tibx.use_recovery_point(0)
    reopened = next(volume for volume in tibx.volumes() if volume.volume_id == 4)
    assert reopened.read(0x1000, 6) == old_part.read(0x1000, 6) == b"first "
    assert reopened.size == old_part.size
    assert list(reopened.extents) == list(old_part.extents)


def test_deleted_partition_stays_deleted_in_its_view() -> None:
    # Slice 5 deletes disk1/part2. A view of slice 5 must not resurrect the stream its
    # slice-2 record still points at, and the older view must still see that stream.
    tibx = _two_partition_chain()
    old_view = tibx.view("oldest")
    deleted_view = tibx.view(2)

    assert [volume.volume_id for volume in old_view.volumes()] == [4, 9]
    assert [volume.volume_id for volume in deleted_view.volumes()] == [12]
    assert deleted_view.stream_size(9) is None
    assert old_view.stream_size(9) == 0x2000


def test_views_share_the_decompressed_segment_cache() -> None:
    tibx = _two_partition_chain()
    old = tibx.view(0)
    new = tibx.view(1)
    old_part = next(volume for volume in old.volumes() if volume.volume_id == 4)
    new_part = next(volume for volume in new.volumes() if volume.volume_id == 8)

    # The unchanged tail lives in one segment both generations reference. Reading it
    # through the first view must serve the second view from the same cache entry, not
    # duplicate decompressed data per view.
    assert old_part.read(0x1100, 11) == b"shared tail"
    cached = dict(tibx._segment_cache)
    assert new_part.read(0x1100, 11) == b"shared tail"
    assert dict(tibx._segment_cache) == cached
    assert old.tibx is new.tibx is tibx


def test_view_with_only_deleted_partitions_has_no_volumes() -> None:
    # A backup whose imap names partitions but whose every version is deleted or
    # incomplete must not fall back to content classification: that would surface a
    # stream the partition no longer owns.
    boot = _ntfs_boot(0x20)
    extents = [
        ExtentSpec(4, 0, boot + b"\x00" * 0x100, slice_id=2),
        ExtentSpec(4, 0x1000, b"old content", slice_id=2),
    ]
    items = [
        ImapItem(2, b"disk1/part1", 4, 0x2000),
        ImapItem(3, b"disk1/part1", 4, 0x2000, flags=c_tibx.ItemFlags(0)),
    ]
    tibx = TIBX(io.BytesIO(build_lsm_archive(extents, slices=SLICES, extra_slots={0: imap(items)})))

    assert [volume.volume_id for volume in tibx.view(0).volumes()] == [4]
    assert tibx.view(1).volumes() == []


def test_view_from_locked_archive_sees_imap_after_unlock() -> None:
    # A view created while the imap is unreadable caches an empty item list. Unlocking
    # must let that same view see the volumes and sizes it now may read, without
    # rebuilding the view or dropping the extent table it already resolved.
    from dissect.archive.tibx.exception import InvalidPasswordError

    password = b"password"
    boot = _ntfs_boot(0x20)
    items = [ImapItem(2, b"disk1/part1", 4, 0x2000)]
    archive = build_lsm_archive(
        [ExtentSpec(4, 0, boot + b"\x00" * 512, slice_id=2), ExtentSpec(4, 0x1000, b"secret", slice_id=2)],
        slices=[2],
        password=password,
        extra_slots={0: imap(items)},
    )
    tibx = TIBX(io.BytesIO(archive))

    def locked() -> list:
        raise InvalidPasswordError("imap encrypted")

    tibx._item_streams = locked  # as if the imap itself were encrypted and still locked
    view = tibx.view(0)
    extents = view.extents
    assert view.volumes() == []

    del tibx._item_streams
    tibx.unlock(password)
    assert view.extents is extents
    assert [volume.volume_id for volume in view.volumes()] == [4]
    assert view.stream_size(4) == 0x2000
    assert view.volumes()[0].read(0x1000, 6) == b"secret"
