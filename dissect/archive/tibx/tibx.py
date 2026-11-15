"""TIBX archive facade: volume enumeration and lazy, recency-resolved volume reads.

A backed-up volume is reconstructed from the data_map: possibly-overlapping extents
(incremental/differential backups append new extents over older ones; the base extents
stay in the tree) are flattened per byte into a non-overlapping interval list, keeping
the newest extent -- keyed by the slice id that wrote it, which is the only reliable
global recency signal. Sparse gaps between intervals are genuine unallocated space and
read back as zeros. Only the segments backing a requested range are fetched and
decompressed, so reads are fully lazy.

A :class:`TibxView` is the archive as of one recovery point. Volumes are bound to the
view that created them, so selecting another point on the archive never changes what an
already-open volume reports or reads. Segment plaintext, segment locations and the
layout of extents shared by several backups are immutable properties of the archive and
stay shared across every view.
"""

from __future__ import annotations

import datetime
import heapq
import re
import uuid
import weakref
from array import array
from bisect import bisect_right
from collections import OrderedDict, defaultdict
from itertools import compress, groupby, islice, repeat
from operator import add, itemgetter, le, ne
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.util.stream import AlignedStream, MappingStream

from dissect.archive.tibx.c_tibx import (
    EXT_MAGIC,
    EXT_SUPERBLOCK_OFFSET,
    EXTENT_ALIGNMENT,
    EXTENT_INDEX_WHOLE_SEGMENT,
    IMAP_KEY_SIZE,
    IMAP_STREAM_SIZE,
    IMAP_VALUE_SIZE,
    MBR_SIGNATURE,
    MBR_TYPE_GPT_PROTECTIVE,
    PAGE_SIZE,
    SLICE_TYPE_MASK,
    TLV_IMAP,
    TLV_KEYMAP,
    TLV_META,
    TLV_SLICES,
    TLV_VOLUMES,
    c_boot,
    c_tibx,
)
from dissect.archive.tibx.exception import (
    CorruptArchiveError,
    Error,
    InvalidArchiveError,
    InvalidPasswordError,
    MissingVolumeError,
    UnsupportedFormatError,
)
from dissect.archive.tibx.lsm import iter_tree_cells, read_archive_header
from dissect.archive.tibx.map import load_extents, load_segment_index
from dissect.archive.tibx.page import PageStore
from dissect.archive.tibx.segment import read_plaintext
from dissect.archive.tibx.stream import TibxVolumeStream

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.archive.tibx.lsm import ArchiveHeader
    from dissect.archive.tibx.map import Extent, ExtentTable

# Decompressed segments are cached per archive under a memory budget rather than a fixed
# count: random-access workloads (MFT, registry hives) touch thousands of distinct
# segments, and a count of ~32 thrashed to a near-100% miss rate. A byte budget keeps many
# more small segments resident while still bounding memory for large ones.
SEGMENT_CACHE_BUDGET = 256 * 1024 * 1024

# A partition's item name: Acronis looks partitions up as disk%u/part%u. The same
# partition is also linked as part/<hash>.
PARTITION_NAME_RE = re.compile(rb"disk\d+/part\d+")

SPLIT_PART_RE = re.compile(r"^(?P<stem>.+?)-(?P<num>\d{4})\.tibx$", re.IGNORECASE)

# Smallest stream taken to be a partition rather than Acronis metadata, for a stream whose
# filesystem this parser does not recognise. The two populations are far apart in practice:
# across the sample corpora the largest metadata stream is ~2.6 KB and the smallest real
# partition is 16 MB, so this sits in the middle of a gap of some four orders of magnitude.
# On real disks two kinds of metadata do reach it; see TIBX._is_volume.
MIN_VOLUME_SIZE = 1 << 20

# Partitions are imaged in whole sectors of at least this size
SECTOR_SIZE = 512

# Cluster sizes a filesystem may use, from a sector to the 2 MiB NTFS allows; for telling a
# volume's allocation bitmap by its span
CLUSTER_SIZES = tuple(SECTOR_SIZE << shift for shift in range(13))


class RecoveryPoint:
    """One backup in the archive: a *slice*, in the format's own terms.

    A slice is what Acronis calls a backup and what ``acrocmd list backups`` lists; its
    :attr:`guid` is the id printed there. Every data_map extent records the slice that
    wrote it, so selecting a recovery point means taking the extents up to and including
    that slice -- which is how an incremental chain reconstructs an earlier state.

    Slice ids are not contiguous: a differential chain here numbered its two backups 2 and
    4. Address a point by its list index, and let :attr:`slice_id` stay whatever the
    archive says it is.
    """

    def __init__(self, index: int, slice_id: int, record: c_tibx.slice_record):
        self.index = index
        self.slice_id = slice_id
        self.guid = uuid.UUID(bytes_le=record.guid)
        self._record = record

    def __repr__(self) -> str:
        return (
            f"<RecoveryPoint index={self.index} slice={self.slice_id} guid={self.guid} "
            f"finished={self.finished} type={self.type}>"
        )

    @property
    def type(self) -> str:
        """The type of this backup: ``"FULL"``, ``"INCREMENTAL"`` or ``"DIFFERENTIAL"``.

        A type this parser does not know comes back as ``"unknown (<value>)"``.
        """
        slice_type = c_tibx.SliceType(self._record.flags & SLICE_TYPE_MASK)
        return slice_type.name or f"unknown ({int(slice_type):#x})"

    @property
    def created(self) -> datetime.datetime:
        """When this backup started."""
        return datetime.datetime.fromtimestamp(self._record.ctime_ms / 1000, datetime.timezone.utc)

    @property
    def finished(self) -> datetime.datetime:
        """When this backup finished."""
        return datetime.datetime.fromtimestamp(self._record.ftime_ms / 1000, datetime.timezone.utc)


class ItemStream(NamedTuple):
    """One stream of an item record in the imap ("items"), with what the parser needs of the item."""

    slice_id: int
    name: bytes
    flags: int
    index: int
    id: int
    size: int


class TibxView:
    """The archive as of one recovery point.

    A view owns the filtered extent table, its streams and its volumes, and every
    :class:`TibxVolume` it creates keeps a reference to it. Selecting another recovery
    point on the archive therefore never changes what an existing view (or a volume from
    it) reports or reads. Views of different points can be used interleaved.

    What is immutable in the archive stays shared: segment plaintext and locations live
    in the archive's segment cache and are never copied per view, and the within-segment
    layout of extents shared by several backups is computed once for the archive. A view
    adds only its filtered extent rows and the volumes it enumerates.

    Args:
        tibx: The archive the view belongs to.
        recovery_point: The backup the view reflects, or ``None`` for the live root
            (everything the archive holds, the default "latest" selection).
    """

    def __init__(self, tibx: TIBX, recovery_point: RecoveryPoint | None = None):
        self.tibx = tibx
        self.recovery_point = recovery_point
        tibx._views.add(self)
        self._extents: ExtentTable | None = None
        self._streams: list[TibxVolume] | None = None
        self._volumes: list[TibxVolume] | None = None
        self._partition_history: dict[bytes, list[ItemStream]] | None = None
        self._stream_history: dict[int, list[ItemStream]] | None = None

    def __repr__(self) -> str:
        point = self.recovery_point
        selector = "latest" if point is None else f"index={point.index} slice={point.slice_id}"
        return f"<TibxView {selector}>"

    def _release(self) -> None:
        """Drop the volumes this view enumerated, breaking their back-reference cycle.

        Selecting another recovery point leaves an old view reachable through the volumes
        a caller still holds; only closing the archive explicitly lets go of them.
        """
        self._streams = None
        self._volumes = None

    def _reset_imap_state(self) -> None:
        """Drop what was read through the imap, after the archive's data key changed."""
        self._volumes = None
        self._partition_history = None
        self._stream_history = None

    @property
    def slice_id(self) -> int | None:
        """The slice id this view includes up to, or ``None`` for the live root."""
        return self.recovery_point.slice_id if self.recovery_point is not None else None

    @property
    def extents(self) -> ExtentTable:
        """The data_map extents in this view: all of them, or those up to the selected slice."""
        if self._extents is None:
            extents = self.tibx._unfiltered_extents()
            slice_id = self.slice_id
            if slice_id is not None:
                extents = extents.select(map(le, extents.slice_ids, repeat(slice_id)))
            self._extents = extents
        return self._extents

    def streams(self) -> list[TibxVolume]:
        """Every data_map stream in this view, newest backup generation first, then largest first.

        See :meth:`TIBX.streams` for how a differential backup's stream generations rank.
        """
        if self._streams is None:
            extents = self.extents
            streams = [
                TibxVolume(self, vid, extents, start, stop)
                for vid, start, stop in extents.volume_ranges()
            ]
            streams.sort(key=_stream_order, reverse=True)
            self._streams = streams
        return self._streams

    def volumes(self) -> list[TibxVolume]:
        """The backed-up volumes of this view, newest backup generation first, then largest first.

        See :meth:`TIBX.volumes` for how Acronis metadata streams are told apart from
        partitions, and for the fallback used without partition items in the imap.
        """
        if self._volumes is None:
            if self.tibx.archive_type == "file":
                volumes = []
            elif partitions := self._partitions():
                # The imap's size is the size of the version of the partition this view
                # shows, bound to the volume now: another view naming the same stream
                # differently must not change it.
                by_id = {partition.id: partition for partition in partitions}
                extents = self.extents
                volumes = [
                    TibxVolume(self, vid, extents, start, stop, size=by_id[vid].size)
                    for vid, start, stop in extents.volume_ranges()
                    if vid in by_id
                ]
                volumes.sort(key=_stream_order, reverse=True)
                stored = {volume.volume_id for volume in volumes}
                volumes.extend(
                    TibxVolume(self, partition.id, extents, 0, 0, size=partition.size)
                    for partition in partitions
                    if partition.id not in stored
                )
            else:
                # A partition the imap marks deleted is gone as of this view: its old
                # stream must not resurface through content classification. A partition
                # item that is merely incomplete, as in a backup that never finished, is
                # not a deletion and falls through to the same classification as before.
                streams = self.streams()
                bitmap_spans = _bitmap_spans(streams)
                volumes = [
                    stream
                    for stream in streams
                    if stream.volume_id not in self._deleted_streams() and TIBX._is_volume(stream, bitmap_spans)
                ]
            self._volumes = volumes
        return self._volumes

    def _partitions(self) -> list[ItemStream]:
        """The partitions of this view, as the imap names them, by the record of their data stream.

        Empty if the imap names no partition, or if it is encrypted and the archive locked.
        """
        return [
            versions[-1]
            for versions in self._partition_records().values()
            if versions[-1].flags & c_tibx.ItemFlags.COMPLETE and not versions[-1].flags & c_tibx.ItemFlags.DELETED
        ]

    def _partition_records(self) -> dict[bytes, list[ItemStream]]:
        """The imap versions of every partition name in this view, by slice id, oldest first.

        An item's version in a backup is its newest record up to that backup, as Acronis
        lists items. Slice ids order the versions -- never the order records were read or
        views were created.
        """
        if self._partition_history is None:
            try:
                records = self.tibx._item_streams()
            except InvalidPasswordError:
                # The archive may be unlocked later; a locked view caches nothing
                return {}
            history: dict[bytes, list[ItemStream]] = {}
            slice_id = self.slice_id
            for record in sorted(records):
                if record.index != 0 or not PARTITION_NAME_RE.fullmatch(record.name):
                    continue
                if slice_id is not None and record.slice_id > slice_id:
                    continue
                versions = history.setdefault(record.name, [])
                if versions and versions[-1].slice_id == record.slice_id:
                    versions[-1] = record
                else:
                    versions.append(record)
            self._partition_history = history
        return self._partition_history

    def _stream_size(self, volume_id: int) -> int | None:
        """The size the imap gives data_map stream ``volume_id`` in this view.

        ``None`` if the imap does not name the stream, or if it is encrypted and the archive
        is locked. As for an item, the newest live record up to this view's slice decides.
        """
        for record in reversed(self._item_versions().get(volume_id, [])):
            if not record.flags & c_tibx.ItemFlags.DELETED:
                return record.size
        return None

    def _deleted_streams(self) -> set[int]:
        """The data_map streams of partitions the imap marks deleted as of this view.

        The stream that held a deleted partition's last content is the one its newest live
        version named; a deletion may keep that id or record a zero one. A stream still
        named by a live partition is not deleted, even if an old alias was. Excluding both
        keeps the old data from resurfacing through content classification.
        """
        live: set[int] = set()
        deleted: set[int] = set()
        for versions in self._partition_records().values():
            record = versions[-1]
            if record.flags & c_tibx.ItemFlags.DELETED:
                deleted.update(version.id for version in versions if version.id)
            else:
                live.add(record.id)
        return deleted - live

    def _item_versions(self) -> dict[int, list[ItemStream]]:
        """The imap versions of each data_map stream in this view, by slice id, oldest first.

        Ordered by slice id, never by the order records were read or views were created.
        Empty if the imap is encrypted and the archive is locked.
        """
        if self._stream_history is None:
            try:
                records = self.tibx._item_streams()
            except InvalidPasswordError:
                # The archive may be unlocked later; a locked view caches nothing
                return {}
            history: dict[int, list[ItemStream]] = {}
            slice_id = self.slice_id
            for record in sorted(records):
                if slice_id is not None and record.slice_id > slice_id:
                    continue
                versions = history.setdefault(record.id, [])
                if versions and versions[-1].slice_id == record.slice_id:
                    versions[-1] = record
                else:
                    versions.append(record)
            self._stream_history = history
        return self._stream_history


class TIBX:
    """An Acronis TIBX ("archive3") backup archive.

    Opens at the latest recovery point. Use :meth:`recovery_points` to enumerate the
    backups the archive records and :meth:`use_recovery_point` to select an earlier one
    in a chain. :attr:`view` is the archive as of that selection; :meth:`view_at` builds
    an independent one for any recovery point without changing the selection.

    Args:
        fh: A file-like object of the archive, or the ordered file-like objects of a
            split archive's parts (a raw byte-split of one logical page store).

    Raises:
        ~dissect.archive.tibx.exception.MissingVolumeError: If the archive names more volumes
            (files) than ``fh`` gives.
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO]):
        self._handles: list[BinaryIO] = []
        files = None
        if isinstance(fh, list):
            files = len(fh)
            fh = _stitch(fh)
        self.fh = fh
        self.store = PageStore(fh)
        self.root = self.store.live_root()
        self.header = read_archive_header(self.store, self.root)
        if files is not None:
            self._check_files(files)

        self._recovery_points: list[RecoveryPoint] | None = None
        self._selection: RecoveryPoint | None = None
        self._views: weakref.WeakSet[TibxView] = weakref.WeakSet()
        self._data_key = None
        self._reset_snapshot_caches()

    def _reset_snapshot_caches(self) -> None:
        # Everything derived from the live commit root (not the data key)
        self._all_extents: ExtentTable | None = None
        self._segment_index = None
        self._segment_layout: dict[tuple[int, int], int] | None = None
        self._clear_segment_cache()
        self._reset_imap_caches()

    def _reset_imap_caches(self) -> None:
        # The imap may be encrypted, so what it holds also depends on the data key
        self._item_streams_cache: list[ItemStream] | None = None
        for view in self._views:
            view._reset_imap_state()
        self._reset_view_caches()

    def _reset_view_caches(self) -> None:
        # Only the selected view is cached. A segment's plaintext, its location and the
        # layout of the extents it holds do not depend on the recovery point: a segment is
        # written by one backup, and later backups only reference it again.
        self._view = TibxView(self, self._selection)

    def _clear_segment_cache(self) -> None:
        self._segment_cache: OrderedDict[int, bytes] = OrderedDict()
        self._segment_cache_bytes = 0

    @classmethod
    def open(cls, path: str | Path) -> TIBX:
        """Open an archive from a path, auto-discovering split parts.

        The returned instance owns the file handles; call :meth:`close` (or use it as a
        context manager) to release them.

        Raises:
            ~dissect.archive.tibx.exception.MissingVolumeError: If volumes (files) of the archive are
                missing.
        """
        parts = find_split_parts(Path(path))
        numbers = _part_numbers(parts)
        handles = []
        try:
            # Open one by one so a failure mid-list doesn't leak already-opened handles
            for part in parts:
                # Unbuffered for a single file: every read seeks to a page boundary, so a
                # buffer only doubled single-page reads to its 8 KiB, and split a page run
                # that is no multiple of it into two reads. A split set goes through a
                # MappingStream, which expects whole reads from its parts.
                handles.append(part.open("rb", buffering=0 if len(parts) == 1 else -1))  # noqa: PERF401
            try:
                tibx = cls(_stitch(handles, numbers) if len(handles) > 1 else handles[0])
            except Error as e:
                if numbers[0]:
                    # A later file on its own, which need not even start with a header
                    first = SPLIT_PART_RE.match(parts[0].name).group("stem") + parts[0].suffix
                    raise MissingVolumeError(f"missing the first file of this archive, {first}") from e
                raise
            tibx._check_files(len(handles), numbers)
        except Exception:
            for handle in handles:
                handle.close()
            raise
        tibx._handles = handles
        return tibx

    def _check_files(self, found: int, numbers: list[int] | None = None) -> None:
        """Check that the ``found`` files, numbered ``numbers`` if known, are all the files of the archive.

        The table of the archive as a whole is checked here, after the files were mapped by
        the table in the last one, if it had one: a raw byte-split part has none.

        Raises:
            ~dissect.archive.tibx.exception.MissingVolumeError: If they are not.
        """
        if (missing := _missing_volumes_message(_volume_table(self.header), found, numbers)) is not None:
            raise MissingVolumeError(missing)

    def close(self) -> None:
        """Close the file handles owned by this instance (opened via :meth:`open`).

        Also drops the index and the segment cache. Volumes refer back to their archive, so
        without this the index outlived ``with TIBX.open(...)`` until the cyclic garbage
        collector got to it -- hundreds of MiB for a large archive.
        """
        for handle in self._handles:
            try:
                handle.close()
            except OSError:  # noqa: PERF203
                pass
        self._handles = []
        # Release the views' volumes before dropping them: they refer back to their view,
        # and through it to this archive, so without this the index outlived
        # ``with TIBX.open(...)`` until the cyclic garbage collector got to it.
        for view in list(self._views):
            view._release()
        self._reset_snapshot_caches()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def encrypted(self) -> bool:
        """Whether this archive's data segments are encrypted.

        The superblock's ``encr_alg`` is the archive-level signal and costs nothing, but it
        has only been verified for ``header_version`` 8, so a keymap carrying a wrapped data
        key is accepted as evidence too. Use :attr:`password_protected` to find out whether a
        *password* can open it -- an archive wrapped to a certificate is encrypted all the
        same, and no password will help.
        """
        if self.root.encr_alg != c_tibx.EncrAlg.NONE:
            return True
        return self.password_protected or self._certificate_protected

    @property
    def password_protected(self) -> bool:
        """Whether a password can unlock this archive.

        A keymap tree with records is the cheap precondition; it is then confirmed by
        structurally locating the password-wrapped data key, so a keymap that carries no
        such key does not prompt for a password that could never work.
        """
        keymap = self.header.tree(TLV_KEYMAP)
        if keymap is None or not keymap.has_records:
            return False

        from dissect.archive.tibx.crypto import has_password_wrapped_key

        return has_password_wrapped_key(self.header)

    @property
    def _certificate_protected(self) -> bool:
        """Whether the keymap wraps the data key to a certificate rather than a password."""
        keymap = self.header.tree(TLV_KEYMAP)
        if keymap is None or not keymap.has_records:
            return False

        from dissect.archive.tibx.crypto import has_certificate_wrapped_key

        return has_certificate_wrapped_key(self.header)

    @property
    def meta(self) -> dict[c_tibx.MetaKey, str]:
        """The archive's meta (TLV[9]): the archive type, the product that wrote it, its machine, owner and plan.

        TLV[9] holds a NUL-terminated string per slot, in the order of :class:`MetaKey`,
        as libarchive3's ``ar_meta_keys`` names them. An older product writes fewer slots,
        which are left out: Cyber Protect 15 writes no ``PASSWORD_HINT``, True Image 2020
        no ``CENTRALIZED_PLAN_ID`` either. Bytes after the last NUL are ignored, as Acronis
        ignores them. The meta is stored unencrypted, so it can be read without a password,
        even from an encrypted archive.
        """
        # The last piece is what follows the last NUL. Fewer values than keys is an older
        # writer, more ones are no slot libarchive3 knows
        *values, _ = self.header.tlv[TLV_META].payload.split(b"\x00")
        return {key: value.decode("utf-8", "replace") for key, value in zip(c_tibx.MetaKey, values, strict=False)}

    @property
    def archive_type(self) -> str:
        """What the archive holds: ``"disk"`` for a disk-level backup, ``"file"`` for a file-level one.

        The ``TYPE`` of the :attr:`meta`, which Acronis reads as the archive type:
        libarchive3 creates no backup in an archive without one, and ``tibxread`` opens only
        a ``"disk"`` archive. An empty string if the archive has no type.
        """
        return self.meta.get(c_tibx.MetaKey.TYPE, "")

    def unlock(self, password: str | bytes) -> None:
        """Derive the data key from ``password`` to read encrypted segments.

        Raises:
            ~dissect.archive.tibx.exception.InvalidPasswordError: If the password is wrong.
            ~dissect.archive.tibx.exception.UnsupportedFormatError: If the archive is encrypted but wrapped to a
                certificate, which no password can open.
        """
        from dissect.archive.tibx.crypto import unwrap_data_key

        if not self.password_protected and self._certificate_protected:
            raise UnsupportedFormatError(
                "archive is encrypted, but not password-protected: its data key is wrapped "
                "to a certificate, which this parser cannot use"
            )

        self._data_key = unwrap_data_key(self.header, password)
        self._clear_segment_cache()
        self._reset_imap_caches()

    def recovery_points(self) -> list[RecoveryPoint]:
        """The backups in this archive, oldest first.

        Read from the slices tree (TLV[5]), which is the archive's own record of its
        backups: one record per backup, keyed by slice id, carrying the same GUID that
        ``acrocmd list backups`` prints.

        This deliberately does not enumerate ARCH commit roots. A commit root is a
        transactional checkpoint, not a backup, and Acronis writes a varying number of
        them per backup -- two for a single full backup here, four for a file-level one --
        so counting roots reports recovery points that were never taken.
        """
        if self._recovery_points is None:
            records: dict[int, c_tibx.slice_record] = {}
            slices = self.header.tree(TLV_SLICES)
            if slices is not None and slices.has_records:
                seen: set[bytes] = set()
                # Like every LSM tree, the slices tree moves from its mem-tree into on-disk
                # ctrees as it grows; across those runs the newest record of a key wins
                for cell in iter_tree_cells(self.store, slices):
                    if cell.key in seen:
                        continue
                    seen.add(cell.key)
                    # The tree opens with an empty placeholder record; a real backup has a value.
                    if not cell.alive or len(cell.value) < len(c_tibx.slice_record):
                        continue
                    if len(cell.key) < len(c_tibx.slice_key):
                        continue
                    key = c_tibx.slice_key(cell.key)
                    records[key.slice_id] = c_tibx.slice_record(cell.value)
            self._recovery_points = [
                RecoveryPoint(index, slice_id, records[slice_id]) for index, slice_id in enumerate(sorted(records))
            ]
        return self._recovery_points

    def use_recovery_point(self, recovery_point: int | str | RecoveryPoint = "latest") -> TibxView:
        """Select which recovery point :attr:`extents`, :meth:`streams` and :meth:`volumes` reflect.

        Volumes opened before this call keep the view they were created from: their
        extents, imap slice and reported size do not change. Use :meth:`view_at` to get
        another point without disturbing the selection at all, and :attr:`view` for an
        explicit handle on the selected one.

        Args:
            recovery_point: ``"latest"`` (the live root, default), ``"oldest"``, an
                integer index into :meth:`recovery_points`, or one of the
                :class:`RecoveryPoint` objects it returned.

        Returns:
            The newly selected view.

        Raises:
            ~dissect.archive.tibx.exception.InvalidArchiveError: If an integer index is out of range.
        """
        selected = self._resolve_recovery_point(recovery_point)
        # Extents carry the slice that wrote them, and resolve_extents already treats
        # slice_id as the primary recency signal -- so dropping everything newer than
        # the chosen slice is exactly the archive as it stood after that backup.
        self._selection = selected
        self._reset_view_caches()
        return self.view

    def _resolve_recovery_point(self, recovery_point: int | str | RecoveryPoint) -> RecoveryPoint | None:
        """The recovery point ``recovery_point`` names, or ``None`` for the live root."""
        if recovery_point == "latest":
            return None

        points = self.recovery_points()
        if not points:
            raise InvalidArchiveError("archive records no backups to select from")
        if isinstance(recovery_point, RecoveryPoint):
            # A point of another archive (or a stale one) must not silently select by a
            # slice id that happens to collide: only this archive's own points are valid.
            for point in points:
                if point.slice_id == recovery_point.slice_id and point.guid == recovery_point.guid:
                    return point
            raise InvalidArchiveError(
                f"recovery point {recovery_point!r} is not one of this archive's recovery points"
            )
        if recovery_point == "oldest":
            return points[0]
        try:
            index = int(recovery_point)
        except (TypeError, ValueError):
            raise InvalidArchiveError(f"invalid recovery point {recovery_point!r}")
        if not 0 <= index < len(points):
            raise InvalidArchiveError(f"recovery point {index} out of range (0..{len(points) - 1})")
        return points[index]

    @property
    def view(self) -> TibxView:
        """The archive as of the selected recovery point."""
        return self._view

    def view_at(self, recovery_point: int | str | RecoveryPoint = "latest") -> TibxView:
        """An independent view of ``recovery_point``, without changing the selection.

        The returned view and the volumes it creates stay bound to that recovery point
        however often :meth:`use_recovery_point` is called afterwards. Views of several
        points can therefore be read interleaved; only the archive's immutable segment
        data is shared between them.

        Args:
            recovery_point: ``"latest"`` (the live root), ``"oldest"``, an integer index
                into :meth:`recovery_points`, or one of the :class:`RecoveryPoint`
                objects it returned.

        Raises:
            ~dissect.archive.tibx.exception.InvalidArchiveError: If an integer index is out of range.
        """
        return TibxView(self, self._resolve_recovery_point(recovery_point))

    def disks(self) -> list:
        """Whole-disk views of this archive.

        Not implemented yet: TIBX stores one data stream per partition, and the disk
        bootstrap layout (MBR/GPT region) is not reconstructed. Backed-up partitions are
        exposed through :meth:`volumes` instead, which loses only the partition-table
        context, not any filesystem content.
        """
        return []

    @property
    def extents(self) -> ExtentTable:
        """The data_map extents in view: all of them, or those up to the selected slice."""
        return self.view.extents

    @property
    def _extents(self) -> ExtentTable | None:
        # Compatibility with code that inspected or replaced the selected view's table.
        return self.view._extents

    @_extents.setter
    def _extents(self, extents: ExtentTable | None) -> None:
        self.view._extents = extents

    def _unfiltered_extents(self) -> ExtentTable:
        """Every data_map extent, whatever recovery point is selected."""
        if self._all_extents is None:
            self._all_extents = load_extents(self.store, self.header)
        return self._all_extents

    def streams(self) -> list[TibxVolume]:
        """Every data_map stream in the selected view, backed-up volumes and Acronis metadata alike.

        Ordered newest backup generation first, then largest first. A differential backup
        opens *new* streams for the updated state while the base generation's streams stay
        in the data_map (incrementals overlay the existing stream instead). Ranking by the
        newest slice that touched a stream puts the current generation first, so "latest by
        default" holds for both.

        Most callers want :meth:`volumes`; this is here for inspecting an archive's
        internals without having to reach into the data_map.
        """
        return self.view.streams()

    def volumes(self) -> list[TibxVolume]:
        """The backed-up volumes of the selected recovery point, newest backup generation first, then largest first.

        An archive's data_map holds more streams than it holds volumes. Alongside each
        partition, Acronis stores its own metadata -- the ``metainfo`` XML, allocation
        bitmaps, small index tables -- and the disk's MBR/GPT bootstrap region, all keyed
        by volume id exactly like a partition. And every full or differential backup writes
        its partitions to new streams, while those of the backups before it stay: a chain of
        ten full backups of three partitions holds thirty streams that look like partitions.

        So the volumes are the streams the imap names for the partitions of the selected
        backup, ``disk%u/part%u``. A partition that stores no data at all, such as one never
        formatted, has no data_map stream. It is listed last and reads as zeros, as
        Acronis's ``tibxread`` reads it.

        A partition whose newest version in this view is deleted is not a volume; the
        stream that held its old data is not reported either.

        A file-level backup, of :attr:`archive_type` ``"file"``, has no volumes: its files
        are streams too, and large ones look like partitions.

        Without partitions in the imap otherwise -- it is encrypted and the archive locked,
        or the backup never finished, so that none of its partitions was completed -- a
        stream counts as a volume if its content starts with a filesystem this parser
        recognises, or if it is at least :data:`MIN_VOLUME_SIZE`, a whole number of sectors
        and does not start with a partition table -- which keeps an unformatted or
        unrecognised partition, something ``acrocmd list content`` reports as a partition of
        type ``None``. Use :meth:`streams` for the unfiltered list.
        """
        return self.view.volumes()

    @property
    def _volumes(self) -> list[TibxVolume] | None:
        # Compatibility with code that replaced the selected view's volume list.
        return self.view._volumes

    @_volumes.setter
    def _volumes(self, volumes: list[TibxVolume] | None) -> None:
        self.view._volumes = volumes

    def _partitions(self) -> list[ItemStream]:
        """The partitions of the selected recovery point, as the imap names them.

        Empty if the imap names no partition, or if it is encrypted and the archive locked.
        """
        return self.view._partitions()

    def _item_streams(self) -> list[ItemStream]:
        """Every data stream the imap (TLV[0]) names.

        Every backup records all of its items in the imap -- its disks, partitions and
        Acronis metadata, or its files and directories -- each with the data_map streams
        that hold its data, and their sizes.

        Raises:
            ~dissect.archive.tibx.exception.InvalidPasswordError: If the imap is encrypted and the archive is
                locked.
        """
        if self._item_streams_cache is None:
            records: list[ItemStream] = []
            imap = self.header.tree(TLV_IMAP)
            if imap is not None and imap.has_records:
                seen: set[bytes] = set()
                for cell in iter_tree_cells(self.store, imap, self._data_key):
                    if cell.key in seen:
                        continue
                    seen.add(cell.key)
                    value = cell.value
                    if not cell.alive or len(cell.key) < IMAP_KEY_SIZE or len(value) < IMAP_VALUE_SIZE:
                        continue
                    end = IMAP_VALUE_SIZE + (c_tibx.imap_value(value).extra_streams + 1) * IMAP_STREAM_SIZE
                    if len(value) < end:
                        continue
                    key = c_tibx.imap_key(cell.key)
                    name = cell.key[IMAP_KEY_SIZE:]
                    for offset in range(IMAP_VALUE_SIZE, end, IMAP_STREAM_SIZE):
                        stream = c_tibx.imap_stream(value[offset : offset + IMAP_STREAM_SIZE])
                        records.append(
                            ItemStream(key.slice_id, name, int(key.flags), stream.index, stream.id, stream.size)
                        )
            self._item_streams_cache = records
        return self._item_streams_cache

    def _stream_size(self, volume_id: int, view: TibxView | None = None) -> int | None:
        """The size the imap gives data_map stream ``volume_id`` in ``view``.

        Omitted, the selected view decides. Kept as an archive-level entry point for
        callers that have no view at hand; every volume resolves its size through its own.
        """
        return (view or self.view)._stream_size(volume_id)

    @staticmethod
    def _is_volume(stream: TibxVolume, bitmap_spans: set[int]) -> bool:
        """Whether a data_map stream is a backed-up volume rather than Acronis metadata.

        Size alone does not tell the two apart on real disks. A volume's allocation bitmap
        holds a bit per cluster, so it reaches :data:`MIN_VOLUME_SIZE` for any volume over
        32 GiB, and the bootstrap region before a disk's first partition is a whole 1 MiB
        on a disk partitioned the Windows way. But a partition is imaged in whole sectors,
        so its span is sector-aligned where a bitmap's mostly is not, and the bootstrap
        region starts with the disk's partition table. A bitmap that is a whole number of
        sectors after all, like that of a 100 GiB volume with 4 KiB clusters, still has
        the span of a bit per cluster of another stream, rounded up to a byte (see
        :func:`_bitmap_spans`), or starts with a sector of set bits, which no partition,
        formatted or not, does.

        The size tests run on :attr:`TibxVolume.span`, which comes from the data_map and
        needs no read. That matters for an encrypted archive that has not been unlocked:
        listing what a locked archive contains must not require the password, so a stream
        that cannot be read is judged by its span alone.
        """
        try:
            head = stream.read(0, 2048)
        except Error:
            # Locked, or unreadable for any other reason
            head = None

        if head is not None and _boot_sector_size(head):
            return True
        if stream.span < MIN_VOLUME_SIZE or stream.span % SECTOR_SIZE or stream.span in bitmap_spans:
            return False
        if head is None:
            return True
        return head[:SECTOR_SIZE] != b"\xff" * SECTOR_SIZE and not _is_partition_table(head, stream.span)

    def extent_base(self, extent: Extent) -> int:
        """The within-segment byte offset where ``extent``'s data starts.

        Whole-segment extents (index ``0xFFFF``) start at 0. Extents *sharing* a
        segment are concatenated in ``extent_index`` order, each aligned up to 16
        bytes (empirical rule, exact fit on every observed multi-extent segment --
        including sparse index sequences).
        """
        return self._extent_base(extent.segment_id, extent.extent_index)

    def _extent_base(self, segment_id: int, extent_index: int) -> int:
        if extent_index == EXTENT_INDEX_WHOLE_SEGMENT:
            return 0
        if self._segment_layout is None:
            # From every extent, not just those of the selected recovery point: a volume
            # opened before use_recovery_point() still reads through this layout
            layout: dict[tuple[int, int], int] = {}
            shared: dict[int, dict[int, int]] = defaultdict(dict)
            extents = self._unfiltered_extents()
            indexes = extents.extent_indexes
            for row in compress(range(len(indexes)), map(ne, indexes, repeat(EXTENT_INDEX_WHOLE_SEGMENT))):
                # An incremental backup records the unchanged extents again under its own
                # slice, so one extent of a segment can appear in several rows: count it once
                shared[extents.segment_ids[row]].setdefault(indexes[row], extents.extent_lengths[row])
            for shared_segment, entries in shared.items():
                offset = 0
                for index, length in sorted(entries.items(), key=itemgetter(0)):
                    layout[(shared_segment, index)] = offset
                    offset += length
                    offset = (offset + EXTENT_ALIGNMENT - 1) & ~(EXTENT_ALIGNMENT - 1)
            self._segment_layout = layout
        return self._segment_layout.get((segment_id, extent_index), 0)

    def read_segment(self, segment_id: int) -> bytes:
        """Return the (cached) decompressed plaintext of segment ``segment_id``."""
        cached = self._segment_cache.get(segment_id)
        if cached is not None:
            self._segment_cache.move_to_end(segment_id)
            return cached

        if self._segment_index is None:
            self._segment_index = load_segment_index(self.store, self.header)
        locator = self._segment_index.get(segment_id)
        if locator is None:
            raise CorruptArchiveError(f"segment id {segment_id} not in segment_map")

        plain = read_plaintext(self.store, locator.page_offset, self._data_key, locator.page_count)
        self._segment_cache[segment_id] = plain
        self._segment_cache_bytes += len(plain)
        # Evict oldest until under budget, but always keep the just-added entry so a single
        # segment larger than the budget is still returned (and simply evicted next insert).
        while self._segment_cache_bytes > SEGMENT_CACHE_BUDGET and len(self._segment_cache) > 1:
            _, evicted = self._segment_cache.popitem(last=False)
            self._segment_cache_bytes -= len(evicted)
        return plain


class TibxVolume:
    """One backed-up volume (a data_map volume stream) inside a :class:`TibxView`.

    Its extents are the rows ``start`` up to ``stop`` of the view's extent table, and it
    keeps the view it was created from: selecting another recovery point on the archive
    never changes the bytes or the size this volume reads. The archive's immutable segment
    data is still shared, through :attr:`TIBX.read_segment`.
    """

    def __init__(
        self,
        view: TibxView | TIBX,
        volume_id: int,
        table: ExtentTable,
        start: int = 0,
        stop: int | None = None,
        size: int | None = None,
    ):
        # Accepting the archive too keeps direct construction working: such a volume is
        # bound to the view that was selected when it was made.
        if isinstance(view, TIBX):
            view = view.view
        self.view = view
        self.tibx = view.tibx
        self.volume_id = volume_id
        self.recovery_point = view.recovery_point
        self._table = table
        self._first = start
        self._last = len(table) if stop is None else stop
        # Interval i runs from _starts[i] up to _stops[i] and reads from row _first + _covering[i]
        self._starts, self._stops, self._covering = resolve_extents(table, self._first, self._last)
        lengths = table.extent_lengths[self._first : self._last]
        self._span = max(map(add, table.source_offsets[self._first : self._last], lengths), default=0)
        self._newest_slice = max(table.slice_ids[self._first : self._last], default=0)
        # The size bound to this view. Left None, size resolves it through this view.
        self._size: int | None = size

    def __repr__(self) -> str:
        # The span, not the size: that would read the boot sector, which needs the password
        # on an encrypted archive
        return f"<TibxVolume volume_id={self.volume_id:#x} span={self.span}>"

    @property
    def slice_id(self) -> int | None:
        """The slice id this volume is bound to, or ``None`` for the live root.

        This is the evidence source of a volume's bytes: it names the backup whose extents
        and imap record the volume was reconstructed from, whatever recovery point the
        archive selects later.
        """
        return self.view.slice_id

    @property
    def extents(self) -> ExtentTable:
        """The data_map extents of this volume, in offset order, as its view resolved them."""
        return self._table[self._first : self._last]

    @property
    def span(self) -> int:
        """How far this stream reaches, straight from the data_map.

        Unlike :attr:`size` this needs no read, so it is available for an encrypted
        archive that has not been unlocked.
        """
        return self._span

    @property
    def size(self) -> int:
        """The volume size in bytes, as the imap records it for this volume's recovery point.

        That is the partition's size: an NTFS boot sector leaves the partition's last
        sector out, and a sparse volume's boot sector can say far more than the data_map
        holds. Without an imap record, as for an encrypted archive that is locked, the size
        comes from the boot sector, capped by the data_map span.

        The answer is bound to the view this volume was created from. It does not follow a
        later :meth:`TIBX.use_recovery_point`, even when that point names the same logical
        partition under another stream id.
        """
        if self._size is None:
            size = self.view._stream_size(self.volume_id)
            if size is None:
                span = self._span
                size = _boot_sector_size(self.read(0, 2048))
                # An absent or absurd boot-sector size means this is not a filesystem
                # volume (or the BPB was misread) -- trust the data_map span instead
                if size <= 0 or size > span * 64:
                    size = span
            self._size = size
        return self._size

    def open(self) -> TibxVolumeStream:
        """Open a lazy, seekable stream over the reconstructed volume bytes."""
        return TibxVolumeStream(self)

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at volume offset ``offset`` (sparse gaps read as zeros)."""
        if length <= 0:
            return b""
        # Views into the cached segments and runs of zeros, joined once at the end
        parts: list[bytes | memoryview] = []
        cursor = offset
        end = offset + length
        starts, stops, covering = self._starts, self._stops, self._covering
        table, first = self._table, self._first
        index = bisect_right(starts, offset) - 1
        if index < 0 or stops[index] <= offset:
            index += 1
        while index < len(starts) and starts[index] < end:
            start, stop, row = starts[index], stops[index], first + covering[index]
            index += 1
            segment_id = table.segment_ids[row]
            if segment_id == 0:
                # Discard marker: a newer slice recorded this range as unallocated
                # (e.g. a file deleted between incrementals) -- it reads as zeros
                # and must keep masking the older data underneath
                continue
            begin, finish = max(start, offset), min(stop, end)
            if begin > cursor:
                parts.append(bytes(begin - cursor))  # a sparse hole or a discarded range
            segment = self.tibx.read_segment(segment_id)
            segment_offset = self.tibx._extent_base(segment_id, table.extent_indexes[row])
            segment_offset += begin - table.source_offsets[row]
            chunk = memoryview(segment)[segment_offset : segment_offset + (finish - begin)]
            parts.append(chunk)
            if len(chunk) < finish - begin:
                # Damaged archive: segment shorter than its mapped extent -- zero-fill
                parts.append(bytes(finish - begin - len(chunk)))
            cursor = finish
        if cursor < end:
            parts.append(bytes(end - cursor))
        return b"".join(parts)


def resolve_extents(extents: ExtentTable, start: int = 0, stop: int | None = None) -> tuple[array, array, array]:
    """Flatten possibly-overlapping extents into a recency-resolved interval list.

    Resolves the rows ``start`` up to ``stop`` of ``extents``, one volume's, which are in
    offset order like the data_map. The covering extent of every byte is the one with the
    highest ``(slice_id, extent_id, segment_id)`` -- the slice id (the backup in the chain
    that wrote the extent) is the primary recency signal, because a differential backup can
    reuse or even lower extent and segment ids of the base it supersedes. Resolving per
    byte rather than per start offset matters: a newer *shorter* extent must not mask the
    tail of an older *longer* one at the same offset.

    Extents that do not overlap at all, as in a full backup, are each an interval of their
    own. Otherwise a sweep in offset order keeps the extents that cover the current offset
    in a heap, most recent on top: an interval runs until that extent ends or the next one
    starts.

    Returns ``(starts, stops, covering)``: non-overlapping intervals in offset order as
    arrays, interval ``i`` running from ``starts[i]`` up to ``stops[i]`` and read from row
    ``start + covering[i]`` of ``extents``.
    """
    stop = len(extents) if stop is None else stop
    offsets = extents.source_offsets[start:stop]
    lengths = extents.extent_lengths[start:stop]
    if 0 in lengths:
        # An empty extent covers nothing
        keep = list(map(bool, lengths))
        rows = array("I", compress(range(len(lengths)), keep))
        offsets = array("Q", compress(offsets, keep))
        lengths = array("Q", compress(lengths, keep))
    else:
        rows = array("I", range(len(lengths)))
    ends = array("Q", map(add, offsets, lengths))
    if all(map(le, ends, islice(offsets, 1, None))):
        return offsets, ends, rows

    slice_ids, extent_ids, segment_ids = (
        column[start:stop] for column in (extents.slice_ids, extents.extent_ids, extents.segment_ids)
    )
    count = len(rows)
    covering: list[tuple[int, int, int, int]] = []  # (-slice_id, -extent_id, -segment_id, index)
    interval_starts = array("Q")
    interval_stops = array("Q")
    interval_covering = array("I")
    index = position = 0
    previous = -1
    while index < count or covering:
        if not covering:
            position = offsets[index]  # skip the hole up to the next extent
        while index < count and offsets[index] <= position:
            row = rows[index]
            heapq.heappush(covering, (-slice_ids[row], -extent_ids[row], -segment_ids[row], index))
            index += 1
        while covering and ends[covering[0][3]] <= position:
            heapq.heappop(covering)
        if not covering:
            continue
        winner = covering[0][3]
        until = ends[winner]
        if index < count and offsets[index] < until:
            until = offsets[index]
        if previous == winner and interval_stops[-1] == position:
            # Still the same extent: only a less recent one started underneath it
            interval_stops[-1] = until
        else:
            interval_starts.append(position)
            interval_stops.append(until)
            interval_covering.append(rows[winner])
            previous = winner
        position = until
    return interval_starts, interval_stops, interval_covering


def find_split_parts(path: Path) -> list[Path]:
    """Return the ordered files making up the archive at ``path``.

    Acronis splits large backups at a size boundary into ``Name.tibx`` +
    ``Name-0001.tibx`` + ... -- a raw byte-split of one logical page store. Given any
    member of such a set, the full ordered set is returned; otherwise ``[path]``.
    """
    match = SPLIT_PART_RE.match(path.name)
    stem = match.group("stem") if match else (path.stem if path.suffix.lower() == ".tibx" else path.name)
    # Matched by hand rather than globbed: a stem like "Backup [PC1]" is no glob pattern,
    # and the extension may be upper case on a case-sensitive filesystem
    main = None
    parts = []
    try:
        candidates = list(path.parent.iterdir())
    except OSError:
        return [path]
    for candidate in candidates:
        if candidate.suffix.lower() == ".tibx" and candidate.name == stem + candidate.suffix:
            main = candidate
        elif (part := SPLIT_PART_RE.match(candidate.name)) and part.group("stem") == stem:
            parts.append((int(part.group("num")), candidate))
    if parts and main is not None:
        return [main, *(part for _, part in sorted(parts))]
    return [path]


class _ZeroStream(AlignedStream):
    """Zero-filled backing for logical ranges whose physical pages were compacted away."""

    def _read(self, offset: int, length: int) -> bytes:
        return b"\x00" * length


def _part_numbers(parts: list[Path]) -> list[int]:
    """The number of each file of an archive, as :func:`find_split_parts` returns them: 0 for the first file."""
    if len(parts) == 1:
        # A file named -NNNN on its own: the first file is missing
        match = SPLIT_PART_RE.match(parts[0].name)
        return [int(match.group("num")) if match else 0]
    return [0, *(int(SPLIT_PART_RE.match(part.name).group("num")) for part in parts[1:])]


def _volume_table(header: ArchiveHeader) -> dict[int, int]:
    """The volumes of the archive that ``header``'s TLV[18] names: where each starts in the archive, by index.

    Acronis calls the files of an archive its volumes; they have nothing to do with the
    backed-up volumes of :meth:`TIBX.volumes`. TLV[18] is a run of ``ar_volume`` entries,
    and empty if the header has none.
    """
    payload = header.tlv[TLV_VOLUMES].payload
    count = len(payload) // len(c_tibx.ar_volume)
    entries = c_tibx.ar_volume[count](payload)
    return {entry.index: entry.start_offs for entry in entries}


def _own_volume_table(handle: BinaryIO) -> dict[int, int] | None:
    """The volume table of the newest commit in the file ``handle`` itself.

    Version files carry the archive's newest commit roots, so the *last* file's live root
    has the authoritative table. None if the file has no commit root of its own, as a raw
    byte-split part, a page-misaligned fragment, has not.
    """
    try:
        store = PageStore(handle)
        return _volume_table(read_archive_header(store, store.live_root()))
    except Error:
        return None


def _missing_volumes_message(
    table: dict[int, int], found: int, numbers: list[int] | None = None, max_missing_filenames: int = 10
) -> str | None:
    """The error message naming which of the volumes ``table`` names are missing; None if none are.

    The message speaks of files, as Acronis's own does: those are what a user looks for.

    Args:
        table: The archive's volume table, from :func:`_volume_table`.
        found: How many files of the archive there are.
        numbers: Their numbers, if known: 0 for the first file, NNNN for the one named -NNNN.
        max_missing_filenames: How many missing files, or runs of them, the message names
            before it leaves the rest out.

    A table of no more volumes than files were found names no missing file: any volume it
    does not name is left over.
    """
    if len(table) <= found:
        return None
    if numbers is None or not set(numbers) <= table.keys():
        # Which ones are missing is unknown, or the table does not index the files by number
        return f"missing {len(table) - found} of the {len(table)} files of this archive"
    missing = sorted(table.keys() - set(numbers))
    names = []
    if missing[0] == 0:
        names.append("the first file")
    # Runs of consecutive numbers as one range
    for _, run in groupby(enumerate(number for number in missing if number), lambda item: item[1] - item[0]):
        run_numbers = [number for _, number in run]
        first, last = run_numbers[0], run_numbers[-1]
        names.append(f"-{first:04d}" if first == last else f"-{first:04d} to -{last:04d}")
    if len(names) > max_missing_filenames:
        names[max_missing_filenames:] = ["..."]
    return f"missing {len(missing)} of the {len(table)} files of this archive: {', '.join(names)}"


def _volume_offsets(table: dict[int, int], sizes: list[int], numbers: list[int] | None = None) -> list[int] | None:
    """Where each file of an archive starts in it, by ``table``; None if the table cannot say.

    Args:
        table: The archive's volume table, from :func:`_volume_table`.
        sizes: The size of each file, the first file first.
        numbers: The number of each file, if known: 0 for the first, NNNN for the one named -NNNN.

    An index in the table is the number of a file. A cleanup removes files from between the
    others, and the table still indexes the rest by their number, in every real archive seen.
    A table that does not index them by number but names as many files as there are is taken
    in the order of the files, as it was before.
    """
    if numbers is not None and table.keys() == set(numbers):
        offsets = [table[number] for number in numbers]
    elif len(table) == len(sizes):
        offsets = [table[index] for index in sorted(table)]
    else:
        return None
    if offsets[0] != 0 or offsets != sorted(set(offsets)):
        return None
    # A trustworthy table never maps a file below the previous file's end
    position = 0
    for offset, size in zip(offsets, sizes, strict=True):
        if offset < position:
            return None
        position = offset + size
    return offsets


def _stitch(handles: list[BinaryIO], numbers: list[int] | None = None) -> MappingStream:
    """Map the files of a multi-file archive into one logical page store.

    Split archives are raw byte-splits of one page store: the parts concatenate.
    Version sets (each backup version appended as ``Name-0001.tibx``, ...) instead
    record every file's logical start offset in the volumes of TLV[18]: after a
    "single version scheme" cleanup the base file is compacted -- physically
    truncated, its data pages tombstoned -- while retaining its logical address
    range, so concatenation would misplace every absolute offset in the maps.
    Compacted ranges are mapped as zeros; nothing alive references them.

    Args:
        handles: The files, the first file first.
        numbers: The number of each file, if known: 0 for the first, NNNN for the one
            named -NNNN.

    Raises:
        ~dissect.archive.tibx.exception.MissingVolumeError: If the last file's table names
            volumes that are not among ``handles``.
    """
    sizes = []
    for handle in handles:
        handle.seek(0, 2)
        sizes.append(handle.tell())

    offsets = None
    if len(handles) > 1 and (table := _own_volume_table(handles[-1])) is not None:
        if (missing := _missing_volumes_message(table, len(handles), numbers)) is not None:
            raise MissingVolumeError(missing)
        offsets = _volume_offsets(table, sizes, numbers)
    if offsets is None:
        offsets = []
        position = 0
        for size in sizes:
            offsets.append(position)
            position += size

    stream = MappingStream(align=PAGE_SIZE)
    position = 0
    for handle, size, offset in zip(handles, sizes, offsets, strict=False):
        if offset > position:
            stream.add(position, offset - position, _ZeroStream(offset - position), 0)
        stream.add(offset, size, handle, 0)
        position = offset + size
    return stream


def _stream_order(stream: TibxVolume) -> tuple[int, int]:
    """Sort key of :meth:`TIBX.streams`, which sorts in reverse: the newest backup that wrote to a stream, its span."""
    return stream._newest_slice, stream.span


def _bitmap_spans(streams: list[TibxVolume]) -> set[int]:
    """The spans an allocation bitmap of one of ``streams`` would have, one per cluster size.

    Acronis stores a bit per cluster, rounded up to a whole byte. Across 187 real archives,
    171 metadata streams had that span for an NTFS volume of the same archive and 4 KiB
    clusters, and none of the 572 volumes had it for another one.
    """
    spans = set()
    for stream in streams:
        for cluster_size in CLUSTER_SIZES:
            clusters = -(-stream.span // cluster_size)
            spans.add(-(-clusters // 8))
    return spans


def _is_partition_table(head: bytes, span: int) -> bool:
    """Whether ``head`` starts a disk's bootstrap region rather than a partition.

    That region runs from the MBR to the first partition, so its MBR is either the
    protective one of a GPT disk, or describes partitions that all start at or beyond the
    end of the region itself -- a test the boot code of a partition does not pass by
    chance.
    """
    if len(head) < len(c_boot.mbr):
        return False
    mbr = c_boot.mbr(head)
    if mbr.signature != MBR_SIGNATURE or any(entry.boot_flag not in (0x00, 0x80) for entry in mbr.partitions):
        return False
    used = [entry for entry in mbr.partitions if entry.type and entry.lba_start and entry.sectors]
    if any(entry.type == MBR_TYPE_GPT_PROTECTIVE for entry in used):
        return True
    return bool(used) and min(entry.lba_start for entry in used) * SECTOR_SIZE >= span


def _boot_sector_size(boot: bytes) -> int:
    """Parse the volume size from a boot sector, or 0 if it is not a known filesystem.

    The total-sectors field differs per filesystem, so the filesystem must be sniffed
    first -- reading the wrong offset yields garbage sizes.
    """
    if len(boot) < 512:
        return 0
    try:
        ntfs = c_boot.ntfs_boot_sector(boot)
        if ntfs.oem_id == b"NTFS    ":
            return (ntfs.bytes_per_sector or 512) * ntfs.total_sectors
        exfat = c_boot.exfat_boot_sector(boot)
        if exfat.fs_name == b"EXFAT   ":
            return exfat.volume_length << exfat.bytes_per_sector_shift
        fat = c_boot.fat_boot_sector(boot)
        if fat.fs_type_32.startswith(b"FAT32") or fat.fs_type_16.startswith(b"FAT"):
            return (fat.bytes_per_sector or 512) * (fat.total_sectors_16 or fat.total_sectors_32)
        if len(boot) >= EXT_SUPERBLOCK_OFFSET + len(c_boot.ext_superblock):
            ext = c_boot.ext_superblock(boot[EXT_SUPERBLOCK_OFFSET:])
            if ext.magic == EXT_MAGIC:
                return ext.blocks_count << (10 + ext.log_block_size)
    except EOFError:
        return 0
    return 0
