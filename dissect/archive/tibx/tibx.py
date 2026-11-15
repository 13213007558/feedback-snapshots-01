"""TIBX archive facade: volume enumeration and lazy, recency-resolved volume reads.

A backed-up volume is reconstructed from the data_map: possibly-overlapping extents
(incremental/differential backups append new extents over older ones; the base extents
stay in the tree) are flattened per byte into a non-overlapping interval list, keeping
the newest extent -- keyed by the slice id that wrote it, which is the only reliable
global recency signal. Sparse gaps between intervals are genuine unallocated space and
read back as zeros. Only the segments backing a requested range are fetched and
decompressed, so reads are fully lazy.

Volume enumeration distinguishes what the archive *says* from what this parser *infers*.
A complete ``disk%u/part%u`` imap record confirms a partition; content and span are only
heuristics, and a stream that fits neither population is reported as a candidate rather
than promoted to a partition. See :class:`VolumeCandidate` and :class:`VolumeConfidence`.
"""

from __future__ import annotations

import datetime
import heapq
import re
import uuid
from array import array
from bisect import bisect_right
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, replace
from enum import Enum
from itertools import compress, groupby, islice, repeat
from operator import add, itemgetter, le, ne
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

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
from dissect.util.stream import AlignedStream, MappingStream

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
# The other way a partition is linked in the imap: part/<32 hex digits>
PARTITION_LINK_RE = re.compile(rb"part/[0-9a-fA-F]{32}")

# imap item names a disk-level backup gives its own metadata rather than a file: the
# disk itself (disk%u) and the metainfo blob (meta). Any other name in a disk archive is
# file-level content, which tells a large backed-up file apart from a partition
DISK_ITEM_RE = re.compile(rb"(?:disk\d+|meta)")

SPLIT_PART_RE = re.compile(r"^(?P<stem>.+?)-(?P<num>\d{4})\.tibx$", re.IGNORECASE)

# Smallest stream taken to be a partition rather than Acronis metadata, for a stream whose
# filesystem this parser does not recognise. The two populations are far apart in practice:
# across the sample corpora the largest metadata stream is ~2.6 KB and the smallest real
# partition is 16 MB, so this sits in the middle of a gap of some four orders of magnitude.
# On real disks two kinds of metadata do reach it; see TIBX._classify_unnamed_stream.
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


class VolumeConfidence(str, Enum):
    """How strongly the evidence supports that a data_map stream is a backed-up volume.

    Only :attr:`CONFIRMED` means the archive itself names the stream as a partition, by a
    complete ``disk%u/part%u`` imap record. :attr:`PROBABLE` is a heuristic acceptance:
    a recognised filesystem, or a partition-sized, sector-aligned span whose content is
    unformatted, all zero or an unknown filesystem. :attr:`POSSIBLE` is a stream this
    parser cannot confirm either way; it stays inspectable but is never reported as a
    volume. :attr:`EXCLUDED` has evidence against it being a partition, such as an
    allocation bitmap, a disk's bootstrap region or a file of a file-level backup.
    """

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    EXCLUDED = "excluded"

    @property
    def rank(self) -> int:
        """Ordering by strength: confirmed, probable, possible, excluded."""
        return {
            VolumeConfidence.EXCLUDED: 0,
            VolumeConfidence.POSSIBLE: 1,
            VolumeConfidence.PROBABLE: 2,
            VolumeConfidence.CONFIRMED: 3,
        }[self]


class VolumeClassification(str, Enum):
    """What a data_map stream's evidence says it is."""

    PARTITION = "partition"
    UNFORMATTED_PARTITION = "unformatted-partition"
    ZERO_PARTITION = "zero-partition"
    UNKNOWN_FILESYSTEM = "unknown-filesystem"
    LOCKED = "locked"
    ALLOCATION_BITMAP = "allocation-bitmap"
    DISK_BOOTSTRAP = "disk-bootstrap"
    FILE = "file"
    METADATA = "metadata"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VolumeEvidence:
    """One piece of evidence a :class:`VolumeCandidate` cites.

    ``supports`` is True for evidence that the stream is a volume, False for evidence
    against it, and None for a neutral observation (such as content being unreadable
    while the archive is locked).
    """

    kind: str
    detail: str
    supports: bool | None = None
    source: str = "content"

    def __str__(self) -> str:
        return f"{self.kind}: {self.detail}"


@dataclass(frozen=True)
class VolumeIdentity:
    """The classification a stream had before stronger evidence was obtained."""

    classification: VolumeClassification
    confidence: VolumeConfidence
    evidence: tuple[VolumeEvidence, ...] = ()


@dataclass(frozen=True)
class VolumeCandidate:
    """One data_map stream and the evidence for what it is.

    A candidate is the unit of volume enumeration with provenance: unlike a bare
    :class:`TibxVolume`, it carries the classification, the confidence in it, the
    evidence cited, and -- after unlocking an archive -- the identity the stream had
    while the partition list was still encrypted. The stream itself stays reachable
    through :attr:`stream`, so an unconfirmed candidate can still be read and examined.
    """

    volume_id: int
    span: int
    classification: VolumeClassification
    confidence: VolumeConfidence
    evidence: tuple[VolumeEvidence, ...]
    stream: TibxVolume | None = None
    name: bytes | None = None
    selected: bool = False
    previous: VolumeIdentity | None = None

    def __repr__(self) -> str:
        return (
            f"<VolumeCandidate volume_id={self.volume_id:#x} span={self.span} "
            f"classification={self.classification.value} confidence={self.confidence.value}>"
        )

    @property
    def is_volume(self) -> bool:
        """Whether this candidate is included in :meth:`TIBX.volumes` for the current state."""
        return self.selected

    @property
    def confirmed(self) -> bool:
        """Whether the archive itself names this stream as a partition."""
        return self.confidence is VolumeConfidence.CONFIRMED

    @property
    def evidence_kinds(self) -> tuple[str, ...]:
        """The machine-readable kinds of the cited evidence, in citation order."""
        return tuple(evidence.kind for evidence in self.evidence)

    def to_dict(self) -> dict:
        """A JSON-friendly report of this candidate, its evidence and any identity change."""
        return {
            "volume_id": self.volume_id,
            "span": self.span,
            "name": self.name.decode("utf-8", "replace") if self.name is not None else None,
            "classification": self.classification.value,
            "confidence": self.confidence.value,
            "is_volume": self.is_volume,
            "evidence": [
                {
                    "kind": evidence.kind,
                    "detail": evidence.detail,
                    "supports": evidence.supports,
                    "source": evidence.source,
                }
                for evidence in self.evidence
            ],
            "previous": None
            if self.previous is None
            else {
                "classification": self.previous.classification.value,
                "confidence": self.previous.confidence.value,
                "evidence": [evidence.kind for evidence in self.previous.evidence],
            },
            "explanation": self.explanation,
        }

    @property
    def explanation(self) -> str | None:
        """Why this candidate's classification changed, or None if it did not.

        Unlocking an archive can turn a heuristic guess into an imap-confirmed identity.
        The change is reported here, with the old and new classification and the evidence
        behind each, rather than the new identity silently replacing the old one.
        """
        previous = self.previous
        if previous is None:
            return None
        if previous.classification is self.classification and previous.confidence is self.confidence:
            return None

        before = f"{previous.classification.value} ({previous.confidence.value})"
        after = f"{self.classification.value} ({self.confidence.value})"
        if self.confidence is VolumeConfidence.CONFIRMED and self.name is not None:
            name = self.name.decode("utf-8", "replace")
            reason = f"the imap now confirms this stream as partition {name!r}"
        elif self.name is not None:
            name = self.name.decode("utf-8", "replace")
            reason = f"the imap now names this stream {name!r}"
        else:
            reason = "content became readable and changed the evidence"
        old_evidence = ", ".join(evidence.kind for evidence in previous.evidence) or "none"
        new_evidence = ", ".join(self.evidence_kinds) or "none"
        return f"{before} -> {after}: {reason}; evidence was [{old_evidence}], now [{new_evidence}]"

    def read(self, offset: int, length: int) -> bytes:
        """Read from the underlying stream, confirmed or not."""
        if self.stream is None:
            raise InvalidArchiveError("candidate has no data stream")
        return self.stream.read(offset, length)

    def open(self) -> TibxVolumeStream:
        """Open a lazy stream over the underlying data, confirmed or not."""
        if self.stream is None:
            raise InvalidArchiveError("candidate has no data stream")
        return self.stream.open()

    @property
    def size(self) -> int:
        """The size of the underlying stream, confirmed or not."""
        if self.stream is None:
            raise InvalidArchiveError("candidate has no data stream")
        return self.stream.size

    @property
    def extents(self) -> ExtentTable:
        """The data_map extents of the underlying stream, confirmed or not."""
        if self.stream is None:
            raise InvalidArchiveError("candidate has no data stream")
        return self.stream.extents


class TIBX:
    """An Acronis TIBX ("archive3") backup archive.

    Opens at the latest recovery point. Use :meth:`recovery_points` to enumerate the
    backups the archive records and :meth:`use_recovery_point` to select an earlier one
    in a chain.

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
        self._slice_limit: int | None = None
        self._data_key = None
        self._reset_snapshot_caches()

    def _reset_snapshot_caches(self) -> None:
        # Everything derived from the live commit root (not the data key)
        self._all_extents: ExtentTable | None = None
        self._segment_index = None
        self._segment_layout: dict[tuple[int, int], int] | None = None
        self._reset_identity_history()
        self._clear_segment_cache()
        self._reset_imap_caches()

    def _reset_imap_caches(self) -> None:
        # The imap may be encrypted, so what it holds also depends on the data key
        self._item_streams_cache: list[ItemStream] | None = None
        self._reset_view_caches()

    def _reset_view_caches(self) -> None:
        # Everything that depends on the selected recovery point. A segment's plaintext,
        # its location and the layout of the extents it holds do not: a segment is written
        # by one backup, and later backups only reference it again.
        self._extents: ExtentTable | None = None
        self._streams: list[TibxVolume] | None = None
        self._volumes: list[TibxVolume] | None = None
        self._stream_sizes: dict[int, int] | None = None
        self._partitions_cache: list[ItemStream] | None = None
        self._candidates: list[VolumeCandidate] | None = None
        self._volume_candidates: list[VolumeCandidate] | None = None

    def _reset_identity_history(self) -> None:
        """Forget the identity each stream had before the recovery point changed.

        An identity change is only meaningful within one comparison: unlocking (or an
        unreadable imap becoming readable) changes what the same view shows. Selecting
        another backup instead changes which streams exist, not what they are, so a new
        view starts comparing afresh.
        """
        self._identity_history: dict[int, VolumeIdentity] | None = None

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

    def use_recovery_point(self, recovery_point: int | str = "latest") -> None:
        """Select which recovery point volumes and reads reflect.

        Args:
            recovery_point: ``"latest"`` (the live root, default), ``"oldest"``, or an
                integer index into :meth:`recovery_points`.

        Raises:
            ~dissect.archive.tibx.exception.InvalidArchiveError: If an integer index is out of range.
        """
        if recovery_point == "latest":
            self._slice_limit = None
        else:
            points = self.recovery_points()
            if not points:
                raise InvalidArchiveError("archive records no backups to select from")
            if recovery_point == "oldest":
                chosen = points[0]
            else:
                try:
                    index = int(recovery_point)
                except (TypeError, ValueError):
                    raise InvalidArchiveError(f"invalid recovery point {recovery_point!r}")
                if not 0 <= index < len(points):
                    raise InvalidArchiveError(f"recovery point {index} out of range (0..{len(points) - 1})")
                chosen = points[index]
            # Extents carry the slice that wrote them, and resolve_extents already treats
            # slice_id as the primary recency signal -- so dropping everything newer than
            # the chosen slice is exactly the archive as it stood after that backup.
            self._slice_limit = chosen.slice_id
        self._reset_identity_history()
        self._reset_view_caches()

    def classification_changes(self) -> list[VolumeCandidate]:
        """The candidates whose classification changed since they were last enumerated.

        Unlocking an encrypted archive is the usual cause: a stream that was a
        partition-sized guess or an unknown becomes an imap-confirmed partition. Each
        candidate's :attr:`VolumeCandidate.explanation` says what changed and which
        evidence replaced which, so the new identity is explained rather than silently
        substituted for the old one.
        """
        return [candidate for candidate in self.candidates() if candidate.explanation is not None]

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
        if self._extents is None:
            extents = self._unfiltered_extents()
            if self._slice_limit is not None:
                extents = extents.select(map(le, extents.slice_ids, repeat(self._slice_limit)))
            self._extents = extents
        return self._extents

    def _unfiltered_extents(self) -> ExtentTable:
        """Every data_map extent, whatever recovery point is selected."""
        if self._all_extents is None:
            self._all_extents = load_extents(self.store, self.header)
        return self._all_extents

    def streams(self) -> list[TibxVolume]:
        """Every data_map stream, backed-up volumes and Acronis's own metadata alike.

        Ordered newest backup generation first, then largest first. A differential backup
        opens *new* streams for the updated state while the base generation's streams stay
        in the data_map (incrementals overlay the existing stream instead). Ranking by the
        newest slice that touched a stream puts the current generation first, so "latest by
        default" holds for both.

        Most callers want :meth:`volumes`; this is here for inspecting an archive's
        internals without having to reach into the data_map.
        """
        if self._streams is None:
            extents = self.extents
            streams = [TibxVolume(self, vid, extents, start, stop) for vid, start, stop in extents.volume_ranges()]
            streams.sort(key=_stream_order, reverse=True)
            self._streams = streams
        return self._streams

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

        A file-level backup, of :attr:`archive_type` ``"file"``, has no volumes: its files
        are streams too, and large ones look like partitions.

        Without partitions in the imap otherwise -- it is encrypted and the archive locked,
        or the backup never finished, so that none of its partitions was completed -- the
        volumes are the streams whose content or span makes them a probable volume. A
        recognised filesystem is one; an unformatted or unrecognised partition is kept by
        its partition-sized, sector-aligned span. Use :meth:`volume_candidates` to see the
        evidence for every stream, :meth:`streams` for the unfiltered list.

        A stream that cannot be confirmed either way is *not* reported here; it stays
        inspectable through :meth:`volume_candidates` and :meth:`streams`.

        When the imap names the partitions, only the streams of those partitions are
        resolved: resolving every stream's extents costs seconds per backup on a large
        archive, and the answer is already known.
        """
        if self._volumes is None:
            if named := self._named_partitions():
                self._volumes = self._named_volumes(named)
            else:
                self._volumes = [candidate.stream for candidate in self.volume_candidates() if candidate.is_volume]
        return self._volumes

    def _named_volumes(self, named: dict[int, ItemStream]) -> list[TibxVolume]:
        """Just the streams of the imap-named partitions, resolving nothing else."""
        if self._streams is not None:
            volumes = [stream for stream in self._streams if stream.volume_id in named]
        else:
            extents = self.extents
            volumes = [
                TibxVolume(self, volume_id, extents, start, stop)
                for volume_id, start, stop in extents.volume_ranges()
                if volume_id in named
            ]
            volumes.sort(key=_stream_order, reverse=True)
        stored = {volume.volume_id for volume in volumes}
        volumes.extend(
            TibxVolume(self, partition_id, self.extents, 0, 0) for partition_id in named if partition_id not in stored
        )
        return volumes

    def volume_candidates(self) -> list[VolumeCandidate]:
        """Every data_map stream classified as a volume candidate, with its evidence.

        This is :meth:`volumes` without the final cut: the list holds the streams
        reported as volumes (``selected``) and those that could not be confirmed, so an
        unknown stream remains inspectable instead of disappearing or being passed off
        as a partition. ``confidence`` says how strongly the evidence supports each one;
        only ``CONFIRMED`` means the archive itself named the stream a partition.

        While an encrypted archive is locked, no stream can be imap-confirmed, so the
        guess each stream gets is remembered. After :meth:`unlock`, a stream the imap
        then confirms keeps its old identity in :attr:`VolumeCandidate.previous`, and
        :attr:`VolumeCandidate.explanation` says why the classification changed.
        """
        if self._volume_candidates is None:
            self._volume_candidates = [
                candidate
                for candidate in self._classify_streams()
                if candidate.confidence is not VolumeConfidence.EXCLUDED
            ]
        return self._volume_candidates

    def candidates(self) -> list[VolumeCandidate]:
        """Every data_map stream as a :class:`VolumeCandidate`, including metadata and files.

        :meth:`volume_candidates` is the subset worth considering as volumes; this is
        the whole provenance list, for auditing what the archive holds and why a stream
        was excluded. The order is that of :meth:`streams`.
        """
        return self._classify_streams()

    def volume_report(self) -> list[dict]:
        """Every stream's classification as a JSON-friendly report, evidence included.

        The report is what :meth:`candidates` holds, flattened: for each stream its id,
        span, name, classification, confidence, whether it is reported as a volume, the
        evidence it cites, and -- if it changed -- the identity it had before and why it
        changed. It is meant for forensic output where a bare list of partitions would
        hide how each one was decided.
        """
        return [candidate.to_dict() for candidate in self.candidates()]

    def _classify_streams(self) -> list[VolumeCandidate]:
        """Classify every stream, assigning the selection and the identity change.

        One classification pass answers both :meth:`volume_candidates` and
        :meth:`candidates`, and records each stream's identity for the next pass. A
        candidate's :attr:`VolumeCandidate.previous` is the identity it had in the
        previous pass, so unlocking an archive reports the guess it replaces instead of
        silently overwriting it.
        """
        if self._candidates is not None:
            return self._candidates

        streams = self.streams()
        named = self._named_partitions()
        bitmap_spans = _bitmap_spans(streams)
        archive_type = self.archive_type
        file_level = self._imap_names_files()
        item_names = self._stream_item_names()
        candidates = [
            self._classify_stream(
                stream,
                named.get(stream.volume_id),
                bitmap_spans=bitmap_spans,
                archive_type=archive_type,
                file_level=file_level,
                item_name=item_names.get(stream.volume_id),
            )
            for stream in streams
        ]

        # A partition that stores no data has no data_map stream; keep it in the list
        # as a zero-span candidate, as Acronis's tibxread reads it
        stored = {candidate.volume_id for candidate in candidates}
        candidates.extend(
            self._partition_without_data(partition) for partition in named.values() if partition.id not in stored
        )

        # Explicitly named partitions are the volumes when the archive names any; only
        # without names is the heuristic set reported. This keeps the two populations
        # from being mixed into one list that reads as if every entry were a partition.
        if any(candidate.confirmed for candidate in candidates):
            selected = {candidate.volume_id for candidate in candidates if candidate.confirmed}
        else:
            selected = {
                candidate.volume_id for candidate in candidates if candidate.confidence is VolumeConfidence.PROBABLE
            }

        history = self._identity_history if self._identity_history is not None else {}
        classified = []
        for candidate in candidates:
            previous = history.get(candidate.volume_id)
            if previous is not None and not _identity_differs(previous, candidate):
                previous = None
            classified.append(replace(candidate, selected=candidate.volume_id in selected, previous=previous))
        self._identity_history = {
            candidate.volume_id: VolumeIdentity(candidate.classification, candidate.confidence, candidate.evidence)
            for candidate in classified
        }

        # Newest backup generation first, then largest first, as streams()
        classified.sort(key=_candidate_order, reverse=True)
        self._candidates = classified
        return self._candidates

    def _classify_stream(
        self,
        stream: TibxVolume,
        partition: ItemStream | None,
        *,
        bitmap_spans: set[int],
        archive_type: str,
        file_level: bool,
        item_name: bytes | None,
    ) -> VolumeCandidate:
        """Classify one stream from the imap name, if any, and from its content and span."""
        evidence: list[VolumeEvidence] = []
        if partition is not None:
            evidence.append(
                VolumeEvidence(
                    "imap-name",
                    f"complete imap partition record {partition.name.decode('utf-8', 'replace')!r} "
                    f"(slice {partition.slice_id}, stream {partition.id:#x})",
                    True,
                    "imap",
                )
            )
        elif file_level and archive_type != "file":
            evidence.append(
                VolumeEvidence(
                    "imap-item",
                    "the imap records file-level items, not partitions",
                    False,
                    "imap",
                )
            )
        elif archive_type == "file":
            evidence.append(VolumeEvidence("archive-type", 'archive meta type is "file"', False, "header"))

        try:
            head = stream.read(0, 2048)
        except InvalidPasswordError:
            # Locked: listing what an archive holds must not need the password, so the
            # span alone has to carry the guess
            evidence.append(VolumeEvidence("locked", "content is encrypted and the archive is locked", None, "header"))
            head = None
        except Error as e:
            evidence.append(VolumeEvidence("unreadable", f"content could not be read: {e}", None, "content"))
            head = None

        if partition is not None:
            classification, confidence = self._classify_named_stream(stream, head, evidence)
        elif file_level or archive_type == "file":
            # A file-level backup's large files look like partitions; the imap or the
            # archive's own type says they are files, stronger than any content heuristic
            classification = VolumeClassification.FILE
            confidence = VolumeConfidence.EXCLUDED
            evidence.extend(_span_evidence(stream.span, bitmap_spans))
        else:
            classification, confidence, span_evidence = self._classify_unnamed_stream(
                stream, head, evidence, bitmap_spans=bitmap_spans
            )
            evidence.extend(span_evidence)

        return VolumeCandidate(
            volume_id=stream.volume_id,
            span=stream.span,
            classification=classification,
            confidence=confidence,
            evidence=tuple(evidence),
            stream=stream,
            name=partition.name if partition is not None else item_name,
        )

    def _classify_named_stream(
        self, stream: TibxVolume, head: bytes | None, evidence: list[VolumeEvidence]
    ) -> tuple[VolumeClassification, VolumeConfidence]:
        """Classify a stream the imap names as a partition; the name is the strongest evidence.

        Everything the content adds is a refinement of *which kind* of partition, never
        a reason to call the stream something other than a partition: Acronis's own
        ``disk%u/part%u`` record is a statement about the archive's contents, whereas a
        boot sector may be damaged, zero or absent.
        """
        content = self._content_classification(head, stream, evidence)
        if content in (
            VolumeClassification.PARTITION,
            VolumeClassification.ZERO_PARTITION,
            VolumeClassification.UNFORMATTED_PARTITION,
            VolumeClassification.UNKNOWN_FILESYSTEM,
        ):
            return content, VolumeConfidence.CONFIRMED
        if content is VolumeClassification.UNKNOWN:
            # The name still confirms it; the content just could not refine it
            return VolumeClassification.PARTITION, VolumeConfidence.CONFIRMED
        # Content with evidence against a partition (a bitmap, a partition table, a
        # metadata-sized span) can no longer make it one, but the archive named it one
        evidence.append(
            VolumeEvidence(
                "content-contradiction",
                "content looks like metadata, but a complete imap partition record names this stream as a partition",
                None,
                "imap",
            )
        )
        return VolumeClassification.PARTITION, VolumeConfidence.CONFIRMED

    def _classify_unnamed_stream(
        self, stream: TibxVolume, head: bytes | None, evidence: list[VolumeEvidence], *, bitmap_spans: set[int]
    ) -> tuple[VolumeClassification, VolumeConfidence, list[VolumeEvidence]]:
        """Classify a stream the imap does not name, from its content and its span.

        Returns the verdict, the confidence and the span evidence that led to it: the
        evidence is appended last, so a citation reads as the content first and the
        supporting span second. Span evidence that argues *for* a partition is dropped
        when the content rules it out, so a citation never contradicts its verdict.
        """
        span = stream.span
        span_evidence = _span_evidence(span, bitmap_spans)
        classification = self._content_classification(head, stream, evidence)
        if (
            classification in (VolumeClassification.UNKNOWN, VolumeClassification.UNKNOWN_FILESYSTEM)
            and span >= MIN_VOLUME_SIZE
            and span in bitmap_spans
        ):
            # The span of a bit per cluster of another stream outweighs content that is
            # merely unrecognised; a partition-sized span alone cannot keep it
            return VolumeClassification.ALLOCATION_BITMAP, VolumeConfidence.EXCLUDED, span_evidence
        if classification in (
            VolumeClassification.PARTITION,
            VolumeClassification.ZERO_PARTITION,
            VolumeClassification.UNFORMATTED_PARTITION,
            VolumeClassification.UNKNOWN_FILESYSTEM,
        ):
            # A recognised filesystem or a partition-sized, sector-aligned span; keeping
            # an unformatted or unrecognised partition is what "acrocmd list content"
            # reports as a partition of type None
            return classification, VolumeConfidence.PROBABLE, span_evidence
        if classification in (
            VolumeClassification.ALLOCATION_BITMAP,
            VolumeClassification.DISK_BOOTSTRAP,
        ):
            return classification, VolumeConfidence.EXCLUDED, _against_evidence(span_evidence)
        if head is None:
            if span >= MIN_VOLUME_SIZE and not span % SECTOR_SIZE and span not in bitmap_spans:
                # A partition-sized span is the best evidence a locked stream can give,
                # but it is not a filesystem: this stream stays a candidate, not a fact
                return VolumeClassification.LOCKED, VolumeConfidence.PROBABLE, span_evidence
            # Below the floor, unaligned or a bitmap by span: inspectable, but no reason
            # to present it as a volume
            return VolumeClassification.UNKNOWN, VolumeConfidence.POSSIBLE, span_evidence
        if classification is VolumeClassification.METADATA:
            return classification, VolumeConfidence.EXCLUDED, _against_evidence(span_evidence)
        return classification, VolumeConfidence.POSSIBLE, span_evidence

    def _content_classification(
        self,
        head: bytes | None,
        stream: TibxVolume,
        evidence: list[VolumeEvidence],
    ) -> VolumeClassification:
        """What the stream's head and span say it is, adding the content evidence behind the verdict.

        Span evidence is cited separately by :func:`_span_evidence`, so this adds only
        what the bytes themselves say, plus the span test that makes a zero or unknown
        stream a partition candidate.
        """
        span = stream.span
        partition_sized = span >= MIN_VOLUME_SIZE and not span % SECTOR_SIZE
        if head is None:
            return VolumeClassification.UNKNOWN

        if filesystem_size := _boot_sector_size(head):
            evidence.append(
                VolumeEvidence(
                    "filesystem",
                    f"boot sector declares {_filesystem_name(head)} of {filesystem_size} B",
                    True,
                    "content",
                )
            )
            return VolumeClassification.PARTITION

        if _is_partition_table(head, span):
            evidence.append(
                VolumeEvidence(
                    "partition-table",
                    "content starts with a disk's MBR/GPT partition table",
                    False,
                    "content",
                )
            )
            return VolumeClassification.DISK_BOOTSTRAP

        if head[:SECTOR_SIZE] == b"\xff" * SECTOR_SIZE:
            evidence.append(
                VolumeEvidence(
                    "bitmap-content",
                    "the first sector is all set bits, as an allocation bitmap's is",
                    False,
                    "content",
                )
            )
            return VolumeClassification.ALLOCATION_BITMAP

        if not head.strip(b"\x00"):
            evidence.append(VolumeEvidence("zero-content", "the first 2048 bytes are all zero", None, "content"))
            if partition_sized:
                return VolumeClassification.ZERO_PARTITION
            evidence.append(
                VolumeEvidence(
                    "metadata-sized",
                    f"span {span} B is below the partition floor or not sector-aligned",
                    False,
                    "data_map",
                )
            )
            return VolumeClassification.METADATA

        if not head[:SECTOR_SIZE].strip(b"\x00"):
            # No boot sector was ever written, but the partition holds data further on
            evidence.append(
                VolumeEvidence(
                    "no-boot-sector",
                    "the first sector is zero, but later bytes are not: no boot sector was written",
                    None,
                    "content",
                )
            )
            return VolumeClassification.UNFORMATTED_PARTITION if partition_sized else VolumeClassification.UNKNOWN

        if partition_sized:
            evidence.append(
                VolumeEvidence(
                    "unknown-filesystem",
                    "content starts with no filesystem or partition table this parser knows",
                    True,
                    "content",
                )
            )
            return VolumeClassification.UNKNOWN_FILESYSTEM

        evidence.append(
            VolumeEvidence(
                "metadata-sized",
                f"span {span} B is below the partition floor or not sector-aligned, with no filesystem",
                False,
                "data_map",
            )
        )
        return VolumeClassification.METADATA

    def _partition_without_data(self, partition: ItemStream) -> VolumeCandidate:
        """A candidate for an imap partition that stored no data, which reads as zeros."""
        return VolumeCandidate(
            volume_id=partition.id,
            span=0,
            classification=VolumeClassification.ZERO_PARTITION,
            confidence=VolumeConfidence.CONFIRMED,
            evidence=(
                VolumeEvidence(
                    "imap-name",
                    f"complete imap partition record {partition.name.decode('utf-8', 'replace')!r} "
                    f"(slice {partition.slice_id}, stream {partition.id:#x})",
                    True,
                    "imap",
                ),
                VolumeEvidence("no-data", "the partition stored no data and reads as zeros", None, "imap"),
            ),
            stream=TibxVolume(self, partition.id, self.extents, 0, 0),
            name=partition.name,
        )

    def _named_partitions(self) -> dict[int, ItemStream]:
        """The partition imap records of the selected recovery point, by the stream they name."""
        named: dict[int, ItemStream] = {}
        for partition in self._partitions():
            # One partition is linked under two names, disk%u/part%u and part/<hash>;
            # both name the same stream, so keep the disk%u/part%u one that Acronis lists
            # content under
            current = named.get(partition.id)
            if current is None or (
                PARTITION_NAME_RE.fullmatch(partition.name) and not PARTITION_NAME_RE.fullmatch(current.name)
            ):
                named[partition.id] = partition
        return named

    def _stream_item_names(self) -> dict[int, bytes]:
        """The imap name of every data stream the imap names with a path, by stream id."""
        names: dict[int, bytes] = {}
        try:
            records = self._item_streams()
        except InvalidPasswordError:
            return names
        for record in records:
            if record.index != 0 or (self._slice_limit is not None and record.slice_id > self._slice_limit):
                continue
            if not record.flags & c_tibx.ItemFlags.COMPLETE or record.flags & c_tibx.ItemFlags.DELETED:
                continue
            names[record.id] = record.name
        return names

    def _imap_names_files(self) -> bool:
        """Whether the imap records file-level items, as of the selected recovery point.

        A file-level backup's imap holds paths such as ``C:/Users/...``; a disk-level
        backup's holds ``disk%u/part%u``. This is answered from the imap alone, so a
        large file that looks exactly like a partition is excluded even when its
        name was not matched to this particular stream.
        """
        if self.archive_type == "file":
            return True
        try:
            records = self._item_streams()
        except InvalidPasswordError:
            return False
        for record in records:
            if record.index != 0 or (self._slice_limit is not None and record.slice_id > self._slice_limit):
                continue
            if not record.flags & c_tibx.ItemFlags.COMPLETE or record.flags & c_tibx.ItemFlags.DELETED:
                continue
            if (
                DISK_ITEM_RE.fullmatch(record.name)
                or PARTITION_LINK_RE.fullmatch(record.name)
                or PARTITION_NAME_RE.fullmatch(record.name)
            ):
                continue
            return True
        return False

    def _partitions(self) -> list[ItemStream]:
        """The partitions of the selected recovery point, as the imap names them, by the record of their data stream.

        Empty if the imap names no partition, or if it is encrypted and the archive locked.
        """
        if self._partitions_cache is not None:
            return self._partitions_cache
        try:
            records = self._item_streams()
        except InvalidPasswordError:
            return []
        # An item's version in a backup is its newest record up to that backup, as Acronis
        # lists items; one that is deleted or incomplete is not there
        versions: dict[bytes, ItemStream] = {}
        for record in records:
            if (
                record.index == 0
                and (self._slice_limit is None or record.slice_id <= self._slice_limit)
                and (PARTITION_NAME_RE.fullmatch(record.name) or PARTITION_LINK_RE.fullmatch(record.name))
            ):
                version = versions.get(record.name)
                if version is None or record.slice_id > version.slice_id:
                    versions[record.name] = record
        self._partitions_cache = [
            record
            for record in versions.values()
            if record.flags & c_tibx.ItemFlags.COMPLETE and not record.flags & c_tibx.ItemFlags.DELETED
        ]
        return self._partitions_cache

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

    def _stream_size(self, volume_id: int) -> int | None:
        """The size the imap gives data_map stream ``volume_id``, as of the selected recovery point.

        ``None`` if the imap does not name the stream, or if it is encrypted and the archive
        is locked.
        """
        if self._stream_sizes is None:
            try:
                records = self._item_streams()
            except InvalidPasswordError:
                return None
            # Oldest backup first, so the newest one in view decides
            self._stream_sizes = {
                record.id: record.size
                for record in sorted(records)
                if (self._slice_limit is None or record.slice_id <= self._slice_limit)
                and not record.flags & c_tibx.ItemFlags.DELETED
            }
        return self._stream_sizes.get(volume_id)

    @staticmethod
    def _is_volume(stream: TibxVolume, bitmap_spans: set[int]) -> bool:
        """Whether a data_map stream is a backed-up volume rather than Acronis metadata.

        The single-verdict form of the classifier: a recognised filesystem, or a
        partition-sized, sector-aligned span that is neither an allocation bitmap by
        span nor a disk's bootstrap region by content, is a volume. See
        :meth:`volume_candidates` for the same reasoning with its evidence named.

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
    """One backed-up volume (a data_map volume stream) inside a TIBX archive.

    Its extents are the rows ``start`` up to ``stop`` of the archive's extent table.
    """

    def __init__(self, tibx: TIBX, volume_id: int, table: ExtentTable, start: int = 0, stop: int | None = None):
        self.tibx = tibx
        self.volume_id = volume_id
        self._table = table
        self._first = start
        self._last = len(table) if stop is None else stop
        # Interval i runs from _starts[i] up to _stops[i] and reads from row _first + _covering[i]
        self._starts, self._stops, self._covering = resolve_extents(table, self._first, self._last)
        lengths = table.extent_lengths[self._first : self._last]
        self._span = max(map(add, table.source_offsets[self._first : self._last], lengths), default=0)
        self._newest_slice = max(table.slice_ids[self._first : self._last], default=0)
        self._size: int | None = None

    def __repr__(self) -> str:
        # The span, not the size: that would read the boot sector, which needs the password
        # on an encrypted archive
        return f"<TibxVolume volume_id={self.volume_id:#x} span={self.span}>"

    @property
    def extents(self) -> ExtentTable:
        """The data_map extents of this volume, in offset order."""
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
        """The volume size in bytes, as the imap records it.

        That is the partition's size: an NTFS boot sector leaves the partition's last
        sector out, and a sparse volume's boot sector can say far more than the data_map
        holds. Without an imap record, as for an encrypted archive that is locked, the size
        comes from the boot sector, capped by the data_map span.
        """
        if self._size is None:
            size = self.tibx._stream_size(self.volume_id)
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


def _span_evidence(span: int, bitmap_spans: set[int]) -> list[VolumeEvidence]:
    """The evidence a stream's data_map span gives for or against its being a partition.

    A partition is imaged in whole sectors of at least :data:`MIN_VOLUME_SIZE`, and a
    volume's allocation bitmap has the span of a bit per cluster of another stream (see
    :func:`_bitmap_spans`), which can reach the same floor. The neutral facts are cited
    for any span; the one conclusion they support is cited only when no contradiction
    exists, so a citation never argues both ways at once.
    """
    evidence: list[VolumeEvidence] = []
    if span < MIN_VOLUME_SIZE:
        evidence.append(
            VolumeEvidence(
                "span-below-minimum",
                f"span {span} B is below the {MIN_VOLUME_SIZE} B partition floor",
                None,
                "data_map",
            )
        )
    if span % SECTOR_SIZE:
        evidence.append(
            VolumeEvidence(
                "span-unaligned",
                f"span {span} B is not a whole number of {SECTOR_SIZE} B sectors",
                None,
                "data_map",
            )
        )
    if span >= MIN_VOLUME_SIZE and span in bitmap_spans:
        evidence.append(
            VolumeEvidence(
                "bitmap-span",
                f"span {span} B is a bit per cluster of another stream, rounded up to a byte",
                False,
                "data_map",
            )
        )
    elif span >= MIN_VOLUME_SIZE and not span % SECTOR_SIZE:
        evidence.append(
            VolumeEvidence(
                "partition-sized-span",
                f"span {span} B is at least {MIN_VOLUME_SIZE} B and sector-aligned",
                True,
                "data_map",
            )
        )
    return evidence


def _against_evidence(evidence: list[VolumeEvidence]) -> list[VolumeEvidence]:
    """The evidence that does not argue that a stream is a volume.

    A citation must not contradict its verdict: span evidence that a partition-sized,
    sector-aligned span supports the verdict is dropped once the content has ruled an
    allocation bitmap or metadata-sized stream out.
    """
    return [item for item in evidence if item.supports is not True]


def _stream_order(stream: TibxVolume) -> tuple[int, int]:
    """Sort key of :meth:`TIBX.streams`, which sorts in reverse: the newest backup that wrote to a stream, its span."""
    return stream._newest_slice, stream.span


def _candidate_order(candidate: VolumeCandidate) -> tuple[int, int, int]:
    """Sort key of :meth:`TIBX.candidates`, sorted in reverse.

    Confirmed partition identities rank above heuristics, then the newest backup that
    wrote the stream, then its span, matching :meth:`TIBX.streams` within each
    confidence tier.
    """
    return candidate.confidence.rank, candidate.stream._newest_slice if candidate.stream else 0, candidate.span


def _identity_differs(previous: VolumeIdentity, candidate: VolumeCandidate) -> bool:
    """Whether ``candidate``'s identity changed compared to ``previous``.

    Identity is the classification and the confidence in it; evidence can grow or change
    wording without the stream becoming another kind of thing, and reporting that as an
    identity change would bury the one that matters (a guess becoming a confirmed
    partition) under bookkeeping.
    """
    return previous.classification is not candidate.classification or previous.confidence is not candidate.confidence


def _filesystem_name(head: bytes) -> str:
    """The filesystem whose boot sector ``_boot_sector_size`` recognised in ``head``."""
    if len(head) < 512:
        return "unknown filesystem"
    try:
        if c_boot.ntfs_boot_sector(head).oem_id == b"NTFS    ":
            return "NTFS"
        if c_boot.exfat_boot_sector(head).fs_name == b"EXFAT   ":
            return "exFAT"
        fat = c_boot.fat_boot_sector(head)
        if fat.fs_type_32.startswith(b"FAT32") or fat.fs_type_16.startswith(b"FAT"):
            return "FAT"
        if (
            len(head) >= EXT_SUPERBLOCK_OFFSET + len(c_boot.ext_superblock)
            and c_boot.ext_superblock(head[EXT_SUPERBLOCK_OFFSET:]).magic == EXT_MAGIC
        ):
            return "ext"
    except EOFError:
        pass
    return "unknown filesystem"


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
