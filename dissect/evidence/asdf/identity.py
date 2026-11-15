"""Evidence identity layer for ASDF snapshots.

This module adds a stable, human and machine readable identity layer on top of
the existing ASDF container without changing the on-disk block format. All
extra information is carried inside the regular metadata TAR stream
(``idx=255``) as a single versioned JSON manifest. Old readers that do not know
about the manifest keep working unchanged, and old files without a manifest
remain fully readable through the structural fallback in :class:`IdentityReader`.

Design goals:
    - Never infer that two streams are the same physical device from an offset
      match. Same-device conclusions require an explicit, integrity protected
      claim (a serial number or an acquisition declaration).
    - Keep every byte addressable through a canonical locator that combines the
      container identity (writer GUID / container hash), the stream ``idx`` and
      the absolute in-stream offset.
    - Distinguish what the format proves ("structural") from what an operator
      or tool asserted ("declared") and what a hardware identifier supports
      ("verified").
"""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.evidence.asdf.asdf import (
    IDX_MEMORY,
    IDX_METADATA,
    MAX_IDX,
    RESERVED_IDX,
)

if TYPE_CHECKING:
    from dissect.evidence.asdf.asdf import AsdfSnapshot, AsdfWriter

MANIFEST_PATH = "asdf-identity/manifest.json"
MANIFEST_SCHEMA = "asdf-identity/v1"

# Confidence levels, ordered from strongest to weakest.
VERIFIED = "verified"
DECLARED = "declared"
STRUCTURAL = "structural"

# The block format only assigns a single byte stream index.
KIND_DISK = "disk"
KIND_VOLUME = "volume"
KIND_MEMORY = "memory"
KIND_METADATA = "metadata"
KIND_UNKNOWN = "unknown"


class IdentityError(Exception):
    """Raised when an identity manifest is malformed or inconsistent."""


@dataclass(frozen=True, slots=True)
class StreamIdentity:
    """Identity record for a single ASDF stream.

    Attributes:
        idx: The ASDF stream index (0-255). Reserved indices 254/255 describe
            the memory and metadata streams.
        kind: One of the ``KIND_*`` constants.
        confidence: One of the ``VERIFIED``, ``DECLARED`` or ``STRUCTURAL``
            constants.
        label: Short human readable label suitable for UI display.
        serial: Hardware serial number, when asserted and corroborated.
        device: Free-form device path (for example ``/dev/sda`` or a Windows
            ``PhysicalDriveN`` path).
        volume_base: For a relative volume stream, the byte offset of the volume
            relative to the start of its parent disk. ``None`` for whole-disk
            or non-volume streams.
        parent_idx: Stream index of the parent disk for a relative volume.
        content_sha256: Optional hash over the reconstructed stream content,
            usable as a weak correlation hint only.
        source: Where the record came from: ``manifest`` or ``structure``.
        claim: The raw manifest entry, when the record came from a manifest.
    """

    idx: int
    kind: str = KIND_UNKNOWN
    confidence: str = STRUCTURAL
    label: str = ""
    serial: str | None = None
    device: str | None = None
    volume_base: int | None = None
    parent_idx: int | None = None
    content_sha256: str | None = None
    source: str = "structure"
    claim: dict[str, Any] | None = None

    @property
    def is_reserved(self) -> bool:
        return self.idx in RESERVED_IDX

    def display(self) -> str:
        """Return a label that never overstates the available evidence."""
        if self.label:
            return self.label
        if self.kind == KIND_MEMORY:
            return f"memory stream idx={self.idx} (reserved)"
        if self.kind == KIND_METADATA:
            return f"metadata stream idx={self.idx} (reserved)"
        return f"disk stream idx={self.idx} (unidentified)"


@dataclass(frozen=True, slots=True)
class MergeDecision:
    """Result of a same-device merge evaluation between two streams."""

    same_device: bool
    confidence: str
    reason: str


@dataclass(slots=True)
class IdentityManifest:
    """Builder for the versioned identity manifest stored in the metadata TAR."""

    writer_guid: str
    streams: dict[int, dict[str, Any]] = field(default_factory=dict)
    acquisition: dict[str, Any] = field(default_factory=dict)
    schema: str = MANIFEST_SCHEMA

    def declare_disk(
        self,
        idx: int,
        *,
        serial: str | None = None,
        device: str | None = None,
        label: str | None = None,
        content_sha256: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record an acquisition-side claim for a whole-disk stream.

        A serial number is the strongest identifier available here. Without one
        the entry remains a declaration attributed to the acquisition run, it
        never becomes a hardware-verified identity on its own.
        """
        _validate_disk_idx(idx)
        entry: dict[str, Any] = {"kind": KIND_DISK}
        if serial is not None:
            entry["serial"] = serial
        if device is not None:
            entry["device"] = device
        if label is not None:
            entry["label"] = label
        if content_sha256 is not None:
            entry["content_sha256"] = content_sha256
        if extra:
            entry.update(extra)
        self.streams[idx] = entry
        return entry

    def declare_volume(
        self,
        idx: int,
        *,
        parent_idx: int,
        volume_base: int,
        filesystem: str | None = None,
        label: str | None = None,
        content_sha256: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record a relative volume stream and its mapping back to a disk.

        ``volume_base`` is the byte offset of the volume relative to the start
        of the parent disk. It is the same base the writer already accepts via
        ``copy_bytes(..., base=...)``; blocks are stored at ``base + offset``.
        """
        _validate_disk_idx(idx)
        _validate_disk_idx(parent_idx)
        if volume_base < 0:
            raise IdentityError("volume_base must be a non-negative offset")
        entry: dict[str, Any] = {
            "kind": KIND_VOLUME,
            "parent_idx": parent_idx,
            "volume_base": volume_base,
        }
        if filesystem is not None:
            entry["filesystem"] = filesystem
        if label is not None:
            entry["label"] = label
        if content_sha256 is not None:
            entry["content_sha256"] = content_sha256
        if extra:
            entry.update(extra)
        self.streams[idx] = entry
        return entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "writer_guid": self.writer_guid,
            "acquisition": self.acquisition,
            "streams": {str(idx): entry for idx, entry in sorted(self.streams.items())},
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True).encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityManifest:
        if not isinstance(data, dict):
            raise IdentityError("manifest must be a JSON object")
        if data.get("schema") != MANIFEST_SCHEMA:
            raise IdentityError(f"unsupported manifest schema: {data.get('schema')!r}")
        writer_guid = data.get("writer_guid")
        if not isinstance(writer_guid, str) or not writer_guid:
            raise IdentityError("manifest is missing writer_guid")

        manifest = cls(
            writer_guid=writer_guid,
            acquisition=dict(data.get("acquisition") or {}),
        )
        for raw_idx, entry in (data.get("streams") or {}).items():
            try:
                idx = int(raw_idx)
            except (TypeError, ValueError) as exc:
                raise IdentityError(f"invalid stream index in manifest: {raw_idx!r}") from exc
            if not isinstance(entry, dict):
                raise IdentityError(f"manifest entry for idx={idx} must be an object")
            manifest.streams[idx] = dict(entry)
        return manifest


class IdentityReader:
    """Reads identity records from a snapshot.

    A manifest is optional. When absent (the case for every legacy ASDF file),
    the reader falls back to structural facts derived purely from the block
    table and reserved indices, and reports :data:`STRUCTURAL` confidence.
    """

    def __init__(self, snapshot: AsdfSnapshot):
        self.snapshot = snapshot
        self.manifest = self._load_manifest(snapshot)

    @staticmethod
    def _load_manifest(snapshot: AsdfSnapshot) -> IdentityManifest | None:
        if IDX_METADATA not in snapshot.table:
            return None
        try:
            fh = snapshot.metadata.open(MANIFEST_PATH)
        except KeyError:
            return None
        try:
            data = json.loads(fh.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise IdentityError(f"identity manifest is not valid JSON: {exc}") from exc
        return IdentityManifest.from_dict(data)

    def identities(self) -> dict[int, StreamIdentity]:
        """Return one identity record per stream present in the block table."""
        result: dict[int, StreamIdentity] = {}
        for idx in sorted(self.snapshot.table.keys()):
            result[idx] = self.identity(idx)
        return result

    def identity(self, idx: int) -> StreamIdentity:
        reserved_kind = _reserved_kind(idx)
        claim = self._claim(idx)

        if claim is None:
            # Non-reserved indices are disk/volume streams by format convention;
            # without a manifest we can prove the stream exists but not which
            # physical device it is, so we report disk at structural confidence.
            kind = reserved_kind or KIND_DISK
            return StreamIdentity(idx=idx, kind=kind, confidence=STRUCTURAL, source="structure")

        kind = claim.get("kind", reserved_kind or KIND_DISK)
        confidence = _claim_confidence(claim)
        return StreamIdentity(
            idx=idx,
            kind=kind,
            confidence=confidence,
            label=str(claim.get("label") or ""),
            serial=claim.get("serial"),
            device=claim.get("device"),
            volume_base=claim.get("volume_base"),
            parent_idx=claim.get("parent_idx"),
            content_sha256=claim.get("content_sha256"),
            source="manifest",
            claim=claim,
        )

    def _claim(self, idx: int) -> dict[str, Any] | None:
        if self.manifest is None:
            return None
        return self.manifest.streams.get(idx)

    def locator(self, idx: int, offset: int = 0, size: int | None = None) -> str:
        """Build a canonical, content-independent byte locator.

        The locator never relies on an offset to imply device identity: the
        stream index and writer GUID scope the offset, so equal offsets on
        different streams (disks) always produce different locators while
        distinct ranges of the same disk stay in the same scope.
        """
        if idx not in self.snapshot.table:
            raise IndexError(f"invalid stream idx: {idx}")
        if offset < 0:
            raise ValueError("offset must be non-negative")

        guid = str(self.snapshot.guid)
        kind = self.identity(idx).kind
        if size is None:
            return f"urn:asdf:{guid}:stream/{idx}/{kind}#offset={offset}"
        if size < 0:
            raise ValueError("size must be non-negative")
        return f"urn:asdf:{guid}:stream/{idx}/{kind}#offset={offset}&size={size}"

    def disk_extent(self, idx: int, offset: int, size: int) -> tuple[int, int]:
        """Translate a stream range to an absolute range on the parent disk.

        For a declared relative volume the volume base is added, so a byte at
        in-volume offset ``offset`` maps to ``volume_base + offset`` on the
        parent disk. Whole-disk and reserved streams are returned unchanged.
        """
        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        identity = self.identity(idx)
        base = identity.volume_base or 0
        parent = identity.parent_idx if identity.parent_idx is not None else idx
        return parent, base + offset

    def can_merge(self, left: int, right: int) -> MergeDecision:
        """Decide whether two disk streams may be presented as one device.

        Offset equality is deliberately ignored: identical offsets in two
        different streams provide no device identity. A positive answer needs
        either a matching serial (verified) or an explicit acquisition
        declaration binding the streams together.
        """
        if left == right:
            return MergeDecision(True, STRUCTURAL, "same stream index")

        left_identity = self.identity(left)
        right_identity = self.identity(right)

        if left_identity.serial and right_identity.serial:
            if left_identity.serial == right_identity.serial:
                return MergeDecision(
                    True,
                    VERIFIED,
                    f"matching serial {left_identity.serial!r} on both streams",
                )
            return MergeDecision(
                False,
                VERIFIED,
                f"distinct serials {left_identity.serial!r} vs {right_identity.serial!r}",
            )

        if _same_acquisition_group(left_identity.claim, right_identity.claim, self.manifest):
            return MergeDecision(
                True,
                DECLARED,
                "acquisition declaration explicitly groups the streams",
            )

        return MergeDecision(
            False,
            STRUCTURAL,
            "no serial or acquisition declaration; matching offsets are not device identity",
        )

    def strongest_conclusion(self, idx: int) -> str:
        """Return the strongest defensible statement for a stream.

        This is the wording a UI may use when metadata is missing or partial.
        """
        identity = self.identity(idx)
        if identity.kind == KIND_MEMORY:
            return f"reserved memory stream idx={idx}; content origin not asserted"
        if identity.kind == KIND_METADATA:
            return f"reserved metadata TAR stream idx={idx}"

        if identity.confidence == VERIFIED and identity.serial:
            return f"disk idx={idx} identified by serial {identity.serial!r}"
        if identity.confidence == DECLARED:
            return f"disk idx={idx} bound by acquisition declaration only, serial not verified"
        if identity.volume_base is not None:
            return (
                f"volume idx={idx} relative to disk idx={identity.parent_idx} "
                f"at byte base {identity.volume_base}; physical device not identified"
            )
        return (
            f"distinct byte stream idx={idx} in container {self.snapshot.guid}; "
            "device identity unproven, must not be merged on offset alone"
        )


def attach_manifest(writer: AsdfWriter, manifest: IdentityManifest) -> None:
    """Attach an identity manifest to a writer via the existing metadata API."""
    expected = str(writer.guid)
    if manifest.writer_guid != expected:
        raise IdentityError(
            f"manifest writer_guid {manifest.writer_guid!r} does not match writer {expected!r}"
        )
    writer.add_metadata_file(MANIFEST_PATH, io.BytesIO(manifest.to_bytes()))


def stream_sha256(stream: BinaryIO) -> str:
    """Hash reconstructed stream content for use as a correlation hint.

    A content hash can suggest that two streams hold related data but cannot
    prove they came from the same physical device, so it must never feed the
    same-device decision on its own.
    """
    ctx = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        ctx.update(chunk)
    return ctx.hexdigest()


def _validate_disk_idx(idx: int) -> None:
    if not 0 <= idx <= MAX_IDX:
        raise IdentityError(f"disk/volume stream index must be 0..{MAX_IDX}, got {idx}")


def _reserved_kind(idx: int) -> str | None:
    if idx == IDX_MEMORY:
        return KIND_MEMORY
    if idx == IDX_METADATA:
        return KIND_METADATA
    return None


def _claim_confidence(claim: dict[str, Any]) -> str:
    if claim.get("serial"):
        return VERIFIED
    if claim.get("declared") is True or claim.get("kind") in (KIND_DISK, KIND_VOLUME):
        return DECLARED
    return STRUCTURAL


def _same_acquisition_group(
    left_claim: dict[str, Any] | None,
    right_claim: dict[str, Any] | None,
    manifest: IdentityManifest | None,
) -> bool:
    if not left_claim or not right_claim or manifest is None:
        return False
    group = manifest.acquisition.get("group_id")
    if not group:
        return False
    return left_claim.get("group_id") == group and right_claim.get("group_id") == group
