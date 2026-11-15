"""Evidence identity helpers for ASDF streams.

ASDF itself only gives a byte range per stream index.  A stream index is an
identifier *within one ASDF container*; it is not a disk identifier.  The block
table records the already-translated absolute stream offset, so it cannot say
whether a stream came from a whole disk, a volume starting at an offset, or a
memory capture.  The optional, versioned manifest in this module lives in the
existing metadata tar so an acquisition tool can record those facts without
changing the header, block, table-entry or footer layouts.

The manifest is deliberately advisory.  A reader can always fall back to the
observable container facts (GUID, stream index, captured runs and offsets).
Source identity is only exposed when the manifest contains a serial number or
an acquisition declaration; size, model, label, content hashes or equal offsets
are not treated as device identity.  A serial's provenance is preserved so a
consumer can distinguish a verified serial from an unspecified one.
"""

from __future__ import annotations

import io
import json
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from dissect.evidence.asdf.asdf import IDX_MEMORY, IDX_METADATA
from dissect.evidence.exception import InvalidEvidence

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.evidence.asdf.asdf import AsdfSnapshot, AsdfWriter


IDENTITY_MANIFEST = "asdf/identity.json"
IDENTITY_FORMAT = "dissect.evidence.asdf.identity"
IDENTITY_VERSION = 1
MAX_MANIFEST_SIZE = 1024 * 1024

_IDENTIFIER_RE = re.compile(
    r"^asdf:(?P<guid>[0-9a-fA-F-]{32,36})/stream/(?P<idx>[0-9]{1,3})"
    r"(?:@0x(?P<offset>[0-9a-fA-F]+)\+0x(?P<length>[0-9a-fA-F]+))?$"
)


class StreamRole(str, Enum):
    """The role of a stream, as declared in the manifest."""

    DISK = "disk"
    VOLUME = "volume"
    MEMORY = "memory"
    METADATA = "metadata"
    STREAM = "stream"


class IdentityStrength(str, Enum):
    """The strongest identity conclusion supported by a stream.

    The values are ordered from least to most specific.  Even the strongest
    value is a *declaration*: it never proves two byte ranges are the same.
    """

    CONTAINER_STREAM = "container-stream"
    DECLARED_ROLE = "declared-role"
    DECLARED_ACQUISITION = "declared-acquisition"
    DECLARED_SERIAL = "declared-serial"


class SerialSource(str, Enum):
    """Where a serial number came from.

    ``LABEL`` is intentionally not a serial source.  A user-assigned label is
    useful for display, but it must not be used to coalesce devices.
    """

    ACQUISITION = "acquisition"
    OPERATING_SYSTEM = "os"
    DEVICE = "device"
    LABEL = "label"
    UNKNOWN = "unknown"


_TRUSTED_SERIAL_SOURCES = (SerialSource.ACQUISITION, SerialSource.OPERATING_SYSTEM, SerialSource.DEVICE)


@dataclass(frozen=True)
class SourceClaim:
    """A source declaration recorded by the acquisition tool.

    Args:
        serial: Device serial number, if the acquisition tool observed one.
            Its meaning depends on ``serial_source``.
        serial_source: Provenance of ``serial``.  ``acquisition``, ``os`` and
            ``device`` are verified provenances.  A missing or ``unknown``
            provenance is still a declared serial, but is not verified.
            ``label`` is display-only and never a serial.
        acquisition_id: Case/evidence/acquisition identifier.  This is an
            alternate declaration of source identity when no serial is
            available.
        model: Optional device model.  Not an identity key.
        size: Optional declared source size in bytes.  Not an identity key.
        description: Free-form description.  Not an identity key.
    """

    serial: str | None = None
    serial_source: SerialSource | str | None = None
    acquisition_id: str | None = None
    model: str | None = None
    size: int | None = None
    description: str | None = None

    def __post_init__(self) -> None:
        for name in ("serial", "acquisition_id", "model", "description"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
            if isinstance(value, str):
                object.__setattr__(self, name, value.strip() or None)

        source = self.serial_source
        if isinstance(source, str):
            try:
                source = SerialSource(source.strip().lower())
            except ValueError as e:
                raise ValueError(f"invalid serial_source: {self.serial_source!r}") from e
        elif source is not None and not isinstance(source, SerialSource):
            raise ValueError(f"invalid serial_source: {self.serial_source!r}")

        # A claim with only a model/description is allowed for display, but it
        # will never produce a source key.
        if self.size is not None and (not isinstance(self.size, int) or isinstance(self.size, bool) or self.size < 0):
            raise ValueError("source size must be a non-negative integer")

        object.__setattr__(self, "serial_source", source)

    @property
    def source_key(self) -> str | None:
        """Return a declared source key, or ``None`` if no source was declared.

        The key is only a declaration.  It says that two streams were recorded
        against the same serial/acquisition; it does not prove that two byte
        ranges are the same data and it never causes extents to be merged.
        Use :attr:`serial_verified` to distinguish a verified serial from an
        unspecified one.
        """
        if self.serial and self.serial_source != SerialSource.LABEL:
            return f"serial:{self.serial}"
        if self.acquisition_id:
            return f"acquisition:{self.acquisition_id}"
        return None

    @property
    def strength(self) -> IdentityStrength | None:
        """Return the strongest source conclusion provided by this claim."""
        if self.serial and self.serial_source != SerialSource.LABEL:
            return IdentityStrength.DECLARED_SERIAL
        if self.acquisition_id:
            return IdentityStrength.DECLARED_ACQUISITION
        return None

    @property
    def serial_verified(self) -> bool:
        """Return whether the serial's provenance is acquisition, OS or device."""
        return bool(self.serial) and self.serial_source in _TRUSTED_SERIAL_SOURCES

    def display(self) -> str:
        """Return a human-readable, non-identity description."""
        parts = []
        if self.serial:
            source = self.serial_source.value if isinstance(self.serial_source, SerialSource) else self.serial_source
            field = "label" if self.serial_source == SerialSource.LABEL else "serial"
            parts.append(f"{field}={self.serial!r}" + (f" ({source})" if source else " (provenance unknown)"))
        if self.acquisition_id:
            parts.append(f"acquisition={self.acquisition_id!r}")
        if self.model:
            parts.append(f"model={self.model!r}")
        if self.size is not None:
            parts.append(f"size=0x{self.size:x}")
        if self.description:
            parts.append(self.description)
        return ", ".join(parts) or "unidentified"

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this claim."""
        result: dict[str, Any] = {}
        for key in ("serial", "acquisition_id", "model", "size", "description"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        if self.serial_source is not None:
            result["serial_source"] = (
                self.serial_source.value if isinstance(self.serial_source, SerialSource) else self.serial_source
            )
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SourceClaim:
        """Create a claim from manifest JSON."""
        if not isinstance(value, dict):
            raise ValueError("source must be an object")
        return cls(
            serial=value.get("serial"),
            serial_source=value.get("serial_source"),
            acquisition_id=value.get("acquisition_id"),
            model=value.get("model"),
            size=_as_int(value.get("size"), "source.size"),
            description=value.get("description"),
        )


@dataclass(frozen=True)
class StreamDeclaration:
    """A stream declaration to write into an ASDF manifest.

    Args:
        idx: Stream index (0-253 for data streams, 254 for memory).
        role: Declared role.  Use ``StreamRole.VOLUME`` for a volume stream.
        source: Optional source claim.
        base: Offset in the parent disk that corresponds to offset zero of
            this stream.  This is a read-side translation, not a copy of the
            block table.  For a volume captured in its own relative stream,
            record the partition start here.  If data was copied into the
            parent stream with a non-zero ``AsdfWriter.base``, its block
            offsets already are parent offsets, so use ``base=0``.
        parent_idx: Stream index of the parent disk for a volume stream.
        label: Display label.  Never used as an identity key.
    """

    idx: int
    role: StreamRole = StreamRole.STREAM
    source: SourceClaim | None = None
    base: int = 0
    parent_idx: int | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.idx, int) or isinstance(self.idx, bool):
            raise ValueError("stream idx must be an integer")
        if not 0 <= self.idx <= 255:
            raise ValueError(f"stream idx out of range: {self.idx}")
        if self.idx == IDX_METADATA:
            raise ValueError("the metadata stream cannot describe itself")
        if isinstance(self.role, str):
            try:
                object.__setattr__(self, "role", StreamRole(self.role.strip().lower()))
            except ValueError as e:
                raise ValueError(f"invalid declared role: {self.role!r}") from e
        elif not isinstance(self.role, StreamRole):
            raise ValueError(f"invalid declared role: {self.role!r}")
        if self.idx == IDX_MEMORY:
            if self.role != StreamRole.MEMORY:
                raise ValueError("stream 254 must have role memory")
        elif self.role == StreamRole.MEMORY:
            raise ValueError("only stream 254 can have role memory")
        if self.role not in (StreamRole.DISK, StreamRole.VOLUME, StreamRole.MEMORY, StreamRole.STREAM):
            raise ValueError(f"invalid declared role: {self.role}")
        if not isinstance(self.base, int) or isinstance(self.base, bool) or self.base < 0:
            raise ValueError("base must be a non-negative integer")
        if self.role != StreamRole.VOLUME and self.base:
            raise ValueError("only a volume stream can have a non-zero base")
        if self.role != StreamRole.VOLUME and self.parent_idx is not None:
            raise ValueError("only a volume stream can have a parent_idx")
        if self.parent_idx is not None:
            if not isinstance(self.parent_idx, int) or isinstance(self.parent_idx, bool):
                raise ValueError("parent_idx must be an integer")
            if not 0 <= self.parent_idx < IDX_MEMORY:
                raise ValueError("parent_idx must be a disk or volume stream index")
            if self.parent_idx == self.idx:
                raise ValueError("a stream cannot be its own parent")
        if self.source is not None and not isinstance(self.source, SourceClaim):
            raise ValueError("source must be a SourceClaim")

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON representation of this declaration."""
        result: dict[str, Any] = {
            "idx": self.idx,
            "role": self.role.value,
            "base": self.base,
        }
        if self.parent_idx is not None:
            result["parent_idx"] = self.parent_idx
        if self.label is not None:
            result["label"] = self.label
        if self.source is not None:
            result["source"] = self.source.as_dict()
        return result


@dataclass(frozen=True)
class StreamRun:
    """A captured run in a stream's coordinate system."""

    offset: int
    size: int
    file_offset: int

    @property
    def end(self) -> int:
        """Return the exclusive end offset of this run."""
        return self.offset + self.size


@dataclass(frozen=True)
class EvidenceExtent:
    """A concrete byte range in one ASDF stream.

    The container GUID, stream index and byte range are all part of the
    identity.  Two extents are only equal when all components match.  There is
    intentionally no operation that merges extents from different streams,
    even if their offsets or declared serials are equal.
    """

    container: uuid.UUID
    idx: int
    role: StreamRole
    offset: int
    length: int
    source_key: str | None = None
    base: int | None = None
    parent_idx: int | None = None
    captured: bool = True

    @property
    def identifier(self) -> str:
        """Return the stable, parseable evidence identifier."""
        return f"asdf:{self.container}/stream/{self.idx}@{self.offset:#x}+{self.length:#x}"

    @property
    def source_offset(self) -> int | None:
        """Return the offset in the declared source coordinate system."""
        if self.base is None:
            return None
        return self.base + self.offset

    def to_parent(self) -> tuple[int, int, int] | None:
        """Return ``(parent_idx, parent_offset, length)`` for a volume extent."""
        if self.parent_idx is None or self.source_offset is None:
            return None
        return self.parent_idx, self.source_offset, self.length

    def same_stream(self, other: EvidenceExtent) -> bool:
        """Return whether both extents address the same ASDF stream."""
        return self.container == other.container and self.idx == other.idx

    def overlaps(self, other: EvidenceExtent) -> bool:
        """Return whether both extents overlap in the same stream."""
        if not self.same_stream(other):
            return False
        return self.offset < other.offset + other.length and other.offset < self.offset + self.length

    def __str__(self) -> str:
        return self.identifier


@dataclass(frozen=True)
class StreamIdentity:
    """Identity information for one ASDF stream."""

    container: uuid.UUID
    idx: int
    role: StreamRole
    size: int
    runs: tuple[StreamRun, ...]
    source: SourceClaim | None = None
    base: int | None = None
    parent_idx: int | None = None
    label: str | None = None
    declared: bool = False

    @property
    def identifier(self) -> str:
        """Return the stable stream identifier (without a byte range)."""
        return f"asdf:{self.container}/stream/{self.idx}"

    @property
    def source_key(self) -> str | None:
        """Return the declared source key, if the manifest supplied one."""
        return self.source.source_key if self.source else None

    @property
    def display_name(self) -> str:
        """Return a label suitable for UI, without hiding the stream index."""
        if self.label:
            return f"{self.label} [stream {self.idx}]"
        return f"{self.role.value} stream {self.idx}"

    @property
    def identity_strength(self) -> IdentityStrength:
        """Return the strongest identity conclusion supported by the data.

        ``container-stream`` means only the container GUID, stream index and
        captured runs are known.  ``declared-role`` adds a manifest role or
        label.  ``declared-acquisition`` and ``declared-serial`` add an
        explicit source claim.  None of these values claim that a byte range
        belongs to the same device as another stream unless the source claim
        is present.
        """
        if self.source is not None and self.source.source_key is not None:
            return self.source.strength
        if self.declared:
            return IdentityStrength.DECLARED_ROLE
        return IdentityStrength.CONTAINER_STREAM

    def covers(self, offset: int, length: int) -> bool:
        """Return whether every byte in the range is captured in a data run."""
        if length <= 0:
            return False
        end = offset + length
        pos = offset
        for run in self.runs:
            if run.end <= pos:
                continue
            if run.offset > pos:
                return False
            pos = min(end, run.end)
            if pos >= end:
                return True
        return False

    def locate(self, offset: int, length: int | None = None) -> EvidenceExtent:
        """Locate a byte range in this stream.

        Args:
            offset: Offset in the ASDF stream coordinate system.
            length: Number of bytes.  Defaults to the rest of the captured
                stream.
        """
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if length is not None and (not isinstance(length, int) or isinstance(length, bool)):
            raise ValueError("length must be an integer")
        if length is None:
            length = self.size - offset
        if length <= 0:
            raise ValueError("length must be positive")
        if offset + length > self.size:
            raise ValueError(f"range 0x{offset:x}+0x{length:x} exceeds stream size 0x{self.size:x}")

        return EvidenceExtent(
            container=self.container,
            idx=self.idx,
            role=self.role,
            offset=offset,
            length=length,
            source_key=self.source_key,
            base=self.base,
            parent_idx=self.parent_idx,
            captured=self.covers(offset, length),
        )

    def __str__(self) -> str:
        return self.identifier


@dataclass(frozen=True)
class EvidenceIndex:
    """Evidence identities resolved from one ASDF snapshot.

    The index is read-only.  It never changes ``AsdfSnapshot.open`` or the
    numeric stream indexes, so old ASDF files and old callers keep working.
    """

    container: uuid.UUID
    streams: tuple[StreamIdentity, ...]
    metadata_names: tuple[str, ...] = ()
    manifest_present: bool = False
    manifest_ignored: bool = False
    warnings: tuple[str, ...] = ()
    manifest: dict[str, Any] | None = field(default=None, compare=False, repr=False)

    @classmethod
    def from_snapshot(cls, snapshot: AsdfSnapshot, *, strict: bool = False) -> EvidenceIndex:
        """Build an index from a snapshot.

        Args:
            snapshot: The parsed ASDF snapshot.
            strict: Raise :class:`InvalidEvidence` for a malformed or
                mismatched manifest.  The default degrades to observable
                container facts and records warnings.
        """
        warnings: list[str] = []
        manifest: dict[str, Any] | None = None
        manifest_present = False
        manifest_ignored = False
        metadata_names: tuple[str, ...] = ()

        if IDX_METADATA in snapshot.table:
            try:
                metadata_names = tuple(snapshot.metadata.names())
            except Exception as e:
                if strict:
                    raise InvalidEvidence(f"unable to list metadata: {e}") from e
                warnings.append(f"unable to list metadata: {e}")

            try:
                manifest = _read_manifest(snapshot)
            except Exception as e:
                if strict:
                    raise InvalidEvidence(str(e)) from e
                manifest_present = True
                manifest_ignored = True
                warnings.append(f"unable to read {IDENTITY_MANIFEST}: {e}")
            else:
                manifest_present = manifest is not None

        records: dict[int, dict[str, Any]] = {}
        if manifest is not None:
            try:
                records = _validate_manifest(manifest, snapshot.guid, warnings)
            except InvalidEvidence as e:
                if strict:
                    raise
                warnings.append(str(e))
                manifest_ignored = True

        for idx in records:
            if idx not in snapshot.table:
                warnings.append(f"identity manifest declares absent stream {idx}")

        streams = []
        for idx in sorted(snapshot.table):
            table = snapshot.table[idx]
            size = table[-1][0] + table[-1][1]
            runs = tuple(StreamRun(offset, run_size, file_offset) for offset, run_size, file_offset, _ in table)
            role = _fallback_role(idx)

            record = records.get(idx)
            source = None
            base = None
            parent_idx = None
            label = None
            declared = False

            if record:
                try:
                    role, source, base, parent_idx, label = _parse_record(
                        idx, record, records, set(snapshot.table), warnings
                    )
                except (InvalidEvidence, ValueError) as e:
                    if strict:
                        raise InvalidEvidence(f"stream {idx} has an invalid identity record: {e}") from e
                    warnings.append(f"stream {idx} has an invalid identity record: {e}")
                else:
                    declared = True

            streams.append(
                StreamIdentity(
                    container=snapshot.guid,
                    idx=idx,
                    role=role,
                    size=size,
                    runs=runs,
                    source=source,
                    base=base,
                    parent_idx=parent_idx,
                    label=label,
                    declared=declared,
                )
            )

        return cls(
            container=snapshot.guid,
            streams=tuple(streams),
            metadata_names=metadata_names,
            manifest_present=manifest_present,
            manifest_ignored=manifest_ignored,
            warnings=tuple(warnings),
            manifest=manifest,
        )

    def get(self, idx: int) -> StreamIdentity:
        """Return the identity for a stream index."""
        for stream in self.streams:
            if stream.idx == idx:
                return stream
        raise IndexError(f"invalid stream idx: {idx}")

    def data_streams(self) -> tuple[StreamIdentity, ...]:
        """Return all non-reserved streams in index order."""
        return tuple(stream for stream in self.streams if stream.idx not in (IDX_MEMORY, IDX_METADATA))

    def locate(self, idx: int, offset: int = 0, length: int | None = None) -> EvidenceExtent:
        """Locate a range by stream index and ASDF offset."""
        return self.get(idx).locate(offset, length)

    def resolve(self, identifier: str, *, length: int | None = None) -> EvidenceExtent:
        """Resolve a textual identifier produced by :attr:`EvidenceExtent.identifier`."""
        if not isinstance(identifier, str):
            raise ValueError("identifier must be a string")
        match = _IDENTIFIER_RE.match(identifier)
        if not match:
            raise ValueError(f"invalid ASDF evidence identifier: {identifier!r}")

        try:
            container = uuid.UUID(match.group("guid"))
        except ValueError as e:
            raise ValueError(f"invalid container guid in identifier: {identifier!r}") from e
        if container != self.container:
            raise ValueError(f"identifier belongs to another container: {container}")

        idx = int(match.group("idx"))
        offset = int(match.group("offset"), 16) if match.group("offset") else 0
        parsed_length = int(match.group("length"), 16) if match.group("length") else length
        return self.locate(idx, offset, parsed_length)


def write_identity_manifest(writer: AsdfWriter, streams: Iterable[StreamDeclaration]) -> None:
    """Write an identity manifest into the writer's metadata tar.

    The manifest is an ordinary metadata member, so the ASDF header, block
    header, table entry and footer layouts are unchanged.  Old readers ignore
    the new member; old files without the member remain readable through
    :meth:`EvidenceIndex.from_snapshot`.

    Args:
        writer: The ASDF writer.  Call before :meth:`AsdfWriter.close`.
        streams: Stream declarations.
    """
    declarations = list(streams)
    seen = set()
    for declaration in declarations:
        if declaration.idx in seen:
            raise ValueError(f"duplicate stream idx in identity manifest: {declaration.idx}")
        seen.add(declaration.idx)

    manifest = {
        "format": IDENTITY_FORMAT,
        "version": IDENTITY_VERSION,
        "container_guid": str(writer.guid),
        "streams": [declaration.as_dict() for declaration in declarations],
    }
    data = json.dumps(manifest, indent=2, sort_keys=True).encode()
    writer.add_metadata_file(IDENTITY_MANIFEST, io.BytesIO(data), len(data))


def _read_manifest(snapshot: AsdfSnapshot) -> dict[str, Any] | None:
    try:
        fh = snapshot.metadata.open(IDENTITY_MANIFEST)
    except (KeyError, FileNotFoundError):
        return None

    if fh is None:
        return None

    data = fh.read(MAX_MANIFEST_SIZE + 1)
    if len(data) > MAX_MANIFEST_SIZE:
        raise InvalidEvidence(f"{IDENTITY_MANIFEST} exceeds {MAX_MANIFEST_SIZE} bytes")

    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise InvalidEvidence(f"invalid {IDENTITY_MANIFEST}: {e}") from e

    if not isinstance(manifest, dict):
        raise InvalidEvidence(f"{IDENTITY_MANIFEST} must contain a JSON object")
    return manifest


def _validate_manifest(manifest: dict[str, Any], guid: uuid.UUID, warnings: list[str]) -> dict[int, dict[str, Any]]:
    if manifest.get("format") != IDENTITY_FORMAT:
        raise InvalidEvidence(f"unsupported identity manifest format: {manifest.get('format')!r}")
    version = manifest.get("version")
    if isinstance(version, bool) or version != IDENTITY_VERSION:
        raise InvalidEvidence(f"unsupported identity manifest version: {version!r}")

    declared_guid = manifest.get("container_guid")
    try:
        manifest_guid = uuid.UUID(str(declared_guid))
    except (ValueError, TypeError, AttributeError) as e:
        raise InvalidEvidence(f"invalid container_guid in identity manifest: {declared_guid!r}") from e
    if manifest_guid != guid:
        raise InvalidEvidence(f"identity manifest guid {manifest_guid} does not match container {guid}")

    stream_records = manifest.get("streams")
    if not isinstance(stream_records, list):
        raise InvalidEvidence("identity manifest streams must be a list")

    records: dict[int, dict[str, Any]] = {}
    for position, record in enumerate(stream_records):
        if not isinstance(record, dict):
            warnings.append(f"identity manifest stream #{position} is not an object; ignored")
            continue
        try:
            idx = _as_int(record.get("idx"), f"streams[{position}].idx")
        except InvalidEvidence as e:
            warnings.append(str(e))
            continue
        if idx is None or not 0 <= idx <= 255:
            warnings.append(f"identity manifest stream #{position} has an invalid idx; ignored")
            continue
        if idx == IDX_METADATA:
            warnings.append("identity manifest describes the metadata stream; ignored")
            continue
        if idx in records:
            warnings.append(f"identity manifest contains duplicate idx {idx}; later record ignored")
            continue
        records[idx] = record
    return records


def _parse_record(
    idx: int,
    record: dict[str, Any],
    records: dict[int, dict[str, Any]],
    available: set[int],
    warnings: list[str],
) -> tuple[StreamRole, SourceClaim | None, int | None, int | None, str | None]:
    role = _fallback_role(idx)
    declared_role = record.get("role")
    if idx == IDX_MEMORY:
        role = StreamRole.MEMORY
        if declared_role not in (None, StreamRole.MEMORY.value):
            warnings.append(f"stream 254 is reserved for memory; ignoring declared role {declared_role!r}")
    elif declared_role in (StreamRole.DISK.value, StreamRole.VOLUME.value, StreamRole.STREAM.value):
        role = StreamRole(declared_role)
    elif declared_role == StreamRole.MEMORY.value:
        warnings.append(f"stream {idx} declared as memory but is not stream 254; using stream role")
    elif declared_role is not None:
        warnings.append(f"stream {idx} has invalid role {declared_role!r}; using {role.value}")

    source = None
    source_value = record.get("source")
    if source_value is not None:
        try:
            source = SourceClaim.from_dict(source_value)
        except (TypeError, ValueError) as e:
            warnings.append(f"stream {idx} has invalid source: {e}")

    base = _as_int(record.get("base", 0), f"streams[{idx}].base")
    if base is None or base < 0:
        warnings.append(f"stream {idx} has invalid base; using 0")
        base = 0
    if role in (StreamRole.MEMORY, StreamRole.STREAM, StreamRole.DISK):
        if role == StreamRole.DISK and base:
            warnings.append(f"disk stream {idx} has a non-zero base; only volume streams can be relative")
        # Memory, unclassified and whole-disk streams do not have a declared
        # parent-disk coordinate system, so do not invent one from the offset.
        base = None

    parent_idx = _as_int(record.get("parent_idx"), f"streams[{idx}].parent_idx")
    if parent_idx is not None and role != StreamRole.VOLUME:
        warnings.append(f"stream {idx} is not a volume but declares a parent; parent not asserted")
        parent_idx = None
    if parent_idx is not None:
        if parent_idx == idx:
            warnings.append(f"stream {idx} cannot be its own parent; ignoring parent")
            parent_idx = None
        elif parent_idx >= IDX_MEMORY:
            warnings.append(f"stream {idx} references reserved parent {parent_idx}; parent not asserted")
            parent_idx = None
        elif parent_idx not in available:
            warnings.append(
                f"stream {idx} references parent {parent_idx} absent from the snapshot; parent not asserted"
            )
            parent_idx = None
        elif parent_idx not in records:
            warnings.append(f"stream {idx} references undeclared parent {parent_idx}; parent not asserted")
            parent_idx = None
        elif records[parent_idx].get("role") in (StreamRole.MEMORY.value, StreamRole.VOLUME.value):
            warnings.append(f"stream {idx} references memory stream {parent_idx}; parent not asserted")
            parent_idx = None

    label = record.get("label")
    if label is not None and not isinstance(label, str):
        warnings.append(f"stream {idx} has a non-string label; ignoring label")
        label = None

    return role, source, base, parent_idx, label


def _fallback_role(idx: int) -> StreamRole:
    if idx == IDX_MEMORY:
        return StreamRole.MEMORY
    if idx == IDX_METADATA:
        return StreamRole.METADATA
    return StreamRole.STREAM


def _as_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidEvidence(f"{name} must be an integer")
    return value
