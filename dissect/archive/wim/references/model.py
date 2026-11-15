from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.archive.wim.references.enums import StreamReferenceType

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.archive.wim.wim import Resource

ZERO_HASH = b"\x00" * 20


@dataclass(frozen=True, slots=True)
class ByteRange:
    """A half-open byte range ``[start, end)`` of a resource's uncompressed data."""

    start: int
    end: int

    @property
    def size(self) -> int:
        """Number of bytes covered by the range."""
        return self.end - self.start

    def __iter__(self) -> Iterator[int]:
        yield self.start
        yield self.end


@dataclass(frozen=True, slots=True)
class ResourceVerificationResult:
    """Outcome of verifying a resource's stored hash against its actual bytes.

    WIM resources are content-addressed by a SHA-1 hash. Small resources store the plain
    SHA-1 of their data; large resources store a :class:`~dissect.archive.wim.c_wim.WIMHASH`
    structure containing per-chunk hashes plus a hash over the whole data. The verification
    always records which byte ranges of the uncompressed resource were actually covered, so
    callers can distinguish a fully verified resource from a partial one.
    """

    resource: Resource
    expected_hash: bytes
    computed_hash: bytes
    matches: bool
    covered_ranges: tuple[ByteRange, ...]
    chunk_size: int | None
    has_chunked_hash: bool

    @property
    def fully_covered(self) -> bool:
        """Whether the verification covered every uncompressed byte of the resource."""
        if not self.covered_ranges:
            return self.resource.original_size == 0

        return (
            self.covered_ranges[0].start == 0
            and self.covered_ranges[-1].end == self.resource.original_size
            and all(
                current.start == previous.end
                for previous, current in zip(self.covered_ranges, self.covered_ranges[1:])
            )
        )


@dataclass(frozen=True, slots=True)
class ResourceLocation:
    """Where a resource lives in the on-disk WIM file.

    Resources can be stored compressed, in which case ``size`` is the compressed size and
    ``original_size`` the uncompressed size. ``byte_range`` covers the stored blob starting at
    ``Resource.offset``; for compressed resources this is the compressed region, including the
    chunk lookup table that precedes the compressed chunks.
    """

    offset: int
    size: int
    original_size: int
    compressed: bool
    metadata: bool
    byte_range: ByteRange

    @classmethod
    def from_resource(cls, resource: Resource) -> ResourceLocation:
        """Derive the on-disk location of a resource descriptor."""
        return cls(
            offset=resource.offset,
            size=resource.size,
            original_size=resource.original_size,
            compressed=resource.is_compressed,
            metadata=resource.is_metadata,
            byte_range=ByteRange(resource.offset, resource.offset + resource.size),
        )


@dataclass(frozen=True, slots=True)
class StreamReference:
    """A single stream of a directory entry that points at a resource hash.

    Every stream gets its own record, even when multiple streams or images share a hash. The
    reference type distinguishes default streams, alternate data streams, empty streams and
    references whose resource cannot be located in the resource table.
    """

    image_index: int
    path: str
    stream_name: str
    stream_type: StreamReferenceType
    hash: bytes
    is_directory: bool
    location: ResourceLocation | None
    resource: Resource | None

    @property
    def is_alternate_stream(self) -> bool:
        """Whether this reference points at a named alternate data stream."""
        return self.stream_type is StreamReferenceType.ALTERNATE_STREAM

    @property
    def is_missing(self) -> bool:
        """Whether the referenced resource cannot be located in the resource table."""
        return self.stream_type is StreamReferenceType.MISSING_RESOURCE

    @property
    def full_name(self) -> str:
        """The NTFS-style name of the referenced stream (``file.txt:stream``)."""
        if self.stream_name:
            return f"{self.path}:{self.stream_name}"

        return self.path


@dataclass(slots=True)
class ResourceDescriptor:
    """All evidence attached to a single resource hash.

    The same hash may be shared by many streams across images and may even occur more than
    once in the resource table itself. Neither kind of sharing is collapsed: ``resources``
    keeps every on-disk descriptor and ``references`` keeps every referencing stream.
    """

    hash: bytes
    resources: list[Resource] = field(default_factory=list)
    references: list[StreamReference] = field(default_factory=list)
    _verification: ResourceVerificationResult | None = None

    @property
    def is_metadata_resource(self) -> bool:
        """Whether any descriptor for this hash backs image metadata rather than file content."""
        return any(resource.is_metadata for resource in self.resources)

    @property
    def has_conflicting_descriptors(self) -> bool:
        """Whether the resource table holds more than one descriptor for this hash."""
        return len(self.resources) > 1

    @property
    def locations(self) -> tuple[ResourceLocation, ...]:
        """On-disk locations of every descriptor, in resource table order."""
        return tuple(ResourceLocation.from_resource(resource) for resource in self.resources)

    def verify(self) -> ResourceVerificationResult:
        """Verify the stored hash against the resource bytes, reusing a cached result."""
        if self._verification is None:
            from dissect.archive.wim.references.verification import verify_resource

            self._verification = verify_resource(self)

        return self._verification
