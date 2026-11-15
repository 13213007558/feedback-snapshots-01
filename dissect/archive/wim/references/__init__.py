from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.archive.wim.references.enums import StreamReferenceType
from dissect.archive.wim.references.model import (
    ByteRange,
    ResourceDescriptor,
    ResourceLocation,
    ResourceVerificationResult,
    StreamReference,
)
from dissect.archive.wim.references.verification import classify_stream, verify_resource

if TYPE_CHECKING:
    from dissect.archive.wim.wim import DirectoryEntry, WIM

__all__ = [
    "ByteRange",
    "ResourceDescriptor",
    "ResourceLocation",
    "ResourceVerificationResult",
    "StreamReference",
    "StreamReferenceType",
    "build_resource_references",
    "classify_stream",
    "verify_resource",
]


def build_resource_references(wim: WIM) -> dict[bytes, ResourceDescriptor]:
    """Build a reverse map from resource hash to every descriptor and reference.

    Each stream of every directory entry in every image produces one
    :class:`StreamReference`, so files that share content keep separate evidence records.
    Resource table entries are grouped by hash without collapsing duplicates: when the table
    holds multiple descriptors for one hash the conflict is retained on
    :attr:`ResourceDescriptor.has_conflicting_descriptors`. Image metadata resources are
    included as descriptors but are never reported as file content, and streams whose hash is
    absent from the table are kept as missing-resource references.
    """
    descriptors: dict[bytes, ResourceDescriptor] = {}

    for resource in wim.resource_table:
        descriptor = descriptors.setdefault(resource.hash, ResourceDescriptor(resource.hash))
        descriptor.resources.append(resource)

    for image_index, image in enumerate(wim.images(), start=1):
        _walk_directory(image_index, image.root, "", descriptors)

    return descriptors


def _walk_directory(
    image_index: int,
    entry: DirectoryEntry,
    path: str,
    descriptors: dict[bytes, ResourceDescriptor],
) -> None:
    if path:
        for stream_name, stream_hash in entry.streams.items():
            _record_stream(image_index, path, stream_name, stream_hash, entry, descriptors)

    if not entry.is_dir():
        return

    for child in entry.iterdir():
        child_path = f"{path}\\{child.name}" if path else child.name
        _walk_directory(image_index, child, child_path, descriptors)


def _record_stream(
    image_index: int,
    path: str,
    stream_name: str,
    stream_hash: bytes,
    entry: DirectoryEntry,
    descriptors: dict[bytes, ResourceDescriptor],
) -> None:
    resource = entry.image.wim.resources.get(stream_hash)
    stream_type = classify_stream(stream_name, stream_hash, resource)
    location = ResourceLocation.from_resource(resource) if resource is not None else None

    reference = StreamReference(
        image_index=image_index,
        path=path,
        stream_name=stream_name,
        stream_type=stream_type,
        hash=stream_hash,
        is_directory=entry.is_dir(),
        location=location,
        resource=resource,
    )

    descriptor = descriptors.setdefault(stream_hash, ResourceDescriptor(stream_hash))
    descriptor.references.append(reference)
