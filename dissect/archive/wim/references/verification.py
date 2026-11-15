from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from dissect.archive.wim.c_wim import c_wim

from dissect.archive.wim.references.enums import StreamReferenceType
from dissect.archive.wim.references.model import ByteRange, ResourceDescriptor, ResourceVerificationResult, ZERO_HASH

if TYPE_CHECKING:
    from dissect.archive.wim.wim import Resource

WIMHASH_PLAIN_THRESHOLD = 1024 * 1024
DEFAULT_CHUNK_SIZE = 32 * 1024
WIMHASH_HEADER_SIZE = 12


def verify_resource(descriptor: ResourceDescriptor) -> ResourceVerificationResult:
    """Verify a resource descriptor's stored hash against its actual bytes.

    A WIM resource hash is one of two things:

    * the plain SHA-1 of the uncompressed data for resources up to one megabyte;
    * a serialized :class:`~dissect.archive.wim.c_wim.WIMHASH` structure for larger
      resources, holding one SHA-1 per chunk followed by a SHA-1 over the whole data.

    The returned result always records the uncompressed byte ranges that were actually
    hashed, so forensic output can state precisely what a positive match covers. The first
    descriptor in the table is verified; when descriptors share a hash they describe the same
    content-addressed data, so the result is reused.
    """
    resource = descriptor.resources[0]
    expected_hash = descriptor.hash
    original_size = resource.original_size
    chunk_size = resource.wim.header.CompressionSize or DEFAULT_CHUNK_SIZE

    with resource.open() as fh:
        data = fh.read()

    if len(data) != original_size:
        return ResourceVerificationResult(
            resource=resource,
            expected_hash=expected_hash,
            computed_hash=b"",
            matches=False,
            covered_ranges=(ByteRange(0, len(data)),),
            chunk_size=None,
            has_chunked_hash=False,
        )

    if original_size <= WIMHASH_PLAIN_THRESHOLD or len(expected_hash) == c_wim.HASH_SIZE:
        computed_hash = hashlib.sha1(data).digest()
        return ResourceVerificationResult(
            resource=resource,
            expected_hash=expected_hash,
            computed_hash=computed_hash,
            matches=computed_hash == expected_hash,
            covered_ranges=(ByteRange(0, original_size),) if original_size else (),
            chunk_size=None,
            has_chunked_hash=False,
        )

    return _verify_chunked(resource, data, expected_hash, chunk_size)


def _verify_chunked(
    resource: Resource, data: bytes, expected_hash: bytes, chunk_size: int
) -> ResourceVerificationResult:
    try:
        wimhash = c_wim.WIMHASH(expected_hash)
    except (EOFError, ValueError):
        return ResourceVerificationResult(
            resource=resource,
            expected_hash=expected_hash,
            computed_hash=b"",
            matches=False,
            covered_ranges=(ByteRange(0, len(data)),),
            chunk_size=None,
            has_chunked_hash=False,
        )

    # The zero-length flex array does not read itself; take the hash list from the raw blob.
    element_count = wimhash.NumElements
    hash_list = expected_hash[WIMHASH_HEADER_SIZE:]
    if (
        wimhash.Size != len(expected_hash)
        or wimhash.ChunkSize != chunk_size
        or len(hash_list) != element_count * c_wim.HASH_SIZE
    ):
        return ResourceVerificationResult(
            resource=resource,
            expected_hash=expected_hash,
            computed_hash=b"",
            matches=False,
            covered_ranges=(ByteRange(0, len(data)),),
            chunk_size=chunk_size,
            has_chunked_hash=True,
        )

    covered_ranges = []
    matches = True
    computed_chunks = []
    for index in range(element_count - 1):
        start = index * chunk_size
        end = min(start + chunk_size, len(data))
        chunk_hash = hashlib.sha1(data[start:end]).digest()
        computed_chunks.append(chunk_hash)

        stored_hash = hash_list[index * c_wim.HASH_SIZE : (index + 1) * c_wim.HASH_SIZE]
        matches &= chunk_hash == stored_hash
        covered_ranges.append(ByteRange(start, end))

    overall_hash = hashlib.sha1(data).digest()
    stored_overall = hash_list[(element_count - 1) * c_wim.HASH_SIZE : element_count * c_wim.HASH_SIZE]
    matches &= overall_hash == stored_overall

    computed_hash = expected_hash[:WIMHASH_HEADER_SIZE] + b"".join(computed_chunks) + overall_hash
    return ResourceVerificationResult(
        resource=resource,
        expected_hash=expected_hash,
        computed_hash=computed_hash,
        matches=matches,
        covered_ranges=tuple(covered_ranges),
        chunk_size=chunk_size,
        has_chunked_hash=True,
    )


def classify_stream(stream_name: str, stream_hash: bytes, resource: Resource | None) -> StreamReferenceType:
    """Classify how a stream hash relates to the WIM resource table."""
    if stream_hash == ZERO_HASH or stream_hash.strip(b"\x00") == b"":
        return StreamReferenceType.EMPTY_STREAM

    if resource is None:
        return StreamReferenceType.MISSING_RESOURCE

    if stream_name:
        return StreamReferenceType.ALTERNATE_STREAM

    return StreamReferenceType.DEFAULT_STREAM
