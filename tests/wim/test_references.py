from __future__ import annotations

import gzip
import hashlib
import io

import pytest

from dissect.archive.wim.references import (
    ByteRange,
    StreamReferenceType,
    build_resource_references,
)
from dissect.archive.wim.references.model import ResourceDescriptor
from dissect.archive.wim.references.verification import (
    WIMHASH_PLAIN_THRESHOLD,
    verify_resource,
)
from dissect.archive.wim.wim import WIM
from tests._tools.wim import (
    DEFAULT_CHUNK_SIZE,
    build_wim,
    directory_entry,
    file_entry,
    make_wimhash,
    missing_stream_entry,
)
from tests._util import absolute_path

SHARED_CONTENT = b"the same bytes are referenced by both images" * 4
UNIQUE_ONE = b"content that only exists in the first image"
UNIQUE_TWO = b"second image alternate data stream payload"
NESTED_CONTENT = b"a file living in a nested directory"
ADS_CONTENT = b"zone identifier marker data"
SHARED_HASH = hashlib.sha1(SHARED_CONTENT).digest()


def _build_shared_content_wim() -> bytes:
    """Two images sharing one blob but using different file names and ADS layouts."""
    image_one = directory_entry(
        None,
        [
            file_entry("alpha.txt", SHARED_CONTENT),
            file_entry("unique-one.txt", UNIQUE_ONE),
            directory_entry("docs", [file_entry("nested.txt", NESTED_CONTENT)]),
        ],
    )
    image_two = directory_entry(
        None,
        [
            file_entry("beta.txt", SHARED_CONTENT, alternate_streams={"Zone.Identifier": ADS_CONTENT}),
            file_entry("unique-two.txt", UNIQUE_TWO),
            missing_stream_entry("orphan.txt", "ghost-stream"),
        ],
    )
    return build_wim([image_one, image_two], duplicate_hashes={SHARED_HASH})


@pytest.fixture
def shared_wim() -> WIM:
    return WIM(io.BytesIO(_build_shared_content_wim()))


def test_shared_content_keeps_distinct_file_identities(shared_wim: WIM) -> None:
    descriptor = shared_wim.reverse_references[SHARED_HASH]

    references = descriptor.references
    assert len(references) == 2
    assert {(ref.image_index, ref.path, ref.stream_name) for ref in references} == {
        (1, "alpha.txt", ""),
        (2, "beta.txt", ""),
    }
    assert all(ref.stream_type is StreamReferenceType.DEFAULT_STREAM for ref in references)
    assert all(not ref.is_directory for ref in references)
    # Both references resolve independently even though they share one hash.
    assert {ref.resource for ref in references} == {descriptor.resources[0]}


def test_shared_content_lists_every_reference_path_and_location(shared_wim: WIM) -> None:
    descriptor = shared_wim.reverse_references[SHARED_HASH]

    # Duplicate descriptors for one hash are retained instead of merged away.
    assert descriptor.has_conflicting_descriptors
    assert len(descriptor.resources) == 2
    locations = descriptor.locations
    assert len(locations) == 2
    assert {location.offset for location in locations} == {resource.offset for resource in descriptor.resources}
    assert all(location.size == len(SHARED_CONTENT) for location in locations)
    assert all(not location.metadata for location in locations)
    assert all(not location.compressed for location in locations)

    full_names = {ref.full_name for ref in descriptor.references}
    assert full_names == {"alpha.txt", "beta.txt"}


def test_reverse_references_distinguishes_default_ads_empty_and_missing(shared_wim: WIM) -> None:
    references = {(ref.image_index, ref.full_name): ref for ref in shared_wim.stream_references()}

    default_ref = references[(1, "alpha.txt")]
    assert default_ref.stream_type is StreamReferenceType.DEFAULT_STREAM
    assert default_ref.location is not None
    assert default_ref.resource is not None

    ads_ref = references[(2, "beta.txt:Zone.Identifier")]
    assert ads_ref.stream_type is StreamReferenceType.ALTERNATE_STREAM
    assert ads_ref.is_alternate_stream
    assert ads_ref.location is not None
    assert ads_ref.hash == hashlib.sha1(ADS_CONTENT).digest()

    empty_refs = [ref for ref in references.values() if ref.stream_type is StreamReferenceType.EMPTY_STREAM]
    assert {(ref.image_index, ref.full_name) for ref in empty_refs} == {
        (1, "docs"),
        (2, "orphan.txt"),
    }
    assert all(ref.location is None and ref.resource is None for ref in empty_refs)

    missing_ref = references[(2, "orphan.txt:ghost-stream")]
    assert missing_ref.stream_type is StreamReferenceType.MISSING_RESOURCE
    assert missing_ref.is_missing
    assert missing_ref.location is None
    assert missing_ref.resource is None

    missing = shared_wim.reverse_references[missing_ref.hash]
    assert missing.resources == []
    assert missing.references == [missing_ref]


def test_directory_metadata_resources_are_not_file_content(shared_wim: WIM) -> None:
    metadata_descriptors = [d for d in shared_wim.reverse_references.values() if d.is_metadata_resource]
    assert len(metadata_descriptors) == 2

    for descriptor in metadata_descriptors:
        assert descriptor.references == []
        assert all(location.metadata for location in descriptor.locations)

    # The metadata resources are still present in the raw resource table.
    metadata_table_entries = [r for r in shared_wim.resource_table if r.is_metadata]
    assert len(metadata_table_entries) == 2


def test_each_file_identity_is_preserved_across_images(shared_wim: WIM) -> None:
    all_refs = list(shared_wim.stream_references())

    image_one = [ref for ref in all_refs if ref.image_index == 1]
    image_two = [ref for ref in all_refs if ref.image_index == 2]
    assert {ref.full_name for ref in image_one} == {"alpha.txt", "unique-one.txt", "docs", "docs\\nested.txt"}
    assert {ref.full_name for ref in image_two} == {
        "beta.txt",
        "beta.txt:Zone.Identifier",
        "unique-two.txt",
        "orphan.txt",
        "orphan.txt:ghost-stream",
    }

    # The unique files keep their own descriptors even though they live in one archive.
    unique_one_hash = hashlib.sha1(UNIQUE_ONE).digest()
    unique_two_hash = hashlib.sha1(UNIQUE_TWO).digest()
    assert unique_one_hash != unique_two_hash
    assert shared_wim.reverse_references[unique_one_hash].references[0].path == "unique-one.txt"
    assert shared_wim.reverse_references[unique_two_hash].references[0].path == "unique-two.txt"


def test_shared_hash_verification_is_computed_once_and_reused(shared_wim: WIM) -> None:
    descriptor = shared_wim.reverse_references[SHARED_HASH]

    result = descriptor.verify()
    assert result.matches
    assert result.fully_covered
    assert result.covered_ranges == (ByteRange(0, len(SHARED_CONTENT)),)
    assert not result.has_chunked_hash

    # Repeated verification hands back the cached result instead of rehashing.
    assert descriptor.verify() is result

    # Both file references rely on the same conclusion but remain separate evidence records.
    resource_result = descriptor.resources[0].verify_digest()
    assert resource_result is result
    assert len(descriptor.references) == 2


def test_plain_resource_digest_reports_covered_range(shared_wim: WIM) -> None:
    nested_hash = hashlib.sha1(NESTED_CONTENT).digest()
    descriptor = shared_wim.reverse_references[nested_hash]
    result = descriptor.verify()

    assert result.matches
    assert result.computed_hash == nested_hash
    assert result.covered_ranges == (ByteRange(0, len(NESTED_CONTENT)),)
    assert result.fully_covered
    assert result.expected_hash == nested_hash


def test_resource_table_index_keeps_first_descriptor_for_lookups(shared_wim: WIM) -> None:
    # The legacy mapping still resolves stream opens to one descriptor...
    assert shared_wim.resources[SHARED_HASH] is shared_wim.resource_table[0]

    # ...while the full table preserves both conflicting descriptors.
    matching = [r for r in shared_wim.resource_table if r.hash == SHARED_HASH]
    assert len(matching) == 2


def test_build_resource_references_matches_cached_property(shared_wim: WIM) -> None:
    rebuilt = build_resource_references(shared_wim)
    assert set(rebuilt) == set(shared_wim.reverse_references)
    for hash_value, descriptor in shared_wim.reverse_references.items():
        assert len(rebuilt[hash_value].references) == len(descriptor.references)
        assert len(rebuilt[hash_value].resources) == len(descriptor.resources)


def test_stream_reference_full_name_and_type_helpers() -> None:
    wim = WIM(
        io.BytesIO(
            build_wim(
                [directory_entry(None, [file_entry("f.txt", b"data", alternate_streams={"ads": b"x"})])]
            )
        )
    )
    references = {ref.full_name: ref for ref in wim.stream_references()}
    assert references["f.txt"].full_name == "f.txt"
    assert references["f.txt:ads"].full_name == "f.txt:ads"
    assert references["f.txt:ads"].stream_type.has_resource
    assert references["f.txt"].stream_type.has_resource


class _FakeHeader:
    CompressionSize = DEFAULT_CHUNK_SIZE


class _FakeWim:
    header = _FakeHeader()


class _FakeResource:
    def __init__(self, data: bytes):
        self._data = data
        self.original_size = len(data)
        self.wim = _FakeWim()

    def open(self):
        return io.BytesIO(self._data)


def test_chunked_wimhash_verification_records_every_byte_range() -> None:
    data = bytes((index * 7 + 3) % 256 for index in range(DEFAULT_CHUNK_SIZE * 33 + 5000))
    assert len(data) > WIMHASH_PLAIN_THRESHOLD

    wimhash = make_wimhash(data, DEFAULT_CHUNK_SIZE)
    descriptor = ResourceDescriptor(hash=wimhash, resources=[_FakeResource(data)], references=[])
    result = verify_resource(descriptor)

    assert result.matches
    assert result.has_chunked_hash
    assert result.chunk_size == DEFAULT_CHUNK_SIZE
    assert result.fully_covered
    assert len(result.covered_ranges) == 34
    assert result.covered_ranges[0] == ByteRange(0, DEFAULT_CHUNK_SIZE)
    assert result.covered_ranges[-1].end == len(data)
    # Ranges are contiguous and ordered.
    for previous, current in zip(result.covered_ranges, result.covered_ranges[1:]):
        assert previous.end == current.start


def test_chunked_wimhash_detects_tampered_chunk_and_overall_hash() -> None:
    data = bytes((index * 13 + 1) % 256 for index in range(DEFAULT_CHUNK_SIZE * 33 + 5000))
    wimhash = bytearray(make_wimhash(data, DEFAULT_CHUNK_SIZE))

    tampered_chunk = bytearray(wimhash)
    tampered_chunk[12] ^= 0xFF
    chunk_result = verify_resource(
        ResourceDescriptor(hash=bytes(tampered_chunk), resources=[_FakeResource(data)], references=[])
    )
    assert not chunk_result.matches
    assert chunk_result.has_chunked_hash
    assert chunk_result.fully_covered

    tampered_overall = bytearray(wimhash)
    tampered_overall[-1] ^= 0xFF
    overall_result = verify_resource(
        ResourceDescriptor(hash=bytes(tampered_overall), resources=[_FakeResource(data)], references=[])
    )
    assert not overall_result.matches
    assert overall_result.fully_covered


def test_synthetic_wim_round_trips_through_parser(shared_wim: WIM) -> None:
    images = list(shared_wim.images())
    assert len(images) == 2

    assert images[0].get("alpha.txt").open().read() == SHARED_CONTENT
    assert images[0].get("docs/nested.txt").open().read() == NESTED_CONTENT
    assert images[1].get("beta.txt").open().read() == SHARED_CONTENT
    assert images[1].get("beta.txt").open("Zone.Identifier").read() == ADS_CONTENT


def test_reverse_references_work_on_real_compressed_wim() -> None:
    with gzip.open(absolute_path("_data/wim/basic4k.wim.gz")) as fh:
        wim = WIM(fh)
        references = {(ref.path, ref.stream_name): ref for ref in wim.stream_references()}

        default_ref = references[("file.txt", "")]
        assert default_ref.stream_type is StreamReferenceType.DEFAULT_STREAM
        assert default_ref.location is not None
        assert default_ref.location.byte_range.start == default_ref.resource.offset

        ads_ref = references[("ads.txt", "spookystream")]
        assert ads_ref.stream_type is StreamReferenceType.ALTERNATE_STREAM

        directory_ref = references[("dir", "")]
        assert directory_ref.stream_type is StreamReferenceType.EMPTY_STREAM
        assert directory_ref.is_directory

        # Metadata resources back images but never appear as file content references.
        metadata_descriptors = [d for d in wim.reverse_references.values() if d.is_metadata_resource]
        assert metadata_descriptors
        assert all(descriptor.references == [] for descriptor in metadata_descriptors)
        assert all(location.metadata for descriptor in metadata_descriptors for location in descriptor.locations)

        result = wim.reverse_references[default_ref.hash].verify()

    assert result.matches
    assert result.fully_covered
    assert result.covered_ranges == (ByteRange(0, default_ref.resource.original_size),)
