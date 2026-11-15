from __future__ import annotations

import hashlib
import io

import pytest

from dissect.archive.exception import (
    AmbiguousResourceError,
    FileNotFoundError,
    NotFileContentError,
)
from dissect.archive.wim.wim import (
    EMPTY_HASH,
    WIM,
    ReferenceStatus,
    StreamKind,
    VerificationStatus,
)
from tests._tools.wim._synth import (
    ImageSpec,
    Node,
    ResourceSpec,
    build_wim_images,
    load,
)

SHARED = b"the same payload in two images"
OTHER = b"an unrelated alternate-stream host"
GHOST_HASH = bytes.fromhex("11" * 20)


def _root(children: list[Node]) -> Node:
    return Node("", children=children)


def _sample() -> bytes:
    image_one = _root(
        [
            Node("shared_default.txt", streams={"": SHARED}),
            Node("shared_ads.txt", streams={"": OTHER, "alpha": SHARED}),
            Node("empty_by_zero.txt"),
            Node("empty_by_hash.txt", streams={"": b""}),
            Node("missing.txt", streams={"": b"not backed by a row"}, stream_hashes={"": GHOST_HASH}),
            Node("metadata_copy.txt", streams={"": b"placeholder"}),
        ]
    )
    image_two = _root(
        [
            Node("other_name.bin", streams={"": SHARED}),
            Node("ads_host.bin", streams={"": OTHER, "beta": SHARED}),
        ]
    )

    # Build once to learn the second image's metadata hash, then reference it from the first image's
    # file. Rebuilding only changes the first image's metadata stream, so the target stays stable.
    base = build_wim_images([ImageSpec(image_one), ImageSpec(image_two)])
    base_wim = load(base)
    metadata_hash = next(
        resource.hash for image, resource in zip(base_wim.images(), base_wim._images, strict=True) if image.index == 1
    )
    image_one.children[5].stream_hashes = {"": metadata_hash}

    return build_wim_images([ImageSpec(image_one), ImageSpec(image_two)])


@pytest.fixture
def sample() -> WIM:
    return load(_sample())


def test_shared_hash_lists_every_image_file_and_ads(sample: WIM) -> None:
    shared_hash = hashlib.sha1(SHARED).digest()
    references = sample.resource_references(shared_hash)

    assert references.is_shared
    assert references.paths == ["shared_default.txt", "shared_ads.txt", "other_name.bin", "ads_host.bin"]
    assert references.display_paths == [
        "shared_default.txt",
        "shared_ads.txt:alpha",
        "other_name.bin",
        "ads_host.bin:beta",
    ]

    # No merged evidence record: four distinct file identities, two per image.
    assert {reference.image_index for reference in references.references} == {0, 1}
    identities = {
        (reference.image_index, reference.entry_offset, reference.stream_name) for reference in references.references
    }
    assert len(identities) == 4
    assert [reference.stream_kind for reference in references.references] == [
        StreamKind.DEFAULT,
        StreamKind.ADS,
        StreamKind.DEFAULT,
        StreamKind.ADS,
    ]

    # Every reference resolves to the same single content descriptor and the declared content.
    assert len(references.descriptors) == 1
    descriptor = references.descriptors[0]
    assert descriptor.is_metadata is False
    for reference in references.references:
        assert reference.status is ReferenceStatus.RESOLVED
        assert reference.resources == (descriptor,)
        assert reference.resource_indices == (descriptor.index,)
        with reference.entry.open(reference.stream_name) as fh:
            assert fh.read() == SHARED

    # The descriptor knows its own physical location and every path that depends on it.
    assert descriptor.location == (descriptor.offset, descriptor.offset + descriptor.size)
    assert descriptor.references.paths == references.paths


def test_reference_identity_survives_image_iteration(sample: WIM) -> None:
    images = list(sample.images())
    again = list(sample.images())
    assert images[0] is again[0]
    assert images[1] is again[1]

    shared_hash = hashlib.sha1(SHARED).digest()
    shared_ads = sample.resource_references(shared_hash).references[1]
    resolved = images[0].get("shared_ads.txt")
    assert shared_ads.entry_offset == resolved.offset
    assert shared_ads.entry.streams == resolved.streams
    assert sample.resource_references_for(resolved, "alpha") == [shared_ads]
    assert shared_ads.entry.open("alpha").read() == SHARED


def test_per_image_reverse_lookup_keeps_names_apart(sample: WIM) -> None:
    images = list(sample.images())
    shared_hash = hashlib.sha1(SHARED).digest()

    first = images[0].resource_references(shared_hash)
    second = images[1].resource_references(shared_hash)

    assert first.display_paths == ["shared_default.txt", "shared_ads.txt:alpha"]
    assert second.display_paths == ["other_name.bin", "ads_host.bin:beta"]
    assert first.descriptors == second.descriptors


def test_empty_streams_and_missing_resources_stay_distinct(sample: WIM) -> None:
    empty_zero = sample.resource_references(b"\x00" * 20)
    empty_hash = sample.resource_references(EMPTY_HASH)

    assert empty_zero.display_paths == ["empty_by_zero.txt"]
    assert empty_hash.display_paths == ["empty_by_hash.txt"]
    assert [reference.status for reference in empty_zero.references] == [ReferenceStatus.EMPTY]
    assert [reference.status for reference in empty_hash.references] == [ReferenceStatus.EMPTY]
    assert empty_zero.descriptors == []
    assert empty_hash.descriptors == []

    for reference in [*empty_zero.references, *empty_hash.references]:
        assert reference.entry.open(reference.stream_name).read() == b""
        result = reference.verify()
        assert result.status is VerificationStatus.EMPTY
        assert result.resource is None
        assert result.coverages == ()

    missing = sample.resource_references(GHOST_HASH)
    assert missing.display_paths == ["missing.txt"]
    assert missing.references[0].status is ReferenceStatus.MISSING
    assert missing.descriptors == []
    assert missing.unresolved == missing.references
    assert missing.verify() == []
    assert missing.references[0].verify().status is VerificationStatus.MISSING
    with pytest.raises(FileNotFoundError):
        missing.references[0].entry.open("")


def test_directory_metadata_is_not_file_content(sample: WIM) -> None:
    metadata = [resource for resource in sample.resource_entries if resource.is_metadata]
    assert metadata

    # The first image's file points its default stream at the second image's metadata hash.
    target = metadata[1]
    references = sample.resource_references(target.hash)

    assert references.display_paths == ["metadata_copy.txt"]
    assert references.references[0].status is ReferenceStatus.METADATA
    assert references.metadata_descriptors == [target]
    assert references.content_descriptors == []
    assert references.descriptors[0].is_metadata
    assert references.unresolved == references.references

    # Directory metadata must never be returned or opened as ordinary file bytes.
    assert sample.resource_for(target.hash, content=True) is None
    with pytest.raises(NotFileContentError):
        references.references[0].entry.open("")
    assert [result.status for result in references.verify()] == [VerificationStatus.METADATA]
    assert references.verify()[0].coverages == ()

    # The directory entries themselves are not reversed as content references.
    assert all(not reference.entry.is_dir() for reference in references.references)


def test_verification_reuses_one_read_for_shared_content(sample: WIM) -> None:
    class CountingIO(io.BytesIO):
        def __init__(self, data: bytes):
            super().__init__(data)
            self.reads = 0

        def read(self, *args: object) -> bytes:
            self.reads += 1
            return super().read(*args)

    counting = CountingIO(_sample())
    wim = WIM(counting)
    references = wim.resource_references(hashlib.sha1(SHARED).digest())

    first = references.verify_one()
    reads_after_first = counting.reads
    second = references.verify_one()

    assert first is second
    assert counting.reads == reads_after_first
    assert first.status is VerificationStatus.VERIFIED
    assert first.declared_hash == hashlib.sha1(SHARED).digest()
    assert first.computed_hash == hashlib.sha1(SHARED).digest()

    # The conclusion states the byte scope it actually covered.
    assert first.logical_range == (0, len(SHARED))
    assert first.physical_range == references.descriptors[0].location
    assert first.covers_full_resource
    assert first.coverages[0].logical_length == len(SHARED)
    assert first.coverages[0].physical_length == len(SHARED)

    # Other references to the same descriptor share the cached conclusion.
    for reference in references.references:
        assert reference.verify() is first


def test_duplicate_descriptors_are_kept_and_verified_separately() -> None:
    shared_hash = hashlib.sha1(SHARED).digest()
    root = _root([Node("shared.txt", streams={"": SHARED})])
    data = build_wim_images(
        [ImageSpec(root)],
        extra_resources=[ResourceSpec(hash=shared_hash, content=SHARED, reference_count=2)],
    )
    wim = load(data)

    references = wim.resource_references(shared_hash)
    assert references.has_conflict
    assert len(references.descriptors) == 2
    assert references.descriptors[0].index != references.descriptors[1].index
    assert references.descriptors[0].offset != references.descriptors[1].offset
    assert references.conflicts == references.descriptors

    # Picking one silently is refused, both for the table and for the file entry.
    with pytest.raises(AmbiguousResourceError):
        wim.resource_for(shared_hash)
    with pytest.raises(AmbiguousResourceError):
        references.references[0].entry.open("")

    verifications = references.verify()
    assert len(verifications) == 2
    assert {id(result) for result in verifications} == {id(result) for result in references.verify()}
    assert all(result.status is VerificationStatus.VERIFIED for result in verifications)
    assert all(result.covers_full_resource for result in verifications)
    assert {result.physical_range for result in verifications} == {
        descriptor.location for descriptor in references.descriptors
    }


def test_mismatch_is_reported_for_the_covering_descriptor() -> None:
    declared = hashlib.sha1(b"declared payload").digest()
    root = _root([Node("lying.txt", streams={"": b"declared payload"})])
    data = build_wim_images(
        [ImageSpec(root)],
        extra_resources=[ResourceSpec(hash=declared, content=b"actual payload")],
    )
    wim = load(data)

    # Two rows claim the same hash: one matches the bytes and one does not. Both conclusions are kept.
    verifications = wim.resource_references(declared).verify()
    assert len(verifications) == 2
    assert {result.status for result in verifications} == {VerificationStatus.VERIFIED, VerificationStatus.MISMATCH}

    mismatch = next(result for result in verifications if result.status is VerificationStatus.MISMATCH)
    assert mismatch.declared_hash == declared
    assert mismatch.computed_hash == hashlib.sha1(b"actual payload").digest()
    assert mismatch.logical_range == (0, len(b"actual payload"))
    assert mismatch.covers_full_resource
    assert mismatch.physical_range == (mismatch.resource.offset, mismatch.resource.offset + len(b"actual payload"))


def test_truncated_descriptor_reports_the_covered_range() -> None:
    content = b"a complete resource before the file is cut"
    root = _root([Node("cut.txt", streams={"": content})])
    data = build_wim_images([ImageSpec(root)])
    wim = load(data)

    descriptor = wim.resource_descriptors(hashlib.sha1(content).digest())[0]
    descriptor.offset = len(data)
    result = descriptor.verify(as_content=True)

    assert result.status is VerificationStatus.TRUNCATED
    assert result.covers_full_resource is False
    assert result.physical_range == (len(data), len(data))
    assert result.logical_range == (0, 0)
    assert result.coverages[0].physical_length == 0
    assert result.coverages[0].logical_length == 0


def test_missing_resource_can_be_dropped_from_table() -> None:
    payload = b"content whose row was removed"
    root = _root([Node("orphan.txt", streams={"": payload})])
    wim = load(build_wim_images([ImageSpec(root)], drop_resources=[hashlib.sha1(payload).digest()]))

    references = wim.resource_references(hashlib.sha1(payload).digest())
    assert references.display_paths == ["orphan.txt"]
    assert references.references[0].status is ReferenceStatus.MISSING
    assert references.missing == references.references
    assert references.verify() == []

    # The directory entry itself survives; only its backing resource is gone.
    assert references.references[0].entry.name == "orphan.txt"
    assert references.references[0].entry.streams[""] == hashlib.sha1(payload).digest()


def test_metadata_verification_is_explicitly_not_content(sample: WIM) -> None:
    target = next(resource for resource in sample.resource_entries if resource.is_metadata)
    assert target.is_metadata

    result = target.verify(as_content=True)
    assert result.status is VerificationStatus.METADATA
    assert result.computed_hash is None
    assert result.coverages == ()
    assert result.covers_full_resource is False

    # The same descriptor can still be verified as metadata bytes, which is a separate conclusion.
    as_metadata = target.verify(as_content=False)
    assert as_metadata.status is VerificationStatus.VERIFIED
    assert as_metadata.covers_full_resource
    assert as_metadata is not result
