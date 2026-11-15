from __future__ import annotations

import gzip
import hashlib
import io
import struct

import pytest

from dissect.archive.exception import (
    EmptySecurityDescriptorError,
    InvalidDirectoryEntryError,
    InvalidSecurityDataError,
    SecurityIdOutOfRangeError,
)
from dissect.archive.wim.wim import SECURITY_ID_NONE, WIM, DirectoryEntry, Image, SecurityEntry
from tests._tools.wim._synth import (
    FileSpec,
    descriptor,
    metadata_stream,
    security_block,
    wim_file,
)
from tests._util import absolute_path


def _image(data: bytes, index: int = 0) -> Image:
    return list(WIM(io.BytesIO(data)).images())[index]


def _entries(image: Image) -> dict[str, DirectoryEntry]:
    return image.root.listdir()


def _bytes_of_descriptor(data: bytes, block_offset: int, entry: SecurityEntry) -> bytes:
    absolute = block_offset + entry.offset
    return data[absolute : absolute + entry.length]


def test_security_table_preserves_empty_slots() -> None:
    first = descriptor("first")
    last = descriptor("last")
    block = security_block([first, None, last])

    image = _image(wim_file([metadata_stream(block, [])]))

    assert image.security.header.NumEntries == 3
    assert image.security.header.TotalLength == len(block)
    assert image.security.entry_lengths == (len(first), 0, len(last))
    assert [entry.is_empty for entry in image.security.entries] == [False, True, False]
    assert image.security.descriptors == [first, None, last]

    # Index 0 is a real slot, not a "no descriptor" marker, and the empty slot
    # must not shift the third descriptor down to index 1.
    assert image.security[0].data == first
    assert image.security[1].data is None
    assert image.security[2].data == last
    assert image.security.resolve(2).data == last


def test_security_ids_are_resolved_from_original_bytes() -> None:
    first = descriptor("first")
    middle = descriptor("middle", size=52)
    last = descriptor("last", size=68)
    block = security_block([first, middle, None, last])

    files = [
        FileSpec("first.bin", 0),
        FileSpec("middle.bin", 1),
        FileSpec("last.bin", 3),
        FileSpec("none.bin", SECURITY_ID_NONE),
    ]
    data = wim_file([metadata_stream(block, files)])
    image = _image(data)
    entries = _entries(image)

    for spec in files:
        entry = entries[spec.name]
        assert entry.security_id == spec.security_id

    assert entries["first.bin"].security_descriptor == first
    assert entries["middle.bin"].security_descriptor == middle
    assert entries["last.bin"].security_descriptor == last
    assert entries["none.bin"].security_descriptor is None

    # Compare against the raw WIM bytes, not just against the table copy.
    assert image.resource is not None
    for name, expected in (("first.bin", first), ("middle.bin", middle), ("last.bin", last)):
        entry = entries[name]
        raw = _bytes_of_descriptor(data, image.resource.offset, entry.security_entry)
        assert raw == expected
        assert entry.security_descriptor == raw


def test_two_images_do_not_share_security_tables() -> None:
    first_image_block = security_block([descriptor("one-a"), None, descriptor("one-b")])
    second_image_block = security_block([descriptor("two-a"), descriptor("two-b")])

    first_metadata = metadata_stream(first_image_block, [FileSpec("a.txt", 2), FileSpec("b.txt", 0)])
    second_metadata = metadata_stream(second_image_block, [FileSpec("a.txt", 1), FileSpec("b.txt", 0)])

    data = wim_file([first_metadata, second_metadata])
    wim = WIM(io.BytesIO(data))
    images = list(wim.images())
    assert len(images) == 2

    first, second = images
    first_files = _entries(first)
    second_files = _entries(second)

    assert first_files["a.txt"].security_id == 2
    assert second_files["a.txt"].security_id == 1

    # The same SecurityId in each image resolves inside that image only.
    assert first_files["a.txt"].security_descriptor == descriptor("one-b")
    assert first_files["b.txt"].security_descriptor == descriptor("one-a")
    assert second_files["a.txt"].security_descriptor == descriptor("two-b")
    assert second_files["b.txt"].security_descriptor == descriptor("two-a")

    assert first.security.descriptors != second.security.descriptors
    assert first_files["a.txt"].security_descriptor != second_files["a.txt"].security_descriptor


def test_missing_and_empty_and_out_of_range_are_distinct() -> None:
    block = security_block([descriptor("only"), None])
    files = [
        FileSpec("missing.bin", SECURITY_ID_NONE),
        FileSpec("empty.bin", 1),
        FileSpec("outside.bin", 2),
    ]
    image = _image(wim_file([metadata_stream(block, files)]))
    entries = _entries(image)

    assert entries["missing.bin"].security_entry is None
    assert entries["missing.bin"].security_descriptor is None

    empty_entry = entries["empty.bin"].security_entry
    assert empty_entry is not None
    assert empty_entry.is_empty
    assert empty_entry.index == 1
    with pytest.raises(EmptySecurityDescriptorError):
        entries["empty.bin"].security_descriptor

    with pytest.raises(SecurityIdOutOfRangeError):
        entries["outside.bin"].security_entry
    with pytest.raises(SecurityIdOutOfRangeError):
        entries["outside.bin"].security_descriptor

    assert entries["empty.bin"].security_id < image.security.header.NumEntries
    assert entries["outside.bin"].security_id >= image.security.header.NumEntries


def test_all_empty_security_table_still_fails_association() -> None:
    image = _image(wim_file([metadata_stream(security_block([None, None]), [FileSpec("f.bin", 1)])]))
    entry = _entries(image)["f.bin"]

    assert len(image.security) == 2
    assert entry.security_entry is not None
    assert entry.security_entry.is_empty

    with pytest.raises(EmptySecurityDescriptorError):
        entry.security_descriptor


def test_corrupt_security_table_fails_explicitly() -> None:
    good = security_block([descriptor("a"), None, descriptor("b")])

    # Declared total length is one byte longer than the entries allow.
    corrupt_end = bytearray(good)
    struct.pack_into("<I", corrupt_end, 0, len(good) + 1)
    with pytest.raises(InvalidSecurityDataError):
        _image(wim_file([metadata_stream(bytes(corrupt_end), [])]))

    # Declared header is larger than the total table.
    oversized_header = bytearray(good)
    struct.pack_into("<I", oversized_header, 4, 4)
    with pytest.raises(InvalidSecurityDataError):
        _image(wim_file([metadata_stream(bytes(oversized_header), [])]))

    # Slot lengths that do not add up to the declared table size.
    short_slot = bytearray(good)
    struct.pack_into("<Q", short_slot, 8, 4)
    with pytest.raises(InvalidSecurityDataError):
        _image(wim_file([metadata_stream(bytes(short_slot), [])]))

    # Truncated descriptor payload: the security header is intact but the
    # last descriptor is cut short.
    data = wim_file([metadata_stream(good, [])])
    metadata_offset = WIM(io.BytesIO(data))._images[0].offset
    truncated = data[: metadata_offset + len(good) - 1]
    with pytest.raises(InvalidSecurityDataError):
        list(WIM(io.BytesIO(truncated)).images())


@pytest.mark.parametrize("security_id", [2, 99])
def test_out_of_range_security_id_never_falls_back_to_slot_zero(security_id: int) -> None:
    block = security_block([descriptor("first"), descriptor("second")])
    metadata = bytearray(metadata_stream(block, [FileSpec("file.bin", 1)]))
    root_offset = (len(block) + 7) & ~7
    child_offset = int.from_bytes(metadata[root_offset + 16 : root_offset + 24], "little")

    # Point the file's SecurityId outside the table. The parser must not return
    # the first descriptor as a fallback.
    struct.pack_into("<I", metadata, child_offset + 12, security_id)
    entry = _entries(_image(wim_file([bytes(metadata)])))["file.bin"]
    assert entry.security_id == security_id

    with pytest.raises(SecurityIdOutOfRangeError) as exc_info:
        entry.security_entry
    assert exc_info.value.security_id == security_id
    assert exc_info.value.num_entries == 2

    with pytest.raises(SecurityIdOutOfRangeError):
        entry.security_descriptor


def test_directory_entry_length_and_alignment_validated() -> None:
    # A length that is not a multiple of 8 is corrupt, even if it fits the data.
    block = security_block([descriptor("a")])
    metadata = bytearray(metadata_stream(block, [FileSpec("x.bin", 0)]))
    root_offset = (len(block) + 7) & ~7
    child_offset = int.from_bytes(metadata[root_offset + 16 : root_offset + 24], "little")

    struct.pack_into("<q", metadata, child_offset, 111)
    with pytest.raises(InvalidDirectoryEntryError):
        _image(wim_file([bytes(metadata)])).root.listdir()

    # A length smaller than the fixed directory entry header is corrupt.
    metadata = bytearray(metadata_stream(block, [FileSpec("x.bin", 0)]))
    struct.pack_into("<q", metadata, child_offset, 64)
    with pytest.raises(InvalidDirectoryEntryError):
        _image(wim_file([bytes(metadata)])).root.listdir()


@pytest.mark.parametrize("name", ["basic4k", "basic8k", "basic16k", "basic32k"])
def test_real_sample_security_associations(name: str) -> None:
    with gzip.open(absolute_path(f"_data/wim/{name}.wim.gz")) as fh:
        image = _image(fh.read())

    assert image.security.header.NumEntries == 3
    assert image.security.entry_lengths == (164, 152, 164)
    assert [hashlib.sha1(descriptor).hexdigest() for descriptor in image.security.descriptors] == [
        "a8a6e91ef45fc0b989de50075ff0e6c5378fd64e",
        "4c8cb1a69d37691da57e58c068ecf0ce892133de",
        "4a165a43b707c55e3173d392d25c3859e4b5e229",
    ]

    expected = {
        "ads.txt": (1, "4c8cb1a69d37691da57e58c068ecf0ce892133de"),
        "file.txt": (2, "4a165a43b707c55e3173d392d25c3859e4b5e229"),
        "link.txt": (0, "a8a6e91ef45fc0b989de50075ff0e6c5378fd64e"),
        "dir": (0, "a8a6e91ef45fc0b989de50075ff0e6c5378fd64e"),
        "dir/another.txt": (2, "4a165a43b707c55e3173d392d25c3859e4b5e229"),
    }
    image.metadata.seek(0)
    metadata_bytes = image.metadata.read()
    for path, (security_id, digest) in expected.items():
        entry = image.get(path)
        assert entry.security_id == security_id
        assert hashlib.sha1(entry.security_descriptor).hexdigest() == digest

        # Trace the association back to the decompressed metadata bytes.
        slot = entry.security_entry
        assert slot is not None
        start = image.security.offset + slot.offset
        assert metadata_bytes[start : start + slot.length] == entry.security_descriptor

    # The first descriptor is only returned for SecurityId 0, and descriptor 2
    # is not shifted into slot 1 by anything in the table.
    assert image.get("link.txt").security_descriptor == image.security[0].data
    assert image.get("ads.txt").security_descriptor == image.security[1].data
