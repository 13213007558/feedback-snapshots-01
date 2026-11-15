from __future__ import annotations

import struct
from io import BytesIO
from pathlib import Path

import pytest

from dissect.squashfs import OutOfBoundsError, SquashFS
from dissect.squashfs.c_squashfs import c_squashfs

DATA_DIR = Path(__file__).parent / "_data"
SUPERBLOCK_SIZE = len(c_squashfs.squashfs_super_block)

# On-disk offsets of the pointer/table fields in the SquashFS 4.0 superblock.
SB_OFFSETS = {
    "bytes_used": 40,
    "id_table_start": 48,
    "xattr_id_table_start": 56,
    "inode_table_start": 64,
    "directory_table_start": 72,
    "fragment_table_start": 80,
    "lookup_table_start": 88,
}


@pytest.fixture
def gzip_bytes() -> bytes:
    return (DATA_DIR / "gzip.sqfs").read_bytes()


def _superblock(data: bytes) -> c_squashfs.squashfs_super_block:
    return c_squashfs.squashfs_super_block(BytesIO(data))


def _patch_superblock(data: bytes, field: str, value: int) -> bytes:
    patched = bytearray(data)
    struct.pack_into("<q", patched, SB_OFFSETS[field], value)
    return bytes(patched)


def _patch_fragment_start_block(data: bytes, start_block: int) -> bytes:
    """Point the first fragment entry's data block at ``start_block`` (relative to the FS start)."""
    sb = _superblock(data)
    fragment_pointer = struct.unpack("<Q", data[sb.fragment_table_start : sb.fragment_table_start + 8])[0]
    entry_offset = fragment_pointer + 2

    patched = bytearray(data)
    struct.pack_into("<q", patched, entry_offset, start_block)
    return bytes(patched)


def test_subimage_independent_of_prefix(gzip_bytes: bytes) -> None:
    """The same FS behind two different prefixes must expose identical contents."""
    next_partition = b"next-partition" * 32
    prefixes = (b"boot-header", b"P" * 777)

    file_contents = []
    for prefix in prefixes:
        image = prefix + gzip_bytes + next_partition
        fs = SquashFS.from_subimage(BytesIO(image), len(prefix), len(gzip_bytes))

        assert fs.base == len(prefix)
        assert fs.region_size == len(gzip_bytes)
        assert fs.size == _superblock(gzip_bytes).bytes_used
        assert fs.get("small-file").open().read() == b"contents\n"
        file_contents.append(fs.get("large-file").open().read())

    assert file_contents[0] == file_contents[1]


def test_subimage_allows_trailing_padding(gzip_bytes: bytes) -> None:
    """A region larger than bytes_used is accepted; only the trailing padding differs."""
    sb = _superblock(gzip_bytes)
    padding = b"\x00" * 4096
    image = gzip_bytes + padding

    fs = SquashFS.from_subimage(BytesIO(image), 0, len(image))
    assert fs.region_size == len(image)
    assert fs.size == sb.bytes_used
    assert fs.get("small-file").open().read() == b"contents\n"


def test_subimage_default_constructor_matches(gzip_bytes: bytes) -> None:
    fs = SquashFS(BytesIO(gzip_bytes))
    assert fs.base == 0
    assert fs.region_size == len(gzip_bytes)
    assert fs.get("small-file").open().read() == b"contents\n"


def test_bytes_used_cannot_extend_region(gzip_bytes: bytes) -> None:
    sb = _superblock(gzip_bytes)
    with pytest.raises(OutOfBoundsError, match="superblock bytes_used") as exc_info:
        SquashFS.from_subimage(BytesIO(gzip_bytes), 0, sb.bytes_used - 1)

    assert exc_info.value.reference == "superblock bytes_used"
    assert exc_info.value.offset == sb.bytes_used
    assert exc_info.value.limit == sb.bytes_used - 1


def test_region_smaller_than_superblock_rejected(gzip_bytes: bytes) -> None:
    with pytest.raises(OutOfBoundsError, match="superblock"):
        SquashFS.from_subimage(BytesIO(gzip_bytes), 0, SUPERBLOCK_SIZE - 1)


def test_fragment_pointer_into_next_partition_rejected(gzip_bytes: bytes) -> None:
    """A fragment entry pointing at plausible data in the following partition must be refused."""
    sb = _superblock(gzip_bytes)

    # Beyond both bytes_used and the original image, i.e. clearly inside a following partition.
    evil_block = len(gzip_bytes) + 64
    image = _patch_fragment_start_block(gzip_bytes, evil_block) + b"\xde\xad\xbe\xef" * 64

    fs = SquashFS.from_subimage(BytesIO(image), 0, len(image))

    with pytest.raises(OutOfBoundsError) as exc_info:
        fs.get("small-file").open().read()

    error = exc_info.value
    assert error.reference == "fragment table"
    assert error.offset == evil_block
    assert error.limit == sb.bytes_used


def test_fragment_pointer_into_padding_rejected(gzip_bytes: bytes) -> None:
    """Pointers may not borrow bytes from the padding between bytes_used and the region end."""
    sb = _superblock(gzip_bytes)
    padding_block = sb.bytes_used + 8
    image = _patch_fragment_start_block(gzip_bytes, padding_block) + b"\x00" * 512

    fs = SquashFS.from_subimage(BytesIO(image), 0, len(image))

    with pytest.raises(OutOfBoundsError) as exc_info:
        fs.get("small-file").open().read()

    assert exc_info.value.reference == "fragment table"
    assert exc_info.value.offset == padding_block
    assert exc_info.value.limit == sb.bytes_used


@pytest.mark.parametrize(
    ("field", "reference"),
    [
        ("id_table_start", "ID table"),
        ("xattr_id_table_start", "xattr ID table"),
        ("inode_table_start", "inode table"),
        ("directory_table_start", "directory table"),
        ("fragment_table_start", "fragment table"),
        ("lookup_table_start", "inode lookup table"),
    ],
)
def test_superblock_table_pointer_out_of_bounds(gzip_bytes: bytes, field: str, reference: str) -> None:
    sb = _superblock(gzip_bytes)
    patched = _patch_superblock(gzip_bytes, field, sb.bytes_used + 128)

    with pytest.raises(OutOfBoundsError) as exc_info:
        SquashFS.from_subimage(BytesIO(patched), 0, len(gzip_bytes))

    assert exc_info.value.reference == reference
    assert exc_info.value.offset == sb.bytes_used + 128
    assert exc_info.value.limit == sb.bytes_used


def test_superblock_bytes_used_out_of_bounds_names_reference(gzip_bytes: bytes) -> None:
    patched = _patch_superblock(gzip_bytes, "bytes_used", len(gzip_bytes) + 1024)

    with pytest.raises(OutOfBoundsError) as exc_info:
        SquashFS.from_subimage(BytesIO(patched), 0, len(gzip_bytes))

    assert exc_info.value.reference == "superblock bytes_used"
    assert exc_info.value.offset == len(gzip_bytes) + 1024
    assert exc_info.value.limit == len(gzip_bytes)


@pytest.mark.parametrize("field", ["xattr_id_table_start", "fragment_table_start", "lookup_table_start"])
def test_absent_optional_table_sentinel_accepted(gzip_bytes: bytes, field: str) -> None:
    """The SQUASHFS_INVALID_BLK sentinel marks an absent optional table and is not an out-of-bounds pointer."""
    patched = _patch_superblock(gzip_bytes, field, c_squashfs.SQUASHFS_INVALID_BLK)
    fs = SquashFS.from_subimage(BytesIO(patched), 0, len(gzip_bytes))

    if field != "fragment_table_start":
        # small-file lives in a fragment, so only keep the content check when fragments remain available
        assert fs.get("small-file").open().read() == b"contents\n"
    else:
        assert fs.root.is_dir()


def test_bounded_stream_cannot_read_past_region(gzip_bytes: bytes) -> None:
    """The hard boundary is the caller-provided region, even if bytes_used is smaller."""
    padding = b"\x00" * 256
    image = gzip_bytes + padding
    fs = SquashFS.from_subimage(BytesIO(image), 0, len(image))

    with pytest.raises(OutOfBoundsError):
        fs.fh.seek(len(image))
        fs.fh.read(1)

    with pytest.raises(OutOfBoundsError):
        fs.fh.seek(len(image) - 1)
        fs.fh.read(2)


def test_caller_handle_is_not_closed_or_written(gzip_bytes: bytes) -> None:
    handle = BytesIO(gzip_bytes)
    fs = SquashFS(handle)
    assert fs.get("small-file").open().read() == b"contents\n"

    fs.fh.close()

    # The caller still owns and can use the underlying handle.
    assert not handle.closed
    handle.seek(0)
    assert handle.read(4) == b"hsqs"


def test_invalid_constructor_arguments(gzip_bytes: bytes) -> None:
    with pytest.raises(ValueError, match="base"):
        SquashFS.from_subimage(BytesIO(gzip_bytes), -1, len(gzip_bytes))

    with pytest.raises(ValueError, match="size"):
        SquashFS(BytesIO(gzip_bytes), base=0, size=-1)
