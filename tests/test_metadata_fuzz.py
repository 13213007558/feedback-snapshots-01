from __future__ import annotations

import stat
import struct
import zlib
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.exceptions import MetadataError
from dissect.squashfs.squashfs import SquashFS

if TYPE_CHECKING:
    from collections.abc import Sequence
    from typing import BinaryIO

DATA_START = 128
METADATA_SIZE = c_squashfs.SQUASHFS_METADATA_SIZE


@dataclass(frozen=True)
class Frame:
    """A synthetic metadata frame.

    ``declared`` is the on-disk length field, ``payload`` the decompressed contents. Padding
    after a compressed stream is intentionally accepted by zlib, while truncating it is not.
    """

    payload: bytes
    declared: int | None = None
    compressed: bool = True

    def build(self) -> bytes:
        stored = zlib.compress(self.payload) if self.compressed else self.payload
        declared = len(stored) if self.declared is None else self.declared
        if not 0 <= declared <= METADATA_SIZE:
            raise ValueError(f"invalid declared metadata length: {declared}")

        data = stored[:declared]
        data += b"\x00" * (declared - len(data))

        field = declared if self.compressed else declared | c_squashfs.SQUASHFS_COMPRESSED_BIT
        return struct.pack("<H", field) + data


class RecordingReader(BytesIO):
    """BytesIO that records the actual low-level read and seek calls."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.reads: list[tuple[int, int, int]] = []
        self.seeks: list[tuple[int, int]] = []

    def read(self, size: int = -1) -> bytes:
        offset = self.tell()
        data = super().read(size)
        self.reads.append((offset, size, len(data)))
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        self.seeks.append((offset, whence))
        return super().seek(offset, whence)

    def clear_trace(self) -> None:
        self.reads.clear()
        self.seeks.clear()

    @property
    def read_offsets(self) -> list[int]:
        return [offset for offset, _, _ in self.reads]


def _assert_each_frame_read_at_most_once(reader: RecordingReader) -> None:
    # Every metadata block costs one read for the length field and one for the contents;
    # a frame that is read again would indicate a chain that loops back or re-reads data.
    counts: dict[int, int] = {}
    for offset in reader.read_offsets:
        counts[offset] = counts.get(offset, 0) + 1
    assert all(count <= 1 for count in counts.values()), counts


def _append_frames(image: bytearray, frames: Sequence[Frame]) -> list[int]:
    offsets = []
    for frame in frames:
        offsets.append(len(image))
        image += frame.build()
    return offsets


def _build_image(
    inode_frames: Sequence[Frame], directory_frames: Sequence[Frame], block_size: int = 4096
) -> tuple[bytes, list[int], list[int]]:
    image = bytearray(DATA_START)
    inode_offsets = _append_frames(image, inode_frames)
    directory_offsets = _append_frames(image, directory_frames)

    superblock = c_squashfs.squashfs_super_block(
        s_magic=c_squashfs.SQUASHFS_MAGIC,
        inodes=0,
        mkfs_time=0,
        block_size=block_size,
        fragments=0,
        compression=c_squashfs.ZLIB_COMPRESSION,
        block_log=12,
        flags=0,
        no_ids=0,
        s_major=4,
        s_minor=0,
        root_inode=0,
        bytes_used=len(image),
        id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        xattr_id_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        inode_table_start=inode_offsets[0] if inode_offsets else c_squashfs.SQUASHFS_INVALID_BLK,
        directory_table_start=directory_offsets[0] if directory_offsets else c_squashfs.SQUASHFS_INVALID_BLK,
        fragment_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
        lookup_table_start=c_squashfs.SQUASHFS_INVALID_BLK,
    )
    superblock_bytes = bytes(superblock)
    image[: len(superblock_bytes)] = superblock_bytes

    return bytes(image), inode_offsets, directory_offsets


def _open_metadata(
    inode_frames: Sequence[Frame], directory_frames: Sequence[Frame]
) -> tuple[SquashFS, RecordingReader, list[int], list[int]]:
    image, inode_offsets, directory_offsets = _build_image(inode_frames, directory_frames)
    reader = RecordingReader(image)
    fs = SquashFS(reader)
    fs._read_block.cache_clear()
    reader.clear_trace()
    return fs, reader, inode_offsets, directory_offsets


def _dir_inode_header(
    *,
    file_size: int = 0,
    offset: int = 0,
    start_block: int = 0,
    inode_number: int = 42,
) -> bytes:
    return bytes(
        c_squashfs.squashfs_dir_inode_header(
            inode_type=c_squashfs.SQUASHFS_DIR_TYPE,
            mode=0o755,
            uid=0,
            guid=0,
            mtime=1_700_000_000,
            inode_number=inode_number,
            start_block=start_block,
            nlink=2,
            file_size=file_size,
            offset=offset,
            parent_inode=1,
        )
    )


def _directory_payload() -> tuple[bytes, list[tuple[str, int]]]:
    names = [b"alpha", b"beta"]
    payload = bytearray(
        bytes(c_squashfs.squashfs_dir_header(count=len(names) - 1, start_block=0, inode_number=10))
    )
    expected = []
    for index, name in enumerate(names, start=1):
        payload += bytes(
            c_squashfs.squashfs_dir_entry(
                offset=0,
                inode_number=index,
                type=c_squashfs.SQUASHFS_FILE_TYPE,
                size=len(name) - 1,
            )
        )
        payload += name
        expected.append((name.decode(), 10 + index))
    return bytes(payload), expected


@pytest.mark.parametrize("compressed", [True, False], ids=["compressed", "raw"])
@pytest.mark.parametrize(
    ("first_size", "offset", "tail"),
    [
        (4, 0, 1),
        (4, 2, 0),
        (4, 3, 1),
        (4, 4, 1),
        (7, 3, 2),
        (15, 7, 2),
        (16, 15, 3),
        (16, 16, 3),
        (32, 31, 4),
    ],
)
def test_read_metadata_crosses_frame_boundary(
    compressed: bool, first_size: int, offset: int, tail: int
) -> None:
    first = bytes(index % 251 for index in range(first_size))
    second = bytes((index + 100) % 251 for index in range(tail + 3))
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(first, compressed=compressed), Frame(second, compressed=compressed)],
        [],
    )

    margin = first_size - offset
    block, cursor, data = fs._read_metadata(first_block, offset, margin + tail)

    assert data == first[offset:] + second[:tail]
    assert block == second_block
    assert cursor == tail
    assert reader.read_offsets.count(first_block) == 1
    if tail:
        assert reader.read_offsets.count(second_block) == 1
    else:
        # The record ended exactly on the boundary, so the next frame was not needed.
        assert reader.read_offsets.count(second_block) == 0


def test_read_metadata_crosses_multiple_frames() -> None:
    fs, reader, (first_block, second_block, third_block), _ = _open_metadata(
        [Frame(b"aa"), Frame(b"bbb"), Frame(b"cccc")],
        [],
    )

    block, cursor, data = fs._read_metadata(first_block, 1, 6)

    assert data == b"abbbcc"
    assert block == third_block
    assert cursor == 2
    assert reader.read_offsets.count(first_block) == 1
    assert reader.read_offsets.count(second_block) == 1
    assert reader.read_offsets.count(third_block) == 1


def test_offset_at_frame_end_is_a_valid_zero_margin_crossing() -> None:
    fs, _, (first_block, second_block), _ = _open_metadata([Frame(b"01234567"), Frame(b"ABCD")], [])

    block, cursor, data = fs._read_metadata(first_block, 8, 2)

    assert data == b"AB"
    assert block == second_block
    assert cursor == 2


def test_record_ending_at_frame_boundary_advances_cursor() -> None:
    fs, reader, (first_block, second_block), _ = _open_metadata([Frame(b"01234567"), Frame(b"ABCD")], [])

    block, cursor, data = fs._read_metadata(first_block, 3, 5)

    assert data == b"34567"
    assert block == second_block
    assert cursor == 0
    # The record ended exactly on the boundary, so the next frame's contents were not needed.
    assert first_block in reader.read_offsets
    assert second_block not in reader.read_offsets


@pytest.mark.parametrize("payload_size", [1, 7, 8, 16, 255, METADATA_SIZE - 1, METADATA_SIZE])
def test_decompressed_frame_sizes_are_bounded(payload_size: int) -> None:
    first = b"A" * payload_size
    fs, reader, (first_block, second_block), _ = _open_metadata([Frame(first), Frame(b"BBBB")], [])

    block, cursor, data = fs._read_metadata(first_block, payload_size - 1, 4)

    assert data == b"ABBB"
    assert block == second_block
    assert cursor == 3
    assert reader.read_offsets.count(first_block) == 1
    assert reader.read_offsets.count(second_block) == 1


def test_declared_length_padding_does_not_shift_the_chain() -> None:
    payload = b"01234567"
    stored = zlib.compress(payload)
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(payload, declared=len(stored) + 5), Frame(b"abcdefgh")],
        [],
    )

    block, cursor, data = fs._read_metadata(first_block, 6, 5)

    assert data == b"67abc"
    assert block == second_block
    assert cursor == 3
    content_reads = [entry for entry in reader.reads if entry[0] == first_block + 2]
    assert content_reads == [(first_block + 2, len(stored) + 5, len(stored) + 5)]


def test_uncompressed_declared_length_extends_the_logical_frame() -> None:
    fs, _, (first_block, second_block), _ = _open_metadata(
        [Frame(b"AB", declared=4, compressed=False), Frame(b"CD")],
        [],
    )

    block, cursor, data = fs._read_metadata(first_block, 0, 5)

    assert data == b"AB\x00\x00C"
    assert block == second_block
    assert cursor == 1


@pytest.mark.parametrize("truncate", [1, 2, 4])
def test_short_declared_compressed_frame_is_rejected(truncate: int) -> None:
    payload = b"x" * 64
    stored = zlib.compress(payload)
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(payload, declared=max(1, len(stored) - truncate)), Frame(b"FAKE")],
        [],
    )

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(first_block, 0, 8)

    error = exc_info.value
    assert error.block == first_block
    assert error.offset == 0
    assert isinstance(error.__cause__, zlib.error)
    assert reader.read_offsets.count(first_block) == 1
    assert all(offset < second_block for offset in reader.read_offsets)


def test_decompressed_frame_larger_than_metadata_block_is_rejected() -> None:
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(b"\x00" * (METADATA_SIZE + 1)), Frame(b"FAKE")],
        [],
    )

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(first_block, 0, 4)

    error = exc_info.value
    assert error.block == first_block
    assert error.offset == 0
    assert isinstance(error.__cause__, ValueError)
    assert "too large" in str(error.__cause__)
    assert reader.read_offsets.count(first_block) == 1
    assert all(offset < second_block for offset in reader.read_offsets)


@pytest.mark.parametrize("compressed", [True, False], ids=["compressed", "raw"])
def test_empty_frame_is_rejected_without_reading_the_next_frame(compressed: bool) -> None:
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(b"", compressed=compressed), Frame(b"FAKE")],
        [],
    )

    with pytest.raises(MetadataError, match="empty metadata block") as exc_info:
        fs._read_metadata(first_block, 0, 16)

    error = exc_info.value
    assert error.block == first_block
    assert error.offset == 0
    assert reader.read_offsets == [first_block, first_block + 2]
    # An uncompressed empty frame has zero stored bytes, so the next frame starts right after
    # its length field; no non-empty read may consume any of the next frame's contents.
    assert all(size == 0 or offset < second_block for offset, size, _ in reader.reads)


@pytest.mark.parametrize("offset", [9, 16, 1000])
def test_offset_outside_frame_is_rejected_before_the_next_frame(offset: int) -> None:
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(b"01234567"), Frame(_dir_inode_header())],
        [],
    )

    with pytest.raises(MetadataError, match="offset outside block") as exc_info:
        fs._read_metadata(first_block, offset, 16)

    error = exc_info.value
    assert error.block == first_block
    assert error.offset == offset
    assert reader.read_offsets.count(first_block) == 1
    assert all(read_offset < second_block for read_offset in reader.read_offsets)


@pytest.mark.parametrize("split", [1, 2, 8, 15, 16, 17, 24, 31, 32])
@pytest.mark.parametrize("compressed", [True, False], ids=["compressed", "raw"])
def test_inode_header_recovers_across_frames(split: int, compressed: bool) -> None:
    header = _dir_inode_header(file_size=1234)
    second_frame = Frame(header[split:], compressed=compressed)
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(header[:split], compressed=compressed), second_frame],
        [],
    )

    node = fs.inode(0, 0, name="/")

    assert node.header.inode_type == c_squashfs.SQUASHFS_DIR_TYPE
    assert node.header.inode_number == 42
    assert node.header.file_size == 1234
    assert node.header.start_block == 0
    assert node.header.offset == 0
    assert node.is_dir()
    assert node.size == 1234
    if split == len(header):
        # The whole header fit in the first frame, so the cursor advanced to the next frame.
        assert node.data_block == second_block
        assert node.data_offset == 0
        assert second_block not in reader.read_offsets
    else:
        # The header was consumed exactly up to the end of the second frame.
        assert node.data_block == second_block + len(second_frame.build())
        assert node.data_offset == 0
        assert reader.read_offsets.count(second_block) == 1
    assert reader.read_offsets.count(first_block) == 1


@pytest.mark.parametrize("compressed", [True, False], ids=["compressed", "raw"])
def test_inode_offset_outside_frame_does_not_borrow_the_next_frame(compressed: bool) -> None:
    first = b"xxxx"
    fake_header = _dir_inode_header(inode_number=7331)
    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(first, compressed=compressed), Frame(fake_header, compressed=compressed)],
        [],
    )

    node = fs.inode(0, len(first) + 1)

    with pytest.raises(MetadataError, match="offset outside block") as exc_info:
        node.header

    error = exc_info.value
    assert error.block == first_block
    assert error.offset == len(first) + 1
    assert all(offset < second_block for offset in reader.read_offsets)


@pytest.mark.parametrize("split", list(range(1, 34)))
def test_directory_entries_recover_across_frames(split: int) -> None:
    payload, expected = _directory_payload()
    header = _dir_inode_header(file_size=len(payload) + 3)
    fs, reader, _, (first_block, second_block) = _open_metadata(
        [Frame(header)],
        [Frame(payload[:split]), Frame(payload[split:])],
    )

    node = fs.inode(0, 0, name="/")
    entries = list(node.iterdir())

    assert [(entry.name, entry.inode_number) for entry in entries] == expected
    assert all(entry.type == stat.S_IFREG for entry in entries)
    _assert_each_frame_read_at_most_once(reader)
    assert reader.read_offsets.count(first_block) == 1
    assert reader.read_offsets.count(second_block) == 1


def test_directory_entries_recover_from_a_single_frame() -> None:
    payload, expected = _directory_payload()
    header = _dir_inode_header(file_size=len(payload) + 3)
    fs, reader, _, (directory_block,) = _open_metadata([Frame(header)], [Frame(payload)])

    entries = list(fs.inode(0, 0, name="/").iterdir())

    assert [(entry.name, entry.inode_number) for entry in entries] == expected
    _assert_each_frame_read_at_most_once(reader)
    assert reader.read_offsets.count(directory_block) == 1


def test_directory_record_outside_frame_does_not_create_a_fake_entry() -> None:
    fake_payload, _ = _directory_payload()
    first = b"short"
    header = _dir_inode_header(file_size=len(fake_payload) + 3, offset=len(first) + 1)
    fs, reader, _, (first_block, second_block) = _open_metadata(
        [Frame(header)],
        [Frame(first), Frame(fake_payload)],
    )

    node = fs.inode(0, 0, name="/")

    with pytest.raises(MetadataError, match="offset outside block") as exc_info:
        list(node.iterdir())

    error = exc_info.value
    assert error.block == first_block
    assert error.offset == len(first) + 1
    assert all(offset < second_block for offset in reader.read_offsets)


def test_error_reports_the_current_frame_and_logical_offset() -> None:
    fs, reader, (first_block, second_block, third_block), _ = _open_metadata(
        [Frame(b"aa"), Frame(b"bbb"), Frame(b"")],
        [],
    )

    with pytest.raises(MetadataError, match="empty metadata block") as exc_info:
        fs._read_metadata(first_block, 1, 10)

    error = exc_info.value
    assert error.block == third_block
    assert error.offset == 0
    assert error.frame == third_block
    assert error.logical_offset == 0
    assert reader.read_offsets.count(first_block) == 1
    assert reader.read_offsets.count(second_block) == 1
    assert reader.read_offsets.count(third_block) == 1


class _StalledSquashFS(SquashFS):
    """SquashFS whose metadata chain never advances to a new physical frame."""

    def __init__(self, fh: BinaryIO) -> None:
        super().__init__(fh)
        self.block_reads = 0

    def _read_block(self, block: int, length: int | None = None) -> tuple[int, bytes]:
        self.block_reads += 1
        return block, b"A"


def test_chain_that_does_not_advance_is_rejected_deterministically() -> None:
    image, (inode_block,), _ = _build_image([Frame(b"placeholder")], [])
    fs = _StalledSquashFS(RecordingReader(image))
    fs._read_block.cache_clear()
    fs.block_reads = 0

    with pytest.raises(MetadataError, match="does not advance") as exc_info:
        fs._read_metadata(inode_block, 0, 10)

    error = exc_info.value
    assert error.block == inode_block
    assert error.offset == 1
    assert fs.block_reads == 1


def test_zero_margin_into_empty_frame_is_rejected_with_the_next_frame_context() -> None:
    fs, reader, (first_block, second_block), _ = _open_metadata([Frame(b"ABCD"), Frame(b"")], [])

    with pytest.raises(MetadataError, match="empty metadata block") as exc_info:
        fs._read_metadata(first_block, 4, 16)

    error = exc_info.value
    assert error.block == second_block
    assert error.offset == 0
    assert reader.read_offsets.count(first_block) == 1
    assert reader.read_offsets.count(second_block) == 1


def test_metadata_frame_uses_metadata_size_as_decompression_bound() -> None:
    # A 4 KiB block size is common for small firmware images, but metadata frames may still
    # decompress to up to 8192 bytes. Backends that truncate to ``expected`` (e.g. LZ4) must be
    # told the metadata size, otherwise a legal frame would silently lose its tail.
    payload = bytes(index % 251 for index in range(6000))
    image, inode_offsets, _ = _build_image([Frame(payload), Frame(b"tail")], [], block_size=4096)
    first_block, second_block = inode_offsets
    fs = SquashFS(BytesIO(image))
    fs._read_block.cache_clear()

    seen: list[int] = []
    original = fs._compression

    class RecordingCompression:
        def decompress(self, data: bytes, expected: int) -> bytes:
            seen.append(expected)
            return original.decompress(data, expected)

    fs._compression = RecordingCompression()

    block, cursor, data = fs._read_metadata(first_block, 0, 6000)

    assert data == payload
    assert block == second_block
    assert cursor == 0
    assert seen == [METADATA_SIZE]
_MATRIX_CASES = [
    (1, 0, 1),
    (1, 0, 4),
    (7, 0, 1),
    (7, 3, 2),
    (7, 6, 1),
    (64, 0, 0),
    (64, 32, 3),
    (64, 63, 2),
    (1024, 0, 1),
    (1024, 512, 4),
    (1024, 1023, 1),
    (8192, 4095, 3),
    (8192, 8191, 1),
]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if metafunc.function.__name__ == "test_boundary_matrix_has_exact_bytes_and_reads":
        # Padding only changes the on-disk length of a compressed frame; an uncompressed frame's
        # declared length *is* its logical content, so that combination is covered elsewhere.
        cases = []
        for compressed in (True, False):
            for declared_padding in (0, 1, 4):
                if not compressed and declared_padding:
                    continue
                for payload_size, offset, tail in _MATRIX_CASES:
                    stored_size = len(zlib.compress(bytes(index % 251 for index in range(payload_size))))
                    if stored_size + declared_padding > METADATA_SIZE:
                        continue
                    cases.append(pytest.param(compressed, declared_padding, payload_size, offset, tail))

        metafunc.parametrize(("compressed", "declared_padding", "payload_size", "offset", "tail"), cases)


def test_boundary_matrix_has_exact_bytes_and_reads(
    compressed: bool, declared_padding: int, payload_size: int, offset: int, tail: int
) -> None:
    """Vary declared length, decompressed length, start offset and cross-frame margin together."""
    payload = bytes(index % 251 for index in range(payload_size))
    stored = zlib.compress(payload) if compressed else payload
    second_payload = b"BCDE"

    fs, reader, (first_block, second_block), _ = _open_metadata(
        [Frame(payload, declared=len(stored) + declared_padding, compressed=compressed), Frame(second_payload)],
        [],
    )

    length = (payload_size - offset) + tail
    block, cursor, data = fs._read_metadata(first_block, offset, length)

    assert data == (payload[offset:] + second_payload)[:length]
    if tail == 0:
        # The record ended exactly on this frame's boundary, so the cursor moved to the next one.
        assert cursor == 0
        assert block == second_block
        assert reader.read_offsets == [first_block, first_block + 2]
    elif tail == len(second_payload):
        # The record also ended exactly on the second frame's boundary.
        assert cursor == 0
        assert block == second_block + len(Frame(second_payload).build())
        assert reader.read_offsets == [first_block, first_block + 2, second_block, second_block + 2]
    else:
        assert cursor == tail
        assert block == second_block
        assert reader.read_offsets == [first_block, first_block + 2, second_block, second_block + 2]


def test_declared_length_larger_than_metadata_block_is_rejected() -> None:
    image, (inode_block,), _ = _build_image([Frame(b"placeholder")], [])
    image = bytearray(image)
    # Rewrite the first frame header to declare a compressed frame larger than any metadata block.
    image[inode_block : inode_block + 2] = struct.pack("<H", METADATA_SIZE + 1)
    fs = SquashFS(BytesIO(bytes(image)))
    fs._read_block.cache_clear()

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(inode_block, 0, 4)

    error = exc_info.value
    assert error.block == inode_block
    assert error.offset == 0
    assert isinstance(error.__cause__, ValueError)
    assert "too large" in str(error.__cause__)


def test_truncated_frame_at_end_of_image_is_rejected() -> None:
    image, (inode_block,), _ = _build_image([Frame(b"0123456789")], [])
    truncated = image[: inode_block + 2 + 4]
    fs = SquashFS(BytesIO(truncated))
    fs._read_block.cache_clear()

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(inode_block, 0, 4)

    error = exc_info.value
    assert error.block == inode_block
    assert error.offset == 0
    assert isinstance(error.__cause__, EOFError)


def test_chain_loop_back_to_an_earlier_frame_is_rejected() -> None:
    image, (inode_block,), _ = _build_image([Frame(b"0123456789")], [])
    fs = SquashFS(BytesIO(image))
    fs._read_block.cache_clear()

    class LoopingSquashFS(SquashFS):
        def _read_block(self, block: int, length: int | None = None) -> tuple[int, bytes]:
            return block - 1, b"0123456789"

    looping = LoopingSquashFS(BytesIO(image))
    looping._read_block.cache_clear()

    with pytest.raises(MetadataError, match="does not advance") as exc_info:
        looping._read_metadata(inode_block, 0, 20)

    assert exc_info.value.block == inode_block
