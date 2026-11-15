from __future__ import annotations

import itertools
import random
import zlib
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.squashfs.c_squashfs import c_squashfs
from dissect.squashfs.compression import NativeZlib
from dissect.squashfs.exceptions import MetadataError
from dissect.squashfs.squashfs import SquashFS

if TYPE_CHECKING:
    from dissect.squashfs.compression import Compression

COMPRESSED_BIT = c_squashfs.SQUASHFS_COMPRESSED_BIT
# Deterministic read budget. A well behaved chain terminates well before this on the synthetic
# images below; the assertion turns any runaway loop into a failure instead of a timeout.
MAX_FRAME_READS = 32


class RecordingStream(BytesIO):
    """In-memory file handle recording every low level read issued against the image."""

    def __init__(self, data: bytes = b""):
        super().__init__(data)
        self.reads: list[tuple[int, int, int]] = []

    @property
    def read_count(self) -> int:
        return len(self.reads)

    def read(self, size: int = -1) -> bytes:
        position = self.tell()
        data = super().read(size)
        self.reads.append((position, size, len(data)))
        return data


def make_frame(payload: bytes, compress: bool = False) -> bytes:
    """Serialize one SquashFS metadata frame (2-byte header + data)."""
    if compress:
        blob = zlib.compress(payload)
        return len(blob).to_bytes(2, "little") + blob
    return (COMPRESSED_BIT | len(payload)).to_bytes(2, "little") + payload


def make_chain_fs(image: bytes, compression: Compression | None = None) -> SquashFS:
    """Build a minimal SquashFS without parsing a superblock for direct chain testing."""
    fs = SquashFS.__new__(SquashFS)
    fs.fh = RecordingStream(image)
    fs._compression = compression
    fs.block_size = c_squashfs.SQUASHFS_METADATA_SIZE
    return fs


def frame_locations(image: bytes) -> list[int]:
    """Physical start position of every metadata frame in a serialized chain."""
    positions = []
    offset = 0
    while offset < len(image):
        positions.append(offset)
        declared = int.from_bytes(image[offset : offset + 2], "little") & ~COMPRESSED_BIT
        offset += 2 + declared
    return positions


def assert_bounded(fs: SquashFS) -> None:
    assert fs.fh.read_count <= MAX_FRAME_READS


def test_zero_length_read_touches_no_frames() -> None:
    fs = make_chain_fs(make_frame(b"abcdefgh"))

    block, offset, data = fs._read_metadata(0, 2, 0)

    assert data == b""
    assert block == 0
    assert offset == 2
    assert fs.fh.read_count == 0


# ---------------------------------------------------------------------------
# Successful cross-frame reconstruction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("compress", [False, True], ids=["raw", "zlib"])
@pytest.mark.parametrize(
    ("split_at", "start_offset"),
    [
        (32, 0),  # record fully inside the first frame
        (10, 4),  # starts mid-frame, ends exactly on the frame boundary
        (12, 4),  # straddles the boundary with a multi-byte remainder
        (1, 0),  # only one record byte remains in the first frame
        (16, 15),  # one record byte in frame one; the remaining record starts at frame two
    ],
)
def test_cross_frame_record_reconstructed(compress: bool, split_at: int, start_offset: int) -> None:
    record = bytes(range(16))
    first_payload = b"P" * start_offset + record[: max(0, split_at - start_offset)]
    second_payload = record[max(0, split_at - start_offset) :]

    image = make_frame(first_payload, compress) + make_frame(second_payload, compress)
    fs = make_chain_fs(image, NativeZlib() if compress else None)

    block, offset, data = fs._read_metadata(0, start_offset, len(record))

    assert data == record
    assert block >= 0
    assert offset >= 0
    assert_bounded(fs)


def test_cross_frame_record_across_three_frames() -> None:
    record = bytes(range(40))
    image = make_frame(record[:10]) + make_frame(record[10:25]) + make_frame(record[25:])
    fs = make_chain_fs(image)

    block, offset, data = fs._read_metadata(0, 0, len(record))

    assert data == record
    # Record ends exactly on the frame three boundary, so block advances to frame three's data end.
    frame_starts = frame_locations(image)
    assert block == frame_starts[2] + 2 + len(record[25:])
    assert offset == 0
    assert fs.fh.read_count == 6  # one header read + one payload read per frame


def test_empty_frame_between_data_frames_is_skipped() -> None:
    record = bytes(range(16))
    image = make_frame(record[:8]) + make_frame(b"") + make_frame(record[8:])
    fs = make_chain_fs(image)

    _, _, data = fs._read_metadata(0, 0, len(record))

    assert data == record
    assert_bounded(fs)


# ---------------------------------------------------------------------------
# Malformed chains: deterministic, bounded termination
# ---------------------------------------------------------------------------


def test_offset_outside_frame_keeps_physical_frame_and_logical_offset() -> None:
    image = make_frame(b"abc")
    fs = make_chain_fs(image)
    frame_start = frame_locations(image)[0]

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(0, 10, 4)

    assert exc_info.value.block == frame_start
    assert exc_info.value.offset == 10
    assert_bounded(fs)


def test_offset_at_frame_end_does_not_assemble_from_next_frame() -> None:
    second_frame = make_frame(b"FAKEDATA!!")
    image = make_frame(b"abc") + second_frame
    fs = make_chain_fs(image)
    first_start, second_start = frame_locations(image)

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(0, 3, 8)

    assert exc_info.value.block == first_start
    assert exc_info.value.offset == 3
    # Only the first frame (header + payload) is read; the forged frame is never touched.
    assert fs.fh.read_count == 2
    assert all(position < second_start for position, _, _ in fs.fh.reads)


def test_empty_frame_skips_to_following_data_frame() -> None:
    # An empty frame at a chain boundary is legal as long as a later frame carries the record.
    record = bytes(range(16))
    image = make_frame(b"") + make_frame(record)
    fs = make_chain_fs(image)

    block, offset, data = fs._read_metadata(0, 0, len(record))

    assert data == record
    assert offset == 0
    assert_bounded(fs)


def test_trailing_empty_frame_is_a_no_progress_chain() -> None:
    # The empty frame is the last frame in the image: its successor points at itself, so the chain
    # cannot advance and must terminate explicitly rather than spinning until a timeout.
    image = make_frame(b"")
    fs = make_chain_fs(image)
    frame_start = frame_locations(image)[0]

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(0, 0, 4)

    # The error keeps the physical frame that stalled and the logical offset within it.
    assert exc_info.value.block in (frame_start, frame_start + 2)
    assert exc_info.value.offset == 0
    assert fs.fh.read_count == 3  # header + empty payload + self-referential header re-read at EOF


def test_empty_frame_does_not_assemble_forged_record() -> None:
    # An empty leading frame must not cause bytes to be read from the middle of another frame.
    # The chain advances to the first non-empty frame at logical offset zero and concatenates the
    # complete frames in order, rather than fabricating a record that starts inside a frame.
    record = b"TRUSTED123456789"
    forged = b"FORGED!!"
    image = make_frame(b"") + make_frame(forged) + make_frame(record)
    fs = make_chain_fs(image)

    _, _, data = fs._read_metadata(0, 0, len(record))

    assert data == (forged + record)[: len(record)]
    assert data.startswith(forged)
    assert_bounded(fs)


def test_empty_compressed_frame_terminates_without_timeout() -> None:
    image = make_frame(b"", compress=True)
    fs = make_chain_fs(image, NativeZlib())
    frame_start = frame_locations(image)[0]

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(0, 0, 4)

    assert frame_start <= exc_info.value.block <= len(image)
    assert exc_info.value.offset == 0
    assert_bounded(fs)


def test_truncated_declared_length_terminates_bounded() -> None:
    image = (COMPRESSED_BIT | 500).to_bytes(2, "little")  # declares 500 bytes, none follow
    fs = make_chain_fs(image)

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(0, 0, 4)

    assert exc_info.value.offset == 0
    assert exc_info.value.block >= 0
    assert_bounded(fs)
    # The payload read starts right after the 2-byte header and returns zero bytes at EOF.
    assert fs.fh.reads[1] == (2, 500, 0)


def test_corrupt_compressed_payload_terminates_bounded() -> None:
    image = (20).to_bytes(2, "little") + b"\x00" * 20
    fs = make_chain_fs(image, NativeZlib())

    with pytest.raises(zlib.error):
        fs._read_metadata(0, 0, 4)

    assert_bounded(fs)


def test_truncated_chain_at_frame_header_terminates_bounded() -> None:
    fs = make_chain_fs(make_frame(b"abcdefgh"))

    with pytest.raises(MetadataError) as exc_info:
        fs._read_metadata(0, 0, 16)

    # The failure records the physical frame whose continuation header is missing.
    assert exc_info.value.block == 2 + 8
    assert exc_info.value.offset == 0
    assert_bounded(fs)


# ---------------------------------------------------------------------------
# Directed fuzzing: vary declared length, decompressed length, offset, remainder
# ---------------------------------------------------------------------------


def test_directed_metadata_chain_fuzz() -> None:
    declared_options = [0, 1, 3, 7, 8, 16, 31, 100]
    offset_options = [0, 1, 2, 7, 8, 15, 16, 17, 100, c_squashfs.SQUASHFS_METADATA_SIZE]
    remainder_options = [0, 1, 2, 5, 16, 33]

    cases = 0
    for compress, payload_len, offset, remainder in itertools.product(
        (False, True), declared_options, offset_options, remainder_options
    ):
        payload = bytes((index % 251) + 1 for index in range(payload_len))
        image = make_frame(payload, compress)
        fs = make_chain_fs(image, NativeZlib() if compress else None)
        wanted = max(1, (payload_len - offset) + remainder)
        cases += 1

        if offset >= payload_len:
            with pytest.raises(MetadataError) as exc_info:
                fs._read_metadata(0, offset, wanted)
            assert exc_info.value.offset == offset
            # Block is either the offending frame header (out-of-range offset) or its
            # self-referential successor when an empty trailing frame cannot advance.
            assert exc_info.value.block >= frame_locations(image)[0]
            assert_bounded(fs)
            continue

        try:
            _, next_offset, data = fs._read_metadata(0, offset, wanted)
        except MetadataError as error:
            assert error.block >= frame_locations(image)[0]
            assert error.offset >= 0
            assert_bounded(fs)
            continue

        available = payload_len - offset
        if wanted <= available:
            assert data == payload[offset : offset + wanted]
            if wanted < available:
                assert next_offset == offset + wanted
        else:
            # Single-frame image cannot satisfy the remainder; continuation must hit EOF bounded.
            assert_bounded(fs)

    assert cases > 200


def test_randomized_chain_fuzz_bounded() -> None:
    random.seed(20261115)

    for _ in range(150):
        frame_count = random.randint(1, 4)
        frames = []
        for _ in range(frame_count):
            size = random.choice([0, 0, 1, 5, 16, 40])
            frames.append(make_frame(random.randbytes(size), compress=random.choice([False, True])))

        image = b"".join(frames)
        fs = make_chain_fs(image, NativeZlib())
        offset = random.choice([0, 0, 1, 3, 16, 99])
        wanted = random.choice([1, 4, 16, 64])

        try:
            fs._read_metadata(0, offset, wanted)
        except MetadataError as error:
            assert error.offset >= 0
            assert error.block >= 0
        except zlib.error:
            # Corrupt compressed payloads are allowed to surface the underlying codec failure.
            pass

        assert_bounded(fs)
