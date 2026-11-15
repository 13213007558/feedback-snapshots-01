from __future__ import annotations

import hashlib
import io
import zlib
from io import BytesIO

import pytest

from dissect.evidence.asdf.asdf import FOOTER_MAGIC, IDX_METADATA, AsdfSnapshot, AsdfWriter, c_asdf
from dissect.evidence.asdf.stream import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exception import InvalidSnapshot


class FaultyFile(io.BytesIO):
    """BytesIO that can fail or short-write at a specific write offset.

    Args:
        fail_at: Offset in the output at which writes start failing.
        short_at: Offset in the output at which writes are cut short.
        short_size: Maximum amount of bytes a single write accepts.
    """

    def __init__(self, fail_at: int | None = None, short_at: int | None = None, short_size: int = 1):
        super().__init__()
        self.fail_at = fail_at
        self.short_at = short_at
        self.short_size = short_size

    def close(self) -> None:
        # Keep the buffer accessible for inspection after a writer closes us
        pass

    def write(self, b: bytes) -> int:
        if not isinstance(b, (bytes, bytearray, memoryview)):
            b = bytes(b)

        pos = super().tell()

        if self.fail_at is not None:
            if pos >= self.fail_at:
                raise OSError("injected write failure")

            if pos + len(b) > self.fail_at:
                # Accept everything before the failure point, fail on the next write
                b = bytes(b)[: self.fail_at - pos]

        if self.short_at is not None and pos >= self.short_at:
            b = bytes(b)[: self.short_size]

        return super().write(b)


BLOCK_A = b"\x11" * 0x1000
BLOCK_B = b"\x22" * 0x1000
BLOCK_C = b"\x33" * 0x100


def make_writer(fh: FaultyFile, with_metadata: bool = False) -> AsdfWriter:
    """Create a writer and add a known sequence of blocks."""
    writer = AsdfWriter(fh, block_crc=True)
    writer.add_bytes(BLOCK_A, base=0)
    writer.add_bytes(BLOCK_B, base=0x4000)
    if with_metadata:
        writer.add_metadata_file("file", BytesIO(b"content"))
    writer.add_bytes(BLOCK_C, base=0x8000)
    return writer


def write_snapshot(fh: FaultyFile, with_metadata: bool = False) -> None:
    """Write and close a known sequence of blocks."""
    make_writer(fh, with_metadata=with_metadata).close()


def build_snapshot(with_metadata: bool = False) -> tuple[bytes, AsdfSnapshot]:
    """Build a known good snapshot and return its bytes and parsed representation."""
    fh = FaultyFile()
    write_snapshot(fh, with_metadata=with_metadata)

    data = fh.getvalue()
    return data, AsdfSnapshot(BytesIO(data))


def failure_points(with_metadata: bool = False) -> dict[str, int]:
    """Return a write offset inside each stage of the snapshot that can fail."""
    data, snapshot = build_snapshot(with_metadata=with_metadata)
    first_run = snapshot.table[0][0]
    points = {
        "data": first_run[3] + first_run[1] // 2,
        "table": snapshot.footer.table_offset + 10,
        "footer": len(data) - len(FOOTER_MAGIC) - 20,
    }
    if with_metadata:
        metadata_run = snapshot.table[IDX_METADATA][0]
        points["metadata"] = metadata_run[3] + metadata_run[1] // 2

    return points


def test_asdf(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    asdf_writer.add_bytes(b"\x08" * 0x1000, idx=1, base=0x2000)
    asdf_writer.add_bytes(b"\x10" * 0x1000, idx=1, base=0x5000)
    asdf_writer.add_bytes(b"\x12" * 0x1000, idx=1, base=0x8000)
    asdf_writer.add_bytes(b"\x14" * 0x1000, idx=1, base=0xB000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=1, base=0xE000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream_0 = reader.open(0)
    assert [(run_start, run_size) for run_start, run_size, _, _ in stream_0.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream_0.read(0x1000) == b"\x00" * 0x1000
    assert stream_0.read(0x1000) == (b"\xa5\xdf" * (0x1000 // 2))
    assert stream_0.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x02" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))

    stream_0.seek(0)
    assert stream_0.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )

    stream_1 = reader.open(1)
    assert stream_1.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x08" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))


def test_asdf_overlap(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    assert asdf_writer._table_lookup[0] == [0, 200]

    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.add_bytes(b"\x05" * 50, base=25)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 50),
        (150, 50),
        (200, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x03" * 50) + (b"\x04" * 50) + (b"\x02" * 100)


def test_asdf_overlap_all(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]
    asdf_writer.add_bytes(b"\x06" * 400, base=0)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 300),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x06" * 300)


def test_asdf_overlap_contiguous(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.add_bytes(b"\x03" * 75, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x02" * 100)


def test_asdf_overlap_seek(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 100, base=0)
    asdf_writer.add_bytes(b"\x00" * 100, base=200)
    asdf_writer.add_bytes(bytes(range(200)), base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
        (200, 100),
    ]
    assert stream.read() == (b"\x00" * 100) + bytes(range(50, 150)) + (b"\x00" * 100)


def test_asdf_mid_run(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(bytes([v & 0xFF for v in range(4096)]), base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)
    stream.align = 512

    stream.seek(1100)
    assert stream.read(512) == bytes([v & 0xFF for v in range(1100, 1100 + 512)])


def test_asdf_metadata(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_metadata_file("file", BytesIO(b"content"))
    asdf_writer.add_metadata_file("dir/file", BytesIO(b"content here too"))

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)

    assert reader.metadata.names() == ["file", "dir/file"]
    assert reader.metadata.open("file").read() == b"content"
    assert reader.metadata.open("dir/file").read() == b"content here too"

    with pytest.raises(KeyError):
        reader.metadata.open("nonexistent")


def test_asdf_stream_crc32() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream.write(b"srt was here")
    stream.finalize()

    assert fh.getvalue() == b"srt was here\x2f\x0e\x60\xa4"


def test_asdf_stream_compressed() -> None:
    fh = BytesIO()
    stream = CompressedStream(fh)
    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert zlib.decompress(fh.getvalue()) == b"srt was here" * 100


def test_asdf_stream_hashed() -> None:
    fh = BytesIO()
    stream = HashedStream(fh)
    stream.write(b"srt was here")
    assert stream.hexdigest() == "cd7bd850d261f8fa39a41d0963b42dae5f303615db19ac79e5044586d0825b7b"


def test_asdf_stream_combined() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream = CompressedStream(stream)
    stream = HashedStream(stream)

    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert stream.hexdigest() == "ba40ab3ee826d6aa0f085dfccbb72d8feefa72548015c4456c1fd741d0266a94"
    assert fh.getvalue() == bytes.fromhex("789c2b2e2a51284f2c56c8482d4a2d1e658fb247d9a3ec41cc06004445c530665f35fc")


def test_asdf_scrape(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    # Don't close so we don't have a footer and block table
    asdf_writer._fh.seek(0)

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(asdf_writer._fh)

    asdf_writer._fh.seek(0)
    reader = AsdfSnapshot(asdf_writer._fh, recover=True)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )


def test_asdf_fault_success_baseline() -> None:
    """A successful write must stay byte-for-byte compatible."""
    data, snapshot = build_snapshot()
    footer_offset = len(data) - len(c_asdf.footer)

    assert hashlib.sha256(data[:footer_offset]).digest() == snapshot.footer.sha256
    assert snapshot.footer.table_offset < footer_offset
    assert [(start, size) for start, size, _, _ in snapshot.open(0).table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x100),
    ]


@pytest.mark.parametrize("point", ["data", "metadata", "table", "footer"])
def test_asdf_fault_no_completed_snapshot(point: str) -> None:
    """A failure in any stage must never leave a file that looks complete."""
    with_metadata = point == "metadata"
    offset = failure_points(with_metadata=with_metadata)[point]

    fh = FaultyFile(fail_at=offset)
    writer = AsdfWriter(fh, block_crc=True)

    if point == "data":
        # The failure happens while adding data, so retry close afterwards
        with pytest.raises(OSError):
            writer.add_bytes(BLOCK_A, base=0)

        with pytest.raises(OSError):
            writer.close()
    else:
        writer = make_writer(fh, with_metadata=with_metadata)
        with pytest.raises(OSError):
            writer.close()

    partial = fh.getvalue()
    assert writer.failed is not None

    # Normal reading must refuse the file
    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(BytesIO(partial))

    if point != "footer":
        # A footer is only written once everything before it was accepted
        assert not partial.endswith(FOOTER_MAGIC)


@pytest.mark.parametrize("point", ["metadata", "table", "footer"])
def test_asdf_fault_close_stays_failed(point: str) -> None:
    """A failed close must re-raise on subsequent close attempts."""
    with_metadata = point == "metadata"
    offset = failure_points(with_metadata=with_metadata)[point]

    fh = FaultyFile(fail_at=offset)
    writer = make_writer(fh, with_metadata=with_metadata)

    with pytest.raises(OSError) as first:
        writer.close()

    assert writer.failed is first.value

    with pytest.raises(OSError) as second:
        writer.close()

    assert second.value is first.value


def test_asdf_fault_write_failure_makes_close_fail() -> None:
    """A failed data write is not turned into a successful close."""
    offset = failure_points()["data"]

    fh = FaultyFile(fail_at=offset)
    writer = AsdfWriter(fh, block_crc=True)

    with pytest.raises(OSError) as exc:
        writer.add_bytes(BLOCK_A, base=0)

    partial = fh.getvalue()
    assert not partial.endswith(FOOTER_MAGIC)

    with pytest.raises(OSError) as close_exc:
        writer.close()

    assert close_exc.value is exc.value

    # The diagnostic information of the original failure is preserved
    assert writer.failed is exc.value
    assert fh.getvalue() == partial


def test_asdf_fault_duplicate_close() -> None:
    """A successful close is idempotent and does not append anything."""
    fh = FaultyFile()
    writer = make_writer(fh)
    writer.close()
    data = fh.getvalue()

    writer.close()
    assert fh.getvalue() == data


def test_asdf_fault_write_after_close() -> None:
    """Writing after close must not change the file anymore."""
    fh = FaultyFile()
    writer = make_writer(fh)
    writer.close()
    data = fh.getvalue()

    with pytest.raises((ValueError, OSError)):
        writer.add_bytes(b"\xff" * 100, base=0x9000)

    assert fh.getvalue() == data


def test_asdf_fault_hash_reflects_accepted_bytes() -> None:
    """The footer hash must only cover the bytes that were actually accepted."""
    fh = FaultyFile()

    class ShortWrites(FaultyFile):
        def write(self, b: bytes) -> int:
            if isinstance(b, memoryview):
                b = bytes(b)
            return super().write(b[:7])

    short = ShortWrites()
    writer = make_writer(short)  # type: ignore[arg-type]
    writer.close()

    data = short.getvalue()
    footer_offset = len(data) - len(c_asdf.footer)
    snapshot = AsdfSnapshot(BytesIO(data))

    assert snapshot.footer.sha256 == hashlib.sha256(data[:footer_offset]).digest()
    assert [(start, size) for start, size, _, _ in snapshot.open(0).table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x100),
    ]
    assert snapshot.open(0).read(0x1000) == BLOCK_A


def test_asdf_fault_recover_truncated_block() -> None:
    """Recovery must not present a truncated block as complete data."""
    data, snapshot = build_snapshot()
    last_run = snapshot.table[0][-1]
    # Cut the file in the middle of the last block's data
    truncated = data[: last_run[3] + last_run[1] // 2]

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(BytesIO(truncated))

    reader = AsdfSnapshot(BytesIO(truncated), recover=True)
    runs = [(start, size) for start, size, _, _ in reader.open(0).table]

    # The interrupted block is not part of the recovered snapshot
    assert runs == [(0, 0x1000), (0x4000, 0x1000)]


def test_asdf_fault_recover_short_block_header() -> None:
    """A partial block header at the end of a file must not be recovered."""
    data, _ = build_snapshot()
    truncated = data[: len(c_asdf.header) + 10]

    reader = AsdfSnapshot(BytesIO(truncated), recover=True)
    assert dict(reader.table) == {}


def test_asdf_fault_recover_keeps_interruption_boundary() -> None:
    """Recovery of a failed close keeps exactly the complete blocks before the failure."""
    data, snapshot = build_snapshot()
    last_run = snapshot.table[0][-1]
    # Fail while writing the third block, before any of the closing data
    offset = last_run[3] + 50

    fh = FaultyFile(fail_at=offset)
    writer = AsdfWriter(fh, block_crc=True)
    writer.add_bytes(BLOCK_A, base=0)
    writer.add_bytes(BLOCK_B, base=0x4000)
    with pytest.raises(OSError):
        writer.add_bytes(BLOCK_C, base=0x8000)

    reader = AsdfSnapshot(BytesIO(fh.getvalue()), recover=True)
    assert [(start, size) for start, size, _, _ in reader.open(0).table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
    ]
    assert reader.open(0).read(0x5000) == BLOCK_A + (b"\xa5\xdf" * (0x3000 // 2)) + BLOCK_B


class CountingShortFile(io.BytesIO):
    """BytesIO that always accepts at most ``chunk`` bytes per write."""

    def __init__(self, chunk: int = 3, fail_after: int | None = None):
        super().__init__()
        self.chunk = chunk
        self.fail_after = fail_after

    def close(self) -> None:
        # Keep the buffer accessible for inspection after a writer closes us
        pass

    def write(self, b: bytes) -> int:
        if self.fail_after is not None and self.tell() >= self.fail_after:
            raise OSError("injected write failure")

        if not isinstance(b, (bytes, bytearray, memoryview)):
            b = bytes(b)

        return super().write(bytes(b)[: self.chunk])


def test_asdf_stream_short_writes_complete() -> None:
    """Wrappers retry short writes so the complete payload is stored and hashed."""
    fh = CountingShortFile(chunk=3)
    stream = HashedStream(Crc32Stream(fh))

    payload = b"short writes are retried"
    assert stream.write(payload) == len(payload)
    stream.finalize()

    assert fh.getvalue() == payload + stream.fh.digest()
    assert stream.hexdigest() == hashlib.sha256(payload).hexdigest()


def test_asdf_stream_failure_hashes_only_accepted() -> None:
    """A failure mid-write must only hash the bytes accepted before the failure."""
    fh = CountingShortFile(chunk=4, fail_after=10)
    stream = HashedStream(fh)

    with pytest.raises(OSError):
        stream.write(b"0123456789abcdef")

    # Three writes of 4 bytes were accepted, the fourth one failed before accepting anything
    accepted = b"0123456789ab"
    assert fh.getvalue() == accepted
    assert stream.hexdigest() == hashlib.sha256(accepted).hexdigest()


def test_asdf_writer_short_write_file() -> None:
    """A writer on a short-writing destination still produces a readable snapshot."""
    fh = CountingShortFile(chunk=5)
    writer = make_writer(fh)  # type: ignore[arg-type]
    writer.close()

    data = fh.getvalue()
    snapshot = AsdfSnapshot(BytesIO(data))

    assert snapshot.footer.sha256 == hashlib.sha256(data[: len(data) - len(c_asdf.footer)]).digest()
    assert snapshot.open(0).read(0x5000) == BLOCK_A + (b"\xa5\xdf" * (0x3000 // 2)) + BLOCK_B


def test_asdf_writer_compressed_short_write_file() -> None:
    """Compression with a short-writing destination still round-trips."""
    fh = CountingShortFile(chunk=5)
    writer = AsdfWriter(fh, compress=True)  # type: ignore[arg-type]
    writer.add_bytes(BLOCK_A, base=0)
    writer.close()

    # The reader doesn't transparently decompress, so verify the gzip stream itself
    snapshot = AsdfSnapshot(BytesIO(zlib.decompress(fh.getvalue(), wbits=31)))
    assert snapshot.open(0).read(0x1000) == BLOCK_A


class PartialFooterFile(FaultyFile):
    """Accept part of the footer, then fail, so a plausible footer magic can be present."""

    def __init__(self, footer_at: int, accept: int = 10):
        super().__init__()
        self.footer_at = footer_at
        self.accept = accept

    def write(self, b: bytes) -> int:
        if not isinstance(b, (bytes, bytearray, memoryview)):
            b = bytes(b)

        if self.tell() >= self.footer_at:
            remaining = self.footer_at + self.accept - self.tell()
            if remaining <= 0:
                raise OSError("injected footer failure")

            return super().write(bytes(b)[:remaining])

        return super().write(b)


def test_asdf_fault_partial_footer() -> None:
    """A partially written footer must not be accepted as a complete snapshot."""
    good = FaultyFile()
    writer = AsdfWriter(good)
    writer.add_bytes(BLOCK_A, base=0)
    writer.close()
    footer_at = len(good.getvalue()) - len(c_asdf.footer)

    fh = PartialFooterFile(footer_at)
    writer = AsdfWriter(fh)
    writer.add_bytes(BLOCK_A, base=0)

    with pytest.raises(OSError):
        writer.close()

    partial = fh.getvalue()
    # The footer magic was written, but the file is still incomplete
    assert partial[footer_at : footer_at + len(FOOTER_MAGIC)] == FOOTER_MAGIC

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(BytesIO(partial))

    # Recovery still finds the block that was completely written
    reader = AsdfSnapshot(BytesIO(partial), recover=True)
    assert [(start, size) for start, size, _, _ in reader.open(0).table] == [(0, 0x1000)]

    with pytest.raises(OSError) as exc:
        writer.close()

    assert writer.failed is exc.value
