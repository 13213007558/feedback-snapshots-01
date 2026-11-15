from __future__ import annotations

import hashlib
import io
from typing import BinaryIO

import pytest

from dissect.evidence.asdf.asdf import (
    BLOCK_MAGIC,
    FOOTER_MAGIC,
    IDX_METADATA,
    AsdfSnapshot,
    AsdfWriter,
)
from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.asdf.stream import HashedStream
from dissect.evidence.exception import InvalidSnapshot

BLOCK_SIZE = 4096
HEADER_SIZE = len(c_asdf.header)
BLOCK_HEADER_SIZE = len(c_asdf.block)
FOOTER_SIZE = len(c_asdf.footer)


class FaultyFile(io.RawIOBase):
    """In-memory file object that can fail or short write at a byte boundary.

    Two independent injection modes are supported, both keyed on the absolute
    number of bytes accepted so far (the physical file position):

        - ``fail_at``: accept bytes up to this boundary, then raise
          ``exc`` on the first write that would cross it.
        - ``short_write_at``: the first write that would cross this boundary
          only accepts ``short_amount`` bytes instead of raising. Subsequent
          writes proceed normally, which lets callers prove they retry.

    The buffer is never cleared on close so the partial snapshot survives for
    inspection, mirroring the ``asdf_writer`` fixture.
    """

    def __init__(
        self,
        fail_at: int | None = None,
        exc: Exception | None = None,
        short_write_at: int | None = None,
        short_amount: int = 1,
    ):
        self.buf = bytearray()
        self.fail_at = fail_at
        self.exc = exc if exc is not None else OSError("injected write failure")
        self.short_write_at = short_write_at
        self.short_amount = short_amount
        self.armed = False
        self.close_count = 0
        self.flush_count = 0

    def arm(self) -> None:
        """Enable a previously configured failure or short-write point."""
        self.armed = True

    def write(self, b: bytes) -> int:
        position = len(self.buf)

        if self.armed and self.fail_at is not None and position < self.fail_at <= position + len(b):
            accepted = self.fail_at - position
            self.buf.extend(b[:accepted])
            raise self.exc

        if (
            self.armed
            and self.short_write_at is not None
            and position < self.short_write_at <= position + len(b)
        ):
            self.short_write_at = None
            self.buf.extend(b[: self.short_amount])
            return self.short_amount

        self.buf.extend(b)
        return len(b)

    def tell(self) -> int:
        return len(self.buf)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence != io.SEEK_SET:
            raise NotImplementedError
        if offset < len(self.buf):
            del self.buf[offset:]
        return offset

    def read(self, size: int = -1) -> bytes:
        return bytes(self.buf)

    def flush(self) -> None:
        self.flush_count += 1

    def close(self) -> None:
        self.close_count += 1

    @property
    def data(self) -> bytes:
        return bytes(self.buf)


def populate(writer: AsdfWriter) -> AsdfWriter:
    writer.add_bytes(b"\xaa" * BLOCK_SIZE, idx=0, base=0)
    writer.add_bytes(b"\xbb" * BLOCK_SIZE, idx=0, base=BLOCK_SIZE)
    writer.add_metadata_file("info", io.BytesIO(b"diagnostic"))
    return writer


def writer_with_first_block(fh: BinaryIO) -> AsdfWriter:
    """Stage a writer whose next data block is the second disk block."""
    writer = AsdfWriter(fh)
    writer.add_bytes(b"\xaa" * BLOCK_SIZE, idx=0, base=0)
    return writer


def block_positions(data: bytes) -> list[int]:
    positions = []
    start = 0
    while True:
        needle = data.find(BLOCK_MAGIC, start)
        if needle == -1:
            break
        positions.append(needle)
        start = needle + 1
    return positions


@pytest.fixture
def complete_layout() -> bytes:
    fh = FaultyFile()
    populate(AsdfWriter(fh)).close()
    return fh.data


def assert_poisoned(writer: AsdfWriter, fh: FaultyFile) -> None:
    # The failure is sticky and cannot turn into a successful close.
    with pytest.raises(OSError):
        writer.close()
    assert isinstance(writer._close_error, OSError)
    # The destination stays open so the caller keeps the partial data.
    assert fh.close_count == 0
    # No footer means the file can never look complete.
    assert FOOTER_MAGIC not in fh.data


def assert_well_formed(data: bytes) -> None:
    """Read a snapshot through the normal entry point and check its payload."""
    snapshot = AsdfSnapshot(io.BytesIO(data))
    stream = snapshot.open(0)
    assert stream.read() == (b"\xaa" * BLOCK_SIZE) + (b"\xbb" * BLOCK_SIZE)
    assert snapshot.metadata.names() == ["info"]
    assert snapshot.metadata.open("info").read() == b"diagnostic"


def test_faulty_file_records_a_complete_layout(complete_layout: bytes) -> None:
    footer_offset = len(complete_layout) - FOOTER_SIZE
    assert complete_layout[:4] == b"ASDF"
    assert complete_layout[footer_offset : footer_offset + 4] == FOOTER_MAGIC
    assert block_positions(complete_layout) == [48, 4172, 8296]


def test_data_block_write_failure_poisons_writer(complete_layout: bytes) -> None:
    positions = block_positions(complete_layout)
    # Fail 100 bytes into the data region of the second block.
    fail_at = positions[1] + BLOCK_HEADER_SIZE + 100

    fh = FaultyFile(fail_at=fail_at)
    writer = writer_with_first_block(fh)
    fh.arm()

    with pytest.raises(OSError):
        writer.add_bytes(b"\xbb" * BLOCK_SIZE, idx=0, base=BLOCK_SIZE)
    assert_poisoned(writer, fh)

    # The file is cut exactly at the interruption boundary. Bytes after the
    # instance-specific header (timestamp, GUID) match a healthy snapshot.
    assert len(fh.data) == fail_at
    assert fh.data[HEADER_SIZE:] == complete_layout[HEADER_SIZE:fail_at]


def test_data_block_failure_normal_entry_rejects(complete_layout: bytes) -> None:
    positions = block_positions(complete_layout)
    fail_at = positions[1] + BLOCK_HEADER_SIZE + 100

    fh = FaultyFile(fail_at=fail_at)
    writer = writer_with_first_block(fh)
    fh.arm()
    with pytest.raises(OSError):
        writer.add_bytes(b"\xbb" * BLOCK_SIZE, idx=0, base=BLOCK_SIZE)

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(io.BytesIO(fh.data))


def test_data_block_failure_recovery_preserves_boundary(complete_layout: bytes) -> None:
    positions = block_positions(complete_layout)
    fail_at = positions[1] + BLOCK_HEADER_SIZE + 100

    fh = FaultyFile(fail_at=fail_at)
    writer = writer_with_first_block(fh)
    fh.arm()
    with pytest.raises(OSError):
        writer.add_bytes(b"\xbb" * BLOCK_SIZE, idx=0, base=BLOCK_SIZE)

    recovered = AsdfSnapshot(io.BytesIO(fh.data), recover=True)
    stream = recovered.open(0)

    # Both block headers reached disk, including the truncated one.
    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, BLOCK_SIZE),
        (BLOCK_SIZE, BLOCK_SIZE),
    ]

    # The fully accepted block reads back intact.
    assert stream.read(BLOCK_SIZE) == b"\xaa" * BLOCK_SIZE
    # The interrupted block only yields the bytes that actually landed.
    partial = stream.read(BLOCK_SIZE)
    assert partial == b"\xbb" * (fail_at - positions[1] - BLOCK_HEADER_SIZE)
    assert len(partial) < BLOCK_SIZE

    # The metadata block never started, so there is no metadata stream.
    assert IDX_METADATA not in recovered.table


def test_short_write_is_retried_and_keeps_format_compatible(complete_layout: bytes) -> None:
    positions = block_positions(complete_layout)
    # Inject a short write inside the first block's data region.
    short_at = positions[0] + BLOCK_HEADER_SIZE + 123

    fh = FaultyFile(short_write_at=short_at, short_amount=7)
    writer = populate(AsdfWriter(fh))
    fh.arm()
    writer.close()

    # The retry loop still produces a fully readable, well-formed snapshot.
    assert len(fh.data) == len(complete_layout)
    assert_well_formed(fh.data)


def test_hash_only_covers_accepted_bytes() -> None:
    class FailAfter(io.RawIOBase):
        def __init__(self, limit: int):
            self.limit = limit
            self.buf = bytearray()

        def write(self, b: bytes) -> int:
            remaining = self.limit - len(self.buf)
            if remaining <= 0:
                raise OSError("no space left")
            accepted = min(remaining, len(b))
            self.buf.extend(b[:accepted])
            return accepted

    payload = b"abcdefghij" * 200
    raw = FailAfter(50)
    hashed = HashedStream(raw)
    with pytest.raises(OSError):
        hashed.write(payload)

    accepted = bytes(raw.buf)
    assert len(accepted) == 50
    assert hashed.digest() == hashlib.sha256(accepted).digest()
    assert hashed.digest() != hashlib.sha256(payload).digest()


def test_zero_progress_write_raises() -> None:
    class ZeroProgress(io.RawIOBase):
        def write(self, b: bytes) -> int:
            return 0

    hashed = HashedStream(ZeroProgress())
    with pytest.raises(OSError):
        hashed.write(b"data")
    # Empty writes remain valid no-ops.
    assert hashed.write(b"") == 0


def test_metadata_finalization_failure_poisons_writer(complete_layout: bytes) -> None:
    positions = block_positions(complete_layout)
    # Fail partway through the metadata block's data region.
    fail_at = positions[2] + BLOCK_HEADER_SIZE + 20

    fh = FaultyFile(fail_at=fail_at)
    writer = populate(AsdfWriter(fh))
    fh.arm()

    with pytest.raises(OSError):
        writer.close()
    assert_poisoned(writer, fh)
    assert len(fh.data) == fail_at

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(io.BytesIO(fh.data))

    recovered = AsdfSnapshot(io.BytesIO(fh.data), recover=True)
    # The data blocks are untouched and still readable.
    stream = recovered.open(0)
    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, BLOCK_SIZE),
        (BLOCK_SIZE, BLOCK_SIZE),
    ]
    assert stream.read(BLOCK_SIZE) == b"\xaa" * BLOCK_SIZE
    # The truncated metadata entry is visible but cannot be opened as a tar.
    assert IDX_METADATA in recovered.table
    assert recovered.metadata.names() == []


def test_footer_write_failure_poisons_writer(complete_layout: bytes) -> None:
    footer_offset = len(complete_layout) - FOOTER_SIZE

    fh = FaultyFile(fail_at=footer_offset)
    writer = populate(AsdfWriter(fh))
    fh.arm()

    with pytest.raises(OSError):
        writer.close()
    assert_poisoned(writer, fh)

    # Everything up to and including the block table is on disk.
    assert len(fh.data) == footer_offset

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(io.BytesIO(fh.data))

    recovered = AsdfSnapshot(io.BytesIO(fh.data), recover=True)
    stream = recovered.open(0)
    assert stream.read(BLOCK_SIZE) == b"\xaa" * BLOCK_SIZE
    assert stream.read(BLOCK_SIZE) == b"\xbb" * BLOCK_SIZE
    assert recovered.metadata.open("info").read() == b"diagnostic"


def test_repeated_close_is_idempotent_on_success() -> None:
    fh = FaultyFile()
    writer = populate(AsdfWriter(fh))
    writer.close()
    writer.close()
    writer.close()

    assert fh.close_count == 1
    assert_well_formed(fh.data)


def test_footer_hash_matches_accepted_bytes(complete_layout: bytes) -> None:
    footer_offset = len(complete_layout) - FOOTER_SIZE
    footer = c_asdf.footer(io.BytesIO(complete_layout[footer_offset:]))
    expected = hashlib.sha256(complete_layout[:footer_offset]).digest()
    assert footer.sha256 == expected


def test_diagnostics_survive_failed_close(complete_layout: bytes) -> None:
    positions = block_positions(complete_layout)
    boundary = positions[1] + BLOCK_HEADER_SIZE + 100

    broken = FaultyFile(fail_at=boundary)
    writer = writer_with_first_block(broken)
    broken.arm()
    with pytest.raises(OSError):
        writer.add_bytes(b"\xbb" * BLOCK_SIZE, idx=0, base=BLOCK_SIZE)

    # The caller can still copy the accepted bytes for diagnostics, and the
    # stored exception carries the original failure details.
    diagnostic = bytes(broken.data)
    assert len(diagnostic) == boundary
    assert diagnostic[HEADER_SIZE:] == complete_layout[HEADER_SIZE:boundary]
    assert str(writer._close_error) == "injected write failure"
    assert broken.close_count == 0
