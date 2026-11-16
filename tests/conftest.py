from __future__ import annotations

import gzip
import struct
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


HEADER_SIZE = 0x1000
CHECKSUM_OFFSET = 508
CHECKSUM_LENGTH = 508
SEQUENCE1_OFFSET = 4
SEQUENCE2_OFFSET = 8
HBIN_SIZE_OFFSET = HEADER_SIZE + 8


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file_gz(name: str) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        yield fh


def read_file_gz(name: str) -> bytes:
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        return fh.read()


@pytest.fixture
def system_hive() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/SYSTEM.gz")


@pytest.fixture
def bad_key_value_cell_hive() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/BadKeyValueCell.gz")


@pytest.fixture
def fastleaf_hive() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/FastLeaf.gz")


def xor32(data: bytes) -> int:
    checksum = 0
    for ii in struct.unpack(f"<{len(data) // 4}I", data):
        checksum ^= ii
    return checksum


def recalculate_checksum(data: bytearray) -> None:
    data[CHECKSUM_OFFSET : CHECKSUM_OFFSET + 4] = struct.pack("<I", xor32(bytes(data[:CHECKSUM_LENGTH])))


def build_hive(
    *,
    checksum_ok: bool = True,
    sequences_match: bool = True,
    hbin_out_of_bounds: bool = False,
) -> BytesIO:
    """Build one of the four integrity samples from the known-good CORRUPTVAL hive."""
    data = bytearray(read_file_gz("_data/BadKeyValueCell.gz"))

    if not sequences_match:
        data[SEQUENCE2_OFFSET : SEQUENCE2_OFFSET + 4] = struct.pack("<I", 0x12345678)

    if hbin_out_of_bounds:
        # Keep the header intact and make the first hbin claim to extend past
        # the declared end of the hive and the end of the file.
        data[HBIN_SIZE_OFFSET : HBIN_SIZE_OFFSET + 4] = struct.pack("<I", 0x9000)

    recalculate_checksum(data)

    if not checksum_ok:
        # Flip one bit in an otherwise unused header byte (Reserved1 starts at
        # 112) after calculating the checksum, so the stored checksum no longer
        # matches while the sequence numbers stay untouched.
        data[112] ^= 0xFF

    return BytesIO(bytes(data))
