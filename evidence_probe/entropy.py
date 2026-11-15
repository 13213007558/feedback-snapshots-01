"""Shannon entropy helper used by the L1 statistical smell detector."""

from __future__ import annotations

import math
from typing import BinaryIO

# Mirrors the threshold dissect.fve itself uses in is_veracrypt_volume().
VERACRYPT_ENTROPY_THRESHOLD = 7.9
SMELL_SAMPLE_BYTES = 4096
SECTOR_SIZE = 512


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def stream_size(fh: BinaryIO) -> int:
    """Best-effort total size without assuming a ``.size`` attribute."""
    if hasattr(fh, "size"):
        return int(fh.size)  # type: ignore[attr-defined]
    current = fh.tell()
    end = fh.seek(0, 2)  # SEEK_END
    fh.seek(current)
    return end
