"""Plaintext size matrix spanning every OLE layout transition.

Sizes are plaintext ("original package") byte lengths fed to the Agile
encryption. The matrix brackets three distinct boundary families:

* mini-stream region  -- EncryptedPackage <= 4096 bytes lands (incorrectly, see
  the validator) in the mini stream instead of the regular FAT;
* regular FAT growth  -- each additional FAT sector covers another 128 data
  sectors (~65 KiB);
* DIFAT extension     -- once more than 109 FAT sectors are needed, the header
  DIFAT overflows into dedicated DIFAT sectors (empirically at plaintext 7083505).

``expect_mini`` is a property of the *container*, derived from the encrypted
package length, not an assumption hard-coded here.
"""

from __future__ import annotations

import math

#: Empirically located first plaintext size that forces a DIFAT sector.
DIFAT_ONSET_PLAINTEXT = 7_083_505

#: Plaintext sizes one 4096-byte crypto segment below/at the DIFAT onset.
_DIFAT_SEG = (DIFAT_ONSET_PLAINTEXT // 4096) * 4096

#: The labelled matrix. Each entry: (label, plaintext_size, region tag).
MATRIX_SIZES = [
    # --- mini-stream / EncryptedPackage <= 4096 (the writer's broken region) ---
    ("empty", 0, "mini"),
    ("one-byte", 1, "mini"),
    ("mini-63B-boundary", 63, "mini"),
    ("mini-64B-boundary", 64, "mini"),
    ("mini-65B-boundary", 65, "mini"),
    ("mini-128B-boundary", 128, "mini"),
    ("mini-mid", 1500, "mini"),
    ("mini-near-cutoff", 3000, "mini"),
    ("pkg-4088-cutoff", 4080, "mini"),          # package length 4088 (<=4096)
    ("pkg-4104-above-cutoff", 4087, "regular"),  # package length 4104 (>4096)
    ("one-sector-regular", 5000, "regular"),

    # --- regular FAT, a few sectors in ---
    ("regular-64k", 64_000, "regular"),
    ("regular-256k", 256_000, "regular"),
    ("regular-1m", 1_000_000, "regular"),

    # --- FAT sector growth approaching the 109-sector header DIFAT limit ---
    ("fat-108-sector", 7_016_448, "regular"),
    ("fat-109-sector", 7_081_984, "regular"),

    # --- DIFAT extension boundary (one byte and one crypto segment either side) ---
    ("difat-prev-segment", _DIFAT_SEG - 4096, "regular"),
    ("difat-onset-segment", _DIFAT_SEG, "difat"),
    ("difat-onset-minus-one", DIFAT_ONSET_PLAINTEXT - 1, "regular"),
    ("difat-onset-plus-one", DIFAT_ONSET_PLAINTEXT, "difat"),
    ("difat-next-segment", _DIFAT_SEG + 4096, "difat"),

    # --- comfortably inside the DIFAT region, multiple DIFAT pointers used ---
    ("difat-deep-7p3m", 7_300_000, "difat"),
]


def package_length(plaintext_size: int) -> int:
    """EncryptedPackage stream length for a plaintext of this size.

    Layout: an 8-byte little-endian original-size prefix, then 4096-byte
    crypto segments. Only the *final* segment is padded up to the 16-byte AES
    block size; full preceding segments stay exactly 4096 bytes. An empty
    plaintext yields just the 8-byte prefix.
    """
    if plaintext_size == 0:
        return 8
    segments = math.ceil(plaintext_size / 4096)
    last_plain = plaintext_size - (segments - 1) * 4096
    last_enc = math.ceil(last_plain / 16) * 16
    return 8 + (segments - 1) * 4096 + last_enc


def package_uses_mini_stream(plaintext_size: int) -> bool:
    """Whether the writer routes EncryptedPackage through the mini stream."""
    return package_length(plaintext_size) <= 4096


def matrix_entries():
    """Yield (label, size, region, goes_mini) for every matrix row."""
    for label, size, region in MATRIX_SIZES:
        yield label, size, region, package_uses_mini_stream(size)
