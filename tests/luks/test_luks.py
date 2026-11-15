from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import struct
from typing import BinaryIO

import pytest

from dissect.fve.crypto import create_cipher
from dissect.fve.luks.c_luks import LUKS2_MAGIC_1ST, LUKS2_MAGIC_2ND
from dissect.fve.luks.luks import LUKS, derive_passphrase_key
from dissect.fve.luks.metadata import Keyslot
from tests._util import open_file_gz


def _verify_crypto_stream(luks_obj: LUKS) -> None:
    stream = luks_obj.open()
    for i in range(4):
        assert stream.read(512) == bytes([i] * 512)


def _verify_passphrase_crypto(test_file: BinaryIO, passphrase: str, cipher_type: str) -> None:
    luks_obj = LUKS(test_file)

    assert not luks_obj.unlocked
    assert luks_obj.keyslots

    try:
        luks_obj.unlock_with_passphrase(passphrase)
    except ValueError as e:
        if "Hashing failed: out of memory" in str(e):
            pytest.skip("Argon2 failed due to insufficient memory, skipping")
        raise

    assert luks_obj.find_segment(luks_obj._active_keyslot_id).encryption == cipher_type
    _verify_crypto_stream(luks_obj)


@pytest.mark.parametrize(
    ("test_file", "password", "cipher"),
    [
        pytest.param("_data/luks1/aes-ecb.bin.gz", "password", "aes-ecb", id="luks1-aes-ecb"),
        pytest.param("_data/luks1/sha1.bin.gz", "password", "aes-ecb", id="luks1-aes-ecb-sha1"),
        pytest.param("_data/luks2/aes-cbc-plain.bin.gz", "password", "aes-cbc-plain", id="luks2-aes-cbc-plain"),
        pytest.param("_data/luks2/aes-cbc-essiv.bin.gz", "password", "aes-cbc-essiv:sha256", id="luks2-aes-cbc-essiv"),
        pytest.param("_data/luks2/aes-ecb-pbkdf2.bin.gz", "password", "aes-ecb", id="luks2-aes-ecb-pbkdf2"),
        pytest.param("_data/luks2/aes-xts-plain64.bin.gz", "password", "aes-xts-plain64", id="luks2-aes-xts-plain64"),
        pytest.param("_data/luks2/multiple-slots.bin.gz", "password", "aes-cbc-plain", id="luks2-multiple-slots-1"),
        pytest.param("_data/luks2/multiple-slots.bin.gz", "another", "aes-cbc-plain", id="luks2-multiple-slots-2"),
        pytest.param(
            "_data/luks2/aes-ecb-binary-passphrase.bin.gz",
            b"\x00\x01\x02\x03KUSJESVANSRT\x03\x02\x01\x00",
            "aes-cbc-plain",
            id="luks2-aes-cbc-plain-binary-passphrase",
        ),
    ],
)
def test_luks(test_file: str, password: str, cipher: str, request: pytest.FixtureRequest) -> None:
    with contextlib.contextmanager(open_file_gz)(test_file) as fh:
        _verify_passphrase_crypto(fh, password, cipher)


def test_luks_kdf_pbkdf2() -> None:
    keyslot = Keyslot.from_dict(
        {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": "32768", "size": "131072", "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "pbkdf2",
                "hash": "sha256",
                "iterations": 3426718,
                "salt": "fmh2v7DaJ2D/tFkvvGB+mogBu3s+tUpDuKaf0vQyqIA=",
            },
        }
    )

    assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
        "05cff19a3cbc2d5612bdbcaee94db532b95b2cd33a997d1f2b30ffb166f302a6"
    )


def test_luks_kdf_argon2i() -> None:
    keyslot = Keyslot.from_dict(
        {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": "32768", "size": "131072", "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "argon2i",
                "time": 5,
                "memory": 1048576,
                "cpus": 4,
                "salt": "fsv0tZWR6Q/WkidkWY6p0jiP1A+am8CH8h3D8gYEoYE=",
            },
        }
    )

    try:
        assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
            "37f6085467d330749f59ea348491908a4faddabcb67523efc649419ecb52bd94"
        )
    except ValueError as e:
        if "Hashing failed: out of memory" in str(e):
            pytest.skip("Argon2 failed due to insufficient memory, skipping")
        raise


def test_luks_kdf_argon2id() -> None:
    keyslot = Keyslot.from_dict(
        {
            "type": "luks2",
            "key_size": 32,
            "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
            "area": {"type": "raw", "offset": "32768", "size": "131072", "encryption": "aes-ecb", "key_size": 32},
            "kdf": {
                "type": "argon2id",
                "time": 5,
                "memory": 1048576,
                "cpus": 4,
                "salt": "yssVZKHcjdSON4vM096WRyzZBWfz5Pf+a08cRzPdcZg=",
            },
        }
    )

    try:
        assert derive_passphrase_key(b"password", keyslot) == bytes.fromhex(
            "15b7b31551e6df90e6dbc58bb5dbc5f82efa8f36fdab9422f8a9bdfa72a8af85"
        )
    except ValueError as e:
        if "Hashing failed: out of memory" in str(e):
            pytest.skip("Argon2 failed due to insufficient memory, skipping")
        raise


DETACHED_HEADER_SIZE = 0x4000
DETACHED_KEYSLOT_OFFSET = 0x8000
DETACHED_KEYSLOT_AREA_SIZE = 0x1000
DETACHED_SEGMENT_OFFSET = 0x10000


def _build_luks2_layout(passphrase: bytes, volume_key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """Build a synthetic LUKS2 layout with a known passphrase.

    Returns a tuple of (combined image, detached header, detached data image). The detached
    data image keeps the segment at the same absolute offset as the combined image, like a
    real data device used with ``cryptsetup --header``.
    """
    key_size = len(volume_key)
    kdf_salt = b"k" * 32
    digest_salt = b"d" * 32
    iterations = 1000

    kek = hashlib.pbkdf2_hmac("sha256", passphrase, kdf_salt, iterations, key_size)
    # A single AF stripe makes the split an identity operation
    keyslot_area = create_cipher("aes-ecb", kek, key_size * 8).encrypt(volume_key)

    digest = hashlib.pbkdf2_hmac("sha256", volume_key, digest_salt, iterations, key_size)

    metadata = {
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": key_size,
                "af": {"type": "luks1", "stripes": 1, "hash": "sha256"},
                "area": {
                    "type": "raw",
                    "offset": str(DETACHED_KEYSLOT_OFFSET),
                    "size": str(DETACHED_KEYSLOT_AREA_SIZE),
                    "encryption": "aes-ecb",
                    "key_size": key_size,
                },
                "kdf": {
                    "type": "pbkdf2",
                    "hash": "sha256",
                    "iterations": iterations,
                    "salt": base64.b64encode(kdf_salt).decode(),
                },
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": [0],
                "segments": [0],
                "hash": "sha256",
                "iterations": iterations,
                "salt": base64.b64encode(digest_salt).decode(),
                "digest": base64.b64encode(digest).decode(),
            }
        },
        "segments": {
            "0": {
                "type": "crypt",
                "offset": str(DETACHED_SEGMENT_OFFSET),
                "size": str(len(plaintext)),
                "iv_tweak": "0",
                "encryption": "aes-cbc-plain",
                "sector_size": "512",
            }
        },
        "tokens": {},
        "config": {
            "json_size": str(DETACHED_HEADER_SIZE - 4096),
            "keyslots_size": str(DETACHED_KEYSLOT_OFFSET - DETACHED_HEADER_SIZE),
        },
    }
    json_area = json.dumps(metadata).encode()
    assert len(json_area) <= DETACHED_HEADER_SIZE - 4096

    binary_header = struct.pack(
        ">6sHQQ48s32s64s40s48sQ184s64s3584s",
        LUKS2_MAGIC_1ST,
        2,
        DETACHED_HEADER_SIZE,
        1,
        b"",
        b"sha256",
        b"s" * 64,
        b"12345678-1234-1234-1234-123456789abc",
        b"",
        0,
        b"",
        b"",
        b"",
    )
    assert len(binary_header) == 4096
    secondary_header = LUKS2_MAGIC_2ND + binary_header[6:]

    header = bytearray(DETACHED_KEYSLOT_OFFSET + DETACHED_KEYSLOT_AREA_SIZE)
    header[0:4096] = binary_header
    header[4096 : 4096 + len(json_area)] = json_area
    header[DETACHED_HEADER_SIZE : DETACHED_HEADER_SIZE + 4096] = secondary_header
    header[DETACHED_HEADER_SIZE + 4096 : DETACHED_HEADER_SIZE + 4096 + len(json_area)] = json_area
    header[DETACHED_KEYSLOT_OFFSET : DETACHED_KEYSLOT_OFFSET + len(keyslot_area)] = keyslot_area

    ciphertext = create_cipher("aes-cbc-plain", volume_key, key_size * 8, 512, 512).encrypt(plaintext)

    data = b"\x00" * DETACHED_SEGMENT_OFFSET + ciphertext
    combined = bytes(header) + b"\x00" * (DETACHED_SEGMENT_OFFSET - len(header)) + ciphertext
    return combined, bytes(header), data


def test_luks_detached_header_matches_single_file() -> None:
    plaintext = b"".join(bytes([i] * 512) for i in range(4))
    combined, header, data = _build_luks2_layout(b"password", bytes(range(32)), plaintext)

    single = LUKS(io.BytesIO(combined))
    single.unlock_with_passphrase("password")
    assert single.open().read() == plaintext

    header_fh = io.BytesIO(header)
    data_fh = io.BytesIO(data)
    detached = LUKS(header_fh, data_fh)
    detached.unlock_with_passphrase("password")
    assert detached.open().read() == plaintext

    assert not header_fh.closed
    assert not data_fh.closed


def test_luks_detached_header_swapped_data_image() -> None:
    plaintext_a = b"".join(bytes([i] * 512) for i in range(4))
    plaintext_b = b"".join(bytes([255 - i] * 512) for i in range(4))
    _, header_a, _ = _build_luks2_layout(b"password-a", bytes(range(32)), plaintext_a)
    _, _, data_b = _build_luks2_layout(b"password-b", bytes(range(32, 64)), plaintext_b)

    header_fh = io.BytesIO(header_a)
    data_fh = io.BytesIO(data_b)
    luks_obj = LUKS(header_fh, data_fh)

    # Key material only comes from the header source, so unlocking still works
    luks_obj.unlock_with_passphrase("password-a")
    assert luks_obj.unlocked

    # The swapped data image only surfaces as wrong plaintext, not as a key material error
    assert luks_obj.open().read() != plaintext_a

    assert not header_fh.closed
    assert not data_fh.closed


def test_luks_detached_header_truncated_header() -> None:
    plaintext = b"".join(bytes([i] * 512) for i in range(4))
    combined, header, _ = _build_luks2_layout(b"password", bytes(range(32)), plaintext)

    # Truncate inside the keyslot area
    header_fh = io.BytesIO(header[: DETACHED_KEYSLOT_OFFSET + 16])
    # The data image carries a full combined layout, including valid keyslot bytes at the
    # keyslot offset, but key material must not be assembled across the two sources
    data_fh = io.BytesIO(combined)

    with pytest.raises(ValueError, match="header source"):
        LUKS(header_fh, data_fh)

    assert not header_fh.closed
    assert not data_fh.closed


def test_luks_detached_header_truncated_data_image() -> None:
    plaintext = b"".join(bytes([i] * 512) for i in range(4))
    _, header, data = _build_luks2_layout(b"password", bytes(range(32)), plaintext)

    header_fh = io.BytesIO(header)
    data_fh = io.BytesIO(data[:-512])

    luks_obj = LUKS(header_fh, data_fh)
    luks_obj.unlock_with_passphrase("password")
    assert luks_obj.unlocked

    with pytest.raises(ValueError, match="data image"):
        luks_obj.open()

    assert not header_fh.closed
    assert not data_fh.closed
