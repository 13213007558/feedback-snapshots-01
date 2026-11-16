from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass

from dissect.fve.crypto import create_cipher
from dissect.fve.crypto.util import xor
from dissect.fve.luks import af
from dissect.fve.luks.c_luks import LUKS2_MAGIC_1ST, LUKS2_MAGIC_2ND, c_luks

SECTOR_SIZE = 512
HEADER_SIZE = 0x4000
KEY_SIZE = 32
STRIPES = 1000
PAYLOAD_OFFSET = 0x10000
PASSPHRASE = b"password"

# Distinct, easy to recognize plaintext blocks
PLAINTEXT = b"".join(bytes([i]) * SECTOR_SIZE for i in range(4))
OTHER_PLAINTEXT = b"".join(bytes([0xF0 + i]) * SECTOR_SIZE for i in range(4))


@dataclass
class Layout:
    """A generated LUKS volume in its equivalent single-file and detached forms."""

    passphrase: bytes
    volume_key: bytes
    plaintext: bytes
    single: bytes
    header: bytes
    data: bytes


def _split_key(key: bytes, key_size: int, stripes: int, hash_spec: str) -> bytes:
    """Create an encrypted AF-split keyslot area that merges back into ``key``."""
    blocks = [secrets.token_bytes(key_size) for _ in range(stripes - 1)]

    tmp = bytearray(key_size)
    for block in blocks:
        xor(block, tmp, output=tmp)
        tmp[:] = af.diffuse(bytes(tmp), hash_spec)

    last = bytes(a ^ b for a, b in zip(key, tmp, strict=True))
    return b"".join(blocks) + last


def _encrypt_keyslot(key: bytes, kek: bytes, key_size: int, stripes: int, hash_spec: str) -> bytes:
    split = _split_key(key, key_size, stripes, hash_spec)
    cipher = create_cipher("aes-ecb", kek, key_size * 8)
    return cipher.encrypt(split)


def _encrypt_payload(plaintext: bytes, key: bytes, key_size: int) -> bytes:
    cipher = create_cipher("aes-ecb", key, key_size * 8)
    return cipher.encrypt(plaintext)


def _pbkdf2(passphrase: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase, salt, iterations, length)


def build_luks1(
    passphrase: bytes = PASSPHRASE,
    volume_key: bytes | None = None,
    plaintext: bytes = PLAINTEXT,
) -> Layout:
    vk = volume_key or secrets.token_bytes(KEY_SIZE)
    salt = secrets.token_bytes(32)
    iterations = 1000
    keyslot_offset = 8 * SECTOR_SIZE

    kek = _pbkdf2(passphrase, salt, iterations, KEY_SIZE)
    material = _encrypt_keyslot(vk, kek, KEY_SIZE, STRIPES, "sha256")

    header = c_luks.luks_phdr()
    header.magic = b"LUKS\xba\xbe"
    header.version = 1
    header.cipherName = b"aes"
    header.cipherMode = b"ecb"
    header.hashSpec = b"sha256"
    header.payloadOffset = PAYLOAD_OFFSET // SECTOR_SIZE
    header.keyBytes = KEY_SIZE
    header.mkDigestSalt = secrets.token_bytes(32)
    header.mkDigestIterations = iterations
    header.mkDigest = _pbkdf2(vk, header.mkDigestSalt, iterations, 20)
    header.uuid = b"11111111-2222-3333-4444-555555555555\x00\x00\x00\x00"

    keyblock = header.keyblock[0]
    keyblock.active = c_luks.LUKS_KEY_ENABLED
    keyblock.passwordIterations = iterations
    keyblock.passwordSalt = salt
    keyblock.keyMaterialOffset = keyslot_offset // SECTOR_SIZE
    keyblock.stripes = STRIPES

    header_area = bytearray(header.dumps().ljust(HEADER_SIZE, b"\x00"))
    image = bytearray(max(keyslot_offset + len(material), PAYLOAD_OFFSET))
    image[:HEADER_SIZE] = header_area
    image[keyslot_offset : keyslot_offset + len(material)] = material
    image.extend(b"\x00" * (PAYLOAD_OFFSET - len(image)))
    image.extend(_encrypt_payload(plaintext, vk, KEY_SIZE))

    return Layout(
        passphrase=passphrase,
        volume_key=vk,
        plaintext=plaintext,
        single=bytes(image),
        # A real detached header carries the complete keyslot area up to the payload offset
        header=bytes(image[:PAYLOAD_OFFSET]),
        data=bytes(image),
    )


def build_luks2(
    passphrase: bytes = PASSPHRASE,
    volume_key: bytes | None = None,
    plaintext: bytes = PLAINTEXT,
) -> Layout:
    vk = volume_key or secrets.token_bytes(KEY_SIZE)
    salt = secrets.token_bytes(32)
    digest_salt = secrets.token_bytes(32)
    iterations = 1000
    keyslot_offset = 0x8000
    keyslot_size = PAYLOAD_OFFSET - keyslot_offset

    kek = _pbkdf2(passphrase, salt, iterations, KEY_SIZE)
    material = _encrypt_keyslot(vk, kek, KEY_SIZE, STRIPES, "sha256")
    assert len(material) <= keyslot_size

    metadata = {
        "keyslots": {
            "0": {
                "type": "luks2",
                "key_size": KEY_SIZE,
                "af": {"type": "luks1", "stripes": STRIPES, "hash": "sha256"},
                "area": {
                    "type": "raw",
                    "offset": str(keyslot_offset),
                    "size": str(keyslot_size),
                    "encryption": "aes-ecb",
                    "key_size": KEY_SIZE,
                },
                "kdf": {
                    "type": "pbkdf2",
                    "hash": "sha256",
                    "iterations": iterations,
                    "salt": base64.b64encode(salt).decode(),
                },
            }
        },
        "digests": {
            "0": {
                "type": "pbkdf2",
                "keyslots": ["0"],
                "segments": ["0"],
                "hash": "sha256",
                "iterations": iterations,
                "salt": base64.b64encode(digest_salt).decode(),
                "digest": base64.b64encode(_pbkdf2(vk, digest_salt, iterations, 32)).decode(),
            }
        },
        "segments": {
            "0": {
                "type": "crypt",
                "offset": str(PAYLOAD_OFFSET),
                "size": "dynamic",
                "iv_tweak": "0",
                "encryption": "aes-ecb",
                "sector_size": SECTOR_SIZE,
            }
        },
        "tokens": {},
        "config": {"json_size": str(HEADER_SIZE - 4096), "keyslots_size": str(keyslot_size)},
    }
    json_area = json.dumps(metadata, separators=(",", ":")).encode()

    def build_header(hdr_offset: int, seqid: int) -> bytes:
        hdr = c_luks.luks2_hdr_disk()
        # LUKS2 stores the secondary header magic in reverse byte order
        hdr.magic = LUKS2_MAGIC_1ST if hdr_offset == 0 else LUKS2_MAGIC_2ND
        hdr.version = 2
        hdr.hdr_size = HEADER_SIZE
        hdr.seqid = seqid
        hdr.label = b"\x00" * 48
        hdr.checksum_alg = b"sha256".ljust(32, b"\x00")
        hdr.salt = secrets.token_bytes(64)
        hdr.uuid = b"11111111-2222-3333-4444-666666666666\x00\x00\x00\x00"
        hdr.subsystem = b"\x00" * 48
        hdr.hdr_offset = hdr_offset
        hdr.csum = b"\x00" * 64

        blob = bytearray(hdr.dumps())
        blob[4096 : 4096 + len(json_area)] = json_area
        checksum = hashlib.sha256(blob).digest()
        hdr.csum = checksum + b"\x00" * (64 - len(checksum))
        return (hdr.dumps() + bytes(blob[4096:])).ljust(HEADER_SIZE, b"\x00")

    header_blob = build_header(0, 1) + build_header(HEADER_SIZE, 2)

    image = bytearray(PAYLOAD_OFFSET)
    image[: len(header_blob)] = header_blob
    image[keyslot_offset : keyslot_offset + len(material)] = material
    image.extend(_encrypt_payload(plaintext, vk, KEY_SIZE))

    return Layout(
        passphrase=passphrase,
        volume_key=vk,
        plaintext=plaintext,
        single=bytes(image),
        # A real detached header carries the entire declared keyslot area
        header=bytes(image[:PAYLOAD_OFFSET]),
        data=bytes(image),
    )
