"""From-scratch MS-OFFCRYPTO Agile decryption and integrity verification.

This is an independent re-implementation used to prove the produced containers
are genuine Agile-encrypted Office files, not merely artifacts that
msoffcrypto can read back. It relies only on ``olefile`` (container parsing)
and ``cryptography`` (AES/HMAC/SHA). None of msoffcrypto's decrypt code is
called.

Steps (per MS-OFFCRYPTO 2.3.4.1):

1. Read the ``EncryptionInfo`` stream and parse the Agile XML descriptor.
2. Re-derive the password hash (salt + UTF-16 password, spun ``spinCount``
   times) and the secret key via the encryptedKeyValue block key.
3. AES-CBC decrypt every 4096-byte segment of ``EncryptedPackage`` using the
   per-segment IV = hash(keyDataSalt || blockId) truncated to 16 bytes.
4. Truncate to the original size stored in the leading 8-byte prefix.
5. Recompute the data-integrity HMAC and compare against the descriptor.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import olefile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_KEY_ENCRYPTED_KEY = bytes([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])
BLOCK_KEY_INTEGRITY_1 = bytes([0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6])
BLOCK_KEY_INTEGRITY_2 = bytes([0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33])
SEGMENT_LENGTH = 4096

_HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
           "SHA384": hashlib.sha384, "SHA512": hashlib.sha512}
_NS = {"enc": "http://schemas.microsoft.com/office/2006/encryption",
       "p": "http://schemas.microsoft.com/office/2006/keyEncryptor/password"}


@dataclass
class CryptoResult:
    plaintext: bytes
    integrity_ok: bool
    password_verified: bool
    hash_algorithm: str
    segment_count: int


def _aes_cbc_decrypt(data, key, iv):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _parse_descriptor(encryption_info: bytes):
    # The stream begins with a 4-byte version + 4-byte header-size prefix.
    xml_bytes = encryption_info[8:]
    root = ET.fromstring(xml_bytes)
    key_data = root.find("enc:keyData", _NS)
    integrity = root.find("enc:dataIntegrity", _NS)
    enc_key = root.find(".//p:encryptedKey", _NS)

    def b64(node, attr):
        return base64.b64decode(node.get(attr))

    return {
        "keyDataSalt": b64(key_data, "saltValue"),
        "hashAlgorithm": key_data.get("hashAlgorithm"),
        "keyBits": int(key_data.get("keyBits")),
        "blockSize": int(key_data.get("blockSize")),
        "spinCount": int(enc_key.get("spinCount")),
        "passwordSalt": b64(enc_key, "saltValue"),
        "encryptedKeyValue": b64(enc_key, "encryptedKeyValue"),
        "encryptedVerifierHashInput": b64(enc_key, "encryptedVerifierHashInput"),
        "encryptedVerifierHashValue": b64(enc_key, "encryptedVerifierHashValue"),
        "encryptedHmacKey": b64(integrity, "encryptedHmacKey"),
        "encryptedHmacValue": b64(integrity, "encryptedHmacValue"),
    }


def _derive_secret_key(password, desc):
    hash_func = _HASHES[desc["hashAlgorithm"]]
    h = hash_func(desc["passwordSalt"] + password.encode("UTF-16LE"))
    for i in range(desc["spinCount"]):
        h = hash_func(struct.pack("<I", i) + h.digest())
    final = hash_func(h.digest() + BLOCK_KEY_ENCRYPTED_KEY).digest()
    key = final[: desc["keyBits"] // 8]
    return _aes_cbc_decrypt(desc["encryptedKeyValue"], key, desc["passwordSalt"])


def _password_verifier_ok(password, desc):
    hash_func = _HASHES[desc["hashAlgorithm"]]
    h = hash_func(desc["passwordSalt"] + password.encode("UTF-16LE"))
    for i in range(desc["spinCount"]):
        h = hash_func(struct.pack("<I", i) + h.digest())
    key_in = hash_func(h.digest() + bytes([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])).digest()[: desc["keyBits"] // 8]
    key_val = hash_func(h.digest() + bytes([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E])).digest()[: desc["keyBits"] // 8]
    verifier_input = _aes_cbc_decrypt(desc["encryptedVerifierHashInput"], key_in, desc["passwordSalt"])
    verifier_value = _aes_cbc_decrypt(desc["encryptedVerifierHashValue"], key_val, desc["passwordSalt"])
    expected = hash_func(verifier_input).digest()
    return hmac.compare_digest(expected, verifier_value[: len(expected)])


def _check_integrity(desc, secret_key, package):
    hash_func = _HASHES[desc["hashAlgorithm"]]
    iv1 = hash_func(desc["keyDataSalt"] + BLOCK_KEY_INTEGRITY_1).digest()[:16]
    iv2 = hash_func(desc["keyDataSalt"] + BLOCK_KEY_INTEGRITY_2).digest()[:16]
    hash_size = hash_func().digest_size
    hmac_key = _aes_cbc_decrypt(desc["encryptedHmacKey"], secret_key, iv1)[:hash_size]
    hmac_value = _aes_cbc_decrypt(desc["encryptedHmacValue"], secret_key, iv2)[:hash_size]
    actual = hmac.new(hmac_key, package, hash_func).digest()
    return hmac.compare_digest(hmac_value, actual)


def decrypt_container(blob: bytes, password: str) -> CryptoResult:
    """Independently decrypt an Agile OLE container and verify integrity."""
    ole = olefile.OleFileIO(io.BytesIO(blob))
    try:
        encryption_info = ole.openstream("EncryptionInfo").read()
        package = ole.openstream("EncryptedPackage").read()
    finally:
        ole.close()

    desc = _parse_descriptor(encryption_info)
    secret_key = _derive_secret_key(password, desc)
    hash_func = _HASHES[desc["hashAlgorithm"]]
    salt = desc["keyDataSalt"]

    # A structurally broken container (e.g. the mini-stream routing defect) can
    # expose a truncated EncryptedPackage. Surface that as a failed CryptoResult
    # instead of raising inside the AES layer.
    body = package[8:]
    if len(package) < 8 or (body and len(body) % 16 != 0):
        return CryptoResult(b"", False, _password_verifier_ok(password, desc),
                            desc["hashAlgorithm"], 0)

    declared_size = struct.unpack("<Q", package[:8])[0]
    out = bytearray()
    segments = 0
    for block_id in range((len(body) + SEGMENT_LENGTH - 1) // SEGMENT_LENGTH):
        chunk = body[block_id * SEGMENT_LENGTH:(block_id + 1) * SEGMENT_LENGTH]
        iv = hash_func(salt + struct.pack("<I", block_id)).digest()[:16]
        out.extend(_aes_cbc_decrypt(chunk, secret_key, iv))
        segments += 1
    plaintext = bytes(out[:declared_size])

    integrity_ok = _check_integrity(desc, secret_key, package)
    password_ok = _password_verifier_ok(password, desc)
    return CryptoResult(plaintext, integrity_ok, password_ok,
                        desc["hashAlgorithm"], segments)
