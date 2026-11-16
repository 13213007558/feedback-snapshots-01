"""pinUvAuthProtocol v2 primitives and the encrypted Info-field KDF.

Two distinct key derivations live here and must never be conflated:

1. The *pinUvAuthProtocol v2* channel keys, derived from the ECDH shared
   secret ``Z`` with HKDF-SHA-256, salt = 32 zero bytes, and purpose-specific
   ``info`` strings::

       HMAC key <- HKDF(ikm=Z, info=b"CTAP2 HMAC key", L=32)
       AES  key <- HKDF(ikm=Z, info=b"CTAP2 AES key",  L=32)

   The AES key wraps the PIN/UV auth token in transit (AES-256-CBC, random IV).
   The HMAC key authenticates protocol messages.  Purpose separation means the
   same shared secret yields two independent keys.

2. The *encrypted Info field* keys, derived not from ``Z`` but from the
   established persistent PIN/UV auth token itself, again with separated
   ``info`` strings and a 16-byte (AES-128) output::

       identifier key    <- HKDF(ikm=PUAT, info=b"encIdentifier",    L=16)
       cred-store key    <- HKDF(ikm=PUAT, info=b"encCredStoreState", L=16)

These mirror ``fido2.ctap2.pin.PinProtocolV2`` and
``fido2.ctap2.base.Info._decrypt`` exactly; the software device reuses the
same construction so bytes produced here can be read back through the real
library calls.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .trust import MissingFieldError, UnparseableFieldError

HKDF_SALT = b"\x00" * 32
INFO_HMAC_KEY = b"CTAP2 HMAC key"
INFO_AES_KEY = b"CTAP2 AES key"
INFO_ENC_IDENTIFIER = b"encIdentifier"
INFO_ENC_CRED_STORE_STATE = b"encCredStoreState"
BLOCK_SIZE = 16
TOKEN_LEN = 32


def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=HKDF_SALT,
        info=info,
        backend=default_backend(),
    ).derive(ikm)


def derive_channel_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    """Return ``(hmac_key, aes_key)`` for a pinUvAuthProtocol v2 session."""
    return (
        _hkdf(shared_secret, INFO_HMAC_KEY, 32),
        _hkdf(shared_secret, INFO_AES_KEY, 32),
    )


def derive_info_key(pin_uv_token: bytes, info: bytes) -> bytes:
    """Derive the AES-128 key used for one encrypted Info field."""
    return _hkdf(pin_uv_token, info, 16)


def platform_encapsulate(
    peer_cose_public_key: dict,
) -> tuple[dict, bytes]:
    """Platform side of ECDH (mirrors ``PinProtocolV2.encapsulate``).

    Returns the platform COSE public key to send and the raw shared secret.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    numbers = private_key.public_key().public_numbers()
    cose_key = {
        1: 2,
        3: -25,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(peer_cose_public_key[-2], "big"),
        int.from_bytes(peer_cose_public_key[-3], "big"),
        ec.SECP256R1(),
    ).public_key(default_backend())
    return cose_key, private_key.exchange(ec.ECDH(), peer)


def device_shared_secret(
    device_private_key: ec.EllipticCurvePrivateKey,
    platform_cose_public_key: dict,
) -> bytes:
    """Authenticator side of the same ECDH."""
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(platform_cose_public_key[-2], "big"),
        int.from_bytes(platform_cose_public_key[-3], "big"),
        ec.SECP256R1(),
    ).public_key(default_backend())
    return device_private_key.exchange(ec.ECDH(), peer)


def cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-CBC with a fresh random IV prefixed to the ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    encryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv), default_backend()
    ).encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def cbc_decrypt(key: bytes, blob: bytes) -> bytes:
    """AES-CBC decrypt. Raises ``UnparseableFieldError`` on bad framing."""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 2 * BLOCK_SIZE:
        raise UnparseableFieldError(
            "encrypted field needs a 16-byte IV plus at least one cipher block"
        )
    iv, ciphertext = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    if len(ciphertext) % BLOCK_SIZE:
        raise UnparseableFieldError("ciphertext is not a whole number of blocks")
    decryptor = Cipher(
        algorithms.AES(key), modes.CBC(iv), default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return _hmac.new(key, message, hashlib.sha256).digest()


def pkcs7_pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding]) * padding


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise UnparseableFieldError("plaintext has invalid block framing")
    padding = data[-1]
    if not 1 <= padding <= BLOCK_SIZE or data[-padding:] != bytes([padding]) * padding:
        raise UnparseableFieldError("invalid PKCS#7 padding")
    return data[:-padding]


def encrypt_info_field(pin_uv_token: bytes, info: bytes, plaintext: bytes) -> bytes:
    """Device-side helper used by the software authenticator."""
    key = derive_info_key(pin_uv_token, info)
    return cbc_encrypt(key, pkcs7_pad(plaintext))


def decrypt_info_field(pin_uv_token: bytes, info: bytes, blob: bytes | None) -> bytes:
    """Decrypt and unpad an Info field, mapping failures to the taxonomy.

    A missing field raises :class:`MissingFieldError`; present but malformed
    bytes raise :class:`UnparseableFieldError`.  There is deliberately no
    "authentication failure" here: CBC cannot authenticate anything, and this
    function never claims to.
    """
    if not blob:
        raise MissingFieldError(f"Info field for {info.decode()!r} is absent")
    raw = cbc_decrypt(derive_info_key(pin_uv_token, info), blob)
    return pkcs7_unpad(raw)
