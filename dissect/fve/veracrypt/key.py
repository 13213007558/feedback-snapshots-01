from __future__ import annotations

import hashlib
from typing import Literal

#: Maximum allowed Personal Iterations Multiplier (PIM) value, as enforced by VeraCrypt.
MAX_PIM = 65_535


def normalize_pim(pim: int | None = None) -> int | None:
    """Validate and normalize a user supplied Personal Iterations Multiplier (PIM).

    The PIM contract is as follows:
        - ``None``: no PIM specified, the KDF default iteration count is used.
        - ``0``: equivalent to ``None``, matching VeraCrypt semantics.
        - Negative values: rejected with a :exc:`ValueError`.
        - Values larger than :data:`MAX_PIM`: rejected with a :exc:`ValueError`.
        - Non-integer values (including ``bool``): rejected with a :exc:`TypeError`.

    Validation is intentionally cheap so invalid input is rejected before any
    expensive key derivation is started.

    Returns the normalized PIM, where ``None`` means "use the KDF default".

    References:
        - https://veracrypt.jp/en/Personal%20Iterations%20Multiplier%20%28PIM%29.html
    """
    if pim is None:
        return None

    if isinstance(pim, bool) or not isinstance(pim, int):
        raise TypeError(f"PIM must be an integer, got {type(pim).__name__}")
    if pim < 0:
        raise ValueError(f"PIM must not be negative, got {pim}")
    if pim > MAX_PIM:
        raise ValueError(f"PIM must not exceed {MAX_PIM}, got {pim}")

    return pim or None


class KeyDerivation:
    """VeraCrypt PKCS5 header key derivation implementation.

    Takes the password as raw bytes. Encoding of text passphrases is the
    responsibility of the caller, so byte semantics are always explicit.

    References:
        - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/Pkcs5Kdf.h
        - ``pkcs5->DeriveKey(headerKey, password, pim, salt);``
    """

    __hash__: Literal["sha256", "sha512"]
    __type__: str

    password: bytes
    salt: bytes

    def __init__(self, password: bytes, salt: bytes) -> None:
        if not isinstance(password, (bytes, bytearray)):
            raise TypeError(f"Password must be bytes, got {type(password).__name__}")
        self.password = bytes(password)
        self.salt = salt

    def iterations(self, pim: int | None = None) -> int:
        """Translate a user supplied ``pim`` integer to a PBKDF2 iteration count.

        Expects an already normalized PIM, see :func:`normalize_pim`.

        References:
            - https://veracrypt.jp/en/Personal%20Iterations%20Multiplier%20%28PIM%29.html
        """
        raise NotImplementedError

    def derive(self, pim: int | None = None) -> bytes:
        """Implements PBKDF2-HMAC header key derivation based on the provided password.

        Does not implement Argon2id key derivation.

        References:
            - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        """
        pim = normalize_pim(pim)
        return hashlib.pbkdf2_hmac(
            hash_name=self.__hash__,
            password=self.password,
            salt=self.salt,
            iterations=self.iterations(pim),
            dklen=64,
        )


class Pkcs5HmacSha512(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA512 header key derivation."""

    __hash__ = "sha512"
    __type__ = "pkcs5-hmac-sha512"

    def iterations(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else 500_000


class Pkcs5HmacSha256(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 header key derivation."""

    __hash__ = "sha256"
    __type__ = "pkcs5-hmac-sha256"

    def iterations(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else 500_000


class Pkcs5HmacSha256_Boot(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 boot (system encryption) header key derivation."""

    __hash__ = "sha256"
    __type__ = "pkcs5-hmac-sha256-boot"

    def iterations(self, pim: int | None = None) -> int:
        return pim * 2048 if pim else 200_000


#: Key derivation candidates for file containers and non-system partitions.
KEY_DERIVATIONS = (
    Pkcs5HmacSha512,
    Pkcs5HmacSha256,
)

#: Key derivation candidates for system encryption volumes.
SYSTEM_KEY_DERIVATIONS = (
    Pkcs5HmacSha512,
    Pkcs5HmacSha256_Boot,
)
