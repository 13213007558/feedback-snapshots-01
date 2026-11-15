from __future__ import annotations

import hashlib
from typing import Literal

# Personal Iterations Multiplier (PIM) contract.
#
# VeraCrypt derives the PBKDF2 iteration count from the PIM value. When no PIM
# is supplied (``None``) the volume's default iteration count is used. A value
# of ``0`` is never a valid PIM: it is only used internally by VeraCrypt to
# signal "use the default". Negative values are rejected as well.
#
# References:
#   - https://veracrypt.jp/en/Personal%20Iterations%20Multiplier%20%28PIM%29.html
#   - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/VolumePassword.h
PIM_MINIMUM_NON_SYSTEM = 1
PIM_MINIMUM_SYSTEM = 98
# VeraCrypt stores the PIM in a signed 32-bit integer.
PIM_MAXIMUM = (2**31) - 1

# Default PBKDF2 iteration counts when no PIM is supplied.
DEFAULT_ITERATIONS = 500_000
DEFAULT_ITERATIONS_BOOT = 200_000


def validate_pim(pim: int | None, *, is_system: bool = False) -> None:
    """Validate a user supplied Personal Iterations Multiplier (PIM).

    Validation happens before any key derivation is started so that invalid
    input never results in an expensive PBKDF2 run.

    Args:
        pim: The PIM value. ``None`` means that no PIM was specified, in which
            case the volume's default iteration count is used.
        is_system: Whether the target is a system (boot) volume. System
            volumes require a minimum PIM of ``98``; non-system volumes
            require a minimum PIM of ``1``.

    Raises:
        TypeError: If ``pim`` is neither ``None`` nor an integer.
        ValueError: If ``pim`` is zero, negative or outside the allowed range.
    """
    if pim is None:
        return

    # ``bool`` is a subclass of ``int`` but is never a meaningful PIM.
    if not isinstance(pim, int) or isinstance(pim, bool):
        raise TypeError(f"PIM value must be an integer or None, got {type(pim).__name__}")

    minimum = PIM_MINIMUM_SYSTEM if is_system else PIM_MINIMUM_NON_SYSTEM
    volume_kind = "system" if is_system else "non-system"
    if pim == 0:
        raise ValueError("PIM value 0 is not valid; omit the PIM to use the default iteration count")
    if pim < 0:
        raise ValueError(f"PIM value must be a positive integer or None, got {pim}")
    if pim < minimum:
        raise ValueError(f"PIM value {pim} is below the minimum PIM of {minimum} for a {volume_kind} volume")
    if pim > PIM_MAXIMUM:
        raise ValueError(f"PIM value must be <= {PIM_MAXIMUM}, got {pim}")


class KeyDerivation:
    """VeraCrypt PKCS5 header key derivation implementation.

    The passphrase is always handled as raw bytes. Text passphrases must be
    encoded by the caller (VeraCrypt itself uses UTF-8); no encoding guessing
    is performed at this layer.

    References:
        - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/Pkcs5Kdf.h
        - ``pkcs5->DeriveKey(headerKey, password, pim, salt);``
    """

    __hash__: Literal["sha256", "sha512"]
    __system__: bool = False

    passphrase: bytes
    salt: bytes

    def __init__(self, passphrase: bytes, salt: bytes) -> None:
        if not isinstance(passphrase, bytes):
            raise TypeError(f"passphrase must be raw bytes, got {type(passphrase).__name__}; encode text first")
        if not isinstance(salt, bytes):
            raise TypeError(f"salt must be raw bytes, got {type(salt).__name__}")

        self.passphrase = passphrase
        self.salt = salt

        # If the passphrase is longer than the hash block size, create a digest.
        if len(self.passphrase) > (hash := hashlib.new(self.__hash__)).block_size:
            hash.update(self.passphrase)
            self.passphrase = hash.digest()

    def iterations(self, pim: int | None = None) -> int:
        """Translate a validated PIM value into a PBKDF2 iteration count."""
        raise NotImplementedError

    def derive(self, pim: int | None = None) -> bytes:
        """Implement PBKDF2-HMAC header key derivation based on the raw passphrase.

        Does not implement Argon2id key derivation.

        References:
            - https://veracrypt.jp/en/Header%20Key%20Derivation.html
        """
        validate_pim(pim, is_system=self.__system__)
        return hashlib.pbkdf2_hmac(
            hash_name=self.__hash__,
            password=self.passphrase,
            salt=self.salt,
            iterations=self.iterations(pim),
            dklen=64,
        )


class Pkcs5HmacSha512(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA512 header key derivation (non-system volumes)."""

    __hash__ = "sha512"

    def iterations(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else DEFAULT_ITERATIONS


class Pkcs5HmacSha256(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 header key derivation (non-system volumes)."""

    __hash__ = "sha256"

    def iterations(self, pim: int | None = None) -> int:
        return 15_000 + (pim * 1_000) if pim else DEFAULT_ITERATIONS


class Pkcs5HmacSha512_Boot(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA512 boot header key derivation (system volumes)."""

    __hash__ = "sha512"
    __system__ = True

    def iterations(self, pim: int | None = None) -> int:
        return pim * 2_048 if pim else DEFAULT_ITERATIONS


class Pkcs5HmacSha256_Boot(KeyDerivation):
    """VeraCrypt PKCS5 HMAC SHA256 boot header key derivation (system volumes)."""

    __hash__ = "sha256"
    __system__ = True

    def iterations(self, pim: int | None = None) -> int:
        return pim * 2_048 if pim else DEFAULT_ITERATIONS_BOOT


# KDF candidates applicable to regular file containers and non-system partitions.
KEY_DERIVATIONS = (
    Pkcs5HmacSha512,
    Pkcs5HmacSha256,
)

# KDF candidates applicable to system (boot) volumes.
BOOT_KEY_DERIVATIONS = (
    Pkcs5HmacSha512_Boot,
    Pkcs5HmacSha256_Boot,
)
