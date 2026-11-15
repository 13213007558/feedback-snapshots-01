from __future__ import annotations

import hashlib
import struct
from functools import cached_property
from uuid import UUID

from dissect.database.ese.ntds.c_pek import c_pek

try:
    from Crypto.Cipher import AES, ARC4

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


AUTHENTICATOR = UUID("4881d956-91ec-11d1-905a-00c04fc2d4cf")

PEK_LIST_HEADER_SIZE = 24
CLEAR_PEK_LIST_HEADER_SIZE = 32
PEK_ENTRY_SIZE = 20
AES_ATTRIBUTE_HEADER_SIZE = 28


class PEKError(Exception):
    """Base exception for PEK-related errors.

    Messages intentionally only contain structural information (sizes, IDs and versions),
    never key material or decrypted plaintext.
    """

    def __init__(self, message: str, *, reason: str):
        super().__init__(message)
        self.reason = reason


class PEKFormatError(PEKError, EOFError):
    """The PEK list or an encrypted attribute is structurally malformed."""


class PEKUnlockError(PEKError, ValueError):
    """The PEK list could not be authenticated (wrong syskey or modified ciphertext)."""


class UnknownPEKKey(PEKError, KeyError):
    """The requested PEK key ID is not present in the unlocked PEK list."""

    def __str__(self) -> str:
        # KeyError.__str__ would add quotes around the message.
        return str(self.args[0]) if self.args else ""


class UnsupportedPEKVersion(PEKError, NotImplementedError):
    """The PEK list uses an unsupported version."""


class UnsupportedPEKAlgorithm(PEKError, NotImplementedError):
    """An encrypted attribute uses an unsupported algorithm."""


class PEK:
    """Password Encryption Key (PEK) handler.

    Args:
        pek: The raw PEK blob from the NTDS database.
    """

    def __init__(self, pek: bytes):
        self.pek = pek
        self.encrypted = _parse_encrypted_pek_list(pek)
        self.decrypted = None

    def __repr__(self) -> str:
        return (
            f"<PEK version={self.version} unlocked={self.unlocked} "
            f"keys={len(self.keys) if self.unlocked else 0} encrypted_size={len(self.pek)}>"
        )

    @property
    def version(self) -> int:
        """PEK version."""
        return self.encrypted.Version

    @property
    def unlocked(self) -> bool:
        """Indicates whether the PEK has been unlocked."""
        return self.decrypted is not None

    @cached_property
    def keys(self) -> dict[int, bytes]:
        """Dictionary of PEK keys by their key ID."""
        if not self.unlocked:
            raise RuntimeError("PEK is not unlocked")

        return {pek.KeyId: bytes(pek.Key) for pek in self.decrypted.PekArray}

    def unlock(self, key: bytes) -> None:
        """Unlock the PEK list using the provided "syskey".

        Args:
            key: The syskey of the domain controller.

        Raises:
            PEKFormatError: If the encrypted PEK list or decrypted clear PEK list is malformed.
            UnsupportedPEKVersion: If the PEK list uses an unsupported version.
            PEKUnlockError: If the syskey does not authenticate the PEK list.
        """
        if not HAS_CRYPTO:
            raise RuntimeError("Missing pycryptodome dependency")

        if self.unlocked:
            return

        if not bytes(self.encrypted.EncryptedData):
            raise PEKFormatError("Encrypted PEK list contains no ciphertext", reason="pek-ciphertext-empty")

        if self.version == c_pek.PEK_PRE_2012R2_VERSION:
            decrypted = _rc4_decrypt(self.encrypted.EncryptedData, key, self.encrypted.Salt, 1000)

        elif self.version == c_pek.PEK_2016_TP4_VERSION:
            if len(self.encrypted.EncryptedData) % 16 != 0:
                raise PEKFormatError(
                    f"PEK encrypted data is not AES block aligned: {len(self.encrypted.EncryptedData)} bytes",
                    reason="aes-alignment",
                )
            decrypted = _aes_decrypt(self.encrypted.EncryptedData, key, self.encrypted.Salt)

        else:
            raise UnsupportedPEKVersion(f"Unsupported PEK version: {self.version}", reason="unsupported-version")

        if decrypted[:16] != AUTHENTICATOR.bytes_le:
            raise PEKUnlockError("Invalid PEK authenticator after unlocking", reason="authenticator")

        self.decrypted = _parse_clear_pek_list(decrypted)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the PEK list.

        Args:
            data: The encrypted data blob.

        Raises:
            RuntimeError: If the PEK list has not been unlocked yet.
            PEKFormatError: If the encrypted data blob is structurally malformed or truncated.
            UnknownPEKKey: If the encrypted data blob references an unknown key ID.
            UnsupportedPEKAlgorithm: If the encrypted data blob uses an unsupported algorithm.
        """
        if not self.unlocked:
            raise RuntimeError("PEK is not unlocked")

        encrypted_data = _parse_encrypted_data(data)

        if (key := self.keys.get(encrypted_data.KeyId)) is None:
            raise UnknownPEKKey(f"PEK key ID {encrypted_data.KeyId} not found", reason="unknown-key")

        if encrypted_data.AlgorithmId == c_pek.PEK_ENCRYPTION:
            return _rc4_decrypt(encrypted_data.EncryptedData, key, None, 0)

        if encrypted_data.AlgorithmId == c_pek.PEK_ENCRYPTION_WITH_SALT:
            encrypted_data = _parse_encrypted_data_with_salt(data)
            return _rc4_decrypt(encrypted_data.EncryptedData, key, encrypted_data.Salt, 1)

        if encrypted_data.AlgorithmId == c_pek.PEK_ENCRYPTION_WITH_AES:
            encrypted_data_aes = _parse_encrypted_data_with_aes(data)
            return _aes_decrypt_attribute(encrypted_data_aes, key)

        raise UnsupportedPEKAlgorithm(
            f"Unsupported PEK encryption algorithm: {encrypted_data.AlgorithmId}", reason="unsupported-algorithm"
        )


def _rc4_decrypt(data: bytes, key: bytes, salt: bytes | None, iterations: int) -> bytes:
    """Decrypt data using RC4.

    Args:
        data: Encrypted data.
        key: RC4 encryption key.
        salt: Optional salt to use in key derivation.
        iterations: Number of hash iterations to perform if salt is provided.
    """
    ctx = hashlib.md5(key)
    if salt is not None:
        for _ in range(iterations):
            ctx.update(salt)

    cipher = ARC4.new(ctx.digest())
    return cipher.decrypt(data)


def _aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using AES-CBC.

    Args:
        data: Encrypted data.
        key: AES encryption key.
        iv: Initialization vector.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if (align := -len(data) % 16) != 0:
        data += b"\x00" * align
    return cipher.decrypt(data)


def _parse_encrypted_pek_list(data: bytes) -> c_pek.ENCRYPTED_PEK_LIST:
    """Parse and validate the header of an encrypted PEK list."""
    if len(data) < PEK_LIST_HEADER_SIZE:
        raise PEKFormatError(
            f"Encrypted PEK list is truncated: {len(data)} bytes, expected at least {PEK_LIST_HEADER_SIZE}",
            reason="pek-list-truncated",
        )

    try:
        return c_pek.ENCRYPTED_PEK_LIST(data)
    except EOFError as e:
        raise PEKFormatError("Encrypted PEK list header could not be parsed", reason="pek-list-truncated") from e


def _parse_clear_pek_list(data: bytes) -> c_pek.CLEAR_PEK_LIST:
    """Parse and validate a decrypted clear PEK list.

    Only the header, declared key count and key IDs are validated here. The trailing bytes may contain
    AES padding or historic data, so they are intentionally not required to be zero.
    """
    if len(data) < CLEAR_PEK_LIST_HEADER_SIZE:
        raise PEKFormatError(
            f"Clear PEK list is truncated: {len(data)} bytes, expected at least {CLEAR_PEK_LIST_HEADER_SIZE}",
            reason="clear-pek-list-truncated",
        )

    count = struct.unpack_from("<I", data, CLEAR_PEK_LIST_HEADER_SIZE - 4)[0]
    available = (len(data) - CLEAR_PEK_LIST_HEADER_SIZE) // PEK_ENTRY_SIZE
    if count > available:
        raise PEKFormatError(
            f"Clear PEK list declares {count} keys but only {available} entries are available",
            reason="pek-count-overflow",
        )
    if count == 0:
        raise PEKFormatError("Clear PEK list contains no keys", reason="pek-count-empty")

    try:
        pek_list = c_pek.CLEAR_PEK_LIST(data)
    except EOFError as e:
        raise PEKFormatError("Clear PEK list could not be parsed", reason="clear-pek-list-truncated") from e

    key_ids = [entry.KeyId for entry in pek_list.PekArray]
    if len(set(key_ids)) != len(key_ids):
        raise PEKFormatError("Clear PEK list contains duplicate key IDs", reason="pek-duplicate-key-id")

    return pek_list


def _parse_encrypted_data(data: bytes) -> c_pek.ENCRYPTED_DATA:
    """Parse the common header of an encrypted attribute."""
    if len(data) < 8:
        raise PEKFormatError(
            f"Encrypted attribute is truncated: {len(data)} bytes, expected at least 8",
            reason="attribute-header-truncated",
        )

    try:
        return c_pek.ENCRYPTED_DATA(data)
    except EOFError as e:
        raise PEKFormatError(
            "Encrypted attribute header could not be parsed", reason="attribute-header-truncated"
        ) from e


def _parse_encrypted_data_with_salt(data: bytes) -> c_pek.ENCRYPTED_DATA_WITH_SALT:
    """Parse an encrypted attribute that carries a salt."""
    if len(data) < 24:
        raise PEKFormatError(
            f"Encrypted attribute is truncated: {len(data)} bytes, expected at least 24",
            reason="attribute-salt-truncated",
        )

    try:
        return c_pek.ENCRYPTED_DATA_WITH_SALT(data)
    except EOFError as e:
        raise PEKFormatError("Encrypted attribute could not be parsed", reason="attribute-salt-truncated") from e


def _parse_encrypted_data_with_aes(data: bytes) -> c_pek.ENCRYPTED_DATA_WITH_AES:
    """Parse an encrypted attribute that uses AES."""
    if len(data) < AES_ATTRIBUTE_HEADER_SIZE:
        raise PEKFormatError(
            f"Encrypted attribute is truncated: {len(data)} bytes, expected at least {AES_ATTRIBUTE_HEADER_SIZE}",
            reason="attribute-aes-truncated",
        )

    try:
        return c_pek.ENCRYPTED_DATA_WITH_AES(data)
    except EOFError as e:
        raise PEKFormatError("Encrypted attribute could not be parsed", reason="attribute-aes-truncated") from e


def _aes_decrypt_attribute(encrypted: c_pek.ENCRYPTED_DATA_WITH_AES, key: bytes) -> bytes:
    """Decrypt and validate an AES encrypted attribute.

    The declared plaintext length, AES block alignment and PKCS#7 padding are all validated before any
    plaintext is returned. This prevents truncated or length-mismatched blobs from being presented as
    a successful decryption.
    """
    ciphertext = bytes(encrypted.EncryptedData)
    declared_length = encrypted.Length

    if not ciphertext:
        raise PEKFormatError("Encrypted attribute contains no ciphertext", reason="attribute-aes-empty")
    if len(ciphertext) % 16 != 0:
        raise PEKFormatError(
            f"Encrypted attribute is not AES block aligned: {len(ciphertext)} bytes",
            reason="attribute-aes-alignment",
        )
    if declared_length > len(ciphertext):
        raise PEKFormatError(
            f"Encrypted attribute declares {declared_length} plaintext bytes "
            f"but only {len(ciphertext)} ciphertext bytes are available",
            reason="attribute-length-overflow",
        )
    if declared_length == 0:
        raise PEKFormatError("Encrypted attribute declares an empty plaintext", reason="attribute-length-empty")

    decrypted = _aes_decrypt(ciphertext, key, encrypted.IV)
    padding = decrypted[-1]
    if padding < 1 or padding > 16 or decrypted[-padding:] != bytes([padding]) * padding:
        raise PEKFormatError("Encrypted attribute has invalid AES padding", reason="attribute-aes-padding")
    if declared_length != len(decrypted) - padding:
        raise PEKFormatError(
            f"Encrypted attribute declares {declared_length} plaintext bytes "
            f"but AES padding leaves {len(decrypted) - padding}",
            reason="attribute-length-mismatch",
        )

    return decrypted[:declared_length]
