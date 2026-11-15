from __future__ import annotations

import io
import math
import warnings
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.veracrypt.c_veracrypt import (
    TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET,
    c_veracrypt,
)
from dissect.fve.veracrypt.crypto import CIPHERS
from dissect.fve.veracrypt.key import (
    BOOT_KEY_DERIVATIONS,
    KEY_DERIVATIONS,
    validate_pim,
)

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.fve.luks.luks import CryptStream


class VeraCrypt:
    """VeraCrypt full volume encryption implementation.

    Supports encrypted file containers and system partitions using key derivation
    algorithm PKCS5 (SHA512 or SHA256) and AES XTS cipher.

    Passphrase byte semantics are explicit: :meth:`unlock_with_text_passphrase`
    encodes text (UTF-8 by default), :meth:`unlock_with_raw_passphrase` takes
    raw bytes and :meth:`unlock_with_passphrase` keeps the legacy behavior.

    Non-system partitions and hidden volumes are not implemented as well as other key
    derivation algorithms or ciphers. Key files are also not implemented.

    References:
        - https://veracrypt.jp/en/System%20Encryption.html
        - https://github.com/veracrypt/VeraCrypt
    """

    def __init__(self, fh: BinaryIO, *, is_system: bool = False) -> None:
        self.fh = fh
        self.is_system = is_system
        self.unlocked = False
        self.header = None

        self.cipher = None
        self.size = None
        self.version = None
        self.client_version = None

        # Record of the parameters that actually unlocked the volume. These do
        # not contain the passphrase or any derived key material.
        self.passphrase_encoding = None
        self.kdf = None
        self.kdf_iterations = None

        if is_system:
            self.fh.seek(TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET)

        self.header_salt = self.fh.read(64)
        self.header_ciphertext = self.fh.read(512)

    def __repr__(self) -> str:
        return (
            f"<VeraCrypt fh={self.fh} is_system={self.is_system} unlocked={self.unlocked} size={self.size} "
            f"cipher={self.cipher} version={self.version} client_version={self.client_version}>"
        )

    def unlock_with_passphrase(
        self,
        passphrase: str | bytes,
        pim: int | None = None,
    ) -> None:
        """Unlock the volume using the legacy passphrase interface.

        This is a compatibility wrapper around the explicit byte-semantics entry
        points and only exists so existing callers keep working. New code should
        use :meth:`unlock_with_text_passphrase` or
        :meth:`unlock_with_raw_passphrase` instead.

        The exact byte semantics of this wrapper are preserved for reproducibility:

        - ``str`` input is encoded with the legacy ``latin-1`` codec, matching the
          historical implementation. Passphrases containing code points above
          U+00FF cannot be represented this way and should be migrated to
          :meth:`unlock_with_text_passphrase`, which uses VeraCrypt's native
          UTF-8 encoding.
        - ``bytes`` input is used verbatim, as produced by
          :meth:`unlock_with_raw_passphrase`.

        Args:
            passphrase: A legacy text passphrase (``str``) or raw passphrase
                bytes (``bytes``).
            pim: Optional Personal Iterations Multiplier. Invalid values raise
                before any key derivation is attempted.

        Raises:
            ValueError: If the volume cannot be decrypted or if ``pim`` is invalid.
        """
        if isinstance(passphrase, str):
            warnings.warn(
                "unlock_with_passphrase(str) uses the legacy latin-1 encoding; "
                "use unlock_with_text_passphrase(passphrase) for explicit UTF-8 "
                "or unlock_with_raw_passphrase(passphrase_bytes) for raw bytes",
                DeprecationWarning,
                stacklevel=2,
            )
            self._unlock(passphrase.encode("latin-1"), pim, encoding="latin-1 (legacy)")
        elif isinstance(passphrase, bytes):
            self._unlock(passphrase, pim, encoding="raw bytes (legacy passthrough)")
        else:
            raise TypeError(f"passphrase must be str or bytes, got {type(passphrase).__name__}")

    def unlock_with_text_passphrase(
        self,
        passphrase: str,
        pim: int | None = None,
        *,
        encoding: str = "utf-8",
    ) -> None:
        """Unlock the volume with a text passphrase and an explicit text encoding.

        VeraCrypt converts keyboard passphrases to UTF-8 before key derivation,
        so UTF-8 is the default and recommended encoding. The encoding can be
        overridden for interoperability with volumes created using another codec.

        Args:
            passphrase: The text passphrase.
            pim: Optional Personal Iterations Multiplier. Invalid values raise
                before any key derivation is attempted.
            encoding: Text encoding used to turn ``passphrase`` into bytes.

        Raises:
            ValueError: If the volume cannot be decrypted or if ``pim`` is invalid.
            TypeError: If ``passphrase`` is not a string.
            UnicodeEncodeError: If ``passphrase`` cannot be encoded with ``encoding``.
        """
        if not isinstance(passphrase, str):
            raise TypeError(
                f"passphrase must be str, got {type(passphrase).__name__}; use unlock_with_raw_passphrase"
            )
        self._unlock(passphrase.encode(encoding), pim, encoding=encoding)

    def unlock_with_raw_passphrase(self, passphrase: bytes, pim: int | None = None) -> None:
        """Unlock the volume with a passphrase provided as explicit raw bytes.

        No encoding or decoding is performed: the exact byte sequence is fed to
        the key derivation functions. Use this entry point for binary
        passphrases or when the byte semantics are already known.

        Args:
            passphrase: The raw passphrase bytes.
            pim: Optional Personal Iterations Multiplier. Invalid values raise
                before any key derivation is attempted.

        Raises:
            ValueError: If the volume cannot be decrypted or if ``pim`` is invalid.
            TypeError: If ``passphrase`` is not bytes.
        """
        if not isinstance(passphrase, bytes):
            raise TypeError(
                f"passphrase must be bytes, got {type(passphrase).__name__}; use unlock_with_text_passphrase"
            )
        self._unlock(passphrase, pim, encoding="raw bytes")

    def _unlock(self, passphrase: bytes, pim: int | None, *, encoding: str) -> None:
        """Derive header keys from explicit passphrase bytes and decrypt the header.

        Only the KDF candidates applicable to this volume type are tried: boot
        KDFs for system volumes, regular KDFs for file containers and
        non-system partitions. PIM validation happens up front so that invalid
        input never starts a costly derivation.
        """
        # Validate before constructing a single KDF or running PBKDF2.
        validate_pim(pim, is_system=self.is_system)

        candidates = BOOT_KEY_DERIVATIONS if self.is_system else KEY_DERIVATIONS
        for Kdf in candidates:
            kdf = Kdf(passphrase, self.header_salt)
            iterations = kdf.iterations(pim)
            keys = kdf.derive(pim)
            if self._decrypt_header(keys):
                self.passphrase_encoding = encoding
                self.kdf = Kdf
                self.kdf_iterations = iterations
                break

        if not self.unlocked:
            raise ValueError("Unable to decrypt using provided passphrase")

    def unlock_with_header_key(self, keys: bytes) -> None:
        """Unlock the volume with a raw encryption key. Supports AES XTS encryption mode only."""
        if len(keys) not in (32, 64):
            raise ValueError(f"Header key is of invalid length ({len(keys)}), expected 32 or 64 bytes")

        if not self._decrypt_header(keys):
            raise ValueError("Unable to decrypt using provided header keys")

    def unlock_with_key_file(self, path: Path) -> None:
        """Unlock the volume with a key file."""
        raise NotImplementedError

    def unlock_with_key_fh(self, fh: BinaryIO) -> None:
        """Unlock the volume with a key file handle."""
        raise NotImplementedError

    def _decrypt_header(self, keys: bytes) -> bool:
        """Decrypt the VeraCrypt header using any of the available :class:`Cipher` implementations."""
        for Cipher in CIPHERS:
            cipher = Cipher(BytesIO(self.header_ciphertext), keys, 0, 512)
            plaintext = cipher.open().read()
            header = c_veracrypt.VolumeHeader(plaintext)

            if header.magic == b"VERA":
                self.header_keys = keys
                self.header = header
                self.cipher = cipher.__type__
                self.key = self.header.master_keys[0:64]  # NOTE: Could contain more keys if other cipher(s) are used.
                self.size = header.volume_size
                self.version = header.version
                self.client_version = header.client_version
                self.unlocked = True
                break

        return self.unlocked

    def open(self) -> CryptStream:
        """Open this volume and return a readable (decrypted) stream."""
        if not self.unlocked:
            raise ValueError("Volume is locked")

        if not (Cipher := next((c for c in CIPHERS if c.__type__ == self.cipher), None)):
            raise NotImplementedError(f"Unsupported Cipher {self.cipher}")

        offset = self.header.mk_scope_offset
        size = self.header.mk_scope_size
        cipher = Cipher(self.fh, self.key, offset, size)
        return cipher.open()


def entropy(data: bytes) -> float:
    """Simple Shannon entropy implementation.

    References:
        - https://en.wikipedia.org/wiki/Entropy_(information_theory)
    """
    len_data = len(data)
    prob = [float(data.count(c)) / len_data for c in dict.fromkeys(list(data))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


def is_veracrypt_volume(fh: BinaryIO) -> bool:
    """Perform a smell test to see if the provided file-like object could be a VeraCrypt volume."""
    offset = fh.tell()

    if not hasattr(fh, "size"):
        size = fh.seek(0, io.SEEK_END)
        fh.seek(offset)
    else:
        size: int = fh.size  # type: ignore

    # Division test
    if size % 512 != 0:
        return False

    # Entropy test
    chunk = fh.read(4096)
    fh.seek(offset)
    return entropy(chunk) > 7.9

    # TODO: Make sure the volume does not contain any filesystem(s) or magic headers from regular files.
