from __future__ import annotations

import base64
import functools
import hmac
import io
import logging
import os
import secrets
from dataclasses import dataclass
from hashlib import sha1, sha256, sha384, sha512
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import olefile

from msoffcrypto import exceptions
from msoffcrypto.method.container.ecma376_encrypted import ECMA376Encrypted

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ALGORITHM_HASH = {
    "SHA1": sha1,
    "SHA256": sha256,
    "SHA384": sha384,
    "SHA512": sha512,
}

blkKey_VerifierHashInput = bytearray([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79])
blkKey_encryptedVerifierHashValue = bytearray(
    [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E]
)
blkKey_encryptedKeyValue = bytearray([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])
blkKey_dataIntegrity1 = bytearray([0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6])
blkKey_dataIntegrity2 = bytearray([0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33])


def _random_buffer(sz):
    return secrets.token_bytes(sz)


def _get_num_blocks(sz, block):
    return (sz + block - 1) // block


def _round_up(sz, block):
    return _get_num_blocks(sz, block) * block


def _resize_buffer(buf, n, c=b"\0"):
    if len(buf) >= n:
        return buf[:n]

    return buf + c * (n - len(buf))


def _normalize_key(key, n):
    return _resize_buffer(key, n, b"\x36")


def _get_hash_func(algorithm):
    return ALGORITHM_HASH.get(algorithm, sha1)


def _decrypt_aes_cbc(data, key, iv):
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = aes.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return decrypted


def _encrypt_aes_cbc(data, key, iv):
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    encryptor = aes.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()

    return encrypted


def _encrypt_aes_cbc_padded(data, key, iv, blockSize):
    buf = data

    if len(buf) % blockSize:
        buf = _resize_buffer(buf, _round_up(len(buf), blockSize))

    return _encrypt_aes_cbc(buf, key, iv)


def _get_salt(salt_value=None, salt_size=16):
    if salt_value is not None:
        if len(salt_value) != salt_size:
            raise exceptions.EncryptionError(
                f"Invalid salt value size, should be {salt_size}"
            )

        return salt_value

    return _random_buffer(salt_size)


# Hardcoded to AES256 + SHA512 for OOXML.
class ECMA376AgileCipherParams:
    def __init__(self):
        self.cipherName = "AES"
        self.hashName = "SHA512"
        self.saltSize = 16
        self.blockSize = 16
        self.keyBits = 256
        self.hashSize = 64
        self.saltValue: bytes | None = None


def _enc64(b):
    return base64.b64encode(b).decode("UTF-8")


class ECMA376AgileEncryptionInfo:
    def __init__(self):
        self.spinCount = 100000
        self.keyData = ECMA376AgileCipherParams()
        self.encryptedHmacKey: bytes | None = None
        self.encryptedHmacValue: bytes | None = None

        self.encryptedKey = ECMA376AgileCipherParams()
        self.encryptedVerifierHashInput: bytes | None = None
        self.encryptedVerifierHashValue: bytes | None = None
        self.encryptedKeyValue: bytes | None = None

    def getEncryptionDescriptorHeader(self):
        # https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/87020a34-e73f-4139-99bc-bbdf6cf6fa55
        return pack("<HHI", 4, 4, 0x40)

    def toEncryptionDescriptor(self):
        """
        Returns an XML description of the encryption information.
        """
        return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password" xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
    <keyData saltSize="{self.keyData.saltSize}" blockSize="{self.keyData.blockSize}" keyBits="{self.keyData.keyBits}" hashSize="{self.keyData.hashSize}"
             cipherAlgorithm="{self.keyData.cipherName}" cipherChaining="ChainingModeCBC" hashAlgorithm="{self.keyData.hashName}" saltValue="{_enc64(self.keyData.saltValue)}" />
    <dataIntegrity encryptedHmacKey="{_enc64(self.encryptedHmacKey)}" encryptedHmacValue="{_enc64(self.encryptedHmacValue)}" />
    <keyEncryptors>
        <keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
            <p:encryptedKey spinCount="{self.spinCount}" saltSize="{self.encryptedKey.saltSize}" blockSize="{self.encryptedKey.blockSize}" keyBits="{self.encryptedKey.keyBits}"
                            hashSize="{self.encryptedKey.hashSize}" cipherAlgorithm="{self.encryptedKey.cipherName}" cipherChaining="ChainingModeCBC" hashAlgorithm="{self.encryptedKey.hashName}"
                            saltValue="{_enc64(self.encryptedKey.saltValue)}" encryptedVerifierHashInput="{_enc64(self.encryptedVerifierHashInput)}"
                            encryptedVerifierHashValue="{_enc64(self.encryptedVerifierHashValue)}" encryptedKeyValue="{_enc64(self.encryptedKeyValue)}" />
        </keyEncryptor>
    </keyEncryptors>
</encryption>
"""


def _generate_iv(params: ECMA376AgileCipherParams, blkKey, salt_value):
    if not blkKey:
        return _normalize_key(salt_value, params.blockSize)

    hashCalc = _get_hash_func(params.hashName)

    return _normalize_key(hashCalc(salt_value + blkKey).digest(), params.blockSize)


@dataclass(frozen=True)
class PackageViewStats:
    """Counters describing the work performed by an :class:`ECMA376AgilePackageView`.

    ``source_bytes_read`` is the number of bytes actually fetched from the
    encrypted package source, including the 8-byte package header, ciphertext
    segments and the bytes consumed by a full integrity pass.  It is not the
    size of the stream unless the whole stream was read.

    ``segments_decrypted`` counts AES-CBC segment decryptions that were not
    served from the view's segment cache.  ``segment_cache_hits`` counts reads
    served from that cache.  ``integrity_verifications`` counts full-stream
    HMAC passes actually performed (not the reads that reused one), and
    ``integrity_bytes_read`` is the number of encrypted bytes those passes
    hashed.
    """

    source_bytes_read: int = 0
    segments_decrypted: int = 0
    segment_cache_hits: int = 0
    integrity_verifications: int = 0
    integrity_bytes_read: int = 0
    plaintext_bytes_returned: int = 0


class _PackageSource:
    """Read-only random-access byte source used by the package view."""

    size = 0

    def read_at(self, offset, length):
        raise NotImplementedError

    def binding_token(self):
        """Return a token identifying this exact immutable ciphertext.

        The token changes if the source is replaced or if the underlying file
        changes.  ``None`` means the source cannot promise stable contents and
        a verification result must therefore never be reused.
        """
        return None

    def close(self):
        pass


def _file_binding_token(fileobj):
    """Cheap identity for a file object, including inode/mtime if available."""
    try:
        fileno = fileobj.fileno()
    except (AttributeError, OSError, ValueError):
        return None

    st = os.fstat(fileno)
    return (
        id(fileobj),
        fileno,
        st.st_dev,
        st.st_ino,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )


class BytesPackageSource(_PackageSource):
    """Immutable, read-only snapshot of an encrypted package."""

    def __init__(self, data):
        self._data = bytes(data)
        self.size = len(self._data)
        self._token = ("bytes", id(self._data))

    def read_at(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        return self._data[offset : offset + length]

    def binding_token(self):
        return self._token


class SeekablePackageSource(_PackageSource):
    """Read-only source backed by a seekable binary file object.

    The caller keeps ownership of ``fileobj``; this source only seeks and reads
    it.  Verification results are tied to the file's inode/size/mtime/ctime so
    that an in-place modification invalidates a previous full-stream check.
    """

    def __init__(self, fileobj):
        self._file = fileobj
        pos = fileobj.tell()
        fileobj.seek(0, os.SEEK_END)
        self.size = fileobj.tell()
        fileobj.seek(pos)

    def read_at(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset >= self.size or length == 0:
            return b""
        self._file.seek(offset)
        return self._file.read(min(length, self.size - offset))

    def binding_token(self):
        return _file_binding_token(self._file)


class OleStreamPackageSource(_PackageSource):
    """Read-only source that reads an OLE stream sector-by-sector.

    Unlike ``olefile.OleFileIO.openstream()`` this does not materialise the
    entire ``EncryptedPackage`` stream in memory.  Only the requested bytes of
    the stream's sectors (or its mini-stream, for a small package) are read.
    """

    def __init__(self, ole, stream_name="EncryptedPackage"):
        sid = ole._find(stream_name)
        entry = ole.direntries[sid]
        if entry.entry_type != olefile.STGTY_STREAM:
            raise exceptions.FileFormatError(
                "{} is not an OLE stream".format(stream_name)
            )

        self._ole = ole
        self._stream_name = stream_name
        self.size = entry.size
        self._chain = None
        self._embedded = None

        if entry.size == 0:
            self._chain = []
        elif entry.is_minifat:
            # A mini-stream is by definition smaller than the 4096-byte cutoff;
            # copying it does not defeat the purpose of the package view.
            self._embedded = BytesPackageSource(ole.openstream(stream_name).read())
        else:
            if not entry.sect_chain:
                entry.build_sect_chain(ole)
            self._chain = list(entry.sect_chain)
            self._fp = ole.fp
            self._sector_size = ole.sector_size

    def read_at(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset >= self.size or length == 0:
            return b""

        if self._embedded is not None:
            return self._embedded.read_at(offset, length)

        remaining = min(length, self.size - offset)
        sector_index = offset // self._sector_size
        sector_offset = offset % self._sector_size
        result = bytearray()
        chain = self._chain

        while remaining:
            if sector_index >= len(chain):
                raise exceptions.DecryptionError(
                    "EncryptedPackage stream is truncated"
                )
            sector = chain[sector_index]
            if sector >= olefile.MAXREGSECT:
                raise exceptions.DecryptionError(
                    "EncryptedPackage stream contains an invalid sector"
                )

            take = min(self._sector_size - sector_offset, remaining)
            self._fp.seek(self._sector_size * (sector + 1) + sector_offset)
            chunk = self._fp.read(take)
            if len(chunk) != take:
                raise exceptions.DecryptionError(
                    "EncryptedPackage stream is truncated"
                )

            result += chunk
            remaining -= take
            sector_index += 1
            sector_offset = 0

        return bytes(result)

    def binding_token(self):
        file_token = _file_binding_token(self._ole.fp)
        if file_token is None:
            # No stable file identity (e.g. an in-memory OLE container):
            # never reuse a verification result.
            return None
        return (id(self._ole), self._stream_name, self.size, file_token)

    def close(self):
        if self._embedded is not None:
            self._embedded.close()


class ECMA376AgilePackageView(io.RawIOBase):
    """Seekable, read-only view over a decrypted Agile ``EncryptedPackage``.

    The view decrypts only the 4096-byte AES-CBC segments needed for a given
    read.  ``read()``/``seek()`` follow normal file semantics; ``read_range()``
    provides explicit random access.

    ``declared_size`` is the length stored in the 8-byte package header,
    ``encrypted_size`` is the number of ciphertext bytes in the stream (after
    the header), and ``available_size`` is the number of plaintext bytes that
    can actually be returned.  Normally ``available_size == declared_size``;
    for a truncated package it is bounded by the ciphertext capacity and the
    final read is short.

    Integrity is a property of the whole ``EncryptedPackage`` stream, not of
    the segments touched by a read.  With ``require_integrity=True`` the first
    read performs one full-stream HMAC pass before any plaintext is returned.
    That result is reused only while the source is provably the same read-only
    ciphertext (see :meth:`verify_integrity`).
    """

    SEGMENT_LENGTH = 4096
    INTEGRITY_CHUNK_SIZE = 65536

    def __init__(
        self,
        secret_key,
        key_data_salt,
        hash_algorithm,
        block_size,
        encrypted_hmac_key,
        encrypted_hmac_value,
        source,
        require_integrity=False,
        cache_segments=16,
    ):
        super().__init__()
        self._secret_key = secret_key
        self._key_data_salt = key_data_salt
        self._hash_algorithm = hash_algorithm
        self._block_size = int(block_size)
        self._source = (
            source if isinstance(source, _PackageSource) else _make_package_source(source)
        )
        self._encrypted_hmac_key = encrypted_hmac_key
        self._encrypted_hmac_value = encrypted_hmac_value
        self._require_integrity = bool(require_integrity)

        if self._block_size <= 0:
            raise ValueError("block size must be positive")
        if cache_segments is None or cache_segments <= 0:
            cache_segments = 0
        self._cache_segments = cache_segments
        self._segment_cache = {}
        self._cache_order = []

        self._pos = 0
        self._verified_token = None
        self._verified = False
        self._stats = {
            "source_bytes_read": 0,
            "segments_decrypted": 0,
            "segment_cache_hits": 0,
            "integrity_verifications": 0,
            "integrity_bytes_read": 0,
            "plaintext_bytes_returned": 0,
        }

        header = self._read_source(0, 8)
        if len(header) != 8:
            raise exceptions.DecryptionError(
                "EncryptedPackage stream is too short to contain a size header"
            )
        (self.declared_size,) = unpack("<Q", header)
        self.encrypted_size = max(0, self._source.size - 8)
        # AES-CBC can only decrypt complete blocks.  Any trailing partial block
        # is not part of the returnable plaintext range.
        self._decryptable_size = (
            self.encrypted_size // self._block_size
        ) * self._block_size
        self.available_size = min(self.declared_size, self._decryptable_size)

        # A local segment decrypt succeeding does not say anything about the
        # rest of the package: keep this flag independent from reads.
        self._truncated = self.declared_size > self._decryptable_size

    # -- source helpers -------------------------------------------------
    def _read_source(self, offset, length):
        data = self._source.read_at(offset, length)
        self._stats["source_bytes_read"] += len(data)
        return data

    # -- statistics -----------------------------------------------------
    @property
    def stats(self):
        """Return a snapshot of :class:`PackageViewStats`."""
        return PackageViewStats(**self._stats)

    def reset_stats(self):
        """Reset all counters without discarding cached segments."""
        for key in self._stats:
            self._stats[key] = 0

    def replace_source(self, source):
        """Point the view at a different ciphertext source.

        Any previous integrity verification is discarded unconditionally: even
        if the new source happens to report the same binding token, it is not
        the ciphertext that was authenticated.  Cached plaintext segments are
        dropped as well, since they belong to the old source.
        """
        new_source = _make_package_source(source)
        old_source = self._source
        self._source = new_source
        self._segment_cache.clear()
        self._cache_order.clear()
        self._verified = False
        self._verified_token = None
        if old_source is not new_source:
            old_source.close()

        header = self._read_source(0, 8)
        if len(header) != 8:
            raise exceptions.DecryptionError(
                "EncryptedPackage stream is too short to contain a size header"
            )
        (self.declared_size,) = unpack("<Q", header)
        self.encrypted_size = max(0, self._source.size - 8)
        self._decryptable_size = (
            self.encrypted_size // self._block_size
        ) * self._block_size
        self.available_size = min(self.declared_size, self._decryptable_size)
        self._truncated = self.declared_size > self._decryptable_size
        self._pos = 0

    @property
    def source_bytes_read(self):
        return self._stats["source_bytes_read"]

    @property
    def segments_decrypted(self):
        return self._stats["segments_decrypted"]

    @property
    def decryptable_size(self):
        """Ciphertext capacity in complete AES blocks, excluding the header."""
        return self._decryptable_size

    @property
    def truncated(self):
        """True when the declared plaintext size exceeds ciphertext capacity."""
        return self._truncated

    @property
    def verified(self):
        """True if the current source passed verification and is unchanged.

        For a source without a stable identity, a successful check is true
        only until the source is replaced; it is never reused for a later
        check.
        """
        if not self._verified:
            return False
        if self._verified_token is None:
            return True
        return self._source.binding_token() == self._verified_token

    # -- segment decryption --------------------------------------------
    def _decrypt_segment(self, index):
        cached = self._segment_cache.get(index)
        if cached is not None:
            self._stats["segment_cache_hits"] += 1
            self._touch_cache(index)
            return cached

        segment_offset = index * self.SEGMENT_LENGTH
        segment_length = min(
            self.SEGMENT_LENGTH, self._decryptable_size - segment_offset
        )
        if segment_length <= 0:
            return b""
        if segment_length % self._block_size:
            raise exceptions.DecryptionError(
                "EncryptedPackage segment is not block aligned"
            )

        ciphertext = self._read_source(8 + segment_offset, segment_length)
        if len(ciphertext) != segment_length:
            raise exceptions.DecryptionError(
                "EncryptedPackage stream is truncated"
            )

        hash_calc = _get_hash_func(self._hash_algorithm)
        salt_with_block_key = self._key_data_salt + pack("<I", index)
        iv = hash_calc(salt_with_block_key).digest()[: self._block_size]
        plaintext = _decrypt_aes_cbc(ciphertext, self._secret_key, iv)
        self._stats["segments_decrypted"] += 1

        if self._cache_segments:
            self._segment_cache[index] = plaintext
            self._touch_cache(index)
            while len(self._cache_order) > self._cache_segments:
                evicted = self._cache_order.pop(0)
                self._segment_cache.pop(evicted, None)

        return plaintext

    def _touch_cache(self, index):
        try:
            self._cache_order.remove(index)
        except ValueError:
            pass
        self._cache_order.append(index)

    # -- integrity ------------------------------------------------------
    def _integrity_parameters(self):
        hash_calc = _get_hash_func(self._hash_algorithm)
        iv1 = hash_calc(self._key_data_salt + blkKey_dataIntegrity1).digest()
        iv1 = iv1[: self._block_size]
        iv2 = hash_calc(self._key_data_salt + blkKey_dataIntegrity2).digest()
        iv2 = iv2[: self._block_size]

        hash_size = hash_calc().digest_size
        hmac_key = _decrypt_aes_cbc(
            self._encrypted_hmac_key, self._secret_key, iv1
        )[:hash_size]
        hmac_value = _decrypt_aes_cbc(
            self._encrypted_hmac_value, self._secret_key, iv2
        )[:hash_size]
        return hmac_key, hmac_value, hash_calc

    def verify_integrity(self, force=False):
        """Verify the HMAC of the complete ``EncryptedPackage`` stream.

        Returns ``True`` when valid.  A successful result is reused only for
        the exact same read-only ciphertext: the cache is dropped as soon as
        the source binding changes (for example after the backing file is
        modified or replaced).  Sources without a stable identity
        (``binding_token() is None``) are never reused and are re-read for
        every check.  A failed check is never cached.
        """
        token = self._source.binding_token()
        if (
            not force
            and self._verified
            and token is not None
            and token == self._verified_token
        ):
            return True

        hmac_key, hmac_value, hash_calc = self._integrity_parameters()
        msg_hmac = hmac.new(hmac_key, digestmod=hash_calc)

        offset = 0
        while offset < self._source.size:
            chunk = self._read_source(
                offset, min(self.INTEGRITY_CHUNK_SIZE, self._source.size - offset)
            )
            if not chunk:
                raise exceptions.DecryptionError(
                    "EncryptedPackage stream ended during integrity verification"
                )
            msg_hmac.update(chunk)
            offset += len(chunk)

        self._stats["integrity_verifications"] += 1
        self._stats["integrity_bytes_read"] += offset

        verified = hmac.compare_digest(hmac_value, msg_hmac.digest())
        if verified and token is not None:
            # If the source changed while it was being hashed, the bytes that
            # were authenticated are not the bytes currently exposed; do not
            # reuse this result.
            verified = self._source.binding_token() == token

        if verified:
            self._verified = True
            self._verified_token = token
        else:
            self._verified = False
            self._verified_token = None
        return verified

    def _ensure_integrity(self):
        if not self._require_integrity:
            return
        if not self.verify_integrity():
            raise exceptions.InvalidKeyError(
                "Payload integrity verification failed"
            )

    def require_integrity(self, enabled=True):
        """Enable or disable whole-package verification for subsequent reads.

        Enabling this does not by itself verify the package; the next
        non-empty read does.  Disabling it does not discard an existing
        successful verification, which can still be inspected via
        :attr:`verified`.
        """
        self._require_integrity = bool(enabled)
        return self

    # -- reading --------------------------------------------------------
    def read_range(self, offset, length):
        """Read up to ``length`` plaintext bytes starting at ``offset``.

        ``offset`` may start inside a segment, a range may span any number of
        segments, and seeking backwards is allowed.  A range extending past
        ``available_size`` is shortened rather than padded; ``b""`` is
        returned when ``offset`` is at or beyond the end.
        """
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if self.closed:
            raise ValueError("I/O operation on closed package view")
        if offset >= self.available_size or length == 0:
            return b""

        self._ensure_integrity()

        end = min(offset + length, self.available_size)
        position = offset
        out = bytearray()

        while position < end:
            segment_index = position // self.SEGMENT_LENGTH
            segment_offset = position % self.SEGMENT_LENGTH
            segment = self._decrypt_segment(segment_index)
            if segment_offset >= len(segment):
                break
            take = min(len(segment) - segment_offset, end - position)
            out += segment[segment_offset : segment_offset + take]
            position += take

        if self._require_integrity and self._verified_token is not None:
            # The source may have changed while the segments were being read.
            # Do not hand out plaintext authenticated against other bytes.
            token = self._source.binding_token()
            if token != self._verified_token:
                self._verified = False
                self._verified_token = None
                raise exceptions.InvalidKeyError(
                    "Payload integrity verification failed"
                )

        self._stats["plaintext_bytes_returned"] += len(out)
        return bytes(out)

    def read(self, size=-1):
        if self.closed:
            raise ValueError("I/O operation on closed package view")
        if size is None or size < 0:
            size = self.available_size - self._pos
        data = self.read_range(self._pos, size)
        self._pos += len(data)
        return data

    def readinto(self, buffer):
        if self.closed:
            raise ValueError("I/O operation on closed package view")
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def seek(self, offset, whence=os.SEEK_SET):
        if self.closed:
            raise ValueError("I/O operation on closed package view")
        if whence == os.SEEK_SET:
            new_pos = offset
        elif whence == os.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == os.SEEK_END:
            new_pos = self.declared_size + offset
        else:
            raise ValueError("invalid whence value")
        if new_pos < 0:
            raise ValueError("negative seek position")
        self._pos = new_pos
        return self._pos

    def tell(self):
        return self._pos

    def readable(self):
        return True

    def seekable(self):
        return True

    def writable(self):
        return False

    @property
    def size(self):
        """Declared plaintext size from the package header."""
        return self.declared_size

    def close(self):
        if not self.closed:
            self._segment_cache.clear()
            self._cache_order.clear()
            self._source.close()
        super().close()


def _make_package_source(source):
    """Coerce bytes/file objects into a read-only :class:`_PackageSource`."""
    if isinstance(source, _PackageSource):
        return source
    if isinstance(source, olefile.OleFileIO):
        return OleStreamPackageSource(source)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return BytesPackageSource(source)
    if hasattr(source, "read") and hasattr(source, "seek"):
        try:
            source.fileno()
        except (AttributeError, OSError, ValueError):
            # An in-memory stream can be snapshotted so later mutation cannot
            # invalidate (or reuse) a verification result.
            position = source.tell()
            source.seek(0)
            data = source.read()
            source.seek(position)
            return BytesPackageSource(data)
        return SeekablePackageSource(source)
    raise TypeError("Unsupported package source: {!r}".format(type(source)))


class ECMA376Agile:
    def __init__(self):
        pass

    @staticmethod
    def open_package_view(
        secret_key,
        info,
        source,
        require_integrity=False,
        cache_segments=16,
    ):
        """Return a seekable, read-only view over an Agile payload.

        ``info`` is the mapping produced by ``_parseinfo_agile``.  ``source``
        may be an OLE ``OleFileIO``, a seekable binary file, or a bytes-like
        object containing the full ``EncryptedPackage`` stream.
        """
        if isinstance(source, olefile.OleFileIO):
            source = OleStreamPackageSource(source)

        return ECMA376AgilePackageView(
            secret_key,
            info["keyDataSalt"],
            info["keyDataHashAlgorithm"],
            info["keyDataBlockSize"],
            info["encryptedHmacKey"],
            info["encryptedHmacValue"],
            source,
            require_integrity=require_integrity,
            cache_segments=cache_segments,
        )

    @staticmethod
    def _derive_iterated_hash_from_password(
        password, saltValue, hashAlgorithm, spinValue
    ):
        r"""
        Do a partial password-based hash derivation.
        Note the block key is not taken into consideration in this function.
        """
        # TODO: This function is quite expensive and it should only be called once.
        # We need to save the result for later use.
        # This is not covered by the specification, but MS Word does so.

        hashCalc = _get_hash_func(hashAlgorithm)

        # NOTE: Initial round sha512(salt + password)
        h = hashCalc(saltValue + password.encode("UTF-16LE"))

        # NOTE: Iteration of 0 -> spincount-1; hash = sha512(iterator + hash)
        for i in range(0, spinValue, 1):
            h = hashCalc(pack("<I", i) + h.digest())

        return h

    @staticmethod
    def _derive_encryption_key(h, blockKey, hashAlgorithm, keyBits):
        r"""
        Finish the password-based key derivation by hashing last hash + blockKey.
        """
        hashCalc = _get_hash_func(hashAlgorithm)
        h_final = hashCalc(h + blockKey)

        # NOTE: Needed to truncate encryption key to bitsize
        encryption_key = h_final.digest()[: keyBits // 8]

        return encryption_key

    @staticmethod
    def decrypt(key, keyDataSalt, hashAlgorithm, ibuf):
        r"""
        Return decrypted data.

            >>> key = b'@ f\t\xd9\xfa\xad\xf2K\x07j\xeb\xf2\xc45\xb7B\x92\xc8\xb8\xa7\xaa\x81\xbcg\x9b\xe8\x97\x11\xb0*\xc2'
            >>> keyDataSalt = b'\x8f\xc7x"+P\x8d\xdcL\xe6\x8c\xdd\x15<\x16\xb4'
            >>> hashAlgorithm = 'SHA512'
        """
        # NOTE: See https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/9e61da63-8ddb-4c0a-b25d-f85d990f44c8
        SEGMENT_LENGTH = 4096
        hashCalc = _get_hash_func(hashAlgorithm)

        obuf = io.BytesIO()

        # NOTE: See https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/b60c8b35-2db2-4409-8710-59d88a793f83
        ibuf.seek(0)
        totalSize = unpack("<Q", ibuf.read(8))
        totalSize = totalSize[0]
        logger.debug("totalSize: {}".format(totalSize))
        remaining = totalSize
        for i, buf in enumerate(
            iter(functools.partial(ibuf.read, SEGMENT_LENGTH), b"")
        ):
            saltWithBlockKey = keyDataSalt + pack("<I", i)
            iv = hashCalc(saltWithBlockKey).digest()
            iv = iv[:16]
            aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = aes.decryptor()
            dec = decryptor.update(buf) + decryptor.finalize()
            # TODO: Check
            if remaining < len(dec):
                dec = dec[:remaining]
            obuf.write(dec)
            remaining -= len(dec)
            # TODO: Check if this is needed
            if remaining <= 0:
                break
        return obuf.getvalue()  # return obuf.getbuffer()

    @staticmethod
    def encrypt(key, ibuf, salt_value=None, spin_count=100000):
        """
        Return an OLE compound file buffer (complete with headers) which contains ibuf encrypted into a single stream.

        When salt_value is not specified (the default), we generate a random one.
        """

        # Encryption ported from C++ (https://github.com/herumi/msoffice, BSD-3)

        info, secret_key = ECMA376Agile.generate_encryption_parameters(
            key, salt_value, spin_count
        )
        encrypted_data = ECMA376Agile.encrypt_payload(
            ibuf, info.encryptedKey, secret_key, info.keyData.saltValue
        )
        encryption_info = ECMA376Agile.get_encryption_information(
            info, encrypted_data, secret_key
        )

        obuf = io.BytesIO()
        ECMA376Encrypted(encrypted_data, encryption_info).write_to(obuf)

        return obuf.getvalue()

    @staticmethod
    def get_encryption_information(
        info: ECMA376AgileEncryptionInfo, encrypted_data, secretKey
    ):
        """
        Return the content of an EncryptionInfo Stream, including the short header, per the specifications at

        https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/87020a34-e73f-4139-99bc-bbdf6cf6fa55
        """
        hmacKey, hmacValue = ECMA376Agile.generate_integrity_parameter(
            encrypted_data, info.keyData, secretKey, info.keyData.saltValue
        )

        info.encryptedHmacKey = hmacKey
        info.encryptedHmacValue = hmacValue

        xml_descriptor = info.toEncryptionDescriptor().encode("UTF-8")
        header_descriptor = info.getEncryptionDescriptorHeader()

        return header_descriptor + xml_descriptor

    @staticmethod
    def generate_encryption_parameters(key, salt_value=None, spin_count=100000):
        """
        Generates encryption parameters used to encrypt a payload.

        Returns the information + a secret key.
        """
        info = ECMA376AgileEncryptionInfo()
        info.spinCount = spin_count

        info.encryptedKey.saltValue = _get_salt(salt_value, info.encryptedKey.saltSize)

        h = ECMA376Agile._derive_iterated_hash_from_password(
            key, info.encryptedKey.saltValue, info.encryptedKey.hashName, info.spinCount
        ).digest()

        key1 = ECMA376Agile._derive_encryption_key(
            h,
            blkKey_VerifierHashInput,
            info.encryptedKey.hashName,
            info.encryptedKey.keyBits,
        )
        key2 = ECMA376Agile._derive_encryption_key(
            h,
            blkKey_encryptedVerifierHashValue,
            info.encryptedKey.hashName,
            info.encryptedKey.keyBits,
        )
        key3 = ECMA376Agile._derive_encryption_key(
            h,
            blkKey_encryptedKeyValue,
            info.encryptedKey.hashName,
            info.encryptedKey.keyBits,
        )

        verifierHashInput = _random_buffer(info.encryptedKey.saltSize)
        verifierHashInput = _resize_buffer(
            verifierHashInput,
            _round_up(len(verifierHashInput), info.encryptedKey.blockSize),
        )

        info.encryptedVerifierHashInput = _encrypt_aes_cbc(
            verifierHashInput, key1, info.encryptedKey.saltValue
        )

        hashedVerifier = _get_hash_func(info.encryptedKey.hashName)(
            verifierHashInput
        ).digest()
        hashedVerifier = _resize_buffer(
            hashedVerifier, _round_up(len(hashedVerifier), info.encryptedKey.blockSize)
        )

        info.encryptedVerifierHashValue = _encrypt_aes_cbc(
            hashedVerifier, key2, info.encryptedKey.saltValue
        )

        secret_key = _random_buffer(info.encryptedKey.saltSize)
        secret_key = _normalize_key(secret_key, info.encryptedKey.keyBits // 8)

        info.encryptedKeyValue = _encrypt_aes_cbc(
            secret_key, key3, info.encryptedKey.saltValue
        )

        info.keyData.saltValue = _get_salt(salt_size=info.keyData.saltSize)

        return info, secret_key

    @staticmethod
    def encrypt_payload(ibuf, params: ECMA376AgileCipherParams, secret_key, salt_value):
        """
        Encrypts a payload using the params and secrets passed in.

        Returns the encrypted data as a byte array.
        """
        # Specifications calls for storing the original (unpadded) size as a 64 bit little-endian
        # number at the start of the buffer. We'll loop while there's data, and come back at the
        # end to update the total size, instead of seeking to the end of ibuf to get the size,
        # just in case ibuf is a streaming buffer...
        total_size = 0
        obuf = io.BytesIO()
        obuf.write(pack("<Q", total_size))

        hashCalc = _get_hash_func(params.hashName)
        SEGMENT_LENGTH = 4096

        i = 0
        while True:
            buf = ibuf.read(SEGMENT_LENGTH)
            if not buf:
                break

            iv = _normalize_key(
                hashCalc(salt_value + pack("<I", i)).digest(), params.saltSize
            )

            # Per the specifications, we need to make sure the last chunk is padded to our
            # block size
            enc = _encrypt_aes_cbc_padded(buf, secret_key, iv, params.blockSize)

            obuf.write(enc)
            total_size += len(buf)

            i += 1

        # Update size in the header
        obuf.seek(0)
        obuf.write(pack("<Q", total_size))

        return obuf.getvalue()

    @staticmethod
    def generate_integrity_parameter(
        encrypted_data, params: ECMA376AgileCipherParams, secret_key, salt_value
    ):
        """
        Returns the encrypted HmacKey and HmacValue.
        """
        salt = _random_buffer(params.hashSize)

        iv1 = _generate_iv(params, blkKey_dataIntegrity1, salt_value)
        iv2 = _generate_iv(params, blkKey_dataIntegrity2, salt_value)

        encryptedHmacKey = _encrypt_aes_cbc(salt, secret_key, iv1)

        msg_hmac = hmac.new(salt, encrypted_data, _get_hash_func(params.hashName))
        hmacValue = msg_hmac.digest()

        encryptedHmacValue = _encrypt_aes_cbc(hmacValue, secret_key, iv2)

        return encryptedHmacKey, encryptedHmacValue

    @staticmethod
    def verify_password(
        password,
        saltValue,
        hashAlgorithm,
        encryptedVerifierHashInput,
        encryptedVerifierHashValue,
        spinValue,
        keyBits,
    ):
        r"""
        Return True if the given password is valid.

            >>> password = 'Password1234_'
            >>> saltValue = b'\xcb\xca\x1c\x99\x93C\xfb\xad\x92\x07V4\x15\x004\xb0'
            >>> hashAlgorithm = 'SHA512'
            >>> encryptedVerifierHashInput = b'9\xee\xa5N&\xe5\x14y\x8c(K\xc7qM8\xac'
            >>> encryptedVerifierHashValue = b'\x147mm\x81s4\xe6\xb0\xffO\xd8"\x1a|g\x8e]\x8axN\x8f\x99\x9fL\x18\x890\xc3jK)\xc5\xb33`' + \
            ... b'[\\\xd4\x03\xb0P\x03\xad\xcf\x18\xcc\xa8\xcb\xab\x8d\xeb\xe3s\xc6V\x04\xa0\xbe\xcf\xae\\\n\xd0'
            >>> spinValue = 100000
            >>> keyBits = 256
            >>> ECMA376Agile.verify_password(password, saltValue, hashAlgorithm, encryptedVerifierHashInput, encryptedVerifierHashValue, spinValue, keyBits)
            True
        """
        # NOTE: See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/a57cb947-554f-4e5e-b150-3f2978225e92

        h = ECMA376Agile._derive_iterated_hash_from_password(
            password, saltValue, hashAlgorithm, spinValue
        )

        key1 = ECMA376Agile._derive_encryption_key(
            h.digest(), blkKey_VerifierHashInput, hashAlgorithm, keyBits
        )
        key2 = ECMA376Agile._derive_encryption_key(
            h.digest(), blkKey_encryptedVerifierHashValue, hashAlgorithm, keyBits
        )

        hash_input = _decrypt_aes_cbc(encryptedVerifierHashInput, key1, saltValue)
        hashCalc = _get_hash_func(hashAlgorithm)
        acutal_hash = hashCalc(hash_input)
        acutal_hash = acutal_hash.digest()

        expected_hash = _decrypt_aes_cbc(encryptedVerifierHashValue, key2, saltValue)
        # NOTE: The decrypted verifier hash is padded to the block size and must be
        # truncated to the hash size before comparing (e.g. 20 bytes for SHA1)
        expected_hash = expected_hash[: hashCalc().digest_size]

        return hmac.compare_digest(acutal_hash, expected_hash)

    @staticmethod
    def verify_integrity(
        secretKey,
        keyDataSalt,
        keyDataHashAlgorithm,
        keyDataBlockSize,
        encryptedHmacKey,
        encryptedHmacValue,
        stream,
    ):
        r"""
        Return True if the HMAC of the data payload is valid.
        """
        # NOTE: See https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/63d9c262-82b9-4fa3-a06d-d087b93e3b00

        hashCalc = _get_hash_func(keyDataHashAlgorithm)

        iv1 = hashCalc(keyDataSalt + blkKey_dataIntegrity1).digest()
        iv1 = iv1[:keyDataBlockSize]
        iv2 = hashCalc(keyDataSalt + blkKey_dataIntegrity2).digest()
        iv2 = iv2[:keyDataBlockSize]

        # NOTE: The decrypted HMAC key and value are padded to the block size and must
        # be truncated to the hash size (e.g. 20 bytes for SHA1)
        hashSize = hashCalc().digest_size
        hmacKey = _decrypt_aes_cbc(encryptedHmacKey, secretKey, iv1)[:hashSize]
        hmacValue = _decrypt_aes_cbc(encryptedHmacValue, secretKey, iv2)[:hashSize]

        msg_hmac = hmac.new(hmacKey, stream.read(), hashCalc)
        actualHmac = msg_hmac.digest()
        stream.seek(0)

        return hmac.compare_digest(hmacValue, actualHmac)

    @staticmethod
    def makekey_from_privkey(privkey, encryptedKeyValue):
        privkey = serialization.load_pem_private_key(
            privkey.read(), password=None, backend=default_backend()
        )
        skey = privkey.decrypt(encryptedKeyValue, padding.PKCS1v15())
        return skey

    @staticmethod
    def makekey_from_password(
        password, saltValue, hashAlgorithm, encryptedKeyValue, spinValue, keyBits
    ):
        r"""
        Generate intermediate key from given password.

            >>> password = 'Password1234_'
            >>> saltValue = b'Lr]E\xdca\x0f\x93\x94\x12\xa0M\xa7\x91\x04f'
            >>> hashAlgorithm = 'SHA512'
            >>> encryptedKeyValue = b"\xa1l\xd5\x16Zz\xb9\xd2q\x11>\xd3\x86\xa7\x8c\xf4\x96\x92\xe8\xe5'\xb0\xc5\xfc\x00U\xed\x08\x0b|\xb9K"
            >>> spinValue = 100000
            >>> keyBits = 256
            >>> expected = b'@ f\t\xd9\xfa\xad\xf2K\x07j\xeb\xf2\xc45\xb7B\x92\xc8\xb8\xa7\xaa\x81\xbcg\x9b\xe8\x97\x11\xb0*\xc2'
            >>> ECMA376Agile.makekey_from_password(password, saltValue, hashAlgorithm, encryptedKeyValue, spinValue, keyBits) == expected
            True
        """

        h = ECMA376Agile._derive_iterated_hash_from_password(
            password, saltValue, hashAlgorithm, spinValue
        )
        encryption_key = ECMA376Agile._derive_encryption_key(
            h.digest(), blkKey_encryptedKeyValue, hashAlgorithm, keyBits
        )

        skey = _decrypt_aes_cbc(encryptedKeyValue, encryption_key, saltValue)

        return skey
