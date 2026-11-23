# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Common functions and structures for use in cryptographic materials caches.

.. versionadded:: 1.3.0
"""
import time
from threading import Lock

import attr
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from ..exceptions import NotSupportedError
from ..internal.formatting.encryption_context import serialize_encryption_context
from ..internal.formatting.serialize import serialize_encrypted_data_key
from ..materials_managers import DecryptionMaterials, EncryptionMaterials


def _new_cache_key_hasher():
    """Builds a new instance of the hasher used for building cache keys.

    :rtype: cryptography.hazmat.primitives.hashes.Hash
    """
    return hashes.Hash(hashes.SHA512(), backend=default_backend())


def _partition_name_hash(hasher, partition_name):
    """Generates the expected hash for the provided partition name.

    :param hasher: Existing hasher to use
    :type hasher: cryptography.hazmat.primitives.hashes.Hash
    :param bytes partition_name: Partition name to hash
    :returns: Complete hash
    :rtype: bytes
    """
    hasher.update(partition_name)
    return hasher.finalize()


def _encryption_context_hash(hasher, encryption_context):
    """Generates the expected hash for the provided encryption context.

    :param hasher: Existing hasher to use
    :type hasher: cryptography.hazmat.primitives.hashes.Hash
    :param dict encryption_context: Encryption context to hash
    :returns: Complete hash
    :rtype: bytes
    """
    serialized_encryption_context = serialize_encryption_context(encryption_context)
    hasher.update(serialized_encryption_context)
    return hasher.finalize()


def build_encryption_materials_cache_key(partition, request):
    """Generates a cache key for an encrypt request.

    :param bytes partition: Partition name for which to generate key
    :param request: Request for which to generate key
    :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
    :returns: cache key
    :rtype: bytes
    """
    if request.algorithm is None:
        _algorithm_info = b"\x00"
    else:
        _algorithm_info = b"\x01" + request.algorithm.id_as_bytes()

    hasher = _new_cache_key_hasher()
    _partition_hash = _partition_name_hash(hasher=hasher.copy(), partition_name=partition)
    _ec_hash = _encryption_context_hash(hasher=hasher.copy(), encryption_context=request.encryption_context)

    hasher.update(_partition_hash)
    hasher.update(_algorithm_info)
    hasher.update(_ec_hash)
    return hasher.finalize()


def _encrypted_data_keys_hash(hasher, encrypted_data_keys):
    """Generates the expected hash for the provided encrypted data keys.

    :param hasher: Existing hasher to use
    :type hasher: cryptography.hazmat.primitives.hashes.Hash
    :param iterable encrypted_data_keys: Encrypted data keys to hash
    :returns: Concatenated, sorted, list of all hashes
    :rtype: bytes
    """
    hashed_keys = []
    for edk in encrypted_data_keys:
        serialized_edk = serialize_encrypted_data_key(edk)
        _hasher = hasher.copy()
        _hasher.update(serialized_edk)
        hashed_keys.append(_hasher.finalize())
    return b"".join(sorted(hashed_keys))


# 512 bits of 0 for padding between hashes in decryption materials cache ID generation.
_512_BIT_PAD = b"\x00" * 64


def build_decryption_materials_cache_key(partition, request):
    """Generates a cache key for a decrypt request.

    :param bytes partition: Partition name for which to generate key
    :param request: Request for which to generate key
    :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
    :returns: cache key
    :rtype: bytes
    """
    hasher = _new_cache_key_hasher()
    _partition_hash = _partition_name_hash(hasher=hasher.copy(), partition_name=partition)
    _algorithm_info = request.algorithm.id_as_bytes()
    _edks_hash = _encrypted_data_keys_hash(hasher=hasher.copy(), encrypted_data_keys=request.encrypted_data_keys)
    _ec_hash = _encryption_context_hash(hasher=hasher.copy(), encryption_context=request.encryption_context)

    hasher.update(_partition_hash)
    hasher.update(_algorithm_info)
    hasher.update(_edks_hash)
    hasher.update(_512_BIT_PAD)
    hasher.update(_ec_hash)
    return hasher.finalize()


@attr.s(hash=False)
class CryptoMaterialsCacheEntryHints(object):
    """Optional metadata to associate with cryptographic materials cache entries.

    :param float lifetime: Number of seconds to retain entry in cache (optional)
    """

    lifetime = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(float)))


@attr.s(hash=False)
class CacheReservation(object):
    """A single, outstanding reservation of a cache entry's message and byte budget.

    A reservation is created when an encrypting stream asks for materials.  It holds the
    budget the stream may consume until the stream either commits the reservation (it wrote
    at least one ciphertext byte) or releases it (it was cancelled before writing anything).

    Committing or releasing a reservation more than once is a no-op so that callers do not
    have to coordinate stream teardown paths.

    :param entry: Cache entry whose budget is reserved
    :type entry: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
    :param int messages: Number of message slots reserved
    :param int bytes: Number of plaintext bytes reserved
    """

    entry = attr.ib()
    messages = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    bytes = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    def __attrs_post_init__(self):
        """Prepares initial values."""
        self._finalized = False

    @property
    def finalized(self):
        """Returns whether this reservation has already been committed or released."""
        return self._finalized

    def commit(self, actual_bytes=None):
        """Converts the reserved budget into real, billed usage on the entry.

        :param int actual_bytes: Actual plaintext bytes encrypted.  When smaller than the
            reserved byte amount (an unknown-length reservation against an upper bound), the
            unused portion of the reservation is returned.
        """
        if self._finalized:
            return
        self.entry._commit_reservation(self, actual_bytes)  # pylint: disable=protected-access
        self._finalized = True

    def release(self):
        """Returns the reserved budget to the entry without billing it."""
        if self._finalized:
            return
        self.entry._release_reservation(self)  # pylint: disable=protected-access
        self._finalized = True


@attr.s(hash=False)
class CryptoMaterialsCacheEntry(object):
    # pylint: disable=too-many-instance-attributes
    """Value and metadata store for cryptographic materials cache entries.

    :param bytes cache_key: Identifier for entries in cache
    :param value: Value to store in cache entry
    :param hints: Metadata to associate with entry (optional)
    :type hints: aws_encryption_sdk.caches.CryptoMaterialsCacheEntryHints
    """

    cache_key = attr.ib(validator=attr.validators.instance_of(bytes))
    value = attr.ib(validator=attr.validators.instance_of((EncryptionMaterials, DecryptionMaterials)))
    hints = attr.ib(
        default=attr.Factory(CryptoMaterialsCacheEntryHints),
        validator=attr.validators.optional(attr.validators.instance_of(CryptoMaterialsCacheEntryHints)),
    )

    def __attrs_post_init__(self):
        """Prepares initial values."""
        self.creation_time = time.time()
        self.bytes_encrypted = 0
        self.messages_encrypted = 0
        # Billed usage (messages_encrypted / bytes_encrypted) only counts reservations that
        # were committed.  The reserved_* counters track budget promised to in-flight streams
        # that have not yet settled, so concurrent streams cannot oversubscribe an entry.
        self.reserved_messages = 0
        self.reserved_bytes = 0
        self.valid = True
        self._lock = Lock()

        # Enables setattr whitelist restriction
        # Must always be the final line in this method
        self._init_completed = True

    def __setattr__(self, name, value):
        """Disable setting of attributes after __attrs_post_init__ has run.  This provides a bit
        more certainty that usage values have not been modified.
        """
        if hasattr(self, "_init_completed"):
            raise NotSupportedError("Attributes may not be set on CryptoMaterialsCacheEntry objects")
        return super(CryptoMaterialsCacheEntry, self).__setattr__(name, value)

    @property
    def age(self):
        """Returns this entry's current age in seconds.

        :rtype: float
        """
        return time.time() - self.creation_time

    def is_too_old(self):
        """Determines if if this entry's lifetime has passed.

        :rtype: bool
        """
        if self.hints.lifetime is None:
            return False
        return self.age > self.hints.lifetime

    def _update_with_message_bytes_encrypted(self, bytes_encrypted):
        """Updates this cache entry's usage metadata to reflect one more message of size
        `bytes_encrypted` having been encrypted with this entry.

        :param int bytes_encrypted: Number of bytes encrypted in registered use.
        """
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__("messages_encrypted", self.messages_encrypted + 1)
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "bytes_encrypted", self.bytes_encrypted + bytes_encrypted
            )

    def can_reserve(self, messages, bytes_encrypted, max_messages, max_bytes):
        """Determines whether reserving `messages` and `bytes_encrypted` stays within budget.

        Billed usage and every still-outstanding reservation both count against the limits,
        so two concurrent streams can never be promised the same final slot.

        :param int messages: Message slots the caller wants to reserve
        :param int bytes_encrypted: Plaintext bytes the caller wants to reserve
        :param int max_messages: Maximum allowed messages for the owning caching CMM
        :param int max_bytes: Maximum allowed bytes for the owning caching CMM
        :rtype: bool
        """
        with self._lock:
            return (
                self.messages_encrypted + self.reserved_messages + messages <= max_messages
                and self.bytes_encrypted + self.reserved_bytes + bytes_encrypted <= max_bytes
            )

    def reserve(self, messages, bytes_encrypted):
        """Promises budget to an in-flight stream and returns a reservation handle.

        :param int messages: Message slots to reserve
        :param int bytes_encrypted: Plaintext bytes to reserve
        :rtype: aws_encryption_sdk.caches.CacheReservation
        """
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "reserved_messages", self.reserved_messages + messages
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "reserved_bytes", self.reserved_bytes + bytes_encrypted
            )
        return CacheReservation(entry=self, messages=messages, bytes=bytes_encrypted)

    def _commit_reservation(self, reservation, actual_bytes=None):
        """Bills a reservation as real usage and clears its hold on the reserved budget.

        When `actual_bytes` is supplied, only that many bytes are billed; any bytes reserved
        beyond the real plaintext size (unknown-length upper bound) are released.
        """
        billed_bytes = reservation.bytes if actual_bytes is None else actual_bytes
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "reserved_messages", self.reserved_messages - reservation.messages
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "reserved_bytes", self.reserved_bytes - reservation.bytes
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "messages_encrypted", self.messages_encrypted + reservation.messages
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "bytes_encrypted", self.bytes_encrypted + billed_bytes
            )

    def _release_reservation(self, reservation):
        """Returns a reservation's budget without billing it."""
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "reserved_messages", self.reserved_messages - reservation.messages
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "reserved_bytes", self.reserved_bytes - reservation.bytes
            )

    def invalidate(self):
        """Marks a cache entry as invalidated."""
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__("valid", False)
