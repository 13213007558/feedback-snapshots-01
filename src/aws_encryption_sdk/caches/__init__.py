# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Common functions and structures for use in cryptographic materials caches.

.. versionadded:: 1.3.0
"""
import logging
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

_LOGGER = logging.getLogger(__name__)


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
        self.bytes_reserved = 0
        self.messages_reserved = 0
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

    def reserve(self, bytes_to_reserve, max_messages_encrypted, max_bytes_encrypted):
        """Reserves capacity on this entry for a new encryption job.

        The check and the counter update happen while holding the entry lock, so concurrent
        jobs cannot both pass the limit check against the same remaining capacity. Limits are
        evaluated against the sum of committed usage and outstanding reservations so that
        in-flight jobs keep counting against the key while they are still running.

        :param int bytes_to_reserve: Number of plaintext bytes the job expects to encrypt
        :param int max_messages_encrypted: Maximum number of messages allowed on this entry
        :param int max_bytes_encrypted: Maximum number of bytes allowed on this entry
        :returns: a reservation handle if capacity was available, otherwise ``None``
        :rtype: aws_encryption_sdk.caches.CacheReservation
        """
        with self._lock:
            if not self.valid:
                return None
            projected_messages = self.messages_encrypted + self.messages_reserved + 1
            projected_bytes = self.bytes_encrypted + self.bytes_reserved + bytes_to_reserve
            if projected_messages > max_messages_encrypted or projected_bytes > max_bytes_encrypted:
                return None
            super(CryptoMaterialsCacheEntry, self).__setattr__("messages_reserved", self.messages_reserved + 1)
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "bytes_reserved", self.bytes_reserved + bytes_to_reserve
            )
            return CacheReservation(
                entry=self,
                reserved_bytes=bytes_to_reserve,
                reserved_messages=1,
            )

    def commit_reservation(self, reservation, bytes_encrypted):
        """Converts a reservation into committed usage once a job finishes successfully.

        :param reservation: Reservation previously granted by :meth:`reserve`
        :type reservation: aws_encryption_sdk.caches.CacheReservation
        :param int bytes_encrypted: Number of plaintext bytes actually encrypted
        """
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "bytes_reserved", self.bytes_reserved - reservation.reserved_bytes
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "messages_reserved", self.messages_reserved - reservation.reserved_messages
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "bytes_encrypted", self.bytes_encrypted + bytes_encrypted
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "messages_encrypted", self.messages_encrypted + reservation.reserved_messages
            )

    def release_reservation(self, reservation):
        """Returns a reservation's capacity without recording any committed usage.

        Used when a job is cancelled or only reads part of its source before stopping, so
        capacity that was reserved but never consumed becomes available to other jobs.

        :param reservation: Reservation previously granted by :meth:`reserve`
        :type reservation: aws_encryption_sdk.caches.CacheReservation
        """
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "bytes_reserved", self.bytes_reserved - reservation.reserved_bytes
            )
            super(CryptoMaterialsCacheEntry, self).__setattr__(
                "messages_reserved", self.messages_reserved - reservation.reserved_messages
            )

    def invalidate(self):
        """Marks a cache entry as invalidated."""
        with self._lock:
            super(CryptoMaterialsCacheEntry, self).__setattr__("valid", False)


@attr.s(hash=False)
class CacheReservation(object):
    """Handle representing capacity reserved on a :class:`CryptoMaterialsCacheEntry` for one
    encryption job. Exactly one of :meth:`commit` and :meth:`release` must be invoked for every
    reservation; the object enforces this by making both operations idempotent.

    :param entry: Cache entry on which capacity was reserved
    :type entry: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
    :param int reserved_bytes: Number of bytes reserved for the job
    :param int reserved_messages: Number of message uses reserved for the job (always one)
    """

    entry = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsCacheEntry))
    reserved_bytes = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    reserved_messages = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    def __attrs_post_init__(self):
        """Prepares initial values not handled by attrs."""
        self._open = True

    @property
    def is_open(self):
        """Returns whether this reservation still holds reserved capacity."""
        return self._open

    def commit(self, bytes_encrypted):
        """Records the actual usage of a completed job and releases its reservation.

        :param int bytes_encrypted: Number of plaintext bytes actually encrypted
        """
        if not self._open:
            _LOGGER.debug("Ignoring commit on already closed cache reservation")
            return
        self.entry.commit_reservation(self, bytes_encrypted)
        self._open = False

    def release(self):
        """Cancels the reservation without recording committed usage."""
        if not self._open:
            _LOGGER.debug("Ignoring release on already closed cache reservation")
            return
        self.entry.release_reservation(self)
        self._open = False
