# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Caching crypto material manager."""
import logging
import uuid
from threading import Lock

import attr
import six

from ..caches import (
    CryptoMaterialsCacheEntryHints,
    build_decryption_materials_cache_key,
    build_encryption_materials_cache_key,
)
from ..caches.base import CryptoMaterialsCache
from ..exceptions import CacheKeyError
from ..internal.defaults import MAX_BYTES_PER_KEY, MAX_MESSAGES_PER_KEY
from ..internal.str_ops import to_bytes
from ..key_providers.base import MasterKeyProvider
from . import EncryptionMaterialsRequest
from .base import CryptoMaterialsManager
from .default import DefaultCryptoMaterialsManager

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class CachingCryptoMaterialsManager(CryptoMaterialsManager):
    """Crypto material manager which caches results from an underlying material manager.

    .. versionadded:: 1.3.0

    >>> import aws_encryption_sdk
    >>> kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ... ])
    >>> local_cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=100)
    >>> caching_materials_manager = aws_encryption_sdk.CachingCryptoMaterialsManager(
    ...     master_key_provider=kms_key_provider,
    ...     cache=local_cache,
    ...     max_age=600.0,
    ...     max_messages_encrypted=10
    ... )

    .. note::
        The partition name is used to enable a single cache instance to be used by multiple
        material manager instances by partitioning the entries in that cache based on this
        value.  If no partition name is provided, a random UUID will be used.

    .. note::
        Either `backing_materials_manager` or `master_key_provider` must be provided.
        `backing_materials_manager` will always be used if present.

    :param cache: Crypto cache to use with material manager
    :type cache: aws_encryption_sdk.caches.base.CryptoMaterialsCache
    :param backing_materials_manager: Crypto material manager to back this caching material manager
        (either `backing_materials_manager` or `master_key_provider` required)
    :type backing_materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    :param master_key_provider: Master key provider to use (either `backing_materials_manager` or
        `master_key_provider` required)
    :type master_key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param float max_age: Maximum time in seconds that a cache entry may be kept in the cache
    :param int max_messages_encrypted: Maximum number of messages that may be encrypted under
        a cache entry (optional)
    :param int max_bytes_encrypted: Maximum number of bytes that a cache entry may be used
        to process (optional)
    :param bytes partition_name: Partition name to use for this instance (optional)
    """

    cache = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsCache))
    max_age = attr.ib(validator=attr.validators.instance_of(float))
    max_messages_encrypted = attr.ib(
        default=MAX_MESSAGES_PER_KEY, validator=attr.validators.instance_of(six.integer_types)
    )
    max_bytes_encrypted = attr.ib(default=MAX_BYTES_PER_KEY, validator=attr.validators.instance_of(six.integer_types))
    partition_name = attr.ib(
        default=None, converter=to_bytes, validator=attr.validators.optional(attr.validators.instance_of(bytes))
    )
    master_key_provider = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(MasterKeyProvider))
    )
    backing_materials_manager = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(CryptoMaterialsManager))
    )

    def __attrs_post_init__(self):
        """Applies post-processing which cannot be handled by attrs."""
        if self.max_messages_encrypted < 1:
            raise ValueError("max_messages_encrypted cannot be less than 1")

        if self.max_bytes_encrypted < 0:
            raise ValueError("max_bytes_encrypted cannot be less than 0")

        if self.max_messages_encrypted > MAX_MESSAGES_PER_KEY:
            raise ValueError("max_messages_encrypted cannot exceed {}".format(MAX_MESSAGES_PER_KEY))

        if self.max_bytes_encrypted > MAX_BYTES_PER_KEY:
            raise ValueError("max_bytes_encrypted cannot exceed {}".format(MAX_BYTES_PER_KEY))

        if self.max_age <= 0.0:
            raise ValueError("max_age cannot be less than or equal to 0")

        if self.backing_materials_manager is None:
            if self.master_key_provider is None:
                raise TypeError("Either backing_materials_manager or master_key_provider must be defined")
            self.backing_materials_manager = DefaultCryptoMaterialsManager(self.master_key_provider)

        if self.partition_name is None:
            self.partition_name = to_bytes(str(uuid.uuid4()))

        # Maps the identity of returned encryption materials to the still-outstanding
        # reservations held by the streams using those materials.  A stream settles its
        # reservation exactly once, by committing on first output or releasing on cancellation.
        self._reservation_lock = Lock()
        self._outstanding_reservations = {}
        # Serializes the "find an entry with headroom, otherwise create one" sequence so that
        # concurrent streams cannot each miss the cache and overwrite the same entry.
        self._materials_request_lock = Lock()

    def _cache_entry_has_encrypted_too_many_bytes(self, entry):
        """Determines if a cache entry has exceeded the max allowed bytes encrypted.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return entry.bytes_encrypted > self.max_bytes_encrypted

    def _cache_entry_has_encrypted_too_many_messages(self, entry):
        """Determines if a cache entry has exceeded the max allowed messages encrypted.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return entry.messages_encrypted > self.max_messages_encrypted

    def _cache_entry_is_too_old(self, entry):
        """Determines if a cache entry has exceeded the max allowed age.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return entry.age > self.max_age

    def _cache_entry_has_exceeded_limits(self, entry):
        """Determines if a cache entry has exceeded any security limits.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return (
            self._cache_entry_is_too_old(entry)
            or self._cache_entry_has_encrypted_too_many_messages(entry)
            or self._cache_entry_has_encrypted_too_many_bytes(entry)
        )

    def _should_cache_encryption_request(self, request):
        """Determines whether the encryption materials request should be cached.

        :param request: Encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :rtype: bool
        """
        if request.algorithm is not None and not request.algorithm.safe_to_cache():
            _LOGGER.debug("Encryption materials request not cached because algorithm suite is not safe to cache")
            return False

        return True

    def _reservation_size(self, plaintext_length):
        """Returns the message and byte budget a single request must reserve.

        A known-length plaintext reserves exactly its size.  An unknown-length plaintext
        cannot be measured without reading the whole stream into memory, so instead it
        reserves the most bytes this manager will ever let a single key encrypt.  The
        reservation is settled against real usage once the stream writes or is abandoned.

        :param int plaintext_length: Declared plaintext length, or None if unknown
        :rtype: tuple(int, int)
        """
        if plaintext_length is None:
            return 1, self.max_bytes_encrypted
        return 1, plaintext_length

    def get_encryption_materials(self, request):
        """Provides encryption materials appropriate for the request.

        Budget for the message is reserved before the materials are handed out.  If no cache
        entry can honor the reservation within the message and byte limits, a fresh entry is
        created (or the request bypasses the cache entirely).  The reservation is later settled
        by `commit_encryption_materials_usage` or `release_encryption_materials`.

        :param request: Encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """
        if not self._should_cache_encryption_request(request):
            return self.backing_materials_manager.get_encryption_materials(request)

        reserve_messages, reserve_bytes = self._reservation_size(request.plaintext_length)

        # Inner request strips any information about the plaintext from the actual request.
        # This is done because the resulting encryption materials may be used to encrypt
        #  multiple plaintexts.
        inner_request = EncryptionMaterialsRequest(
            encryption_context=request.encryption_context,
            frame_length=request.frame_length,
            algorithm=request.algorithm,
            commitment_policy=request.commitment_policy,
        )
        cache_key = build_encryption_materials_cache_key(partition=self.partition_name, request=inner_request)

        with self._materials_request_lock:
            cache_entry = self._entry_with_available_budget(
                cache_key=cache_key, reserve_messages=reserve_messages, reserve_bytes=reserve_bytes
            )

            if cache_entry is not None:
                # An existing entry has enough headroom for the reservation, including an
                # unknown-length request reserving the full byte allowance.
                reservation = cache_entry.reserve(messages=reserve_messages, bytes_encrypted=reserve_bytes)
                self._register_reservation(cache_entry.value, reservation)
                return cache_entry.value

            # Nothing usable in cache: ask the material manager for fresh materials.  The cache
            # key is constant for equivalent requests, so on return we re-check whether another
            # thread created an entry while this thread was generating the data key.
            new_result = self.backing_materials_manager.get_encryption_materials(inner_request)

            if not new_result.algorithm.safe_to_cache() or reserve_bytes > self.max_bytes_encrypted:
                # The request cannot live inside a reusable entry, so nothing is reserved.
                return new_result

            cache_entry = self._entry_with_available_budget(
                cache_key=cache_key, reserve_messages=reserve_messages, reserve_bytes=reserve_bytes
            )
            if cache_entry is None:
                cache_entry = self.cache.put_encryption_materials(
                    cache_key=cache_key,
                    encryption_materials=new_result,
                    plaintext_length=request.plaintext_length,
                    entry_hints=CryptoMaterialsCacheEntryHints(lifetime=self.max_age),
                )

            reservation = cache_entry.reserve(messages=reserve_messages, bytes_encrypted=reserve_bytes)
            self._register_reservation(cache_entry.value, reservation)
            return cache_entry.value

    def _entry_with_available_budget(self, cache_key, reserve_messages, reserve_bytes):
        """Returns a cache entry that can honor the requested reservation, or None.

        Entries that have aged out or already exhausted their budget are removed.  An entry that
        still exists but lacks enough free budget is left intact so its in-flight reservations
        can settle, and the caller creates a fresh entry instead.

        :param bytes cache_key: Cache identifier to look up
        :param int reserve_messages: Message slots that must be available
        :param int reserve_bytes: Plaintext bytes that must be available
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry or None
        """
        try:
            cache_entry = self.cache.get_encryption_materials(
                cache_key=cache_key, plaintext_length=reserve_bytes
            )
        except CacheKeyError:
            return None

        if self._cache_entry_has_exceeded_limits(cache_entry):
            self.cache.remove(cache_entry)
            return None

        if not cache_entry.can_reserve(
            messages=reserve_messages,
            bytes_encrypted=reserve_bytes,
            max_messages=self.max_messages_encrypted,
            max_bytes=self.max_bytes_encrypted,
        ):
            _LOGGER.debug("Cache entry cannot reserve requested budget; obtaining fresh materials")
            return None

        return cache_entry

    def _register_reservation(self, materials, reservation):
        """Tracks an outstanding reservation keyed by the identity of the materials it covers."""
        with self._reservation_lock:
            self._outstanding_reservations.setdefault(id(materials), []).append(reservation)

    def _pop_reservation(self, materials):
        """Removes and returns one outstanding reservation for the provided materials."""
        with self._reservation_lock:
            reservations = self._outstanding_reservations.get(id(materials))
            if not reservations:
                return None
            reservation = reservations.pop(0)
            if not reservations:
                del self._outstanding_reservations[id(materials)]
            return reservation

    def commit_encryption_materials_usage(self, materials, actual_plaintext_bytes=None):
        """Bills the reservation behind `materials` as a real, completed message.

        A stream that emitted any ciphertext must keep its budget even if it later failed,
        because data key material was already put on the wire.  When the stream really
        encrypted fewer bytes than it reserved (an unknown-length upper bound), the unused
        byte budget is reconciled away.

        :param materials: Encryption materials previously returned by this manager
        :type materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :param int actual_plaintext_bytes: Bytes the stream actually encrypted, when known
        """
        reservation = self._pop_reservation(materials)
        if reservation is not None:
            reservation.commit(actual_plaintext_bytes)

    def release_encryption_materials(self, materials):
        """Returns the reservation behind `materials` without billing it.

        A stream cancelled before its first ciphertext byte consumed nothing, so its reserved
        message and byte budget is made available to concurrent and future streams.

        :param materials: Encryption materials previously returned by this manager
        :type materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """
        reservation = self._pop_reservation(materials)
        if reservation is not None:
            reservation.release()

    def decrypt_materials(self, request):
        """Provides decryption materials appropriate for the request.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        cache_key = build_decryption_materials_cache_key(partition=self.partition_name, request=request)

        # Attempt to retrieve from cache
        try:
            cache_entry = self.cache.get_decryption_materials(cache_key)
        except CacheKeyError:
            pass
        else:
            if self._cache_entry_is_too_old(cache_entry):
                self.cache.remove(cache_entry)
            else:
                return cache_entry.value

        # Nothing found in cache: try the material manager
        new_result = self.backing_materials_manager.decrypt_materials(request)

        # Add results into cache
        self.cache.put_decryption_materials(cache_key=cache_key, decryption_materials=new_result)
        return new_result
