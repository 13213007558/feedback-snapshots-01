# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Base class interface for caches for use with caching crypto material managers."""
import abc

import six

from ..exceptions import NotSupportedError


@six.add_metaclass(abc.ABCMeta)
class CryptoMaterialsCache(object):
    """Parent interface for crypto materials caches.

    .. versionadded:: 1.3.0
    """

    @abc.abstractmethod
    def put_encryption_materials(self, cache_key, encryption_materials, plaintext_length, entry_hints=None):
        """Adds encryption materials to the cache.

        :param bytes cache_key: Identifier for entries in cache
        :param encryption_materials: Encryption materials to add to cache
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :param int plaintext_length: Length of plaintext associated with this request to the cache
        :param entry_hints: Metadata to associate with entry (optional)
        :type entry_hints: aws_encryption_sdk.caches.CryptoCacheEntryHints
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        """

    @abc.abstractmethod
    def put_decryption_materials(self, cache_key, decryption_materials):
        """Adds decryption materials to the cache

        :param bytes cache_key: Identifier for entries in cache
        :param decryption_materials: Decryption materials to add to cache
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        """

    @abc.abstractmethod
    def get_encryption_materials(self, cache_key, plaintext_length):
        """Locates exactly one available encryption materials cache entry for the specified cache_key,
        incrementing the entry's usage stats prior to returning it to the caller.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :param int plaintext_length: Bytes to be encrypted by the encryption materials
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """

    @abc.abstractmethod
    def get_decryption_materials(self, cache_key):
        """Locates exactly one available decryption materials cache entry for the specified cache_key.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """

    def reserve_encryption_materials(
        self, cache_key, plaintext_length, max_messages_encrypted, max_bytes_encrypted
    ):
        """Reserves capacity on the encryption materials cache entry for ``cache_key``.

        Unlike :meth:`get_encryption_materials`, the usage counters are only provisionally
        updated: the returned :class:`aws_encryption_sdk.caches.CacheReservation` must be either
        committed on success or released on cancellation so that the entry's reported usage
        always matches what was actually processed.

        Caches that cannot coordinate reservations raise :class:`NotSupportedError`; callers
        are expected to fall back to a non-cached flow in that case.

        :param bytes cache_key: Cache ID for which to reserve capacity
        :param int plaintext_length: Bytes that the job expects to encrypt
        :param int max_messages_encrypted: Per-entry message limit to enforce
        :param int max_bytes_encrypted: Per-entry byte limit to enforce
        :rtype: aws_encryption_sdk.caches.CacheReservation
        :raises CacheKeyError: if no live entry exists for cache_key
        :raises NotSupportedError: if this cache does not support reservations
        """
        raise NotSupportedError("This cache does not support encryption materials reservations")
