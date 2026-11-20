# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for the reservation-based usage accounting of cached data keys.

These tests deliberately use small quotas, an in-memory cache and readable source streams whose
consumption we control, so that success, early exit and concurrency can each be observed directly.
"""
import io
import threading

import attr
import pytest

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import CommitmentPolicy, EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider

pytestmark = [pytest.mark.functional, pytest.mark.local]

MAX_MESSAGES = 4
MAX_BYTES = 200
MESSAGE_LENGTH = 40


@attr.s(hash=False)
class StaticRawKeyProviderConfig(MasterKeyProviderConfig):
    key_bytes = attr.ib()


class StaticRawKeyProvider(RawMasterKeyProvider):
    """Raw master key provider backed by one static symmetric key, no network needed."""

    provider_id = "reservation-test"
    _config_class = StaticRawKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=self.config.key_bytes,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


class NonSeekableBytesIO(io.RawIOBase):
    """Readable source whose length cannot be discovered up front (no seek/tell support)."""

    def __init__(self, data):
        self._remaining = data

    def readable(self):
        return True

    def read(self, size=-1):
        if not self._remaining:
            return b""
        if size is None or size < 0:
            size = len(self._remaining)
        chunk, self._remaining = self._remaining[:size], self._remaining[size:]
        return chunk


def build_cmm(cache=None, max_messages=MAX_MESSAGES, max_bytes=MAX_BYTES):
    provider = StaticRawKeyProvider(key_bytes=b"\x11" * 32)
    provider.add_master_key("test-key")
    if cache is None:
        cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=50)
    return aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=provider,
        cache=cache,
        max_age=600.0,
        max_messages_encrypted=max_messages,
        max_bytes_encrypted=max_bytes,
    ), provider, cache


def only_entry(cache):
    assert len(cache._cache) == 1
    return next(iter(cache._cache.values()))


def test_successful_stream_commits_actual_usage():
    cmm, _provider, cache = build_cmm()
    client = aws_encryption_sdk.EncryptionSDKClient()
    plaintext = b"a" * MESSAGE_LENGTH

    ciphertext, _header = client.encrypt(source=plaintext, materials_manager=cmm)

    entry = only_entry(cache)
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == MESSAGE_LENGTH
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0

    decrypted, _header = client.decrypt(source=ciphertext, materials_manager=cmm)
    assert decrypted == plaintext


def test_partial_read_then_close_releases_reserved_capacity():
    cmm, _provider, cache = build_cmm()
    plaintext = b"b" * MESSAGE_LENGTH

    encryptor = aws_encryption_sdk.StreamEncryptor(
        source=io.BytesIO(plaintext),
        source_length=MESSAGE_LENGTH,
        materials_manager=cmm,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    )
    # Consume only part of the message, then abandon the stream.
    partial_ciphertext = encryptor.read(5)
    assert partial_ciphertext
    entry_before_close = only_entry(cache)
    assert entry_before_close.messages_reserved == 1
    assert entry_before_close.bytes_reserved == MESSAGE_LENGTH

    encryptor.close()

    entry = only_entry(cache)
    # Nothing was committed because the message never completed; the reservation was returned.
    assert entry.messages_encrypted == 0
    assert entry.bytes_encrypted == 0
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0

    # The released capacity is immediately reusable by a full, successful job.
    client = aws_encryption_sdk.EncryptionSDKClient()
    client.encrypt(source=plaintext, materials_manager=cmm)
    entry = only_entry(cache)
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == MESSAGE_LENGTH
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0


def test_two_tasks_starting_together_both_see_live_materials_within_limit():
    cmm, _provider, cache = build_cmm(max_messages=2, max_bytes=200)
    client = aws_encryption_sdk.EncryptionSDKClient()
    plaintext = b"c" * MESSAGE_LENGTH
    barrier = threading.Barrier(2)
    results = []

    def worker():
        barrier.wait()
        ciphertext, _header = client.encrypt(source=plaintext, materials_manager=cmm)
        results.append(ciphertext)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 2
    entry = only_entry(cache)
    # Both concurrent jobs were served from the same key without exceeding its limits.
    assert entry.messages_encrypted == 2
    assert entry.bytes_encrypted == 2 * MESSAGE_LENGTH
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0


def test_concurrent_tasks_never_hand_out_materials_past_the_limit():
    cmm, _provider, cache = build_cmm(max_messages=2, max_bytes=200)
    client = aws_encryption_sdk.EncryptionSDKClient()
    plaintext = b"d" * MESSAGE_LENGTH
    barrier = threading.Barrier(6)
    seen_entries = []
    observed = threading.Lock()

    def worker():
        barrier.wait()
        client.encrypt(source=plaintext, materials_manager=cmm)
        with observed:
            seen_entries.extend(list(cache._cache.values()))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Every entry that was ever reachable stayed within the configured per-key limits.
    for entry in seen_entries:
        assert entry.messages_encrypted <= 2
        assert entry.bytes_encrypted <= 200
        assert entry.messages_reserved == 0
        assert entry.bytes_reserved == 0


def test_unknown_length_task_bypasses_cache_and_holds_no_reservation():
    cmm, _provider, cache = build_cmm()
    plaintext = b"e" * MESSAGE_LENGTH
    entries_before = len(cache._cache)

    with aws_encryption_sdk.StreamEncryptor(
        source=NonSeekableBytesIO(plaintext),
        materials_manager=cmm,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    ) as encryptor:
        ciphertext = encryptor.read()

    assert len(cache._cache) == entries_before
    # Unknown-length requests are not cached, so no reservation can be left dangling.
    assert all(reservations == [] for reservations in cmm._open_reservations.values())
    assert ciphertext


def test_failed_message_setup_releases_its_reservation():
    cmm, _provider, cache = build_cmm()
    plaintext = b"f" * MESSAGE_LENGTH

    # An unsupported frame length fails message setup after materials (and the reservation)
    # have already been obtained, but before any plaintext is processed.
    with pytest.raises(Exception):
        aws_encryption_sdk.StreamEncryptor(
            source=io.BytesIO(plaintext),
            source_length=MESSAGE_LENGTH,
            materials_manager=cmm,
            frame_length=1,
            commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        ).read()

    entry = only_entry(cache)
    # The failed job must not be charged to the data key.
    assert entry.messages_encrypted == 0
    assert entry.bytes_encrypted == 0
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0
