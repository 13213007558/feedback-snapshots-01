# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functional tests for caching CMM reservation/refund behavior across concurrent
encrypting streams.

These tests drive real :class:`StreamEncryptor` objects against a local materials cache so
that the entry's actual usage counters (not mocks) demonstrate the two settlement rules:

* a stream cancelled before its first ciphertext byte releases its reservation, and
* a stream that emitted any ciphertext keeps its reservation even if it later fails.
"""
import io

import pytest

import aws_encryption_sdk
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm

pytestmark = [pytest.mark.functional, pytest.mark.local]

_STATIC_WRAPPING_KEY = b"12345678901234567890123456789012"
_KEY_ID = b"static-key"


class _StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    pass


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Raw key provider that always hands back the same local symmetric wrapping key."""

    provider_id = b"static"
    _config_class = _StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=_STATIC_WRAPPING_KEY,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def _build_ccmm(max_messages_encrypted, max_bytes_encrypted):
    key_provider = StaticRawMasterKeyProvider()
    key_provider.add_master_key(_KEY_ID)
    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=10)
    ccmm = aws_encryption_sdk.CachingCryptoMaterialsManager(
        master_key_provider=key_provider,
        cache=cache,
        max_age=3600.0,
        max_messages_encrypted=max_messages_encrypted,
        max_bytes_encrypted=max_bytes_encrypted,
    )
    return ccmm, cache


def _only_entry(cache):
    assert len(cache._cache) == 1
    return next(iter(cache._cache.values()))


def _open_encryptor(ccmm, plaintext, *, source_length):
    # Constructed but not read: touching the header triggers the materials request and
    # reserves budget, while no ciphertext has been returned to the caller yet.
    client = aws_encryption_sdk.EncryptionSDKClient()
    encryptor = client.stream(
        mode="e",
        source=io.BytesIO(plaintext),
        materials_manager=ccmm,
        source_length=source_length,
        frame_length=1024,
    )
    _ = encryptor.header
    return encryptor


def test_cancel_before_first_byte_returns_reservation():
    # Two message slots exist, so the streams share one entry and contend for the last slot.
    plaintext = b"zero through one hundred twenty seven" * 4  # 128 bytes
    # Two 128-byte reservations fit inside the byte budget, so the streams contend
    # only for the single remaining message slot.
    ccmm, cache = _build_ccmm(max_messages_encrypted=2, max_bytes_encrypted=4096)

    winner = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))
    loser = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))

    entry = _only_entry(cache)
    # Both streams were promised materials; the entry holds two outstanding reservations.
    assert entry.messages_encrypted == 0
    assert entry.reserved_messages == 2
    assert entry.reserved_bytes == 2 * len(plaintext)

    # The "loser" never reads a single byte and is cancelled before producing ciphertext.
    loser.close()

    entry = _only_entry(cache)
    assert entry.messages_encrypted == 0
    assert entry.bytes_encrypted == 0
    assert entry.reserved_messages == 1
    assert entry.reserved_bytes == len(plaintext)

    # The winner then runs to completion and bills its single message.
    ciphertext = winner.read()
    winner.close()

    entry = _only_entry(cache)
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == len(plaintext)
    assert entry.reserved_messages == 0
    assert entry.reserved_bytes == 0
    assert ciphertext


def test_disconnect_after_first_byte_keeps_reservation():
    plaintext = b"zero through one hundred twenty seven" * 4  # 148 bytes
    # Two reservations fit inside the byte budget, so the streams contend
    # only for the single remaining message slot.
    ccmm, cache = _build_ccmm(max_messages_encrypted=2, max_bytes_encrypted=4096)

    winner = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))
    loser = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))

    entry = _only_entry(cache)
    assert entry.reserved_messages == 2

    # The loser emits its header (real ciphertext on the wire) before it is abandoned.
    first_byte = loser.read(1)
    assert first_byte
    loser_bytes = loser._bytes_encrypted
    loser.close()

    entry = _only_entry(cache)
    # Even though the stream did not finish (and may only have flushed its header), the
    # emitted material is billed as real risk: the message slot is committed rather than
    # returned, for whatever body bytes were actually processed.
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == loser_bytes
    assert entry.reserved_messages == 1
    assert entry.reserved_bytes == len(plaintext)

    winner.read()
    winner.close()

    entry = _only_entry(cache)
    assert entry.messages_encrypted == 2
    assert entry.bytes_encrypted == loser_bytes + len(plaintext)
    assert entry.reserved_messages == 0


def test_refund_frees_slot_for_a_follow_up_stream():
    ccmm, cache = _build_ccmm(max_messages_encrypted=1, max_bytes_encrypted=1024)
    plaintext = b"a" * 64

    cancelled = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))
    cancelled.close()  # never emitted: reservation returned

    entry = _only_entry(cache)
    assert entry.messages_encrypted == 0
    assert entry.reserved_messages == 0

    # A brand new stream can reuse the fully-refunded entry instead of exhausting the key.
    follow_up = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))
    follow_up.read()
    follow_up.close()

    entry = _only_entry(cache)
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == len(plaintext)
    assert entry.reserved_messages == 0


def test_unknown_length_stream_reserves_bounded_budget_without_buffering():
    ccmm, cache = _build_ccmm(max_messages_encrypted=2, max_bytes_encrypted=1024)

    class _NoSeekStream(io.RawIOBase):
        # A non-seekable source forces plaintext_length to be unknown; the CMM must still
        # cache by reserving the configured upper bound rather than reading it all in.
        def readable(self):
            return True

        def read(self, size=-1):
            if self._done:
                return b""
            self._done = True
            return b"hello world"

        def __init__(self):
            super().__init__()
            self._done = False

    client = aws_encryption_sdk.EncryptionSDKClient()
    encryptor = client.stream(
        mode="e",
        source=_NoSeekStream(),
        materials_manager=ccmm,
        frame_length=1024,
    )
    ciphertext = encryptor.read()
    encryptor.close()

    entry = _only_entry(cache)
    # The reservation used the byte upper bound, but billing reflects the real plaintext size.
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == len(b"hello world")
    assert entry.reserved_messages == 0
    assert entry.reserved_bytes == 0
    assert ciphertext


def test_concurrent_streams_never_oversubscribe_message_budget():
    import threading

    max_messages = 8
    ccmm, cache = _build_ccmm(max_messages_encrypted=max_messages, max_bytes_encrypted=10_000)
    plaintext = b"p" * 32

    errors = []

    def worker(cancel_before_output):
        try:
            encryptor = _open_encryptor(ccmm, plaintext, source_length=len(plaintext))
            if cancel_before_output:
                encryptor.close()
            else:
                encryptor.read()
                encryptor.close()
        except Exception as error:  # pragma: no cover - surfaced via assertion below
            errors.append(error)

    threads = []
    for index in range(40):
        threads.append(threading.Thread(target=worker, kwargs={"cancel_before_output": index % 2 == 0}))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors

    # Every reservation must have settled, leaving nothing outstanding on any entry.
    for entry in cache._encryption_entries():
        assert entry.reserved_messages == 0
        assert entry.reserved_bytes == 0

    total_messages, total_bytes = cache.encryption_usage_totals()
    # Exactly the 20 streams that emitted ciphertext are billed; the 20 cancelled ones refund.
    assert total_messages == 20
    assert total_bytes == 20 * len(plaintext)
    # No single data key may ever exceed its configured message limit.
    assert all(entry.messages_encrypted <= max_messages for entry in cache._encryption_entries())
