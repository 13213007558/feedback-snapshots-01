# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit test suite for CryptoMaterialsCacheEntry and CryptoMaterialsCacheEntryHints"""
import pytest
from mock import MagicMock
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk.caches
from aws_encryption_sdk.caches import CryptoMaterialsCacheEntry, CryptoMaterialsCacheEntryHints
from aws_encryption_sdk.exceptions import NotSupportedError
from aws_encryption_sdk.materials_managers import DecryptionMaterials, EncryptionMaterials

pytestmark = [pytest.mark.unit, pytest.mark.local]

_VALID_KWARGS = {
    "CryptoMaterialsCacheEntryHints": dict(lifetime=5.0),
    "CryptoMaterialsCacheEntry": dict(
        cache_key=b"this is a cache key",
        value=MagicMock(__class__=EncryptionMaterials),
        hints=MagicMock(__class__=CryptoMaterialsCacheEntryHints),
    ),
}


@pytest.fixture
def patch_time(mocker):
    mocker.patch.object(aws_encryption_sdk.caches.time, "time")


@pytest.mark.parametrize(
    "attr_class, invalid_kwargs",
    (
        (CryptoMaterialsCacheEntryHints, dict(lifetime=4)),
        (CryptoMaterialsCacheEntry, dict(cache_key=None)),
        (CryptoMaterialsCacheEntry, dict(value=None)),
    ),
)
def test_attributes_fails(attr_class, invalid_kwargs):
    kwargs = _VALID_KWARGS[attr_class.__name__].copy()
    kwargs.update(invalid_kwargs)
    with pytest.raises(TypeError):
        attr_class(**kwargs)


@pytest.mark.parametrize("attr_class", (CryptoMaterialsCacheEntry, CryptoMaterialsCacheEntryHints))
def test_attributes_valid(attr_class):
    attr_class(**_VALID_KWARGS[attr_class.__name__])


@pytest.mark.parametrize(
    "valid_kwargs_overrides",
    (dict(value=MagicMock(__class__=EncryptionMaterials)), dict(value=MagicMock(__class__=DecryptionMaterials))),
)
def test_crypto_cache_entry_valid_attributes(valid_kwargs_overrides):
    kwargs = _VALID_KWARGS["CryptoMaterialsCacheEntry"].copy()
    kwargs.update(valid_kwargs_overrides)
    CryptoMaterialsCacheEntry(**kwargs)


def test_crypto_cache_entry_init(patch_time):
    mock_creation_time = 3.0
    aws_encryption_sdk.caches.time.time.return_value = mock_creation_time

    entry = CryptoMaterialsCacheEntry(
        cache_key=b"ex_cache_key",
        value=MagicMock(__class__=EncryptionMaterials),
        hints=CryptoMaterialsCacheEntryHints(lifetime=10.0),
    )

    assert entry.creation_time == mock_creation_time
    assert entry.bytes_encrypted == 0
    assert entry.messages_encrypted == 0
    assert entry.bytes_reserved == 0
    assert entry.messages_reserved == 0
    assert entry.valid
    # Because Lock is a helper function that returns whatever native primitive is best,
    #  we cannot test for type.  Instead, testing for interface.
    assert hasattr(entry._lock, "acquire")
    assert callable(entry._lock.acquire)
    assert hasattr(entry._lock, "release")
    assert callable(entry._lock.release)


def test_crypto_cache_entry_defaults():
    entry = CryptoMaterialsCacheEntry(cache_key=b"ex_cache_key", value=MagicMock(__class__=EncryptionMaterials))

    assert entry.hints == CryptoMaterialsCacheEntryHints()


def test_crypto_cache_entry_setattr():
    entry = CryptoMaterialsCacheEntry(**_VALID_KWARGS["CryptoMaterialsCacheEntry"])

    with pytest.raises(NotSupportedError) as excinfo:
        entry.bytes_encrypted = 0

    excinfo.match(r"Attributes may not be set on CryptoMaterialsCacheEntry objects")


def test_crypto_cache_entry_age(patch_time):
    mock_creation_time = 5
    mock_check_time = 10
    aws_encryption_sdk.caches.time.time.return_value = mock_creation_time
    entry = CryptoMaterialsCacheEntry(**_VALID_KWARGS["CryptoMaterialsCacheEntry"])
    aws_encryption_sdk.caches.time.time.return_value = mock_check_time

    assert entry.age == mock_check_time - mock_creation_time


def test_crypto_cache_entry_is_too_old_no_lifetime_hint(patch_time):
    kwargs = _VALID_KWARGS["CryptoMaterialsCacheEntry"].copy()
    kwargs["hints"] = MagicMock(__class__=CryptoMaterialsCacheEntryHints, lifetime=None)
    entry = CryptoMaterialsCacheEntry(**kwargs)

    assert not entry.is_too_old()


@pytest.mark.parametrize("age_modifier, result", ((-1.0, True), (0.0, False), (1.0, False)))
def test_crypto_cache_entry_is_too_old(patch_time, age_modifier, result):
    mock_creation_time = 1
    aws_encryption_sdk.caches.time.time.return_value = mock_creation_time
    lifetime = mock_creation_time + age_modifier
    kwargs = _VALID_KWARGS["CryptoMaterialsCacheEntry"].copy()
    kwargs["hints"] = MagicMock(__class__=CryptoMaterialsCacheEntryHints, lifetime=lifetime)
    entry = CryptoMaterialsCacheEntry(**kwargs)
    assert entry.creation_time == mock_creation_time

    aws_encryption_sdk.caches.time.time.return_value = mock_creation_time + 1
    if result:
        assert entry.is_too_old()
    else:
        assert not entry.is_too_old()


def test_crypto_cache_entry_update_with_message_bytes_encrypted():
    entry = CryptoMaterialsCacheEntry(**_VALID_KWARGS["CryptoMaterialsCacheEntry"])
    super(CryptoMaterialsCacheEntry, entry).__setattr__("messages_encrypted", 10)
    super(CryptoMaterialsCacheEntry, entry).__setattr__("bytes_encrypted", 10)

    entry._update_with_message_bytes_encrypted(50)

    assert entry.messages_encrypted == 11
    assert entry.bytes_encrypted == 60


def test_crypto_cache_entry_invalidate():
    entry = CryptoMaterialsCacheEntry(**_VALID_KWARGS["CryptoMaterialsCacheEntry"])

    assert entry.valid

    entry.invalidate()

    assert not entry.valid


def build_entry():
    return CryptoMaterialsCacheEntry(
        cache_key=b"ex_cache_key",
        value=MagicMock(__class__=EncryptionMaterials),
        hints=CryptoMaterialsCacheEntryHints(lifetime=10.0),
    )


def test_reserve_tracks_outstanding_capacity_without_committing():
    entry = build_entry()

    reservation = entry.reserve(bytes_to_reserve=100, max_messages_encrypted=5, max_bytes_encrypted=500)

    assert reservation.is_open
    assert entry.messages_reserved == 1
    assert entry.bytes_reserved == 100
    assert entry.messages_encrypted == 0
    assert entry.bytes_encrypted == 0


def test_reserve_rejects_message_limit_overflow():
    entry = build_entry()
    super(CryptoMaterialsCacheEntry, entry).__setattr__("messages_encrypted", 4)
    super(CryptoMaterialsCacheEntry, entry).__setattr__("messages_reserved", 1)

    # 4 committed + 1 reserved + 1 new = 6, which exceeds the limit of 5
    assert entry.reserve(bytes_to_reserve=10, max_messages_encrypted=5, max_bytes_encrypted=500) is None
    assert entry.messages_reserved == 1
    assert entry.bytes_reserved == 0


def test_reserve_rejects_byte_limit_overflow_including_outstanding_reservations():
    entry = build_entry()
    reservation = entry.reserve(bytes_to_reserve=400, max_messages_encrypted=5, max_bytes_encrypted=500)

    # 400 already reserved + 200 new = 600, which exceeds the limit of 500 even though nothing
    # has been committed yet.
    assert entry.reserve(bytes_to_reserve=200, max_messages_encrypted=5, max_bytes_encrypted=500) is None
    assert reservation.is_open
    assert entry.bytes_reserved == 400


def test_reserve_accepted_right_up_to_the_limit():
    entry = build_entry()

    reservation = entry.reserve(bytes_to_reserve=500, max_messages_encrypted=5, max_bytes_encrypted=500)

    assert reservation is not None
    assert entry.bytes_reserved == 500
    assert entry.messages_reserved == 1


def test_reserve_rejected_on_invalidated_entry():
    entry = build_entry()
    entry.invalidate()

    assert entry.reserve(bytes_to_reserve=10, max_messages_encrypted=5, max_bytes_encrypted=500) is None
    assert entry.messages_reserved == 0


def test_commit_moves_reservation_into_committed_usage():
    entry = build_entry()
    reservation = entry.reserve(bytes_to_reserve=100, max_messages_encrypted=5, max_bytes_encrypted=500)

    reservation.commit(bytes_encrypted=80)

    assert not reservation.is_open
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0
    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == 80


def test_release_returns_reserved_capacity():
    entry = build_entry()
    reservation = entry.reserve(bytes_to_reserve=100, max_messages_encrypted=5, max_bytes_encrypted=500)

    reservation.release()

    assert not reservation.is_open
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0
    assert entry.messages_encrypted == 0
    assert entry.bytes_encrypted == 0


def test_released_capacity_is_available_again():
    entry = build_entry()
    first = entry.reserve(bytes_to_reserve=450, max_messages_encrypted=5, max_bytes_encrypted=500)
    first.release()

    second = entry.reserve(bytes_to_reserve=500, max_messages_encrypted=5, max_bytes_encrypted=500)

    assert second is not None
    assert entry.bytes_reserved == 500


def test_concurrent_reservations_share_one_limit():
    entry = build_entry()

    first = entry.reserve(bytes_to_reserve=300, max_messages_encrypted=5, max_bytes_encrypted=500)
    second = entry.reserve(bytes_to_reserve=200, max_messages_encrypted=5, max_bytes_encrypted=500)
    third = entry.reserve(bytes_to_reserve=1, max_messages_encrypted=5, max_bytes_encrypted=500)

    assert first is not None and second is not None
    assert third is None
    assert entry.bytes_reserved == 500
    assert entry.messages_reserved == 2

    second.release()
    assert entry.bytes_reserved == 300
    assert entry.messages_reserved == 1


def test_commit_and_release_are_idempotent():
    entry = build_entry()
    reservation = entry.reserve(bytes_to_reserve=100, max_messages_encrypted=5, max_bytes_encrypted=500)
    reservation.commit(bytes_encrypted=100)
    reservation.commit(bytes_encrypted=100)
    reservation.release()

    assert entry.messages_encrypted == 1
    assert entry.bytes_encrypted == 100
    assert entry.messages_reserved == 0
    assert entry.bytes_reserved == 0
