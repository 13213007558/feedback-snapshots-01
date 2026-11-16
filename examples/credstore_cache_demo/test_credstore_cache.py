"""Tests for the scoped credential-cache example.

Run from the repository root::

    python -m pytest examples/credstore_cache_demo
"""

from __future__ import annotations

import os

import pytest

from examples.credstore_cache_demo import pinuv2
from examples.credstore_cache_demo.cred_cache import (
    CredentialCache,
    decode_info_fields,
    get_or_refresh,
)
from examples.credstore_cache_demo.manager import AuthenticatorManager
from examples.credstore_cache_demo.software_device import (
    CredentialRecord,
    SoftwareAuthenticator,
)
from examples.credstore_cache_demo.trust import (
    AuthenticityError,
    CacheMiss,
    TrustedBinding,
    TrustLabel,
    UnparseableFieldError,
)
from fido2.ctap2.base import Info

# --------------------------------------------------------------------------- #
# Key separation and round trips
# --------------------------------------------------------------------------- #


def test_purpose_separated_channel_keys_differ():
    hmac_key, aes_key = pinuv2.derive_channel_keys(b"shared-secret-Z")
    assert hmac_key != aes_key
    assert len(hmac_key) == 32 and len(aes_key) == 32


def test_info_field_keys_are_purpose_separated():
    token = os.urandom(32)
    identifier_key = pinuv2.derive_info_key(token, pinuv2.INFO_ENC_IDENTIFIER)
    state_key = pinuv2.derive_info_key(token, pinuv2.INFO_ENC_CRED_STORE_STATE)
    assert identifier_key != state_key
    assert len(identifier_key) == 16  # AES-128 for Info fields


def test_info_field_round_trip_through_library_info_decryptor():
    token = os.urandom(32)
    plaintext = b"persistent-identifier"
    blob = pinuv2.encrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, plaintext)
    info = Info(versions=["FIDO_2_1"], enc_identifier=blob)
    # The real python-fido2 entry point returns raw CBC output (padding kept),
    # which is itself evidence that decryption is not authenticated decoding.
    library_raw = info.get_identifier(token)
    assert pinuv2.pkcs7_unpad(library_raw) == plaintext
    # Our strict decoder applies framing validation on top of the same bytes.
    assert (
        pinuv2.decrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, blob) == plaintext
    )


def test_random_iv_makes_blobs_nondeterministic():
    token = os.urandom(32)
    plaintext = b"same plaintext"
    first = pinuv2.encrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, plaintext)
    second = pinuv2.encrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, plaintext)
    assert first != second
    assert (
        pinuv2.decrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, first) == plaintext
    )


# --------------------------------------------------------------------------- #
# Error taxonomy stays three-way
# --------------------------------------------------------------------------- #


def test_missing_field_is_distinct_from_malformed():
    with pytest.raises(LookupError) as missing:
        pinuv2.decrypt_info_field(os.urandom(32), pinuv2.INFO_ENC_IDENTIFIER, None)
    assert not isinstance(missing.value, UnparseableFieldError)

    with pytest.raises(UnparseableFieldError):
        pinuv2.decrypt_info_field(
            os.urandom(32), pinuv2.INFO_ENC_IDENTIFIER, b"\x00" * 17
        )

    with pytest.raises(UnparseableFieldError):
        # Whole number of blocks but garbage padding.
        token = os.urandom(32)
        blob = pinuv2.cbc_encrypt(
            pinuv2.derive_info_key(token, pinuv2.INFO_ENC_IDENTIFIER),
            b"\x00" * 16,
        )
        pinuv2.decrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, blob)


def test_decoded_fields_are_labeled_decoded_only():
    device = SoftwareAuthenticator("SN-1", "1234")
    manager = AuthenticatorManager(device, "1234")
    session = manager.open_session("conn")
    info = device.connect("conn").get_info()
    identifier, state = decode_info_fields(info, session.persistent_token)
    assert identifier.label is TrustLabel.DECODED_ONLY
    assert state.label is TrustLabel.DECODED_ONLY
    assert not identifier.is_authenticated


# --------------------------------------------------------------------------- #
# Cache binding and invalidation
# --------------------------------------------------------------------------- #


def _binding(connection_id="conn", generation=1):
    return TrustedBinding(connection_id, generation, 0x40)


def test_cache_hit_requires_full_composite_key():
    cache: CredentialCache[str] = CredentialCache()
    binding = _binding()
    from examples.credstore_cache_demo.cred_cache import CacheKey

    key = CacheKey("conn", 1, b"ident", b"state")
    cache.put(binding, key, ("cred-a",))
    assert cache.get(binding, key) == ("cred-a",)

    with pytest.raises(CacheMiss):
        cache.get(binding, CacheKey("conn", 1, b"ident", b"other-state"))


def test_foreign_connection_rejected_even_with_identical_decoded_bytes():
    cache: CredentialCache[str] = CredentialCache()
    from examples.credstore_cache_demo.cred_cache import CacheKey

    key = CacheKey("conn", 1, b"ident", b"state")
    cache.put(_binding("conn"), key, ("cred-a",))
    with pytest.raises(AuthenticityError):
        cache.get(_binding("conn-elsewhere"), key)


def test_stale_token_generation_rejected():
    cache: CredentialCache[str] = CredentialCache()
    from examples.credstore_cache_demo.cred_cache import CacheKey

    key = CacheKey("conn", 1, b"ident", b"state")
    cache.put(_binding(generation=1), key, ("cred-a",))
    with pytest.raises(AuthenticityError):
        cache.get(_binding(generation=2), key)


def test_get_or_refresh_re_enumerates_only_on_miss():
    calls = 0

    def enumerate_fn():
        nonlocal calls
        calls += 1
        return ("cred-a",)

    device = SoftwareAuthenticator("SN-2", "1234")
    manager = AuthenticatorManager(device, "1234")
    manager.open_session("conn")
    info = device.connect("conn").get_info()
    session = manager._session  # noqa: SLF001

    first, reused_first = get_or_refresh(
        manager.cache, session.binding, info, session.persistent_token, enumerate_fn
    )
    second, reused_second = get_or_refresh(
        manager.cache, session.binding, info, session.persistent_token, enumerate_fn
    )
    assert calls == 1
    assert first == second == ("cred-a",)
    assert reused_first is False and reused_second is True


# --------------------------------------------------------------------------- #
# Software device lifecycle
# --------------------------------------------------------------------------- #


def test_identifier_stable_across_reconnect_but_changes_on_reset():
    device = SoftwareAuthenticator("SN-3", "1234")
    manager = AuthenticatorManager(device, "1234")
    manager.open_session("conn-a")
    token_a = manager._session.persistent_token  # noqa: SLF001
    ident_a, _ = decode_info_fields(device.connect("conn-a").get_info(), token_a)

    manager.reconnect("conn-b")
    token_b = manager._session.persistent_token  # noqa: SLF001
    assert token_b == token_a  # persistent PUAT survives reconnect
    ident_b, _ = decode_info_fields(device.connect("conn-b").get_info(), token_b)
    assert ident_b.value == ident_a.value

    manager.factory_reset()
    manager.open_session("conn-c")
    token_c = manager._session.persistent_token  # noqa: SLF001
    ident_c, _ = decode_info_fields(device.connect("conn-c").get_info(), token_c)
    assert ident_c.value != ident_a.value


def test_store_state_changes_on_credential_mutation():
    device = SoftwareAuthenticator("SN-4", "1234")
    manager = AuthenticatorManager(device, "1234")
    manager.open_session("conn")
    token = manager._session.persistent_token  # noqa: SLF001
    _, state_before = decode_info_fields(device.connect("conn").get_info(), token)

    device.connect("conn").add_credential(CredentialRecord("rp", b"cid", b"uid"))
    _, state_after = decode_info_fields(device.connect("conn").get_info(), token)
    assert state_before.value != state_after.value


def test_token_rotation_invalidates_session_and_cache():
    device = SoftwareAuthenticator("SN-5", "1234")
    manager = AuthenticatorManager(device, "1234")
    manager.open_session("conn")
    manager.list_credentials()  # warm the cache
    manager.rotate_token()
    assert manager._session is None  # noqa: SLF001
    with pytest.raises(AuthenticityError):
        manager.list_credentials()
    manager.open_session("conn2")
    _records, reused = manager.list_credentials()
    assert reused is False


# --------------------------------------------------------------------------- #
# The CBC authenticity counterexample
# --------------------------------------------------------------------------- #


def test_wrong_token_still_decrypts_to_equal_length_bytes():
    device = SoftwareAuthenticator("SN-6", "1234")
    manager = AuthenticatorManager(device, "1234")
    manager.open_session("conn")
    token = manager._session.persistent_token  # noqa: SLF001
    blob = device.connect("conn").get_info().enc_identifier

    real_key = pinuv2.derive_info_key(token, pinuv2.INFO_ENC_IDENTIFIER)
    wrong_key = pinuv2.derive_info_key(b"\xff" * 32, pinuv2.INFO_ENC_IDENTIFIER)
    real_raw = pinuv2.cbc_decrypt(real_key, blob)
    wrong_raw = pinuv2.cbc_decrypt(wrong_key, blob)

    assert len(wrong_raw) == len(real_raw)
    assert wrong_raw != real_raw


def test_lucky_wrong_key_can_produce_valid_padding_but_wrong_value():
    token = os.urandom(32)
    plaintext = b"device:SN-LUCKY"  # 15 bytes -> 0x01 padding
    blob = pinuv2.encrypt_info_field(token, pinuv2.INFO_ENC_IDENTIFIER, plaintext)
    for _ in range(20_000):
        guess = os.urandom(32)
        if guess == token:
            continue
        raw = pinuv2.cbc_decrypt(
            pinuv2.derive_info_key(guess, pinuv2.INFO_ENC_IDENTIFIER), blob
        )
        if raw[-1] == 0x01:
            decoded = pinuv2.pkcs7_unpad(raw)
            assert decoded != plaintext
            return
    pytest.fail("no lucky wrong key found")
