"""End-to-end demonstration of the credential-list cache and its trust rules.

Run with::

    python -m examples.credstore_cache_demo.demo

Each scenario prints whether a value is merely *decoded* or backed by the
*upper-layer authenticated session*, so the trust boundary stays visible.
"""

from __future__ import annotations

import os

from fido2.ctap2.base import Info

from . import pinuv2
from .cred_cache import decode_info_fields
from .manager import AuthenticatorManager
from .software_device import CredentialRecord, SoftwareAuthenticator
from .trust import (
    AuthenticityError,
    MissingFieldError,
    TrustedBinding,
    TrustLabel,
    UnparseableFieldError,
)


def _heading(title: str) -> None:
    print(f"\n=== {title} ===")


def _show(label, value: bytes | None) -> None:
    if value is not None:
        print(f"  {label}: {value.hex()} ({len(value)} bytes)")


def main() -> None:
    device = SoftwareAuthenticator(serial="SN-DEMO-0001", pin="1234")
    manager = AuthenticatorManager(device, pin="1234")

    _heading("1. Same-origin reuse: identical (connection, token, identifier, state)")
    manager.open_session("conn-a")
    first, reused_first = manager.list_credentials()
    second, reused_second = manager.list_credentials()
    print(f"  first call reused cache?  {reused_first}")
    print(f"  second call reused cache? {reused_second}")
    assert reused_first is False and reused_second is True
    print("  trust source: upper-layer HMAC-authenticated management session;")
    print("  decoded identifier/state are only opaque cache keys (DECODED_ONLY).")

    _heading("2. Credential store change: store-state rotates, cache is discarded")
    conn = device.connect("conn-a")
    conn.add_credential(
        CredentialRecord(rp_id="example.com", credential_id=b"cred-1", user_id=b"u1")
    )
    third, reused_third = manager.list_credentials()
    print(f"  after add_credential, reused cache? {reused_third}")
    print(f"  enumerated credentials: {[c.credential_id for c in third]}")
    assert reused_third is False and len(third) == 1
    # A follow-up call within the unchanged state hits the cache again.
    _fourth, reused_fourth = manager.list_credentials()
    assert reused_fourth is True

    _heading("3. Reconnect with persistent PUAT: identifier stable, new binding")
    manager.reconnect("conn-b")
    records, reused_after_reconnect = manager.list_credentials()
    print(f"  reused cache across the new connection handle? {reused_after_reconnect}")
    print("  (expected False: the connection id is a new upper-layer fact, so the")
    print("   list is re-enumerated even though the persistent token still works.)")
    assert reused_after_reconnect is False
    # Same physical device: the decoded identifier is unchanged on conn-b.
    info_b = device.connect("conn-b").get_info()
    session_b = manager._session  # noqa: SLF001 - demo introspection
    ident_b, _state_b = decode_info_fields(info_b, session_b.persistent_token)
    print(f"  decoded identifier still: {ident_b.value.hex()}")
    assert ident_b.label is TrustLabel.DECODED_ONLY

    _heading("4. Token replacement: old generation can no longer authenticate")
    manager.rotate_token()
    try:
        manager.list_credentials()
    except AuthenticityError as error:
        print(f"  rejected as expected: {error}")
    manager.open_session("conn-c")
    records, reused_after_rotate = manager.list_credentials()
    print(f"  fresh session after rotation, cache reused? {reused_after_rotate}")
    assert reused_after_rotate is False

    _heading("5. Factory reset: identifier, state and token all change")
    before_info = device.connect("conn-c").get_info()
    old_ident, old_state = decode_info_fields(
        before_info,
        manager._session.persistent_token,  # noqa: SLF001
    )
    manager.factory_reset()
    try:
        manager.list_credentials()
    except AuthenticityError as error:
        print(f"  pre-reset session rejected: {error}")
    manager.open_session("conn-d")
    after_info = device.connect("conn-d").get_info()
    new_ident, new_state = decode_info_fields(
        after_info,
        manager._session.persistent_token,  # noqa: SLF001
    )
    print(f"  identifier before reset: {old_ident.value.hex()}")
    print(f"  identifier after  reset: {new_ident.value.hex()}")
    print(f"  store state changed?    {old_state.value != new_state.value}")
    assert old_ident.value != new_ident.value
    assert old_state.value != new_state.value

    _heading("6. COUNTEREXAMPLE: wrong token still yields equal-length CBC bytes")
    victim = device.connect("conn-d").get_info()
    real_token = manager._session.persistent_token  # noqa: SLF001
    wrong_token = b"\xff" * 32
    # Raw CBC decryption never raises on a wrong key: output length is fixed.
    real_key = pinuv2.derive_info_key(real_token, pinuv2.INFO_ENC_IDENTIFIER)
    wrong_key = pinuv2.derive_info_key(wrong_token, pinuv2.INFO_ENC_IDENTIFIER)
    real_raw = pinuv2.cbc_decrypt(real_key, victim.enc_identifier)
    wrong_raw = pinuv2.cbc_decrypt(wrong_key, victim.enc_identifier)
    print(f"  ciphertext length:      {len(victim.enc_identifier)} bytes")
    print(f"  correct token raw out:  {real_raw.hex()} ({len(real_raw)} bytes)")
    print(f"  wrong token raw out:    {wrong_raw.hex()} ({len(wrong_raw)} bytes)")
    assert len(wrong_raw) == len(real_raw)
    print("  Both are the same length and both 'decrypted' successfully. With the")
    print("  wrong token the PKCS#7 padding is usually invalid, so strict decoding")
    print("  reports UnparseableFieldError - but framing alone never proves origin.")
    try:
        pinuv2.pkcs7_unpad(wrong_raw)
    except UnparseableFieldError as error:
        print(f"  strict decode with wrong token -> {type(error).__name__}: {error}")

    # Even when padding happens to be valid, the result is garbage, not identity.
    _lucky_padding_counterexample(real_token)

    _heading("7. Missing vs malformed vs unauthenticated stay separate")
    absent = Info(versions=["FIDO_2_1"])
    try:
        decode_info_fields(absent, real_token)
    except MissingFieldError as error:
        print(f"  absent field   -> {type(error).__name__}: {error}")
    try:
        pinuv2.decrypt_info_field(real_token, pinuv2.INFO_ENC_IDENTIFIER, b"\x00" * 17)
    except UnparseableFieldError as error:
        print(f"  malformed blob -> {type(error).__name__}: {error}")
    # Authenticity comes from the upper-layer binding, not from decryption:
    # populate an entry on the current connection, then present a foreign one.
    manager.list_credentials()
    current = manager._session  # noqa: SLF001
    entry = manager.cache._entries[current.connection_id]  # noqa: SLF001
    foreign_binding = TrustedBinding(
        connection_id="conn-elsewhere",
        token_generation=current.binding.token_generation,
        permissions=current.binding.permissions,
    )
    try:
        manager.cache.get(foreign_binding, entry.key)
    except AuthenticityError as error:
        print(f"  stale binding  -> {type(error).__name__}: {error}")

    print("\nAll scenarios passed.")


def _lucky_padding_counterexample(real_token: bytes) -> None:
    """Find a wrong token whose plaintext has valid padding but wrong value.

    Any given wrong key has a 1/256 chance of leaving a final 0x01 byte, so a
    few thousand random guesses find one with overwhelming probability.  This
    is deliberately found by search, not by constructing any new MAC: the
    point is that valid framing carries no proof of origin.
    """
    plaintext = b"device:SN-LUCKY"  # 15 bytes -> one byte of 0x01 padding
    blob = pinuv2.encrypt_info_field(real_token, pinuv2.INFO_ENC_IDENTIFIER, plaintext)
    for _ in range(20_000):
        guess = os.urandom(32)
        if guess == real_token:
            continue
        key = pinuv2.derive_info_key(guess, pinuv2.INFO_ENC_IDENTIFIER)
        raw = pinuv2.cbc_decrypt(key, blob)
        if raw[-1] == 0x01:
            decoded = pinuv2.pkcs7_unpad(raw)
            print("  lucky wrong-key case found:")
            print(f"    wrong token:            {guess.hex()}")
            print(f"    unpadded 'identifier':  {decoded!r}")
            print("    Padding is valid, yet the bytes are not the real identifier.")
            assert decoded != plaintext
            return
    raise AssertionError("no lucky wrong key found in search space")


if __name__ == "__main__":
    main()
