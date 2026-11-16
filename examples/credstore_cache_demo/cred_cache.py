"""Bounded in-memory cache for credential lists.

The cache key is deliberately composite.  A cached list may only be reused
when *all* of the following match:

* the caller-confirmed connection handle (upper-layer fact);
* the PIN/UV token generation (upper-layer fact, changes on re-issuance);
* the decrypted device identifier (opaque, decoded-only bytes);
* the decrypted credential store state (opaque, decoded-only bytes).

The first two bind the entry to an authenticated context; the last two are
opaque freshness hints produced by CBC decryption.  Because CBC has no MAC,
the decoded bytes are never used on their own to decide *which device* this
is - that decision belongs to the caller's trusted connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, TypeVar

from fido2.ctap2.base import Info

from . import pinuv2
from .trust import (
    AuthenticityError,
    CacheMiss,
    DecodedValue,
    TrustedBinding,
    TrustLabel,
)

T = TypeVar("T")


@dataclass(frozen=True)
class CacheKey:
    connection_id: str
    token_generation: int
    identifier: bytes
    store_state: bytes


@dataclass(frozen=True)
class CacheEntry(Generic[T]):
    key: CacheKey
    credentials: tuple[T, ...]

    @property
    def trust_label(self) -> TrustLabel:
        # The list was enumerated through an HMAC-authenticated command.
        return TrustLabel.SESSION_AUTHENTICATED


class CredentialCache(Generic[T]):
    """Holds at most one entry per connection; nothing is persisted to disk."""

    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry[T]] = {}

    def _require_matching_binding(self, binding: TrustedBinding, key: CacheKey) -> None:
        if binding.connection_id != key.connection_id:
            raise AuthenticityError(
                "connection handle changed; decoded bytes alone cannot identify "
                "the device, so the cached list is rejected"
            )
        if binding.token_generation != key.token_generation:
            raise AuthenticityError(
                "PIN/UV token generation changed; re-establish the session and "
                "re-enumerate credentials"
            )

    def get(self, binding: TrustedBinding, key: CacheKey) -> tuple[T, ...]:
        entry = self._entries.get(binding.connection_id)
        if entry is None:
            # Distinguish "no entry on this connection" from "entry exists but
            # the binding is foreign": probe every key before declaring a miss.
            for candidate in self._entries.values():
                if candidate.key == key:
                    # Same decoded bytes, different upper-layer connection.
                    self._require_matching_binding(binding, candidate.key)
            raise CacheMiss(
                "no cached list for this connection/identifier/store-state tuple"
            )
        if entry.key != key:
            raise CacheMiss(
                "no cached list for this connection/identifier/store-state tuple"
            )
        self._require_matching_binding(binding, entry.key)
        return entry.credentials

    def put(self, binding: TrustedBinding, key: CacheKey, credentials: tuple[T, ...]):
        self._require_matching_binding(binding, key)
        self._entries[binding.connection_id] = CacheEntry(key, tuple(credentials))

    def invalidate_connection(self, connection_id: str) -> None:
        self._entries.pop(connection_id, None)

    def clear(self) -> None:
        self._entries.clear()


def decode_info_fields(
    info: Info, persistent_token: bytes
) -> tuple[DecodedValue, DecodedValue]:
    """Decrypt the two Info fields without upgrading their trust level.

    Field absence and malformed framing propagate as the distinct error types
    defined in :mod:`trust`.  On success the values are returned as
    ``DECODED_ONLY``: they are safe as opaque cache keys but must not be
    presented as an authenticated device identity.
    """
    identifier = pinuv2.decrypt_info_field(
        persistent_token, pinuv2.INFO_ENC_IDENTIFIER, info.enc_identifier
    )
    store_state = pinuv2.decrypt_info_field(
        persistent_token,
        pinuv2.INFO_ENC_CRED_STORE_STATE,
        info.enc_cred_store_state,
    )
    return (
        DecodedValue(identifier, TrustLabel.DECODED_ONLY, "encIdentifier"),
        DecodedValue(store_state, TrustLabel.DECODED_ONLY, "encCredStoreState"),
    )


def build_cache_key(
    binding: TrustedBinding, identifier: DecodedValue, store_state: DecodedValue
) -> CacheKey:
    return CacheKey(
        connection_id=binding.connection_id,
        token_generation=binding.token_generation,
        identifier=identifier.value,
        store_state=store_state.value,
    )


def get_or_refresh(
    cache: CredentialCache[T],
    binding: TrustedBinding,
    info: Info,
    persistent_token: bytes,
    enumerate_fn: Callable[[], tuple[T, ...]],
) -> tuple[tuple[T, ...], bool]:
    """Return the cached list when fresh, otherwise call ``enumerate_fn``.

    The enumeration callback is expected to perform the real,
    HMAC-authenticated credential-management exchange.  A returned list is
    therefore ``SESSION_AUTHENTICATED``; the decrypted Info values used to key
    the cache remain ``DECODED_ONLY``.

    Returns ``(credentials, reused)`` where ``reused`` is True on a cache hit.
    """
    identifier, store_state = decode_info_fields(info, persistent_token)
    key = build_cache_key(binding, identifier, store_state)
    try:
        return cache.get(binding, key), True
    except CacheMiss:
        credentials = enumerate_fn()
        cache.put(binding, key, credentials)
        return credentials, False
