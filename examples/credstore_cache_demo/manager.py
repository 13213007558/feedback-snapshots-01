"""Upper-layer orchestration: the part that actually establishes trust.

Everything in this module represents work a real authenticator-management
backend performs *around* python-fido2: opening the transport, obtaining user
verification, minting a token with the right permissions, and checking the
authenticator's pinUvAuthParam HMAC on management commands.

That surrounding, authenticated session is what makes a cached credential list
trustworthy - not the fact that some CBC bytes happened to decrypt.
"""

from __future__ import annotations

from dataclasses import dataclass

from fido2.ctap2.credman import CredentialManagement

from .cred_cache import CredentialCache, get_or_refresh
from .software_device import (
    CredentialRecord,
    SoftwareAuthenticator,
)
from .trust import AuthenticityError, TrustedBinding


@dataclass(frozen=True)
class Session:
    binding: TrustedBinding
    persistent_token: bytes
    channel_hmac_key: bytes
    connection_id: str


class AuthenticatorManager:
    """Backend service that owns one software device and its cache."""

    def __init__(self, device: SoftwareAuthenticator, pin: str) -> None:
        self._device = device
        self._pin = pin
        self._cache: CredentialCache[CredentialRecord] = CredentialCache()
        self._session: Session | None = None

    @property
    def cache(self) -> CredentialCache[CredentialRecord]:
        return self._cache

    def open_session(self, connection_id: str) -> Session:
        """Establish the trusted connection and obtain a persistent PUAT.

        The ECDH/key-agreement exchange and the permission check are the
        upper-layer trust anchor.  A non-persistent token would not survive a
        reconnect, so the cache could not be reused across one; here we
        explicitly request the persistent credential-management permission.
        """
        connection = self._device.connect(connection_id)
        platform_key, _shared_secret = self._key_agreement(connection)
        token, _wrapped, hmac_key = connection.get_persistent_token(
            self._pin,
            platform_key,
            permissions=0x40,
        )
        self._session = Session(
            binding=TrustedBinding(
                connection_id=connection_id,
                token_generation=connection.token_generation,
                permissions=0x40,
            ),
            persistent_token=token,
            channel_hmac_key=hmac_key,
            connection_id=connection_id,
        )
        return self._session

    @staticmethod
    def _key_agreement(connection) -> tuple[dict, bytes]:
        from . import pinuv2

        peer_key = connection.get_key_agreement()
        return pinuv2.platform_encapsulate(peer_key)

    def _require_session(self) -> Session:
        if self._session is None:
            raise AuthenticityError("no authenticated session; call open_session first")
        return self._session

    def list_credentials(self) -> tuple[list[CredentialRecord], bool]:
        """Return credentials, reusing the cache only while every bound fact holds."""
        session = self._require_session()
        connection = self._device.connect(session.connection_id)
        info = connection.get_info()

        def enumerate_authenticated() -> tuple[CredentialRecord, ...]:
            # Mirror CredentialManagement._call: HMAC over the sub-command byte.
            message = bytes([CredentialManagement.CMD.GET_CREDS_METADATA])
            signature = self._hmac(session, message)
            connection.verify_pin_uv_auth(session.channel_hmac_key, message, signature)
            # The metadata command itself is proof the token is accepted; the
            # actual enumeration follows with the same authenticated channel.
            connection.get_credential_metadata()
            return connection.list_credentials()

        records, reused = get_or_refresh(
            self._cache,
            session.binding,
            info,
            session.persistent_token,
            enumerate_authenticated,
        )
        return list(records), reused

    @staticmethod
    def _hmac(session: Session, message: bytes) -> bytes:
        from . import pinuv2

        return pinuv2.hmac_sha256(session.channel_hmac_key, message)

    def reconnect(self, new_connection_id: str) -> None:
        """Reopen the transport, retaining the persistent PUAT generation.

        A new transport means a fresh key-agreement exchange and therefore a
        new channel HMAC key; what makes the token *persistent* is that the
        same 32-byte PUAT (and its generation) remains valid across it.  The
        cache entry is only reusable if the same identifier and store state
        decrypt on the new connection, but because the connection handle is a
        new upper-layer fact, the old entry is discarded and re-enumerated.
        """
        prior = self._require_session()
        connection = self._device.connect(new_connection_id)
        platform_key, _shared_secret = self._key_agreement(connection)
        token, _wrapped, hmac_key = connection.get_persistent_token(
            self._pin, platform_key, permissions=prior.binding.permissions
        )
        if token != prior.persistent_token:
            raise AuthenticityError(
                "persistent token changed across reconnect; refusing to treat the "
                "decoded identifier as proof this is the same device"
            )
        self._session = Session(
            binding=TrustedBinding(
                connection_id=new_connection_id,
                token_generation=connection.token_generation,
                permissions=prior.binding.permissions,
            ),
            persistent_token=token,
            channel_hmac_key=hmac_key,
            connection_id=new_connection_id,
        )
        # A new connection handle must never silently inherit an old entry.
        self._cache.invalidate_connection(prior.connection_id)

    def rotate_token(self) -> None:
        """React to token replacement: rebind to the new generation, drop cache."""
        self._device.rotate_persistent_token()
        self._cache.clear()
        # The old session's token generation is now stale; re-establish.
        self._session = None

    def factory_reset(self) -> None:
        """React to an authenticator reset: nothing from before survives."""
        self._device.factory_reset()
        self._cache.clear()
        self._session = None
