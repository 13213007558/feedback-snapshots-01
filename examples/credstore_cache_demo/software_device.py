"""A self-contained software CTAP authenticator for the cache demo.

It implements only the pieces the example needs - pinUvAuthProtocol v2 key
agreement, a *persistent* PIN/UV auth token (PUAT), the two encrypted Info
fields, and a tiny resident-credential store - while reusing the real
``fido2.ctap2.base.Info`` dataclass so decryption goes through the exact
library code a production backend would call.

The device is intentionally co-operative: it proves the *lifecycle* semantics
(identifier stable across reconnect, store state changing on writes, reset
invalidating everything) but it is not a security boundary.  The trust
analysis in ``README.md`` makes clear which guarantees come from the upper
layer rather than from anything this simulated device enforces.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from fido2.ctap2.base import Info

from . import pinuv2
from .trust import AuthenticityError

# ClientPin.PERMISSION.PERSISTENT_CREDENTIAL_MGMT == 0x40
PERMISSION_PERSISTENT_CREDENTIAL_MGMT = 0x40


def _cose_public_key(private_key: ec.EllipticCurvePrivateKey) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        1: 2,
        3: -25,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


@dataclass(frozen=True)
class CredentialRecord:
    rp_id: str
    credential_id: bytes
    user_id: bytes


@dataclass
class _PhysicalDevice:
    """State that survives reconnects and power cycles.

    A factory reset replaces this whole object, which is why the persistent
    token, the store state and the identifier all change at once.
    """

    serial: str
    pin: str
    key_agreement_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
    )
    persistent_token: bytes = field(
        default_factory=lambda: os.urandom(pinuv2.TOKEN_LEN)
    )
    token_generation: int = 1
    # The identifier is an independent device secret, not a function of the
    # human-readable serial: a factory reset regenerates it even though the
    # enclosure keeps the same printed serial number.
    identifier_secret: bytes = field(default_factory=lambda: os.urandom(16))
    credentials: list[CredentialRecord] = field(default_factory=list)
    store_state: bytes = field(default_factory=lambda: os.urandom(16))
    max_remaining_creds: int = 20


class SoftwareAuthenticator:
    """Factory/owner of connections to one simulated physical device."""

    def __init__(self, serial: str, pin: str) -> None:
        self._device = _PhysicalDevice(serial=serial, pin=pin)

    @property
    def serial(self) -> str:
        return self._device.serial

    def connect(self, connection_id: str) -> "DeviceConnection":
        """Open a new transport connection to the same underlying device."""
        return DeviceConnection(self._device, connection_id)

    def rotate_persistent_token(self) -> None:
        """Simulate token replacement (re-issuance / policy rotation)."""
        self._device.persistent_token = os.urandom(pinuv2.TOKEN_LEN)
        self._device.token_generation += 1

    def factory_reset(self) -> None:
        """Simulate authenticator reset: every persisted secret is replaced."""
        serial = self._device.serial
        pin = self._device.pin
        self._device = _PhysicalDevice(serial=serial, pin=pin)


class DeviceConnection:
    """One connection/session to a :class:`SoftwareAuthenticator`."""

    def __init__(self, device: _PhysicalDevice, connection_id: str) -> None:
        self._device = device
        self.connection_id = connection_id

    @property
    def token_generation(self) -> int:
        return self._device.token_generation

    def get_key_agreement(self) -> dict:
        return _cose_public_key(self._device.key_agreement_key)

    def get_persistent_token(
        self, pin: str, platform_key_agreement: dict, permissions: int
    ) -> tuple[bytes, bytes, bytes]:
        """Run the GET_TOKEN_USING_PIN exchange and return token and HMAC key.

        Returns the *decrypted* 32-byte persistent PUAT plus the channel HMAC
        key the caller should use to authenticate management commands.  A real
        transport would return the AES-wrapped token; here we perform both
        sides of the ECDH so the demo stays in-process.
        """
        if pin != self._device.pin:
            raise AuthenticityError("PIN verification failed")
        shared_secret = pinuv2.device_shared_secret(
            self._device.key_agreement_key, platform_key_agreement
        )
        hmac_key, aes_key = pinuv2.derive_channel_keys(shared_secret)
        # The 32-byte token is already a multiple of the AES block size.
        wrapped = pinuv2.cbc_encrypt(aes_key, self._device.persistent_token)
        return self._device.persistent_token, wrapped, hmac_key

    def get_info(self) -> Info:
        """Build an Info object carrying the two encrypted fields.

        The plaintext identifier is padded and encrypted afresh on every call
        (random IV), mirroring the library test expectation that two
        ``enc_identifier`` blobs differ byte-for-byte while decrypting to the
        same value.
        """
        token = self._device.persistent_token
        identifier_plaintext = (
            b"device:"
            + self._device.serial.encode()
            + b":"
            + self._device.identifier_secret
        )
        enc_identifier = pinuv2.encrypt_info_field(
            token, pinuv2.INFO_ENC_IDENTIFIER, identifier_plaintext
        )
        enc_store_state = pinuv2.encrypt_info_field(
            token, pinuv2.INFO_ENC_CRED_STORE_STATE, self._device.store_state
        )
        return Info(
            versions=["FIDO_2_1"],
            options={"credMgmt": True, "clientPin": True},
            pin_uv_protocols=[2],
            enc_identifier=enc_identifier,
            enc_cred_store_state=enc_store_state,
        )

    def verify_pin_uv_auth(
        self, hmac_key: bytes, message: bytes, signature: bytes
    ) -> None:
        """Authenticator-side check of a management command's pinUvAuthParam."""
        expected = pinuv2.hmac_sha256(hmac_key, message)
        if not _constant_time_eq(expected, signature):
            raise AuthenticityError("pinUvAuthParam verification failed")

    def get_credential_metadata(self) -> dict:
        return {
            1: len(self._device.credentials),
            2: self._device.max_remaining_creds,
        }

    def list_credentials(self) -> tuple[CredentialRecord, ...]:
        return tuple(self._device.credentials)

    def add_credential(self, record: CredentialRecord) -> None:
        self._device.credentials.append(record)
        # Any store mutation produces a new opaque store-state value.
        self._device.store_state = os.urandom(16)

    def delete_credential(self, credential_id: bytes) -> None:
        self._device.credentials = [
            c for c in self._device.credentials if c.credential_id != credential_id
        ]
        self._device.store_state = os.urandom(16)


def _constant_time_eq(left: bytes, right: bytes) -> bool:
    import hmac as _hmac

    return _hmac.compare_digest(left, right)
