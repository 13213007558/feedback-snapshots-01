"""Tests for the explicit PIN/UV token acquisition policy.

A software authenticator records every CTAP clientPin command and its
parameters, allowing tests to prove that:

* constrained (strict) requests never trigger a downgrade to the legacy
  getPinUvAuthTokenUsingPin command,
* compatibility requests still complete against legacy-only devices,
* contradictory capability claims are detected,
* the same guarantees hold for both the PIN and the built-in UV paths, and
* raw tokens never end up in log output.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Mapping

import pytest

from fido2 import cbor
from fido2.client import (
    ClientError,
    DefaultClientDataCollector,
    Fido2Client,
)
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import (
    ClientPin,
    PinProtocolV2,
    TokenPermissionError,
    TokenPolicy,
    TokenResult,
)
from fido2.hid import CAPABILITY, CTAPHID
from fido2.utils import sha256

TEST_PIN = "1234"
RP_ID = "example.com"

# CTAP clientPin parameter indices, see fido2.ctap2.base.Ctap2.client_pin
P_PIN_UV_PROTOCOL = 1
P_SUB_COMMAND = 2
P_KEY_AGREEMENT = 3
P_PIN_HASH_ENC = 6
P_PERMISSIONS = 9
P_PERMISSIONS_RPID = 10


@dataclass
class RecordedCommand:
    sub_command: int
    params: dict[int, Any]


@dataclass
class SoftwareAuthenticator:
    """Minimal CTAP2 authenticator implementing the clientPin token flows."""

    options: dict[str, bool]
    pin_uv_protocols: list[int] = field(default_factory=lambda: [2])
    reject_restricted: bool = False

    def __post_init__(self):
        self.capabilities = CAPABILITY.CBOR
        self.commands: list[RecordedCommand] = []
        self.protocol = PinProtocolV2()
        self._shared_secret: bytes | None = None
        self._key_agreement: Mapping[int, Any] | None = None
        self._authenticator_sk = None
        self.token = b"t" * 32

    # CtapDevice interface -------------------------------------------------
    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        ctap_cmd = data[0]
        args = cbor.decode(data[1:]) if len(data) > 1 else {}

        if ctap_cmd == Ctap2.CMD.GET_INFO:
            return b"\0" + cbor.encode(self._info_dict())
        if ctap_cmd == Ctap2.CMD.CLIENT_PIN:
            return b"\0" + cbor.encode(self._client_pin(args))
        return bytes([CtapError.ERR.INVALID_COMMAND])

    # Helpers --------------------------------------------------------------
    def _info_dict(self):
        return {
            1: ["FIDO_2_1"],
            3: b"\0" * 16,
            4: self.options,
            6: self.pin_uv_protocols,
        }

    def _client_pin(self, args):
        sub_cmd = args[P_SUB_COMMAND]
        self.commands.append(RecordedCommand(sub_cmd, dict(args)))

        if sub_cmd == ClientPin.CMD.GET_KEY_AGREEMENT:
            self._key_agreement = self._make_key_agreement()
            return {ClientPin.RESULT.KEY_AGREEMENT: self._key_agreement}

        if sub_cmd in (
            ClientPin.CMD.GET_TOKEN_USING_PIN,
            ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
            ClientPin.CMD.GET_TOKEN_USING_UV,
        ):
            self._shared_secret = self._derive_shared_secret(
                args[P_KEY_AGREEMENT]
            )
            return self._issue_token(sub_cmd, args)

        raise CtapError(CtapError.ERR.INVALID_COMMAND)

    def _make_key_agreement(self):
        """Generate the authenticator key agreement public key."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        from fido2.utils import int2bytes

        be = default_backend()
        self._authenticator_sk = ec.generate_private_key(ec.SECP256R1(), be)
        pn = self._authenticator_sk.public_key().public_numbers()
        return {
            1: 2,
            3: -25,
            -1: 1,
            -2: int2bytes(pn.x, 32),
            -3: int2bytes(pn.y, 32),
        }

    def _derive_shared_secret(self, platform_key):
        """Derive the shared secret from the client's public key.

        The client runs encapsulate() against the public key returned by
        GET_KEY_AGREEMENT; the matching private key held here yields the same
        ECDH shared secret.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        from fido2.utils import bytes2int

        be = default_backend()
        peer = ec.EllipticCurvePublicNumbers(
            bytes2int(platform_key[-2]),
            bytes2int(platform_key[-3]),
            ec.SECP256R1(),
        ).public_key(be)
        z = self._authenticator_sk.exchange(ec.ECDH(), peer)
        return self.protocol.kdf(z)

    def _issue_token(self, sub_cmd, args):
        assert self._shared_secret is not None

        if sub_cmd == ClientPin.CMD.GET_TOKEN_USING_PIN:
            if self.reject_restricted:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)
            # Verify the PIN hash round-trips under the negotiated secret.
            pin_hash = sha256(TEST_PIN.encode())[:16]
            decrypted = self.protocol.decrypt(
                self._shared_secret, args[P_PIN_HASH_ENC]
            )
            if decrypted != pin_hash:
                raise CtapError(CtapError.ERR.PIN_INVALID)
        elif sub_cmd == ClientPin.CMD.GET_TOKEN_USING_UV:
            if self.reject_restricted:
                raise CtapError(CtapError.ERR.INVALID_COMMAND)
        elif sub_cmd == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY:
            # Legacy devices must never receive permission parameters.
            if P_PERMISSIONS in args or P_PERMISSIONS_RPID in args:
                raise CtapError(CtapError.ERR.INVALID_PARAMETER)

        # A getAssertion-scoped token must carry the matching RP ID.
        if args.get(P_PERMISSIONS_RPID) not in (None, RP_ID):
            raise CtapError(CtapError.ERR.INVALID_PARAMETER)

        token_enc = self.protocol.encrypt(self._shared_secret, self.token)
        return {ClientPin.RESULT.PIN_UV_TOKEN: token_enc}

    @property
    def sub_commands(self):
        return [c.sub_command for c in self.commands]

    def last(self, key):
        return self.commands[-1].params.get(key)


def make_ctap(options, **kwargs):
    device = SoftwareAuthenticator(options=options, **kwargs)
    return device, Ctap2(device)


RESTRICTED_OPTIONS = {"clientPin": True, "pinUvAuthToken": True}
LEGACY_OPTIONS = {"clientPin": True}
# Contradictory: claims pinUvAuthToken support while no PIN/UV auth protocol
# is available, which makes the restricted commands impossible to use.
CONTRADICTORY_OPTIONS = {"clientPin": False, "pinUvAuthToken": True}

PERMS = ClientPin.PERMISSION.GET_ASSERTION


# --------------------------------------------------------------------------
# Device capability / constraint validation
# --------------------------------------------------------------------------


class TestConstraintValidation:
    def test_rpid_without_permissions_rejected(self):
        _, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)
        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN, None, RP_ID, policy=TokenPolicy.REQUIRED
            )

    def test_rpid_requires_get_assertion_permission(self):
        _, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)
        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN,
                ClientPin.PERMISSION.MAKE_CREDENTIAL,
                RP_ID,
                policy=TokenPolicy.REQUIRED,
            )

    def test_make_credential_cannot_be_combined(self):
        _, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)
        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN,
                ClientPin.PERMISSION.MAKE_CREDENTIAL
                | ClientPin.PERMISSION.GET_ASSERTION,
                RP_ID,
                policy=TokenPolicy.REQUIRED,
            )

    def test_empty_permissions_rejected(self):
        _, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)
        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN,
                ClientPin.PERMISSION(0),
                policy=TokenPolicy.REQUIRED,
            )

    def test_empty_rpid_rejected(self):
        _, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)
        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN, PERMS, "", policy=TokenPolicy.REQUIRED
            )

    def test_validation_runs_before_any_ctap_command(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)
        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN, None, RP_ID, policy=TokenPolicy.REQUIRED
            )
        assert device.commands == []


# --------------------------------------------------------------------------
# Restricted-token capable authenticator
# --------------------------------------------------------------------------


class TestRestrictedAuthenticator:
    def test_required_pin_token_sends_restricted_command(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)

        result = client_pin.get_pin_token(
            TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.REQUIRED
        )

        assert isinstance(result, TokenResult)
        assert result.token == device.token
        assert result.restricted is True
        assert result.unmet == ()
        assert device.sub_commands == [
            ClientPin.CMD.GET_KEY_AGREEMENT,
            ClientPin.CMD.GET_TOKEN_USING_PIN,
        ]
        assert device.last(P_PERMISSIONS) == int(PERMS)
        assert device.last(P_PERMISSIONS_RPID) == RP_ID

    def test_required_uv_token_sends_uv_command_with_constraints(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)

        result = client_pin.get_uv_token(
            PERMS, RP_ID, policy=TokenPolicy.REQUIRED
        )

        assert isinstance(result, TokenResult)
        assert result.restricted is True
        assert result.unmet == ()
        assert device.sub_commands == [
            ClientPin.CMD.GET_KEY_AGREEMENT,
            ClientPin.CMD.GET_TOKEN_USING_UV,
        ]
        assert device.last(P_PERMISSIONS) == int(PERMS)
        assert device.last(P_PERMISSIONS_RPID) == RP_ID

    def test_legacy_policy_on_capable_device_is_equivalent(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)

        result = client_pin.get_pin_token(
            TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.LEGACY
        )

        assert result.restricted is True
        assert result.unmet == ()
        assert ClientPin.CMD.GET_TOKEN_USING_PIN in device.sub_commands
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands

    def test_rp_id_is_forwarded_and_accepted_when_it_matches(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)

        result = client_pin.get_uv_token(PERMS, RP_ID, policy=TokenPolicy.REQUIRED)

        assert result.restricted is True
        assert device.last(P_PERMISSIONS_RPID) == RP_ID

    def test_mismatched_rp_id_is_rejected_by_authenticator(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS)
        client_pin = ClientPin(ctap)

        with pytest.raises(CtapError) as exc_info:
            client_pin.get_pin_token(
                TEST_PIN,
                PERMS,
                "attacker.example",
                policy=TokenPolicy.REQUIRED,
            )
        assert exc_info.value.code == CtapError.ERR.INVALID_PARAMETER
        # The constrained command was used, never the legacy one.
        assert device.sub_commands[-1] == ClientPin.CMD.GET_TOKEN_USING_PIN
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands


# --------------------------------------------------------------------------
# Legacy-only authenticator
# --------------------------------------------------------------------------


class TestLegacyAuthenticator:
    def test_required_policy_refuses_legacy_device(self):
        device, ctap = make_ctap(LEGACY_OPTIONS)
        client_pin = ClientPin(ctap)

        with pytest.raises(TokenPermissionError):
            client_pin.get_pin_token(
                TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.REQUIRED
            )

        # No downgrade command may be sent.
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands
        assert ClientPin.CMD.GET_TOKEN_USING_PIN not in device.sub_commands

    def test_legacy_policy_completes_and_reports_unmet_constraints(self):
        device, ctap = make_ctap(LEGACY_OPTIONS)
        client_pin = ClientPin(ctap)

        result = client_pin.get_pin_token(
            TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.LEGACY
        )

        assert isinstance(result, TokenResult)
        assert result.token == device.token
        assert result.restricted is False
        assert "pinUvAuthToken" in result.unmet
        assert any("permissions" in item for item in result.unmet)
        assert any(RP_ID in item for item in result.unmet)
        # The legacy command carries no permission parameters.
        assert device.sub_commands[-1] == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY
        assert P_PERMISSIONS not in device.commands[-1].params
        assert P_PERMISSIONS_RPID not in device.commands[-1].params

    def test_legacy_policy_without_constraints_issues_plain_token(self):
        device, ctap = make_ctap(LEGACY_OPTIONS)
        client_pin = ClientPin(ctap)

        result = client_pin.get_pin_token(TEST_PIN, policy=TokenPolicy.LEGACY)

        assert result.restricted is False
        assert result.unmet == ("pinUvAuthToken",)
        assert device.sub_commands[-1] == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY

    def test_uv_has_no_legacy_command_even_under_legacy_policy(self):
        device, ctap = make_ctap(LEGACY_OPTIONS)
        client_pin = ClientPin(ctap)

        with pytest.raises(TokenPermissionError):
            client_pin.get_uv_token(PERMS, RP_ID, policy=TokenPolicy.LEGACY)
        assert device.commands == []

    def test_default_behavior_remains_backwards_compatible(self):
        device, ctap = make_ctap(LEGACY_OPTIONS)
        client_pin = ClientPin(ctap)

        token = client_pin.get_pin_token(TEST_PIN, PERMS, RP_ID)

        assert isinstance(token, bytes)
        assert token == device.token
        assert device.sub_commands[-1] == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY


# --------------------------------------------------------------------------
# Contradictory capability claims
# --------------------------------------------------------------------------


class TestContradictoryCapabilities:
    def test_claim_without_protocol_is_treated_as_unsupported(self):
        device = SoftwareAuthenticator(
            options=CONTRADICTORY_OPTIONS, pin_uv_protocols=[]
        )
        ctap = Ctap2(device)

        # The option claims pinUvAuthToken support, but no PIN/UV protocol is
        # available: no restricted token flow can run, and the contradiction
        # is rejected before any clientPin command is sent.
        with pytest.raises(ValueError):
            ClientPin(ctap)
        assert device.commands == []

    def test_options_contradiction_rejected_under_required_policy(self):
        # pinUvAuthToken claimed while clientPin is unavailable and the
        # authenticator would reject the restricted command at runtime.
        device, ctap = make_ctap(
            {"clientPin": True, "pinUvAuthToken": True},
            reject_restricted=True,
        )
        client_pin = ClientPin(ctap)

        with pytest.raises(CtapError):
            client_pin.get_pin_token(
                TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.REQUIRED
            )
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands

    def test_restricted_command_rejected_at_runtime_is_not_downgraded(self):
        device, ctap = make_ctap(RESTRICTED_OPTIONS, reject_restricted=True)
        client_pin = ClientPin(ctap)

        # Capability advertisement and actual behavior disagree. A strict
        # request must surface the authenticator error instead of silently
        # retrying the legacy command.
        with pytest.raises(CtapError):
            client_pin.get_pin_token(
                TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.REQUIRED
            )
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands

    def test_legacy_policy_does_not_retry_after_runtime_rejection(self):
        # Capability advertisement and actual behavior disagree: the device
        # accepts the restricted command per getInfo but fails it at runtime.
        # The policy layer must not silently swap in the legacy command.
        device, ctap = make_ctap(RESTRICTED_OPTIONS, reject_restricted=True)
        client_pin = ClientPin(ctap)

        with pytest.raises(CtapError):
            client_pin.get_pin_token(
                TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.LEGACY
            )
        assert device.sub_commands == [
            ClientPin.CMD.GET_KEY_AGREEMENT,
            ClientPin.CMD.GET_TOKEN_USING_PIN,
        ]
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands


# --------------------------------------------------------------------------
# Log hygiene
# --------------------------------------------------------------------------


def test_raw_token_is_never_logged(caplog):
    _, ctap = make_ctap(RESTRICTED_OPTIONS)
    client_pin = ClientPin(ctap)
    result = client_pin.get_pin_token(
        TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.REQUIRED
    )

    caplog.set_level(logging.DEBUG, logger="fido2.ctap2.pin")
    client_pin.get_pin_token(TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.REQUIRED)
    client_pin.get_uv_token(PERMS, RP_ID, policy=TokenPolicy.REQUIRED)

    token_hex = result.token.hex()
    for record in caplog.records:
        assert token_hex not in record.getMessage()
        assert result.token not in record.getMessage().encode("utf-8", "ignore")


# --------------------------------------------------------------------------
# End-to-end wiring through the high-level Fido2Client backend
# --------------------------------------------------------------------------


class _PinInteraction:
    def __init__(self, pin):
        self._pin = pin

    def prompt_up(self):
        pass

    def request_pin(self, permissions, rp_id):
        return self._pin

    def request_uv(self, permissions, rp_id):
        return False


class TestClientWiring:
    def _backend(self, options, policy):
        device = SoftwareAuthenticator(options=options)
        client = Fido2Client(
            device,
            DefaultClientDataCollector(f"https://{RP_ID}"),
            user_interaction=_PinInteraction(TEST_PIN),
            token_policy=policy,
        )
        return device, client._backend

    def test_required_policy_through_client_rejects_legacy_device(self):
        device, backend = self._backend(LEGACY_OPTIONS, TokenPolicy.REQUIRED)
        client_pin = ClientPin(backend.ctap2)

        with pytest.raises(ClientError) as exc_info:
            backend._get_token(
                backend.info,
                client_pin,
                PERMS,
                RP_ID,
                None,
                None,
                allow_internal_uv=False,
                allow_uv=False,
            )
        assert exc_info.value.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED
        assert isinstance(exc_info.value.cause, TokenPermissionError)
        # Strict client path must not have issued any token command.
        assert ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY not in device.sub_commands
        assert ClientPin.CMD.GET_TOKEN_USING_PIN not in device.sub_commands

    def test_legacy_policy_through_client_completes_with_unmet_note(self):
        device, backend = self._backend(LEGACY_OPTIONS, TokenPolicy.LEGACY)
        client_pin = ClientPin(backend.ctap2)

        token = backend._get_token(
            backend.info,
            client_pin,
            PERMS,
            RP_ID,
            None,
            None,
            allow_internal_uv=False,
            allow_uv=False,
        )

        assert token == device.token
        assert device.sub_commands[-1] == ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY
        # The unmet constraints are surfaced through the policy result.
        result = client_pin.get_pin_token(
            TEST_PIN, PERMS, RP_ID, policy=TokenPolicy.LEGACY
        )
        assert result.restricted is False
        assert result.unmet

    def test_default_client_policy_is_legacy(self):
        device = SoftwareAuthenticator(options=LEGACY_OPTIONS)
        client = Fido2Client(
            device,
            DefaultClientDataCollector(f"https://{RP_ID}"),
            user_interaction=_PinInteraction(TEST_PIN),
        )
        assert client._backend.token_policy is TokenPolicy.LEGACY
