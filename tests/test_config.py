# Copyright (c) 2026 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Authentication tests for the CTAP 2.1 authenticatorConfig command.

These tests run entirely against an in-process virtual authenticator. They
never touch a physical device. The virtual authenticator maintains its own
PIN/UV auth token and independently recomputes the pinUvAuthParam over the
exact CBOR bytes received, so a mismatch between what the library signs and
what it sends is detected rather than assumed.
"""

from __future__ import annotations

import hmac
from typing import Any, Callable, Mapping

import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.config import Config
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID

# A token shared out-of-band between the platform and the virtual device.
PIN_TOKEN = bytes(range(32))

CONFIG_CMD = int(Ctap2.CMD.CONFIG)
GET_INFO_CMD = int(Ctap2.CMD.GET_INFO)

# Authentication message prefixes, per the CTAP specification.
CONFIG_PREFIX = b"\xff" * 32 + b"\x0d"
CREDMAN_PREFIX = b"\xff" * 32 + b"\x0a"


class VirtualConfigDevice:
    """A minimal CTAP2 device which only implements getInfo and authenticatorConfig.

    Every configuration request is validated against the capabilities advertised
    in getInfo and an independently computed pinUvAuthParam. Unsupported fields
    are rejected explicitly instead of being silently ignored.
    """

    def __init__(
        self,
        *,
        config_commands: list[int] | None,
        set_min_pin_length: bool = False,
        max_rpids: int = 0,
        pin_complexity_policy: bool | None = None,
    ):
        self.capabilities = CAPABILITY.CBOR
        self._info: dict[int, Any] = {
            1: ["FIDO_2_1"],
            4: {
                "authnrCfg": True,
                "clientPin": True,
                **({"setMinPINLength": True} if set_min_pin_length else {}),
            },
            6: [PinProtocolV1.VERSION, PinProtocolV2.VERSION],
        }
        if config_commands is not None:
            self._info[31] = config_commands
        if max_rpids:
            self._info[16] = max_rpids
        if pin_complexity_policy is not None:
            self._info[27] = pin_complexity_policy

        # Applied configuration state, proving that valid commands take effect.
        self.min_pin_length: int | None = None
        self.min_pin_length_rpids: list[str] | None = None
        self.force_change_pin: bool | None = None
        self.always_uv_toggles = 0

        # Raw data of the most recent successful configuration request.
        self.last_request: bytes | None = None
        # The full HID CBOR payload (command byte + encoded request).
        self.last_transport: bytes | None = None
        # Optional hook used to mutate the request before it is authenticated.
        self.tamper: Callable[[bytes], bytes] | None = None

    def _fail(self, code: CtapError.ERR) -> bytes:
        return bytes([int(code)])

    def _handle_config(self, data: bytes) -> bytes:
        wire = data[1:]
        if self.tamper is not None:
            wire = self.tamper(wire)

        request = cbor.decode(wire)
        sub_cmd = request.get(1)
        params = request.get(2)
        pin_uv_protocol = request.get(3)
        pin_uv_param = request.get(4)

        # The subcommand must be one the device advertised support for.
        if self._config_commands is not None and sub_cmd not in self._config_commands:
            return self._fail(CtapError.ERR.INVALID_SUBCOMMAND)

        if pin_uv_protocol is not None or pin_uv_param is not None:
            if pin_uv_protocol not in (
                PinProtocolV1.VERSION,
                PinProtocolV2.VERSION,
            ):
                return self._fail(CtapError.ERR.MISSING_PARAMETER)
            if not isinstance(pin_uv_param, bytes) or not pin_uv_param:
                return self._fail(CtapError.ERR.PIN_AUTH_INVALID)

            protocol_cls = (
                PinProtocolV2
                if pin_uv_protocol == PinProtocolV2.VERSION
                else PinProtocolV1
            )
            expected_msg = CONFIG_PREFIX + bytes([sub_cmd])
            if params is not None:
                # The authentication input is the exact CBOR encoding placed on the
                # wire, not a re-serialized view of the decoded parameters.
                expected_msg += cbor.encode(params)
            expected_param = protocol_cls().authenticate(PIN_TOKEN, expected_msg)
            if not hmac.compare_digest(expected_param, pin_uv_param):
                return self._fail(CtapError.ERR.PIN_AUTH_INVALID)

        # Auth passed: enforce field semantics against device capabilities.
        if params is not None:
            if not isinstance(params, Mapping):
                return self._fail(CtapError.ERR.CBOR_UNEXPECTED_TYPE)
            if Config.PARAM.NEW_MIN_PIN_LENGTH in params and not isinstance(
                params[Config.PARAM.NEW_MIN_PIN_LENGTH], int
            ):
                return self._fail(CtapError.ERR.INVALID_PARAMETER)
            if Config.PARAM.MIN_PIN_LENGTH_RPIDS in params:
                if not self._rpids_supported:
                    return self._fail(CtapError.ERR.INVALID_PARAMETER)
                rp_ids = params[Config.PARAM.MIN_PIN_LENGTH_RPIDS]
                if not isinstance(rp_ids, list) or not all(
                    isinstance(rp_id, str) for rp_id in rp_ids
                ):
                    return self._fail(CtapError.ERR.INVALID_PARAMETER)
                if self._max_rpids and len(rp_ids) > self._max_rpids:
                    return self._fail(CtapError.ERR.LIMIT_EXCEEDED)
            if Config.PARAM.PIN_COMPLEXITY_POLICY in params and (
                self._pin_complexity_policy is None
            ):
                return self._fail(CtapError.ERR.INVALID_PARAMETER)
            # Any parameter the device has no semantics for is an error, not a
            # silently ignored field.
            known = {p.value for p in Config.PARAM}
            if any(key not in known for key in params):
                return self._fail(CtapError.ERR.INVALID_PARAMETER)

        if sub_cmd == Config.CMD.SET_MIN_PIN_LENGTH:
            self.min_pin_length = (params or {}).get(Config.PARAM.NEW_MIN_PIN_LENGTH)
            self.min_pin_length_rpids = (params or {}).get(
                Config.PARAM.MIN_PIN_LENGTH_RPIDS
            )
            self.force_change_pin = (params or {}).get(
                Config.PARAM.FORCE_CHANGE_PIN, False
            )
        elif sub_cmd == Config.CMD.TOGGLE_ALWAYS_UV:
            self.always_uv_toggles += 1

        self.last_request = wire
        self.last_transport = data
        return b"\x00"

    @property
    def _config_commands(self) -> list[int] | None:
        return self._info.get(31)

    @property
    def _rpids_supported(self) -> bool:
        return self._info[4].get("setMinPINLength") is True or self._info.get(16, 0) > 0

    @property
    def _max_rpids(self) -> int:
        return self._info.get(16, 0)

    @property
    def _pin_complexity_policy(self) -> bool | None:
        return self._info.get(27)

    def call(self, cmd, data=b"", event=None, on_keepalive=None) -> bytes:
        if cmd != CTAPHID.CBOR:
            return self._fail(CtapError.ERR.INVALID_COMMAND)
        if not data:
            return self._fail(CtapError.ERR.INVALID_LENGTH)
        command = data[0]
        if command == GET_INFO_CMD:
            return b"\x00" + cbor.encode(self._info)
        if command == CONFIG_CMD:
            return self._handle_config(data)
        return self._fail(CtapError.ERR.INVALID_COMMAND)

    def close(self) -> None:
        pass

    @classmethod
    def list_devices(cls):
        yield from ()


def make_ctap(device: VirtualConfigDevice) -> Ctap2:
    return Ctap2(device)


def make_config(
    device: VirtualConfigDevice, protocol_cls: type
) -> tuple[Ctap2, Config]:
    ctap = make_ctap(device)
    config = Config(ctap, protocol_cls(), PIN_TOKEN)
    return ctap, config


@pytest.fixture(params=[PinProtocolV1, PinProtocolV2], ids=["pinv1", "pinv2"])
def protocol(request):
    return request.param


@pytest.fixture
def full_device() -> VirtualConfigDevice:
    return VirtualConfigDevice(
        config_commands=[cmd.value for cmd in Config.CMD],
        set_min_pin_length=True,
        max_rpids=8,
        pin_complexity_policy=True,
    )


def test_config_requires_authnr_cfg():
    device = VirtualConfigDevice(config_commands=None)
    device._info[4] = {"clientPin": True}  # No authnrCfg option
    with pytest.raises(ValueError, match="does not support Config"):
        Config(make_ctap(device), PinProtocolV2(), PIN_TOKEN)


def test_unsupported_subcommand_rejected_before_auth(protocol):
    device = VirtualConfigDevice(config_commands=[int(Config.CMD.TOGGLE_ALWAYS_UV)])
    _, config = make_config(device, protocol)
    with pytest.raises(ValueError, match="not supported by Authenticator"):
        config.set_min_pin_length(min_pin_length=6)
    assert device.last_request is None


def test_toggle_always_uv_has_no_params(protocol, full_device):
    _, config = make_config(full_device, protocol)
    config.toggle_always_uv()

    assert full_device.always_uv_toggles == 1
    request = cbor.decode(full_device.last_request)
    assert request[1] == Config.CMD.TOGGLE_ALWAYS_UV
    assert 2 not in request
    assert request[3] == protocol.VERSION
    assert isinstance(request[4], bytes) and request[4]

    # The authenticated message is prefix + subcommand, with no CBOR params.
    expected_msg = CONFIG_PREFIX + bytes([int(Config.CMD.TOGGLE_ALWAYS_UV)])
    expected_param = protocol().authenticate(PIN_TOKEN, expected_msg)
    assert request[4] == expected_param


def test_set_min_pin_length_defaults_include_force_change(protocol, full_device):
    _, config = make_config(full_device, protocol)
    config.set_min_pin_length()

    request = cbor.decode(full_device.last_request)
    assert request[1] == Config.CMD.SET_MIN_PIN_LENGTH
    assert request[2] == {Config.PARAM.FORCE_CHANGE_PIN: False}
    assert full_device.force_change_pin is False
    assert full_device.min_pin_length is None
    assert full_device.min_pin_length_rpids is None


def test_set_min_pin_length_all_fields(protocol, full_device):
    _, config = make_config(full_device, protocol)
    rp_ids = ["example.com", "example.org"]
    config.set_min_pin_length(
        min_pin_length=8,
        rp_ids=rp_ids,
        force_change_pin=True,
        pin_complexity_policy=True,
    )

    request = cbor.decode(full_device.last_request)
    assert request[2] == {
        Config.PARAM.FORCE_CHANGE_PIN: True,
        Config.PARAM.NEW_MIN_PIN_LENGTH: 8,
        Config.PARAM.MIN_PIN_LENGTH_RPIDS: rp_ids,
        Config.PARAM.PIN_COMPLEXITY_POLICY: True,
    }
    assert full_device.min_pin_length == 8
    assert full_device.min_pin_length_rpids == rp_ids
    assert full_device.force_change_pin is True


def test_empty_rpid_list_is_authenticated(protocol, full_device):
    _, config = make_config(full_device, protocol)
    config.set_min_pin_length(rp_ids=[])

    request = cbor.decode(full_device.last_request)
    assert request[2] == {
        Config.PARAM.FORCE_CHANGE_PIN: False,
        Config.PARAM.MIN_PIN_LENGTH_RPIDS: [],
    }
    assert full_device.min_pin_length_rpids == []

    # The empty list must be part of the authenticated CBOR bytes.
    params_cbor = cbor.encode(request[2])
    expected_msg = (
        CONFIG_PREFIX + bytes([int(Config.CMD.SET_MIN_PIN_LENGTH)]) + params_cbor
    )
    assert request[4] == protocol().authenticate(PIN_TOKEN, expected_msg)


def test_rpid_list_rejected_when_capability_absent(protocol):
    device = VirtualConfigDevice(
        config_commands=[int(Config.CMD.SET_MIN_PIN_LENGTH)],
        set_min_pin_length=False,
    )
    _, config = make_config(device, protocol)

    # The library refuses to send a field the device cannot understand, instead
    # of stripping it and reporting success.
    with pytest.raises(ValueError, match="RP ID list"):
        config.set_min_pin_length(rp_ids=["example.com"])
    assert device.last_request is None


def test_rpid_list_length_limited_by_info(protocol):
    device = VirtualConfigDevice(
        config_commands=[int(Config.CMD.SET_MIN_PIN_LENGTH)],
        set_min_pin_length=True,
        max_rpids=1,
    )
    _, config = make_config(device, protocol)
    with pytest.raises(ValueError, match="exceeds the maximum"):
        config.set_min_pin_length(rp_ids=["example.com", "example.org"])
    assert device.last_request is None


def test_rpid_list_allowed_via_max_rpids_capability(protocol):
    # The setMinPINLength option is absent, but maxRIDsForSetMinPINLength still
    # advertises support for the RP ID list parameter.
    device = VirtualConfigDevice(
        config_commands=[int(Config.CMD.SET_MIN_PIN_LENGTH)],
        set_min_pin_length=False,
        max_rpids=4,
    )
    _, config = make_config(device, protocol)
    config.set_min_pin_length(rp_ids=["example.com"])

    request = cbor.decode(device.last_request)
    assert request[2][Config.PARAM.MIN_PIN_LENGTH_RPIDS] == ["example.com"]
    assert device.min_pin_length_rpids == ["example.com"]


def test_pin_complexity_policy_requires_capability(protocol):
    device = VirtualConfigDevice(
        config_commands=[int(Config.CMD.SET_MIN_PIN_LENGTH)],
        set_min_pin_length=True,
    )
    _, config = make_config(device, protocol)
    with pytest.raises(ValueError, match="PIN complexity policy"):
        config.set_min_pin_length(pin_complexity_policy=True)
    assert device.last_request is None


def test_auth_input_matches_wire_cbor_one_to_one(protocol, full_device):
    ctap, config = make_config(full_device, protocol)
    rp_ids = ["example.com", "acme.example"]
    config.set_min_pin_length(min_pin_length=10, rp_ids=rp_ids, force_change_pin=True)

    # Reconstruct the exact bytes the platform transmitted for this command.
    raw = full_device.last_request
    assert cbor.encode(cbor.decode(raw)) == raw

    sent = cbor.decode(raw)
    authenticated = (
        CONFIG_PREFIX
        + bytes([int(Config.CMD.SET_MIN_PIN_LENGTH)])
        + cbor.encode(sent[2])
    )
    assert sent[4] == protocol().authenticate(PIN_TOKEN, authenticated)

    # The CBOR payload handed to the transport carries identical parameters.
    transport_data = ctap.device.last_transport
    assert transport_data == bytes([CONFIG_CMD]) + raw


def test_config_prefix_is_not_credential_management_prefix(protocol, full_device):
    _, config = make_config(full_device, protocol)
    config.toggle_always_uv()
    request = cbor.decode(full_device.last_request)

    config_msg = CONFIG_PREFIX + bytes([int(Config.CMD.TOGGLE_ALWAYS_UV)])
    credman_msg = CREDMAN_PREFIX + bytes([int(Config.CMD.TOGGLE_ALWAYS_UV)])
    assert request[4] == protocol().authenticate(PIN_TOKEN, config_msg)
    assert request[4] != protocol().authenticate(PIN_TOKEN, credman_msg)


def test_tampered_subcommand_fails_authentication(protocol, full_device):
    def tamper(wire: bytes) -> bytes:
        request = cbor.decode(wire)
        request[1] = Config.CMD.ENABLE_ENTERPRISE_ATT
        return cbor.encode(request)

    full_device.tamper = tamper
    _, config = make_config(full_device, protocol)
    with pytest.raises(CtapError) as exc:
        config.toggle_always_uv()
    assert exc.value.code == CtapError.ERR.PIN_AUTH_INVALID
    assert full_device.always_uv_toggles == 0


def test_tampered_pin_length_fails_authentication(protocol, full_device):
    def tamper(wire: bytes) -> bytes:
        request = cbor.decode(wire)
        request[2][Config.PARAM.NEW_MIN_PIN_LENGTH] = 63
        return cbor.encode(request)

    full_device.tamper = tamper
    _, config = make_config(full_device, protocol)
    with pytest.raises(CtapError) as exc:
        config.set_min_pin_length(min_pin_length=4)
    assert exc.value.code == CtapError.ERR.PIN_AUTH_INVALID
    assert full_device.min_pin_length is None


def test_tampered_rpid_list_fails_authentication(protocol, full_device):
    def tamper(wire: bytes) -> bytes:
        request = cbor.decode(wire)
        request[2][Config.PARAM.MIN_PIN_LENGTH_RPIDS] = ["attacker.example"]
        return cbor.encode(request)

    full_device.tamper = tamper
    _, config = make_config(full_device, protocol)
    with pytest.raises(CtapError) as exc:
        config.set_min_pin_length(rp_ids=["example.com"])
    assert exc.value.code == CtapError.ERR.PIN_AUTH_INVALID
    assert full_device.min_pin_length_rpids is None


def test_unknown_parameter_rejected_by_device(protocol, full_device):
    ctap, _ = make_config(full_device, protocol)
    params = {Config.PARAM.FORCE_CHANGE_PIN: False, 99: "unexpected"}
    msg = (
        CONFIG_PREFIX
        + bytes([int(Config.CMD.SET_MIN_PIN_LENGTH)])
        + cbor.encode(params)
    )
    pin_uv_param = protocol().authenticate(PIN_TOKEN, msg)
    with pytest.raises(CtapError) as exc:
        ctap.config(
            Config.CMD.SET_MIN_PIN_LENGTH,
            params,
            protocol.VERSION,
            pin_uv_param,
        )
    assert exc.value.code == CtapError.ERR.INVALID_PARAMETER


def test_wrong_token_fails_authentication(protocol, full_device):
    ctap = make_ctap(full_device)
    config = Config(ctap, protocol(), b"wrong-token-of-the-right-length!!")
    with pytest.raises(CtapError) as exc:
        config.toggle_always_uv()
    assert exc.value.code == CtapError.ERR.PIN_AUTH_INVALID
    assert full_device.always_uv_toggles == 0


def test_protocol_version_is_advertised(protocol, full_device):
    _, config = make_config(full_device, protocol)
    config.set_min_pin_length(min_pin_length=6)
    request = cbor.decode(full_device.last_request)
    assert request[3] == protocol.VERSION


def test_no_auth_token_sends_no_auth_material(full_device):
    ctap = make_ctap(full_device)
    config = Config(ctap)
    config.toggle_always_uv()
    request = cbor.decode(full_device.last_request)
    assert 3 not in request
    assert 4 not in request
    assert full_device.always_uv_toggles == 1
