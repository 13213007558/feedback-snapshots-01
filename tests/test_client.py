# coding=utf-8

# Copyright (c) 2013 Yubico AB
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

import struct
import unittest
from typing import Any, Mapping, cast
from unittest import mock

from fido2 import cbor
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap1 import APDU, Ctap1, RegistrationData
from fido2.ctap2 import AttestationResponse, Ctap2, Info
from fido2.hid import CAPABILITY, CTAPHID
from fido2.utils import sha256
from fido2.webauthn import (
    AttestationObject,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)

APP_ID = "https://foo.example.com"
CLIENT_DATA_COLLECTOR = DefaultClientDataCollector(APP_ID)
REG_DATA = RegistrationData(
    bytes.fromhex(
        "0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"  # noqa E501
    )
)

rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"
_INFO_NO_PIN = bytes.fromhex(
    "a60182665532465f5632684649444f5f325f3002826375766d6b686d61632d7365637265740350f8a011f38c0a4d15800617111f9edc7d04a462726bf5627570f564706c6174f469636c69656e7450696ef4051904b0068101"  # noqa E501
)
_MC_RESP = bytes.fromhex(
    "a301667061636b6564025900c40021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12410000001cf8a011f38c0a4d15800617111f9edc7d0040fe3aac036d14c1e1c65518b698dd1da8f596bc33e11072813466c6bf3845691509b80fb76d59309b8d39e0a93452688f6ca3a39a76f3fc52744fb73948b15783a5010203262001215820643566c206dd00227005fa5de69320616ca268043a38f08bde2e9dc45a5cafaf225820171353b2932434703726aae579fa6542432861fe591e481ea22d63997e1a529003a363616c67266373696758483046022100cc1ef43edf07de8f208c21619c78a565ddcf4150766ad58781193be8e0a742ed022100f1ed7c7243e45b7d8e5bda6b1abf10af7391789d1ef21b70bd69fed48dba4cb163783563815901973082019330820138a003020102020900859b726cb24b4c29300a06082a8648ce3d0403023047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e301e170d3136313230343131353530305a170d3236313230323131353530305a3047310b300906035504061302555331143012060355040a0c0b59756269636f205465737431223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3059301306072a8648ce3d020106082a8648ce3d03010703420004ad11eb0e8852e53ad5dfed86b41e6134a18ec4e1af8f221a3c7d6e636c80ea13c3d504ff2e76211bb44525b196c44cb4849979cf6f896ecd2bb860de1bf4376ba30d300b30090603551d1304023000300a06082a8648ce3d0403020349003046022100e9a39f1b03197525f7373e10ce77e78021731b94d0c03f3fda1fd22db3d030e7022100c4faec3445a820cf43129cdb00aabefd9ae2d874f9c5d343cb2f113da23723f3"  # noqa E501
)


class TestFido2Client(unittest.TestCase):
    def test_ctap1_info(self):
        dev = mock.Mock()
        dev.capabilities = 0
        client = Fido2Client(dev, CLIENT_DATA_COLLECTOR)
        self.assertEqual(client.info.versions, ["U2F_V2"])
        self.assertEqual(client.info.pin_uv_protocols, [])

    @mock.patch("fido2.client.Ctap2")
    def test_make_credential_wrong_app_id(self, PatchedCtap2):
        dev = mock.Mock()
        dev.capabilities = CAPABILITY.CBOR
        ctap2 = mock.MagicMock()
        ctap2.get_info.return_value = Info.from_dict(
            cast(Mapping[int, Any], cbor.decode(_INFO_NO_PIN))
        )
        PatchedCtap2.return_value = ctap2
        client = Fido2Client(dev, CLIENT_DATA_COLLECTOR)
        try:
            client.make_credential(
                PublicKeyCredentialCreationOptions(
                    rp={"id": "bar.example.com", "name": "Invalid RP"},
                    user=user,
                    challenge=challenge,
                    pub_key_cred_params=[{"type": "public-key", "alg": -7}],
                )
            )
            self.fail("make_credential did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.BAD_REQUEST)

    @mock.patch("fido2.client.Ctap2")
    def test_make_credential_existing_key(self, PatchedCtap2):
        dev = mock.Mock()
        dev.capabilities = CAPABILITY.CBOR
        ctap2 = mock.MagicMock()
        ctap2.get_info.return_value = Info.from_dict(
            cast(Mapping[int, Any], cbor.decode(_INFO_NO_PIN))
        )
        ctap2.info = ctap2.get_info()
        ctap2.make_credential.side_effect = CtapError(CtapError.ERR.CREDENTIAL_EXCLUDED)
        PatchedCtap2.return_value = ctap2
        client = Fido2Client(dev, CLIENT_DATA_COLLECTOR)

        try:
            client.make_credential(
                PublicKeyCredentialCreationOptions(
                    rp=rp,
                    user=user,
                    challenge=challenge,
                    pub_key_cred_params=[{"type": "public-key", "alg": -7}],
                    authenticator_selection={"userVerification": "discouraged"},
                )
            )
            self.fail("make_credential did not raise error")
        except ClientError as e:
            self.assertEqual(e.code, ClientError.ERR.DEVICE_INELIGIBLE)

        ctap2.make_credential.assert_called_once()

    @mock.patch("fido2.client.Ctap2")
    def test_make_credential_ctap2(self, PatchedCtap2):
        dev = mock.Mock()
        dev.capabilities = CAPABILITY.CBOR
        ctap2 = mock.MagicMock()
        ctap2.get_info.return_value = Info.from_dict(
            cast(Mapping[int, Any], cbor.decode(_INFO_NO_PIN))
        )
        ctap2.info = ctap2.get_info()
        ctap2.make_credential.return_value = AttestationResponse.from_dict(
            cast(Mapping[int, Any], cbor.decode(_MC_RESP))
        )
        PatchedCtap2.return_value = ctap2
        client = Fido2Client(dev, CLIENT_DATA_COLLECTOR)

        response = client.make_credential(
            PublicKeyCredentialCreationOptions(
                rp=rp,
                user=user,
                challenge=challenge,
                pub_key_cred_params=[{"type": "public-key", "alg": -7}],
                timeout=1000,
                authenticator_selection={"userVerification": "discouraged"},
            )
        ).response

        self.assertIsInstance(response.attestation_object, AttestationObject)
        self.assertIsInstance(response.client_data, CollectedClientData)

        ctap2.make_credential.assert_called_with(
            response.client_data.hash,
            rp,
            user,
            [{"type": "public-key", "alg": -7}],
            None,
            None,
            None,
            None,
            None,
            None,
            event=mock.ANY,
            on_keepalive=mock.ANY,
        )

        self.assertEqual(response.client_data.origin, APP_ID)
        self.assertEqual(response.client_data.type, "webauthn.create")
        self.assertEqual(response.client_data.challenge, challenge)

    def test_make_credential_ctap1(self):
        dev = mock.Mock()
        dev.capabilities = 0  # No CTAP2
        client = Fido2Client(dev, CLIENT_DATA_COLLECTOR)

        ctap1_mock = mock.MagicMock()
        ctap1_mock.get_version.return_value = "U2F_V2"
        ctap1_mock.register.return_value = REG_DATA
        client._backend.ctap1 = ctap1_mock

        response = client.make_credential(
            PublicKeyCredentialCreationOptions(
                rp=rp,
                user=user,
                challenge=challenge,
                pub_key_cred_params=[{"type": "public-key", "alg": -7}],
            )
        ).response

        self.assertIsInstance(response.attestation_object, AttestationObject)
        self.assertIsInstance(response.client_data, CollectedClientData)
        client_data = response.client_data

        ctap1_mock.register.assert_called_with(
            client_data.hash, sha256(rp["id"].encode())
        )

        self.assertEqual(client_data.origin, APP_ID)
        self.assertEqual(client_data.type, "webauthn.create")
        self.assertEqual(client_data.challenge, challenge)

        self.assertEqual(response.attestation_object.fmt, "fido-u2f")


class SoftwareU2fDevice:
    """Software CTAP1 (U2F) authenticator recording every APDU sent to it."""

    capabilities = 0  # No CTAP2 support

    def __init__(self, known_credentials=(), user_presence=0x01):
        self.apdus = []  # (ins, p1, data) of every APDU received
        self.known = set(known_credentials)  # (app_param, key_handle) pairs
        self.user_presence = user_presence

    def call(self, cmd, request, *args):
        _, ins, p1, _, _, length = struct.unpack(">BBBBBH", request[:7])
        data = request[7 : 7 + length]
        self.apdus.append((ins, p1, data))
        if ins == Ctap1.INS.VERSION:
            return b"U2F_V2" + struct.pack(">H", APDU.OK)
        if ins == Ctap1.INS.REGISTER:
            return bytes(REG_DATA) + struct.pack(">H", APDU.OK)
        if ins == Ctap1.INS.AUTHENTICATE:
            app_param = data[32:64]
            key_handle = data[65 : 65 + data[64]]
            if (app_param, key_handle) not in self.known:
                return struct.pack(">H", APDU.WRONG_DATA)
            if p1 == 0x07:  # check-only
                return struct.pack(">H", APDU.USE_NOT_SATISFIED)
            sig = bytes([self.user_presence]) + struct.pack(">I", 1) + b"signature"
            return sig + struct.pack(">H", APDU.OK)
        return struct.pack(">H", APDU.WRONG_DATA)


class SoftwareCtap2Device:
    """Software CTAP2 authenticator recording every CTAP command sent to it."""

    capabilities = CAPABILITY.CBOR

    def __init__(self):
        self.commands = []  # (cmd, decoded CBOR params) of every command received

    def call(self, cmd, request, event=None, on_keepalive=None):
        code = request[0]
        params = cbor.decode(request[1:]) if len(request) > 1 else {}
        self.commands.append((code, params))
        if code == Ctap2.CMD.GET_INFO:
            return b"\x00" + cbor.encode(cbor.decode(_INFO_NO_PIN))
        if code == Ctap2.CMD.MAKE_CREDENTIAL:
            return b"\x00" + cbor.encode(cbor.decode(_MC_RESP))
        if code == Ctap2.CMD.GET_ASSERTION:
            auth_data = sha256(rp["id"].encode()) + b"\x01" + struct.pack(">I", 1)
            return b"\x00" + cbor.encode(
                {1: {"id": b"test-handle", "type": "public-key"}, 2: auth_data, 3: b"sig"}
            )
        return bytes([CtapError.ERR.INVALID_COMMAND])


class NegotiationErrorDevice(SoftwareU2fDevice):
    """Claims CTAP2 support but fails the CTAP2 capability negotiation."""

    capabilities = CAPABILITY.CBOR

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cbor_commands = []

    def call(self, cmd, request, *args):
        if cmd == CTAPHID.CBOR:
            self.cbor_commands.append(request[0])
            return bytes([CtapError.ERR.INVALID_COMMAND])
        return super().call(cmd, request, *args)


class TestCtap1Compat(unittest.TestCase):
    """WebAuthn options to CTAP1 translation: allowed and rejected requests."""

    def _client(self, dev):
        return Fido2Client(dev, CLIENT_DATA_COLLECTOR)

    def _creation_options(self, **overrides):
        params = {
            "rp": rp,
            "user": user,
            "challenge": challenge,
            "pub_key_cred_params": [{"type": "public-key", "alg": -7}],
        }
        params.update(overrides)
        return PublicKeyCredentialCreationOptions(**params)

    def _request_options(self, **overrides):
        params = {
            "challenge": challenge,
            "rp_id": rp["id"],
            "allow_credentials": [{"type": "public-key", "id": b"test-handle"}],
        }
        params.update(overrides)
        return PublicKeyCredentialRequestOptions(**params)

    # Requests allowed to succeed through the compat path

    def test_make_credential_allowed(self):
        dev = SoftwareU2fDevice()
        response = self._client(dev).make_credential(self._creation_options())

        # Exactly one REGISTER APDU, carrying client and RP hashes
        self.assertEqual(len(dev.apdus), 1)
        ins, _, data = dev.apdus[0]
        self.assertEqual(ins, Ctap1.INS.REGISTER)
        client_data = response.response.client_data
        self.assertEqual(data, client_data.hash + sha256(rp["id"].encode()))

        attestation = response.response.attestation_object
        self.assertEqual(attestation.fmt, "fido-u2f")
        # UP and AT only: user touch must not be reported as verification
        self.assertEqual(
            attestation.auth_data.flags,
            AuthenticatorData.FLAG.AT | AuthenticatorData.FLAG.UP,
        )
        # Optional extensions get a clear (empty) result
        self.assertEqual(response.client_extension_results, {})

    def test_make_credential_uv_preferred_allowed(self):
        dev = SoftwareU2fDevice()
        response = self._client(dev).make_credential(
            self._creation_options(
                authenticator_selection={"userVerification": "preferred"}
            )
        )
        flags = response.response.attestation_object.auth_data.flags
        self.assertEqual(flags & AuthenticatorData.FLAG.UV, 0)
        self.assertNotEqual(flags & AuthenticatorData.FLAG.UP, 0)

    def test_make_credential_resident_key_preferred_allowed(self):
        dev = SoftwareU2fDevice()
        response = self._client(dev).make_credential(
            self._creation_options(authenticator_selection={"residentKey": "preferred"})
        )
        self.assertEqual(response.response.attestation_object.fmt, "fido-u2f")

    def test_get_assertion_allowed(self):
        handle = b"test-handle"
        app_param = sha256(rp["id"].encode())
        dev = SoftwareU2fDevice(known_credentials=[(app_param, handle)])
        selection = self._client(dev).get_assertion(self._request_options())

        ins, p1, data = dev.apdus[0]
        self.assertEqual(ins, Ctap1.INS.AUTHENTICATE)
        self.assertEqual(p1, 0x03)  # enforce-user-presence-and-sign
        self.assertEqual(data[32:64], app_param)

        response = selection.get_response(0)
        self.assertEqual(
            response.response.authenticator_data.flags, AuthenticatorData.FLAG.UP
        )
        self.assertEqual(response.client_extension_results, {})

    def test_get_assertion_flags_not_exaggerated(self):
        # Device (incorrectly) reports the UV bit; the client must mask it
        handle = b"test-handle"
        app_param = sha256(rp["id"].encode())
        dev = SoftwareU2fDevice(
            known_credentials=[(app_param, handle)], user_presence=0x05
        )
        selection = self._client(dev).get_assertion(self._request_options())
        flags = selection.get_response(0).response.authenticator_data.flags
        self.assertEqual(flags, AuthenticatorData.FLAG.UP)
        self.assertEqual(flags & AuthenticatorData.FLAG.UV, 0)

    def test_get_assertion_appid_fallback(self):
        handle = b"test-handle"
        appid = "https://appid.example.com"
        dev = SoftwareU2fDevice(
            known_credentials=[(sha256(appid.encode()), handle)]
        )
        options = self._request_options(extensions={"appid": appid})
        selection = self._client(dev).get_assertion(options)

        # First attempt uses the RP ID, the fallback uses the appid
        app_params = [data[32:64] for _, _, data in dev.apdus]
        self.assertEqual(
            app_params, [sha256(rp["id"].encode()), sha256(appid.encode())]
        )

        response = selection.get_response(0)
        self.assertEqual(response.client_extension_results, {"appid": True})
        auth_data = response.response.authenticator_data
        self.assertEqual(auth_data[:32], sha256(appid.encode()))
        self.assertEqual(auth_data.flags, AuthenticatorData.FLAG.UP)

    def test_get_assertion_appid_not_used(self):
        handle = b"test-handle"
        app_param = sha256(rp["id"].encode())
        dev = SoftwareU2fDevice(known_credentials=[(app_param, handle)])
        options = self._request_options(
            extensions={"appid": "https://appid.example.com"}
        )
        selection = self._client(dev).get_assertion(options)

        self.assertEqual(len(dev.apdus), 1)  # No fallback attempted
        response = selection.get_response(0)
        self.assertEqual(response.client_extension_results, {"appid": False})
        auth_data = response.response.authenticator_data
        self.assertEqual(auth_data[:32], app_param)

    def test_get_assertion_appid_no_match(self):
        dev = SoftwareU2fDevice()
        options = self._request_options(
            extensions={"appid": "https://appid.example.com"}
        )
        with self.assertRaises(ClientError) as cm:
            self._client(dev).get_assertion(options)
        self.assertEqual(cm.exception.code, ClientError.ERR.DEVICE_INELIGIBLE)

    # Requests that must be rejected before any command is sent

    def test_make_credential_rejected_requests(self):
        rejected = [
            # Legacy requireResidentKey
            self._creation_options(
                authenticator_selection={"requireResidentKey": True}
            ),
            # Modern residentKey required
            self._creation_options(
                authenticator_selection={"residentKey": "required"}
            ),
            # User verification required
            self._creation_options(
                authenticator_selection={"userVerification": "required"}
            ),
            # No allowed algorithm usable by CTAP1
            self._creation_options(
                pub_key_cred_params=[{"type": "public-key", "alg": -257}]
            ),
            self._creation_options(
                pub_key_cred_params=[{"type": "public-key", "alg": -8}]
            ),
            # Enterprise attestation
            self._creation_options(attestation="enterprise"),
        ]
        for options in rejected:
            dev = SoftwareU2fDevice()
            with self.assertRaises(ClientError) as cm:
                self._client(dev).make_credential(options)
            self.assertEqual(
                cm.exception.code, ClientError.ERR.CONFIGURATION_UNSUPPORTED
            )
            # Rejected before sending any command to the authenticator
            self.assertEqual(dev.apdus, [])

    def test_get_assertion_rejected_requests(self):
        rejected = [
            # User verification required
            self._request_options(user_verification="required"),
            # Empty allow list requires discoverable credentials
            self._request_options(allow_credentials=[]),
        ]
        for options in rejected:
            dev = SoftwareU2fDevice()
            with self.assertRaises(ClientError) as cm:
                self._client(dev).get_assertion(options)
            self.assertEqual(
                cm.exception.code, ClientError.ERR.CONFIGURATION_UNSUPPORTED
            )
            self.assertEqual(dev.apdus, [])

    # CTAP2-capable and negotiation-failing devices

    def test_ctap2_device_commands(self):
        dev = SoftwareCtap2Device()
        client = self._client(dev)
        response = client.make_credential(
            self._creation_options(
                authenticator_selection={"userVerification": "discouraged"}
            )
        )

        mc = [params for code, params in dev.commands if code == Ctap2.CMD.MAKE_CREDENTIAL]
        self.assertEqual(len(mc), 1)
        self.assertEqual(mc[0][1], response.response.client_data.hash)
        self.assertEqual(mc[0][2], rp)
        self.assertEqual(mc[0][4], [{"type": "public-key", "alg": -7}])
        self.assertNotIn(7, mc[0])  # No rk/uv options set

        dev.commands.clear()
        selection = client.get_assertion(
            self._request_options(user_verification="discouraged")
        )
        ga = [params for code, params in dev.commands if code == Ctap2.CMD.GET_ASSERTION]
        self.assertEqual(ga[-1][1], rp["id"])
        self.assertEqual(
            ga[-1][3], [{"type": "public-key", "id": b"test-handle"}]
        )
        flags = selection.get_response(0).response.authenticator_data.flags
        self.assertEqual(flags, AuthenticatorData.FLAG.UP)

    def test_ctap2_uv_required_rejected_before_sending(self):
        dev = SoftwareCtap2Device()  # No PIN/UV configured
        with self.assertRaises(ClientError) as cm:
            self._client(dev).make_credential(
                self._creation_options(
                    authenticator_selection={"userVerification": "required"}
                )
            )
        self.assertEqual(cm.exception.code, ClientError.ERR.CONFIGURATION_UNSUPPORTED)
        sent = [code for code, _ in dev.commands]
        self.assertNotIn(Ctap2.CMD.MAKE_CREDENTIAL, sent)

    def test_negotiation_error_falls_back_to_ctap1(self):
        dev = NegotiationErrorDevice()
        response = self._client(dev).make_credential(self._creation_options())

        # CTAP2 negotiation was attempted and failed
        self.assertEqual(dev.cbor_commands, [Ctap2.CMD.GET_INFO])
        # The ceremony completed over CTAP1 APDUs
        self.assertEqual([ins for ins, _, _ in dev.apdus], [Ctap1.INS.REGISTER])
        self.assertEqual(response.response.attestation_object.fmt, "fido-u2f")
