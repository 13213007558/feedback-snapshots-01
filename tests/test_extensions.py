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

"""Cross-credential regression tests for the prf/hmac-secret extensions.

These tests exercise the full client path of the extension: input
preparation, the CTAP call (against a software authenticator which
independently decrypts the request and produces outputs), and conversion
of the results. They guard against deriving secrets from the inputs of a
different credential than the one that was selected.
"""

import os

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from fido2.ctap2.base import AssertionResponse, Info
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.utils import bytes2int, hmac_sha256, int2bytes, sha256, websafe_encode
from fido2.webauthn import (
    AuthenticatorData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
)

RP_ID = "example.com"
SALT_LEN = HmacSecretExtension.SALT_LEN


def _b64(data):
    return websafe_encode(data)


class SoftHmacSecretAuthenticator:
    """Minimal software authenticator speaking the hmac-secret extension.

    Holds one secret key per credential. For each getAssertion call it
    derives the shared secret on its own, verifies and decrypts the actual
    request sent by the client, and computes the outputs independently.
    """

    def __init__(self, pin_protocol):
        self.pin_protocol = pin_protocol
        self.info = Info(
            versions=["FIDO_2_1"],
            extensions=["hmac-secret"],
            options={"clientPin": True},
            pin_uv_protocols=[pin_protocol.VERSION],
        )
        self._sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.credential_keys = {}
        self.requests = []  # (credential_id, decrypted salts) per CTAP call

    def add_credential(self, credential_id, key):
        self.credential_keys[credential_id] = key
        return PublicKeyCredentialDescriptor(type="public-key", id=credential_id)

    def client_pin(self, version, cmd, **kwargs):
        assert version == self.pin_protocol.VERSION
        assert cmd == ClientPin.CMD.GET_KEY_AGREEMENT
        pn = self._sk.public_key().public_numbers()
        return {
            ClientPin.RESULT.KEY_AGREEMENT: {
                1: 2,
                3: -25,
                -1: 1,
                -2: int2bytes(pn.x, 32),
                -3: int2bytes(pn.y, 32),
            }
        }

    def _shared_secret(self, peer_key):
        pk = ec.EllipticCurvePublicNumbers(
            bytes2int(peer_key[-2]), bytes2int(peer_key[-3]), ec.SECP256R1()
        ).public_key(default_backend())
        return self.pin_protocol.kdf(self._sk.exchange(ec.ECDH(), pk))

    def get_assertion(self, extension_inputs, credential_id, raw_output=None):
        """The CTAP getAssertion call for the hmac-secret extension.

        Decrypts the salts from the actual client request and computes
        HMAC outputs using the key of the given credential. If raw_output
        is given, it is returned (encrypted) instead of a computed output,
        to simulate a malformed authenticator response.
        """
        data = extension_inputs[HmacSecretExtension.NAME]
        shared_secret = self._shared_secret(data[1])
        salt_enc, salt_auth = data[2], data[3]
        expected_auth = self.pin_protocol.authenticate(shared_secret, salt_enc)
        assert expected_auth == salt_auth, "saltAuth does not verify"
        salts = self.pin_protocol.decrypt(shared_secret, salt_enc)
        self.requests.append((credential_id, salts))

        if raw_output is not None:
            output = raw_output
        else:
            key = self.credential_keys[credential_id]
            output = hmac_sha256(key, salts[:SALT_LEN])
            if len(salts) > SALT_LEN:
                output += hmac_sha256(key, salts[SALT_LEN:])

        auth_data = AuthenticatorData.create(
            sha256(RP_ID.encode()),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.ED,
            0,
            extensions={
                HmacSecretExtension.NAME: self.pin_protocol.encrypt(
                    shared_secret, output
                )
            },
        )
        return AssertionResponse(
            credential={"type": "public-key", "id": credential_id},
            auth_data=auth_data,
            signature=b"fake-signature",
        )


@pytest.fixture(params=[PinProtocolV1(), PinProtocolV2()], ids=["pin-v1", "pin-v2"])
def pin_protocol(request):
    return request.param


@pytest.fixture
def auth(pin_protocol):
    return SoftHmacSecretAuthenticator(pin_protocol)


@pytest.fixture
def credentials(auth):
    cred_a = auth.add_credential(b"credential-a", os.urandom(32))
    cred_b = auth.add_credential(b"credential-b", os.urandom(32))
    return cred_a, cred_b


def make_options(allow_credentials=None, extensions=None):
    return PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32),
        rp_id=RP_ID,
        allow_credentials=allow_credentials,
        extensions=extensions,
    )


def run_assertion(extension, auth, options, selected):
    """Run the full client path: inputs, CTAP call, output conversion."""
    processor = extension.get_assertion(auth, options, auth.pin_protocol)
    assert processor is not None
    inputs = processor.prepare_inputs(selected, None)
    if inputs is None:
        # No extension inputs sent: authenticator adds no extension outputs
        response = AssertionResponse(
            credential={"type": "public-key", "id": selected.id},
            auth_data=AuthenticatorData.create(
                sha256(RP_ID.encode()), AuthenticatorData.FLAG.UP, 0
            ),
            signature=b"fake-signature",
        )
    else:
        response = auth.get_assertion(inputs, selected.id)
    return processor.prepare_outputs(response, None)


def prf_extension(**kwargs):
    return {"prf": kwargs}


class TestPrfGetAssertion:
    def test_eval_default_single_salt(self, auth, credentials, pin_protocol):
        cred_a, _ = credentials
        salt = os.urandom(32)
        options = make_options(
            [cred_a], extensions=prf_extension(eval={"first": _b64(salt)})
        )

        outputs = run_assertion(HmacSecretExtension(), auth, options, cred_a)

        # The authenticator received the domain-separated PRF salt
        (cred_id, salts), = auth.requests
        assert cred_id == cred_a.id
        assert salts == sha256(b"WebAuthn PRF\0" + salt)

        results = outputs["prf"].results
        assert len(results.first) == SALT_LEN
        assert results.second is None
        assert results.first == hmac_sha256(
            auth.credential_keys[cred_a.id], sha256(b"WebAuthn PRF\0" + salt)
        )

    def test_eval_default_two_salts(self, auth, credentials, pin_protocol):
        cred_a, _ = credentials
        salt1, salt2 = os.urandom(32), os.urandom(32)
        options = make_options(
            [cred_a],
            extensions=prf_extension(eval={"first": _b64(salt1), "second": _b64(salt2)}),
        )

        outputs = run_assertion(HmacSecretExtension(), auth, options, cred_a)

        (cred_id, salts), = auth.requests
        assert salts == sha256(b"WebAuthn PRF\0" + salt1) + sha256(
            b"WebAuthn PRF\0" + salt2
        )

        results = outputs["prf"].results
        assert len(results.first) == SALT_LEN
        assert len(results.second) == SALT_LEN
        assert results.first != results.second

    def test_eval_by_credential_overrides_eval(self, auth, credentials, pin_protocol):
        cred_a, cred_b = credentials
        salt_default = os.urandom(32)
        salt_a, salt_b = os.urandom(32), os.urandom(32)
        extensions = prf_extension(
            eval={"first": _b64(salt_default)},
            evalByCredential={
                _b64(cred_a.id): {"first": _b64(salt_a)},
                _b64(cred_b.id): {"first": _b64(salt_b)},
            },
        )
        options = make_options([cred_a, cred_b], extensions=extensions)

        # Selecting credential B must derive from B's salts, not A's
        outputs_b = run_assertion(HmacSecretExtension(), auth, options, cred_b)
        assert auth.requests[-1] == (cred_b.id, sha256(b"WebAuthn PRF\0" + salt_b))
        assert outputs_b["prf"].results.first == hmac_sha256(
            auth.credential_keys[cred_b.id], sha256(b"WebAuthn PRF\0" + salt_b)
        )

        # Selecting credential A must derive from A's salts
        outputs_a = run_assertion(HmacSecretExtension(), auth, options, cred_a)
        assert auth.requests[-1] == (cred_a.id, sha256(b"WebAuthn PRF\0" + salt_a))
        assert outputs_a["prf"].results.first == hmac_sha256(
            auth.credential_keys[cred_a.id], sha256(b"WebAuthn PRF\0" + salt_a)
        )

        assert outputs_a["prf"].results.first != outputs_b["prf"].results.first

    def test_eval_by_credential_order_independent(
        self, auth, credentials, pin_protocol
    ):
        cred_a, cred_b = credentials
        salt_a, salt_b = os.urandom(32), os.urandom(32)
        extensions = prf_extension(
            evalByCredential={
                _b64(cred_a.id): {"first": _b64(salt_a)},
                _b64(cred_b.id): {"first": _b64(salt_b)},
            }
        )

        # Swapping the order of allowCredentials must not change the result
        results = []
        for allow_list in ([cred_a, cred_b], [cred_b, cred_a]):
            options = make_options(allow_list, extensions=extensions)
            outputs = run_assertion(HmacSecretExtension(), auth, options, cred_b)
            results.append(outputs["prf"].results.first)

        assert results[0] == results[1]
        assert all(
            r == hmac_sha256(auth.credential_keys[cred_b.id], sha256(b"WebAuthn PRF\0" + salt_b))
            for r in results
        )

    def test_eval_by_credential_falls_back_to_eval(
        self, auth, credentials, pin_protocol
    ):
        cred_a, cred_b = credentials
        salt_default, salt_a = os.urandom(32), os.urandom(32)
        options = make_options(
            [cred_a, cred_b],
            extensions=prf_extension(
                eval={"first": _b64(salt_default)},
                evalByCredential={_b64(cred_a.id): {"first": _b64(salt_a)}},
            ),
        )

        # cred_b has no entry: the default eval values apply
        run_assertion(HmacSecretExtension(), auth, options, cred_b)
        assert auth.requests[-1] == (
            cred_b.id,
            sha256(b"WebAuthn PRF\0" + salt_default),
        )

    def test_eval_by_credential_no_match_no_eval(
        self, auth, credentials, pin_protocol
    ):
        cred_a, cred_b = credentials
        options = make_options(
            [cred_a, cred_b],
            extensions=prf_extension(
                evalByCredential={_b64(cred_a.id): {"first": _b64(os.urandom(32))}}
            ),
        )

        # No matching entry and no eval: no salts are sent, no results
        outputs = run_assertion(HmacSecretExtension(), auth, options, cred_b)
        assert auth.requests == []
        assert outputs is None

    def test_eval_by_credential_rejects_invalid_key(
        self, auth, credentials, pin_protocol
    ):
        cred_a, cred_b = credentials
        options = make_options(
            [cred_a],
            extensions=prf_extension(
                evalByCredential={
                    _b64(cred_a.id): {"first": _b64(os.urandom(32))},
                    _b64(b"unknown-credential"): {"first": _b64(os.urandom(32))},
                }
            ),
        )

        extension = HmacSecretExtension()
        processor = extension.get_assertion(auth, options, pin_protocol)
        with pytest.raises(ValueError, match="invalid key"):
            processor.prepare_inputs(cred_a, None)

    def test_eval_by_credential_requires_allow_list(
        self, auth, credentials, pin_protocol
    ):
        cred_a, _ = credentials
        options = make_options(
            None,
            extensions=prf_extension(
                evalByCredential={_b64(cred_a.id): {"first": _b64(os.urandom(32))}}
            ),
        )

        extension = HmacSecretExtension()
        processor = extension.get_assertion(auth, options, pin_protocol)
        with pytest.raises(ValueError, match="requires allowCredentials"):
            processor.prepare_inputs(cred_a, None)

    def test_shared_state_not_reused_between_requests(
        self, auth, credentials, pin_protocol
    ):
        cred_a, cred_b = credentials
        salt_a, salt_b = os.urandom(32), os.urandom(32)
        extension = HmacSecretExtension()  # One instance, two requests

        options_a = make_options(
            [cred_a, cred_b],
            extensions=prf_extension(
                evalByCredential={_b64(cred_a.id): {"first": _b64(salt_a)}}
            ),
        )
        outputs_a = run_assertion(extension, auth, options_a, cred_a)

        options_b = make_options(
            [cred_a, cred_b],
            extensions=prf_extension(
                evalByCredential={_b64(cred_b.id): {"first": _b64(salt_b)}}
            ),
        )
        outputs_b = run_assertion(extension, auth, options_b, cred_b)

        # Each request used its own credential's salts and key
        assert auth.requests[0] == (cred_a.id, sha256(b"WebAuthn PRF\0" + salt_a))
        assert auth.requests[1] == (cred_b.id, sha256(b"WebAuthn PRF\0" + salt_b))
        assert outputs_a["prf"].results.first == hmac_sha256(
            auth.credential_keys[cred_a.id], auth.requests[0][1]
        )
        assert outputs_b["prf"].results.first == hmac_sha256(
            auth.credential_keys[cred_b.id], auth.requests[1][1]
        )
        assert outputs_a["prf"].results.first != outputs_b["prf"].results.first


class TestHmacSecretDomainSeparation:
    def test_prf_and_hmac_secret_not_interchangeable(
        self, auth, credentials, pin_protocol
    ):
        cred_a, _ = credentials
        salt = os.urandom(32)

        prf_options = make_options(
            [cred_a], extensions=prf_extension(eval={"first": _b64(salt)})
        )
        prf_outputs = run_assertion(HmacSecretExtension(), auth, prf_options, cred_a)

        hmac_options = make_options(
            [cred_a], extensions={"hmacGetSecret": {"salt1": salt}}
        )
        hmac_outputs = run_assertion(
            HmacSecretExtension(allow_hmac_secret=True), auth, hmac_options, cred_a
        )

        # Same input bytes, different derivation domains
        assert auth.requests[0][1] == sha256(b"WebAuthn PRF\0" + salt)
        assert auth.requests[1][1] == salt
        assert (
            prf_outputs["prf"].results.first
            != hmac_outputs["hmacGetSecret"].output1
        )
        assert hmac_outputs["hmacGetSecret"].output1 == hmac_sha256(
            auth.credential_keys[cred_a.id], salt
        )

    def test_hmac_secret_ignored_unless_allowed(
        self, auth, credentials, pin_protocol
    ):
        cred_a, _ = credentials
        options = make_options(
            [cred_a], extensions={"hmacGetSecret": {"salt1": os.urandom(32)}}
        )

        # The default extension does not enable hmac-secret directly
        assert HmacSecretExtension().get_assertion(auth, options, pin_protocol) is None
        assert auth.requests == []

    def test_hmac_secret_two_salts(self, auth, credentials, pin_protocol):
        cred_a, _ = credentials
        salt1, salt2 = os.urandom(32), os.urandom(32)
        options = make_options(
            [cred_a], extensions={"hmacGetSecret": {"salt1": salt1, "salt2": salt2}}
        )

        outputs = run_assertion(
            HmacSecretExtension(allow_hmac_secret=True), auth, options, cred_a
        )

        assert auth.requests[0][1] == salt1 + salt2
        secret = outputs["hmacGetSecret"]
        assert len(secret.output1) == SALT_LEN
        assert len(secret.output2) == SALT_LEN
        assert secret.output1 != secret.output2

    def test_hmac_secret_single_salt_has_no_second_output(
        self, auth, credentials, pin_protocol
    ):
        cred_a, _ = credentials
        options = make_options(
            [cred_a], extensions={"hmacGetSecret": {"salt1": os.urandom(32)}}
        )

        outputs = run_assertion(
            HmacSecretExtension(allow_hmac_secret=True), auth, options, cred_a
        )

        secret = outputs["hmacGetSecret"]
        assert len(secret.output1) == SALT_LEN
        assert secret.output2 is None


class TestMalformedResponses:
    def get_outputs(self, auth, options, selected, raw_output):
        extension = HmacSecretExtension()
        processor = extension.get_assertion(auth, options, auth.pin_protocol)
        inputs = processor.prepare_inputs(selected, None)
        response = auth.get_assertion(inputs, selected.id, raw_output=raw_output)
        return processor.prepare_outputs(response, None)

    def test_short_response_rejected(self, auth, credentials, pin_protocol):
        cred_a, _ = credentials
        options = make_options(
            [cred_a], extensions=prf_extension(eval={"first": _b64(os.urandom(32))})
        )

        with pytest.raises(ValueError, match="output length"):
            self.get_outputs(auth, options, cred_a, os.urandom(16))

    @pytest.mark.parametrize("length", [48, 80, 96])
    def test_extra_segment_rejected(self, auth, credentials, pin_protocol, length):
        cred_a, _ = credentials
        options = make_options(
            [cred_a], extensions=prf_extension(eval={"first": _b64(os.urandom(32))})
        )

        with pytest.raises(ValueError, match="output length"):
            self.get_outputs(auth, options, cred_a, os.urandom(length))

    def test_wrong_credential_mapping_rejected(self, auth, credentials, pin_protocol):
        cred_a, cred_b = credentials
        # evalByCredential keyed only by B, but A is selected and there is
        # no eval fallback: no salts may be sent for A
        options = make_options(
            [cred_a, cred_b],
            extensions=prf_extension(
                evalByCredential={_b64(cred_b.id): {"first": _b64(os.urandom(32))}}
            ),
        )

        outputs = run_assertion(HmacSecretExtension(), auth, options, cred_a)
        assert auth.requests == []
        assert outputs is None
