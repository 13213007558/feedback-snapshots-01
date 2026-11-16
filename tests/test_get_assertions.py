import unittest

from fido2 import cbor
from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.base import MAX_ASSERTIONS
from fido2.hid import CAPABILITY
from fido2.utils import sha256
from fido2.webauthn import AuthenticatorData, PublicKeyCredentialRequestOptions

RP_ID = "example.com"
RP_ID_HASH = sha256(RP_ID.encode())
OTHER_RP_ID_HASH = sha256(b"other.example.com")

_INFO = {
    0x01: ["U2F_V2", "FIDO_2_0"],
    0x02: [],
    0x03: b"\0" * 16,
    0x04: {"rk": True, "up": True, "plat": False},
}


def make_assertion(credential_id, user_id, rp_id_hash=RP_ID_HASH, count=None):
    response = {
        0x01: {"type": "public-key", "id": credential_id},
        0x02: bytes(AuthenticatorData.create(rp_id_hash, AuthenticatorData.FLAG.UP, 1)),
        0x03: b"signature-" + credential_id,
        0x04: {"id": user_id, "name": user_id.decode()},
    }
    if count is not None:
        response[0x05] = count
    return response


class SoftDevice:
    """Software authenticator returning a scripted sequence of responses.

    Each item in `responses` is either a dict (CBOR-encoded success response)
    or an integer CTAP status code to return. The first item is returned for
    getAssertion, the rest for subsequent getNextAssertion calls.
    """

    capabilities = CAPABILITY.CBOR

    def __init__(self, responses):
        self._responses = list(responses)
        self.commands = []

    def call(self, cmd, data, event=None, on_keepalive=None):
        request = data[0]
        self.commands.append(request)
        if request == Ctap2.CMD.GET_INFO:
            return b"\x00" + cbor.encode(_INFO)
        if request in (Ctap2.CMD.GET_ASSERTION, Ctap2.CMD.GET_NEXT_ASSERTION):
            item = self._responses.pop(0)
            if isinstance(item, int):
                return bytes([item])
            return b"\x00" + cbor.encode(item)
        return bytes([CtapError.ERR.INVALID_COMMAND])

    def close(self):
        pass


def multi_user_responses(count=3):
    responses = [
        make_assertion(f"cred-{i}".encode(), f"user-{i}".encode()) for i in range(count)
    ]
    responses[0][0x05] = count
    return responses


class GetAssertionsTest(unittest.TestCase):
    def get_assertions(self, responses):
        device = SoftDevice(responses)
        ctap2 = Ctap2(device)
        return ctap2, ctap2.get_assertions(RP_ID, b"\0" * 32), device

    def test_single_assertion_when_count_not_set(self):
        ctap2, assertions, device = self.get_assertions(
            [make_assertion(b"cred-0", b"user-0")]
        )
        self.assertEqual(len(assertions), 1)
        self.assertEqual(assertions[0].credential["id"], b"cred-0")
        self.assertNotIn(Ctap2.CMD.GET_NEXT_ASSERTION, device.commands)

    def test_multiple_users(self):
        ctap2, assertions, device = self.get_assertions(multi_user_responses(3))
        self.assertEqual(len(assertions), 3)
        for i, assertion in enumerate(assertions):
            # Each candidate carries its own credential and user identity
            self.assertEqual(assertion.credential["id"], f"cred-{i}".encode())
            self.assertEqual(assertion.user["id"], f"user-{i}".encode())
            self.assertEqual(assertion.auth_data.rp_id_hash, RP_ID_HASH)
        # The declared count only applies to the first response
        self.assertEqual(assertions[0].number_of_credentials, 3)
        self.assertIsNone(assertions[1].number_of_credentials)
        self.assertIsNone(assertions[2].number_of_credentials)

    def test_duplicate_credentials(self):
        responses = [
            make_assertion(b"same-cred", b"user-0", count=2),
            make_assertion(b"same-cred", b"user-1"),
        ]
        ctap2, assertions, device = self.get_assertions(responses)
        self.assertEqual(len(assertions), 2)
        self.assertEqual(assertions[0].user["id"], b"user-0")
        self.assertEqual(assertions[1].user["id"], b"user-1")

    def test_overclaimed_count_device_error(self):
        responses = multi_user_responses(2)
        responses[0][0x05] = 5  # Declares 5, only provides 2
        responses.append(CtapError.ERR.NO_CREDENTIALS)
        device = SoftDevice(responses)
        ctap2 = Ctap2(device)
        with self.assertRaises(ValueError) as ctx:
            ctap2.get_assertions(RP_ID, b"\0" * 32)
        # The failure position is preserved
        self.assertIn("3 of 5", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, CtapError)
        self.assertEqual(ctx.exception.__cause__.code, CtapError.ERR.NO_CREDENTIALS)

    def test_excessive_count_rejected(self):
        responses = [make_assertion(b"cred-0", b"user-0", count=MAX_ASSERTIONS + 1)]
        device = SoftDevice(responses)
        ctap2 = Ctap2(device)
        with self.assertRaises(ValueError):
            ctap2.get_assertions(RP_ID, b"\0" * 32)
        # No getNextAssertion commands are issued
        self.assertNotIn(Ctap2.CMD.GET_NEXT_ASSERTION, device.commands)

    def test_zero_count_rejected(self):
        responses = [make_assertion(b"cred-0", b"user-0", count=0)]
        device = SoftDevice(responses)
        ctap2 = Ctap2(device)
        with self.assertRaises(ValueError):
            ctap2.get_assertions(RP_ID, b"\0" * 32)
        self.assertNotIn(Ctap2.CMD.GET_NEXT_ASSERTION, device.commands)

    def test_rp_id_hash_mismatch(self):
        responses = [
            make_assertion(b"cred-0", b"user-0", count=2),
            make_assertion(b"cred-1", b"user-1", rp_id_hash=OTHER_RP_ID_HASH),
        ]
        device = SoftDevice(responses)
        ctap2 = Ctap2(device)
        with self.assertRaises(ValueError) as ctx:
            ctap2.get_assertions(RP_ID, b"\0" * 32)
        self.assertIn("2 of 2", str(ctx.exception))


class GetAssertionClientTest(unittest.TestCase):
    def get_client(self, responses):
        device = SoftDevice(responses)
        client = Fido2Client(
            device,
            DefaultClientDataCollector("https://foo.example.com"),
            extensions=[],
        )
        return client

    def get_options(self):
        return PublicKeyCredentialRequestOptions(
            challenge=b"challenge",
            rp_id=RP_ID,
        )

    def test_select_assertion(self):
        client = self.get_client(multi_user_responses(3))
        selection = client.get_assertion(self.get_options())
        self.assertEqual(len(selection.get_assertions()), 3)
        for i in range(3):
            response = selection.get_response(i)
            self.assertEqual(response.raw_id, f"cred-{i}".encode())
            self.assertEqual(response.response.user_handle, f"user-{i}".encode())

    def test_select_duplicate_credentials(self):
        responses = [
            make_assertion(b"same-cred", b"user-0", count=2),
            make_assertion(b"same-cred", b"user-1"),
        ]
        client = self.get_client(responses)
        selection = client.get_assertion(self.get_options())
        self.assertEqual(selection.get_response(0).response.user_handle, b"user-0")
        self.assertEqual(selection.get_response(1).response.user_handle, b"user-1")

    def test_broken_sequence_not_returned(self):
        responses = multi_user_responses(2)
        responses[0][0x05] = 5  # Declares 5, only provides 2
        responses.append(CtapError.ERR.NO_CREDENTIALS)
        client = self.get_client(responses)
        with self.assertRaises(ValueError):
            client.get_assertion(self.get_options())

    def test_rp_id_hash_mismatch_not_returned(self):
        responses = [
            make_assertion(b"cred-0", b"user-0", count=2),
            make_assertion(b"cred-1", b"user-1", rp_id_hash=OTHER_RP_ID_HASH),
        ]
        client = self.get_client(responses)
        with self.assertRaises(ValueError):
            client.get_assertion(self.get_options())


if __name__ == "__main__":
    unittest.main()
