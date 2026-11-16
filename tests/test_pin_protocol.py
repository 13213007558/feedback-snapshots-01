"""Protocol vector tests for CTAP2 PIN/UV protocols v1 and v2.

These tests run the full client-side PIN protocol chain against a software
authenticator (no security key required): keyAgreement response -> ECDH ->
derived keys -> encrypted PIN request -> decrypted PIN/UV token.

Expected values are fixed vectors computed with independent primitives:
pure-Python P-256 point arithmetic for ECDH, hashlib/hmac for SHA-256,
HKDF and HMAC, and raw AES-CBC for the symmetric operations. The actual
request bytes sent by the client are recorded and compared against the
precomputed vectors for both protocols.
"""

import hashlib
import hmac
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Info, PinProtocolV1, PinProtocolV2
from fido2.utils import bytes2int, int2bytes

# ---------------------------------------------------------------------------
# Independent cryptographic primitives (not shared with fido2.ctap2.pin)
# ---------------------------------------------------------------------------

# NIST P-256 (secp256r1) domain parameters.
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _ec_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _is_on_curve(x, y):
    return 0 <= x < _P and 0 <= y < _P and (y * y - x * x * x - _A * x - _B) % _P == 0


def _hkdf_sha256(ikm, info):
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def _aes_cbc(key, iv, data, decrypt=False):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


# ---------------------------------------------------------------------------
# Fixed vectors (fixed private keys, fixed IV; see module docstring)
# ---------------------------------------------------------------------------

HOST_SCALAR = 0xF75018907E6C506C29AE2E960617814022287EC97BF68D0E7871470BBCC6D27D
DEVICE_SCALAR = 0x7D2E9EBB4E975EB59610151DDB1CBB1D74654CBD4129DDFBD91BA8F226E901F0

PIN = "123456"
NEW_PIN = "987654"
FIXED_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
TOKEN_V1 = bytes.fromhex("d4e5f60718293a4b5c6d7e8f90a1b2c3")  # 16 bytes
TOKEN_V2 = bytes.fromhex("00112233445566778899aabbccddeeff") * 2  # 32 bytes
PERMISSIONS = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
RPID = "example.com"

HOST_X = bytes.fromhex("e575b84f3358923073b3f55ca9dbce960133004a81acca3c03ce1d50ef9ec42f")
HOST_Y = bytes.fromhex("985d550e71b1be3aceb037cf1e635aea45dfe238958c276dc5503219e7278733")
DEVICE_X = bytes.fromhex("2639e51c1f65fbf933f11cf129b0e1556b70cd03926749748c922182e40019c3")
DEVICE_Y = bytes.fromhex("a492b2f57994d5975e93c2b51b9819e367c4fd9de0d410761d39249087dea589")

DEVICE_COSE_KEY = {1: 2, 3: -25, -1: 1, -2: DEVICE_X, -3: DEVICE_Y}

Z = bytes.fromhex("e4ba22f0a2e0fc5294f1a188407abb6d7ca54c67516bf6240829bcc97eb0d6a6")
SHARED_V1 = bytes.fromhex("e935be4e6a35c370f80af08d266614b6900deedf184b5d9f1ba62e0862f0fe77")
SHARED_V2 = bytes.fromhex(
    "59312101fc86b2e248a3e115439ffd72e26a92163a67abf66db30cf996d8834b"
    "88d50e04673b1a5b2663e95cf6603a4084fd844f4b86d4216eafda9eaa429a3d"
)

PIN_HASH = bytes.fromhex("8d969eef6ecad3c29a3a629280e686cf")  # sha256(PIN)[:16]
PIN_HASH_ENC_V1 = bytes.fromhex("9e05d0c89f306f39732cf40a734fe451")
PIN_HASH_ENC_V2 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0ff162417aa2550e0fcb7c1b17da62ad23"
)
TOKEN_ENC_V1 = bytes.fromhex("52d3c2ad7fd2a173db44ff0e0a15f4d8")
TOKEN_ENC_V2 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0fd586990dc3a5ecb9e675965d7e6c19d659"
    "6182ed665ef89db2117cd1eea51555"
)
NEW_PIN_ENC_V1 = bytes.fromhex(
    "80c39fe859784172cceb2abffbd843fe3c6556879437e6bb1bff97d11f94af8e"
    "7676d5b0274b77fa8f5d23da2b09a8eac349733d0d0ce770ed56dd19cf0d7f55"
)
NEW_PIN_ENC_V2 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f12d8cd665f0f00155c526b556818a799b4"
    "b389ce5ca4fffd32c93306c9dcefa8979d72c607c74ad5e768bf02d99cbf51c6d4"
    "f600618facbd3cf1d6f2b33e7ded"
)
PIN_UV_PARAM_V1 = bytes.fromhex("7a8ec6ddca0399dd79b4926f9609831e")  # 16 bytes
PIN_UV_PARAM_V2 = bytes.fromhex(
    "5151a192e729191f5f8fe53c9f0c636c46c64ec24668973e8c7164e619384959"
)  # 32 bytes

# Actual request bytes recorded for both protocols.
REQ_KEY_AGREEMENT_V1 = bytes.fromhex("a201010202")
REQ_KEY_AGREEMENT_V2 = bytes.fromhex("a201020202")
REQ_GET_TOKEN_V1 = bytes.fromhex(
    "a60101020903a501020338182001215820e575b84f3358923073b3f55ca9dbce9601"
    "33004a81acca3c03ce1d50ef9ec42f225820985d550e71b1be3aceb037cf1e635aea"
    "45dfe238958c276dc5503219e727873306509e05d0c89f306f39732cf40a734fe451"
    "09030a6b6578616d706c652e636f6d"
)
REQ_GET_TOKEN_V2 = bytes.fromhex(
    "a60102020903a501020338182001215820e575b84f3358923073b3f55ca9dbce9601"
    "33004a81acca3c03ce1d50ef9ec42f225820985d550e71b1be3aceb037cf1e635aea"
    "45dfe238958c276dc5503219e7278733065820000102030405060708090a0b0c0d0e"
    "0ff162417aa2550e0fcb7c1b17da62ad2309030a6b6578616d706c652e636f6d"
)
REQ_SET_PIN_V1 = bytes.fromhex(
    "a50101020303a501020338182001215820e575b84f3358923073b3f55ca9dbce9601"
    "33004a81acca3c03ce1d50ef9ec42f225820985d550e71b1be3aceb037cf1e635aea"
    "45dfe238958c276dc5503219e727873304507a8ec6ddca0399dd79b4926f9609831e"
    "05584080c39fe859784172cceb2abffbd843fe3c6556879437e6bb1bff97d11f94af"
    "8e7676d5b0274b77fa8f5d23da2b09a8eac349733d0d0ce770ed56dd19cf0d7f55"
)
REQ_SET_PIN_V2 = bytes.fromhex(
    "a50102020303a501020338182001215820e575b84f3358923073b3f55ca9dbce9601"
    "33004a81acca3c03ce1d50ef9ec42f225820985d550e71b1be3aceb037cf1e635aea"
    "45dfe238958c276dc5503219e72787330458205151a192e729191f5f8fe53c9f0c63"
    "6c46c64ec24668973e8c7164e619384959055850000102030405060708090a0b0c0d"
    "0e0f12d8cd665f0f00155c526b556818a799b4b389ce5ca4fffd32c93306c9dcefa8"
    "979d72c607c74ad5e768bf02d99cbf51c6d4f600618facbd3cf1d6f2b33e7ded"
)


# ---------------------------------------------------------------------------
# Software authenticator
# ---------------------------------------------------------------------------


class SoftwareAuthenticator:
    """Stand-in for a Ctap2 device speaking exactly one PIN/UV protocol.

    Derives all key material independently (pure-Python ECDH, hashlib
    SHA-256/HKDF, stdlib HMAC, raw AES-CBC) and records the raw bytes of
    every request it receives.
    """

    def __init__(
        self,
        protocol_version,
        *,
        token,
        pin=PIN,
        key_agreement_response=None,
        truncate_token_to=None,
    ):
        self.protocol_version = protocol_version
        self.pin = pin
        self.token = token
        self.truncate_token_to = truncate_token_to
        self._key_agreement = key_agreement_response or DEVICE_COSE_KEY
        self.info = Info(
            versions=["U2F_V2", "FIDO_2_0"],
            options={"clientPin": True, "pinUvAuthToken": True},
            pin_uv_protocols=[protocol_version],
        )
        self.requests = []  # (pin_uv_protocol, sub_cmd, raw_request_bytes)

    def _shared_secret(self, peer_cose_key):
        x, y = bytes2int(peer_cose_key[-2]), bytes2int(peer_cose_key[-3])
        assert _is_on_curve(x, y)
        zx, _ = _ec_mul(DEVICE_SCALAR, (x, y))
        z = int2bytes(zx, 32)
        if self.protocol_version == 1:
            return hashlib.sha256(z).digest()
        return _hkdf_sha256(z, b"CTAP2 HMAC key") + _hkdf_sha256(z, b"CTAP2 AES key")

    def _crypt(self, shared, data, decrypt=False):
        if self.protocol_version == 1:
            return _aes_cbc(shared, b"\0" * 16, data, decrypt)
        if decrypt:
            return _aes_cbc(shared[32:], data[:16], data[16:], True)
        return FIXED_IV + _aes_cbc(shared[32:], FIXED_IV, data)

    def _auth_length(self):
        return 16 if self.protocol_version == 1 else 32

    def client_pin(
        self,
        pin_uv_protocol,
        sub_cmd,
        key_agreement=None,
        pin_uv_param=None,
        new_pin_enc=None,
        pin_hash_enc=None,
        permissions=None,
        permissions_rpid=None,
        **kwargs,
    ):
        # Encode exactly as Ctap2.client_pin does, and record the raw bytes.
        params = (
            pin_uv_protocol,
            sub_cmd,
            key_agreement,
            pin_uv_param,
            new_pin_enc,
            pin_hash_enc,
            None,
            None,
            permissions,
            permissions_rpid,
        )
        raw = cbor.encode({i: v for i, v in enumerate(params, 1) if v is not None})
        self.requests.append((pin_uv_protocol, sub_cmd, raw))

        if pin_uv_protocol != self.protocol_version:
            raise CtapError(CtapError.ERR.INVALID_PARAMETER)

        if sub_cmd == ClientPin.CMD.GET_KEY_AGREEMENT:
            return {ClientPin.RESULT.KEY_AGREEMENT: self._key_agreement}

        if sub_cmd in (
            ClientPin.CMD.GET_TOKEN_USING_PIN,
            ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
        ):
            shared = self._shared_secret(key_agreement)
            pin_hash = self._crypt(shared, pin_hash_enc, decrypt=True)
            if pin_hash != hashlib.sha256(self.pin.encode()).digest()[:16]:
                raise CtapError(CtapError.ERR.PIN_INVALID)
            token_enc = self._crypt(shared, self.token)
            if self.truncate_token_to is not None:
                token_enc = token_enc[: self.truncate_token_to]
            return {ClientPin.RESULT.PIN_UV_TOKEN: token_enc}

        if sub_cmd == ClientPin.CMD.SET_PIN:
            shared = self._shared_secret(key_agreement)
            hmac_key = shared if self.protocol_version == 1 else shared[:32]
            expected = hmac.new(hmac_key, new_pin_enc, hashlib.sha256).digest()
            if not hmac.compare_digest(pin_uv_param, expected[: self._auth_length()]):
                raise CtapError(CtapError.ERR.PIN_AUTH_INVALID)
            padded = self._crypt(shared, new_pin_enc, decrypt=True)
            self.pin = padded.rstrip(b"\0").decode()
            return {}

        raise CtapError(CtapError.ERR.INVALID_COMMAND)


@pytest.fixture
def fixed_host_key(monkeypatch):
    """Pin the platform key and the v2 IV to the fixed vector values."""
    host_key = ec.derive_private_key(HOST_SCALAR, ec.SECP256R1())
    monkeypatch.setattr(
        "fido2.ctap2.pin.ec.generate_private_key",
        lambda curve, backend=None: host_key,
    )
    real_urandom = os.urandom
    monkeypatch.setattr(
        "fido2.ctap2.pin.os.urandom",
        lambda n: FIXED_IV if n == 16 else real_urandom(n),
    )
    return host_key


def _decode_request(device, index):
    version, cmd, raw = device.requests[index]
    return version, cmd, cbor.decode(raw)


def _check_ecdh_params(cose_key):
    """ECDH public key parameters of a keyAgreement COSE key."""
    assert cose_key[1] == 2  # kty: EC2
    assert cose_key[3] == -25  # alg: ECDH-ES + HKDF-256
    assert cose_key[-1] == 1  # crv: P-256
    assert len(cose_key[-2]) == 32 and len(cose_key[-3]) == 32
    assert _is_on_curve(bytes2int(cose_key[-2]), bytes2int(cose_key[-3]))


def _assert_no_retry(device, version):
    """All recorded requests use one protocol version, with no repeated attempt."""
    versions = [v for v, _, _ in device.requests]
    assert versions == [version] * len(versions)
    cmds = [c for _, c, _ in device.requests]
    assert len(cmds) == len(set(cmds)), "same material retried"


# ---------------------------------------------------------------------------
# Happy-path vectors
# ---------------------------------------------------------------------------


def test_v1_get_pin_token_vector(fixed_host_key):
    device = SoftwareAuthenticator(1, token=TOKEN_V1)
    client = ClientPin(device, PinProtocolV1())

    token = client.get_pin_token(PIN, permissions=PERMISSIONS, permissions_rpid=RPID)

    # Decrypted token handed back to the caller.
    assert token == TOKEN_V1
    assert len(token) == 16  # v1 accepts 16- or 32-byte tokens

    # ECDH public key parameters, device and platform side.
    _check_ecdh_params(DEVICE_COSE_KEY)
    _, cmd, request = _decode_request(device, 1)
    assert cmd == ClientPin.CMD.GET_TOKEN_USING_PIN
    _check_ecdh_params(request[3])
    assert request[3][-2] == HOST_X and request[3][-3] == HOST_Y

    # Derived key: independent ECDH + SHA-256 matches the fixed vector.
    zx, _ = _ec_mul(HOST_SCALAR, (bytes2int(DEVICE_X), bytes2int(DEVICE_Y)))
    assert int2bytes(zx, 32) == Z
    assert hashlib.sha256(Z).digest() == SHARED_V1
    # The client derived the same key: its encrypted PIN hash matches.
    assert request[6] == PIN_HASH_ENC_V1
    assert _aes_cbc(SHARED_V1, b"\0" * 16, request[6], decrypt=True) == PIN_HASH

    # IV: v1 uses an implicit all-zero IV, ciphertext is exactly one block.
    assert len(request[6]) == 16

    # Recorded request bytes match the fixed vector.
    assert device.requests[0][2] == REQ_KEY_AGREEMENT_V1
    assert device.requests[1][2] == REQ_GET_TOKEN_V1


def test_v2_get_pin_token_vector(fixed_host_key):
    device = SoftwareAuthenticator(2, token=TOKEN_V2)
    client = ClientPin(device, PinProtocolV2())

    token = client.get_pin_token(PIN, permissions=PERMISSIONS, permissions_rpid=RPID)

    assert token == TOKEN_V2
    assert len(token) == 32  # v2 requires a 32-byte token

    _check_ecdh_params(DEVICE_COSE_KEY)
    _, cmd, request = _decode_request(device, 1)
    assert cmd == ClientPin.CMD.GET_TOKEN_USING_PIN
    _check_ecdh_params(request[3])
    assert request[3][-2] == HOST_X and request[3][-3] == HOST_Y

    # Derived key: independent ECDH + HKDF-SHA256 matches the fixed vector.
    zx, _ = _ec_mul(HOST_SCALAR, (bytes2int(DEVICE_X), bytes2int(DEVICE_Y)))
    assert int2bytes(zx, 32) == Z
    expected = _hkdf_sha256(Z, b"CTAP2 HMAC key") + _hkdf_sha256(Z, b"CTAP2 AES key")
    assert expected == SHARED_V2
    assert request[6] == PIN_HASH_ENC_V2
    assert _aes_cbc(SHARED_V2[32:], FIXED_IV, request[6][16:], decrypt=True) == PIN_HASH

    # IV: v2 prepends a random 16-byte IV to the ciphertext.
    assert request[6][:16] == FIXED_IV
    assert len(request[6]) == 16 + 16

    assert device.requests[0][2] == REQ_KEY_AGREEMENT_V2
    assert device.requests[1][2] == REQ_GET_TOKEN_V2


@pytest.mark.parametrize(
    "version,protocol,token,req_set,req_ka,new_pin_enc,pin_uv_param",
    [
        (1, PinProtocolV1, TOKEN_V1, REQ_SET_PIN_V1, REQ_KEY_AGREEMENT_V1, NEW_PIN_ENC_V1, PIN_UV_PARAM_V1),
        (2, PinProtocolV2, TOKEN_V2, REQ_SET_PIN_V2, REQ_KEY_AGREEMENT_V2, NEW_PIN_ENC_V2, PIN_UV_PARAM_V2),
    ],
)
def test_set_pin_auth_code_and_lengths(
    fixed_host_key, version, protocol, token, req_set, req_ka, new_pin_enc, pin_uv_param
):
    device = SoftwareAuthenticator(version, token=token, pin="")
    client = ClientPin(device, protocol())

    client.set_pin(NEW_PIN)

    _, cmd, request = _decode_request(device, 1)
    assert cmd == ClientPin.CMD.SET_PIN

    # Auth code (pinUvAuthParam) length: 16 bytes for v1, 32 for v2.
    assert len(request[4]) == 16 * version
    assert request[4] == pin_uv_param
    # Encrypted new PIN: 64-byte padded block, plus 16-byte IV for v2.
    assert len(request[5]) == 64 + (16 if version == 2 else 0)
    assert request[5] == new_pin_enc
    if version == 2:
        assert request[5][:16] == FIXED_IV

    assert device.requests[0][2] == req_ka
    assert device.requests[1][2] == req_set

    # The device independently verified the HMAC and stored the new PIN:
    # a token can now be obtained with it.
    assert client.get_pin_token(NEW_PIN) == token


# ---------------------------------------------------------------------------
# Failure staging: errors must stop at an identifiable stage, without
# retrying the same material under the other protocol version.
# ---------------------------------------------------------------------------


def _p384_key_agreement():
    key = ec.derive_private_key(DEVICE_SCALAR, ec.SECP384R1())
    pn = key.public_key().public_numbers()
    return {1: 2, 3: -25, -1: 2, -2: int2bytes(pn.x, 48), -3: int2bytes(pn.y, 48)}


@pytest.mark.parametrize("version,protocol", [(1, PinProtocolV1), (2, PinProtocolV2)])
def test_wrong_curve_stops_at_key_agreement(fixed_host_key, version, protocol):
    device = SoftwareAuthenticator(
        version, token=TOKEN_V1, key_agreement_response=_p384_key_agreement()
    )
    client = ClientPin(device, protocol())

    with pytest.raises(ValueError):
        client.get_pin_token(PIN)

    # Failure at the key agreement stage: no PIN request was ever sent.
    assert [c for _, c, _ in device.requests] == [ClientPin.CMD.GET_KEY_AGREEMENT]
    _assert_no_retry(device, version)


@pytest.mark.parametrize("version,protocol", [(1, PinProtocolV1), (2, PinProtocolV2)])
def test_invalid_point_stops_at_key_agreement(fixed_host_key, version, protocol):
    bad_point = {
        1: 2,
        3: -25,
        -1: 1,
        -2: DEVICE_X,
        -3: DEVICE_Y[:-1] + bytes([DEVICE_Y[-1] ^ 0x01]),
    }
    assert not _is_on_curve(bytes2int(bad_point[-2]), bytes2int(bad_point[-3]))
    device = SoftwareAuthenticator(
        version, token=TOKEN_V1, key_agreement_response=bad_point
    )
    client = ClientPin(device, protocol())

    with pytest.raises(ValueError):
        client.get_pin_token(PIN)

    assert [c for _, c, _ in device.requests] == [ClientPin.CMD.GET_KEY_AGREEMENT]
    _assert_no_retry(device, version)


@pytest.mark.parametrize(
    "version,protocol,token,truncate_to",
    [
        (1, PinProtocolV1, TOKEN_V1, 15),  # not a multiple of the AES block
        (2, PinProtocolV2, TOKEN_V2, 20),  # 16-byte IV + 4 truncated bytes
    ],
)
def test_truncated_token_stops_at_decrypt(
    fixed_host_key, version, protocol, token, truncate_to
):
    device = SoftwareAuthenticator(
        version, token=token, truncate_token_to=truncate_to
    )
    client = ClientPin(device, protocol())

    with pytest.raises(ValueError):
        client.get_pin_token(PIN)

    # Failure at the token decryption stage: key agreement and the PIN
    # request completed, but no token exists to hand to a follow-up
    # authentication operation, and nothing further was sent.
    assert [c for _, c, _ in device.requests] == [
        ClientPin.CMD.GET_KEY_AGREEMENT,
        ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
    ]
    _assert_no_retry(device, version)


@pytest.mark.parametrize("version,protocol", [(1, PinProtocolV1), (2, PinProtocolV2)])
def test_wrong_pin_is_not_retried(fixed_host_key, version, protocol):
    device = SoftwareAuthenticator(version, token=TOKEN_V1, pin="000000")
    client = ClientPin(device, protocol())

    with pytest.raises(CtapError, match="PIN_INVALID"):
        client.get_pin_token(PIN)

    # The device rejected the PIN; the client must not retry the same
    # material, under this or the other protocol version.
    assert [c for _, c, _ in device.requests] == [
        ClientPin.CMD.GET_KEY_AGREEMENT,
        ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
    ]
    _assert_no_retry(device, version)


def test_16_byte_token_valid_for_v1_invalid_for_v2(fixed_host_key):
    # Material legal only for v1: a 16-byte PIN/UV token.
    v1 = SoftwareAuthenticator(1, token=TOKEN_V1)
    assert ClientPin(v1, PinProtocolV1()).get_pin_token(PIN) == TOKEN_V1

    # The same 16-byte token issued under v2 decrypts fine but must be
    # rejected at token validation, before any further use.
    v2 = SoftwareAuthenticator(2, token=TOKEN_V1)
    with pytest.raises(ValueError, match="32 bytes"):
        ClientPin(v2, PinProtocolV2()).get_pin_token(PIN)

    assert [c for _, c, _ in v2.requests] == [
        ClientPin.CMD.GET_KEY_AGREEMENT,
        ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
    ]
    _assert_no_retry(v2, 2)
