"""Public API contracts for custom (compatibility-layer) algorithms.

The compatibility layer needs to register custom signature algorithms while
each business client remains restricted to the algorithms and key types it
explicitly configured. These tests exercise the whole pipeline:

* PyJWS algorithm registration (``register_algorithm`` / ``from_algorithms``)
* PyJWK ingestion through a custom algorithm registry
* PyJWT end-to-end signing and verification

A custom registration on one client must never alter another caller's
allow-list.
"""

from __future__ import annotations

import json

import pytest

from jwt.algorithms import HMACAlgorithm, has_crypto
from jwt.api_jwk import PyJWK
from jwt.api_jws import PyJWS
from jwt.api_jwt import PyJWT
from jwt.exceptions import (
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    PyJWKError,
)
from jwt.types import JWKDict
from jwt.utils import base64url_decode, base64url_encode

from .utils import crypto_required, key_path

CUSTOM_SYMMETRIC_ALG = "CUSTOM-MAC-256"
CUSTOM_ASYMMETRIC_ALG = "CUSTOM-RSA-256"
SAME_NAME_ALG = "HS256"

# Every key accepted by the custom symmetric algorithm carries this marker,
# so the algorithm can prove it enforces its own key-type policy rather than
# silently accepting arbitrary secrets.
SECRET_MARKER = "custom-mac:"
MARKED_SECRET = (SECRET_MARKER + "0" * 22).encode()
MARKED_SECRET_JWK = {
    "kty": "custom-mac",
    "kid": "custom-mac-key",
    "alg": CUSTOM_SYMMETRIC_ALG,
    "k": base64url_encode(MARKED_SECRET).decode(),
}


class CustomMACAlgorithm(HMACAlgorithm):
    """A custom HMAC-SHA256 algorithm that only accepts marked symmetric keys."""

    def prepare_key(self, key: str | bytes) -> bytes:
        prepared = super().prepare_key(key)
        if not prepared.startswith(SECRET_MARKER.encode()):
            raise InvalidKeyError(
                f"{CUSTOM_SYMMETRIC_ALG} requires a key prefixed with "
                f"{SECRET_MARKER!r}"
            )
        return prepared

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        if isinstance(jwk, str):
            obj: JWKDict = json.loads(jwk)
        else:
            obj = jwk
        if obj.get("kty") != "custom-mac":
            raise InvalidKeyError("Not a custom-mac key")
        key = base64url_decode(obj["k"])
        if not key.startswith(SECRET_MARKER.encode()):
            raise InvalidKeyError("custom-mac JWK does not contain a marked secret")
        return key


if has_crypto:
    from jwt.algorithms import RSAAlgorithm

    class CustomRSAAlgorithm(RSAAlgorithm):
        """A custom name for RSASSA-PKCS1-v1_5 with SHA-256."""


@pytest.fixture
def custom_mac_algorithm() -> CustomMACAlgorithm:
    return CustomMACAlgorithm(HMACAlgorithm.SHA256)


@pytest.fixture
def jws_client(custom_mac_algorithm: CustomMACAlgorithm) -> PyJWS:
    return PyJWS.from_algorithms({CUSTOM_SYMMETRIC_ALG: custom_mac_algorithm})


class TestPyJWSRegistrationContract:
    def test_custom_algorithm_signs_and_verifies(self, jws_client: PyJWS) -> None:
        token = jws_client.encode(
            b"hello world", MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )
        assert jws_client.get_unverified_header(token)["alg"] == CUSTOM_SYMMETRIC_ALG
        assert (
            jws_client.decode(token, MARKED_SECRET, algorithms=[CUSTOM_SYMMETRIC_ALG])
            == b"hello world"
        )

    def test_registry_is_scoped_to_the_client(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        first = PyJWS()
        second = PyJWS()
        first.register_algorithm(CUSTOM_SYMMETRIC_ALG, custom_mac_algorithm)

        assert CUSTOM_SYMMETRIC_ALG in first.get_algorithms()
        assert CUSTOM_SYMMETRIC_ALG not in second.get_algorithms()

        # Unregistering on the first client leaves the second one untouched.
        first.unregister_algorithm(CUSTOM_SYMMETRIC_ALG)
        assert CUSTOM_SYMMETRIC_ALG not in first.get_algorithms()
        assert CUSTOM_SYMMETRIC_ALG not in second.get_algorithms()

    def test_duplicate_registration_is_rejected(self, jws_client: PyJWS) -> None:
        replacement = CustomMACAlgorithm(HMACAlgorithm.SHA256)
        with pytest.raises(ValueError, match="already has a handler"):
            jws_client.register_algorithm(CUSTOM_SYMMETRIC_ALG, replacement)

    def test_non_algorithm_object_is_rejected(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        with pytest.raises(TypeError, match="not of type"):
            PyJWS.from_algorithms({CUSTOM_SYMMETRIC_ALG: object()})  # type: ignore[dict-item]

        client = PyJWS()
        with pytest.raises(TypeError, match="not of type"):
            client.register_algorithm(CUSTOM_SYMMETRIC_ALG, object())  # type: ignore[arg-type]

    def test_from_algorithms_takes_an_independent_copy(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        source = {CUSTOM_SYMMETRIC_ALG: custom_mac_algorithm}
        client = PyJWS.from_algorithms(source)

        source["SHOULD-NOT-LEAK"] = custom_mac_algorithm
        assert "SHOULD-NOT-LEAK" not in client.get_algorithms()
        assert client.get_algorithms() == [CUSTOM_SYMMETRIC_ALG]

    def test_same_named_algorithm_is_supported_per_client(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        # The custom client may shadow a built-in name for itself only.
        shadowed = PyJWS.from_algorithms({SAME_NAME_ALG: custom_mac_algorithm})
        default = PyJWS()

        assert shadowed.get_algorithms() == [SAME_NAME_ALG]
        assert isinstance(
            shadowed.get_algorithm_by_name(SAME_NAME_ALG), CustomMACAlgorithm
        )

        # The default client keeps its original built-in implementation.
        default_hs256 = default.get_algorithm_by_name(SAME_NAME_ALG)
        assert type(default_hs256) is HMACAlgorithm
        assert SAME_NAME_ALG in default.get_algorithms()

        # Same alg id, different enforced key policy: the shadowed client
        # requires the marker while the built-in accepts a plain long secret.
        plain_secret = b"p" * 32
        with pytest.raises(InvalidKeyError):
            shadowed.encode(b"shadowed", plain_secret)
        default.encode(b"default", plain_secret)

        # Tokens minted by the scoped handler stay verifiable on that client.
        token = shadowed.encode(b"shadowed", MARKED_SECRET)
        assert shadowed.decode(token, MARKED_SECRET, algorithms=[SAME_NAME_ALG])

    def test_configured_allow_list_rejects_unlisted_algorithm(
        self, jws_client: PyJWS
    ) -> None:
        token = jws_client.encode(
            b"hello world", MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )

        with pytest.raises(InvalidAlgorithmError, match="not allowed"):
            jws_client.decode(token, MARKED_SECRET, algorithms=["HS256"])

    def test_unregistered_algorithm_is_rejected_at_verification(
        self, jws_client: PyJWS
    ) -> None:
        token = jws_client.encode(
            b"hello world", MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )
        jws_client.unregister_algorithm(CUSTOM_SYMMETRIC_ALG)

        with pytest.raises(InvalidAlgorithmError, match="not supported"):
            jws_client.decode(token, MARKED_SECRET, algorithms=[CUSTOM_SYMMETRIC_ALG])

    def test_custom_algorithm_enforces_its_key_type(self, jws_client: PyJWS) -> None:
        with pytest.raises(InvalidKeyError):
            jws_client.encode(
                b"hello world",
                b"a-raw-secret-without-marker",
                algorithm=CUSTOM_SYMMETRIC_ALG,
            )

    @crypto_required
    def test_asymmetric_custom_algorithm_rejects_wrong_key_family(
        self,
    ) -> None:
        client = PyJWS.from_algorithms(
            {CUSTOM_ASYMMETRIC_ALG: CustomRSAAlgorithm(CustomRSAAlgorithm.SHA256)}
        )
        with open(key_path("testkey_ec.pub"), "rb") as keyfile:
            ec_public_key = keyfile.read()

        with pytest.raises(InvalidKeyError):
            client.encode(
                b"hello world", ec_public_key, algorithm=CUSTOM_ASYMMETRIC_ALG
            )


class TestPyJWKRegistryContract:
    def test_pyjwk_loads_key_from_custom_registry(self) -> None:
        registry = {CUSTOM_SYMMETRIC_ALG: CustomMACAlgorithm(HMACAlgorithm.SHA256)}
        jwk = PyJWK.from_dict(MARKED_SECRET_JWK, algorithms=registry)

        assert jwk.algorithm_name == CUSTOM_SYMMETRIC_ALG
        assert isinstance(jwk.Algorithm, CustomMACAlgorithm)
        assert jwk.key == MARKED_SECRET
        assert jwk.key_type == "custom-mac"

    def test_pyjwk_without_registry_rejects_custom_algorithm(self) -> None:
        with pytest.raises(PyJWKError):
            PyJWK.from_dict(MARKED_SECRET_JWK)

    def test_pyjwk_enforces_custom_key_type(self) -> None:
        registry = {CUSTOM_SYMMETRIC_ALG: CustomMACAlgorithm(HMACAlgorithm.SHA256)}
        bad_jwk = dict(MARKED_SECRET_JWK)
        bad_jwk["k"] = base64url_encode(b"raw-secret-without-marker").decode()

        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(bad_jwk, algorithms=registry)

    @crypto_required
    def test_pyjwk_accepts_alternative_key_class_for_custom_algorithm(
        self,
    ) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            rsa_jwk = json.loads(keyfile.read())
        rsa_jwk["alg"] = CUSTOM_ASYMMETRIC_ALG

        registry = {
            CUSTOM_ASYMMETRIC_ALG: CustomRSAAlgorithm(CustomRSAAlgorithm.SHA256)
        }
        jwk = PyJWK.from_dict(rsa_jwk, algorithms=registry)

        assert jwk.algorithm_name == CUSTOM_ASYMMETRIC_ALG
        assert isinstance(jwk.Algorithm, CustomRSAAlgorithm)
        assert jwk.key_type == "RSA"


class TestPyJWTEndToEndContract:
    def test_pyjwt_client_signs_and_verifies_custom_algorithm(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        client = PyJWT()
        client.jws.register_algorithm(CUSTOM_SYMMETRIC_ALG, custom_mac_algorithm)

        token = client.encode(
            {"hello": "world"}, MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )
        assert client.jws.get_unverified_header(token)["alg"] == CUSTOM_SYMMETRIC_ALG
        assert client.decode(token, MARKED_SECRET, algorithms=[CUSTOM_SYMMETRIC_ALG])

    def test_client_registration_does_not_change_other_allow_lists(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        registering_client = PyJWT()
        other_client = PyJWT()
        registering_client.jws.register_algorithm(
            CUSTOM_SYMMETRIC_ALG, custom_mac_algorithm
        )

        assert CUSTOM_SYMMETRIC_ALG in registering_client.jws.get_algorithms()
        assert CUSTOM_SYMMETRIC_ALG not in other_client.jws.get_algorithms()

        token = registering_client.encode(
            {"hello": "world"}, MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )
        with pytest.raises(InvalidAlgorithmError):
            other_client.decode(token, MARKED_SECRET, algorithms=[CUSTOM_SYMMETRIC_ALG])

    def test_pyjwt_rejects_algorithm_outside_configured_allow_list(
        self, custom_mac_algorithm: CustomMACAlgorithm
    ) -> None:
        client = PyJWT()
        client.jws.register_algorithm(CUSTOM_SYMMETRIC_ALG, custom_mac_algorithm)
        token = client.encode(
            {"hello": "world"}, MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )

        with pytest.raises(InvalidAlgorithmError, match="not allowed"):
            client.decode(token, MARKED_SECRET, algorithms=["HS256"])

    def test_pyjwk_flows_through_pyjwt_verification(self) -> None:
        custom_alg = CustomMACAlgorithm(HMACAlgorithm.SHA256)
        jwk = PyJWK.from_dict(
            MARKED_SECRET_JWK, algorithms={CUSTOM_SYMMETRIC_ALG: custom_alg}
        )

        signing_client = PyJWS.from_algorithms({CUSTOM_SYMMETRIC_ALG: custom_alg})
        token = signing_client.encode(
            b'{"hello":"world"}', MARKED_SECRET, algorithm=CUSTOM_SYMMETRIC_ALG
        )

        verifying_client = PyJWT()
        # The PyJWK carries its own bound algorithm, so the client does not
        # need a global registration to verify with it.
        assert verifying_client.decode(token, jwk) == {"hello": "world"}

        # A tampered token must fail signature verification.
        header, payload, signature = token.split(".")
        flipped = "A" if signature[0] != "A" else "B"
        tampered = ".".join([header, payload, flipped + signature[1:]])
        with pytest.raises(InvalidSignatureError):
            verifying_client.decode(tampered, jwk)
