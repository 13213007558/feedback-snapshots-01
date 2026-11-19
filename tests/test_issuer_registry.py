from __future__ import annotations

import json
from typing import Any
from unittest import mock

import pytest

import jwt
from jwt import IssuerConfig, IssuerRegistry, PyJWKClient
from jwt.exceptions import (
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidSignatureError,
    IssuerConfigurationError,
    MissingRequiredClaimError,
    UnregisteredIssuerError,
)

from .utils import crypto_required, key_path, utc_timestamp

COMPANY_ISSUER = "https://idp.example.com/company"
PARTNER_ISSUER = "https://partner.example.net/oidc"

COMPANY_AUDIENCE = "https://api.example.com/company"
PARTNER_AUDIENCE = "https://api.example.com/partner"

COMPANY_ALGORITHMS = ["RS256"]
PARTNER_ALGORITHMS = ["ES256"]


def _read_key(name: str) -> bytes:
    with open(key_path(name), "rb") as key_file:
        return key_file.read()


@pytest.fixture
def company_private_key() -> bytes:
    return _read_key("testkey_rsa.priv")


@pytest.fixture
def company_public_key() -> bytes:
    return _public_from_private("testkey_rsa.priv", "RS256")


@pytest.fixture
def partner_private_key() -> bytes:
    return _read_key("testkey_ec.priv")


@pytest.fixture
def partner_public_key() -> bytes:
    return _public_from_private("testkey_ec.priv", "ES256")


def _public_from_private(name: str, algorithm: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(_read_key(name), password=None)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_jwk(name: str, algorithm: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization

    from jwt.algorithms import get_default_algorithms

    private_key = serialization.load_pem_private_key(_read_key(name), password=None)
    public_key = private_key.public_key()
    alg = get_default_algorithms()[algorithm]
    return alg.to_jwk(public_key, as_dict=True)


def _claims(issuer: str, audience: str, **extra: Any) -> dict[str, Any]:
    return {
        "iss": issuer,
        "aud": audience,
        "sub": "user-123",
        "iat": utc_timestamp() - 5,
        "exp": utc_timestamp() + 300,
        **extra,
    }


@pytest.fixture
def registry(company_public_key: bytes, partner_public_key: bytes) -> IssuerRegistry:
    registry = IssuerRegistry()
    registry.register(
        issuer=COMPANY_ISSUER,
        algorithms=COMPANY_ALGORITHMS,
        audience=COMPANY_AUDIENCE,
        key=company_public_key,
    )
    registry.register(
        issuer=PARTNER_ISSUER,
        algorithms=PARTNER_ALGORITHMS,
        audience=PARTNER_AUDIENCE,
        key=partner_public_key,
    )
    return registry


@crypto_required
class TestIssuerRegistryRouting:
    def test_routes_company_token_to_company_config(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
            headers={"kid": "company-key"},
        )

        verified = registry.decode(token)

        assert verified.issuer == COMPANY_ISSUER
        assert verified.payload["aud"] == COMPANY_AUDIENCE
        assert verified.header["kid"] == "company-key"

    def test_routes_partner_token_to_partner_config(
        self, registry: IssuerRegistry, partner_private_key: bytes
    ) -> None:
        token = jwt.encode(
            _claims(PARTNER_ISSUER, PARTNER_AUDIENCE),
            partner_private_key,
            algorithm="ES256",
        )

        verified = registry.decode(token)

        assert verified.issuer == PARTNER_ISSUER
        assert verified.payload["aud"] == PARTNER_AUDIENCE

    def test_returns_configured_issuer_not_unverified_claim(self) -> None:
        # The registry stores config under the configured key, and only
        # reports that key after validation; a claimed issuer that is not
        # registered never yields a VerifiedToken at all.
        token = jwt.encode(
            _claims("https://not-configured.example", COMPANY_AUDIENCE),
            "a" * 64,
            algorithm="HS256",
        )

        with pytest.raises(UnregisteredIssuerError):
            IssuerRegistry().decode(token)

    def test_missing_issuer_claim_is_reported(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        token = jwt.encode(
            {"aud": COMPANY_AUDIENCE, "sub": "user-123"},
            company_private_key,
            algorithm="RS256",
        )

        with pytest.raises(MissingRequiredClaimError) as exc_info:
            registry.decode(token)
        assert exc_info.value.claim == "iss"

    def test_unregistered_issuer_never_touches_key_source(
        self, company_private_key: bytes
    ) -> None:
        jwks_client = mock.Mock(spec=PyJWKClient)
        registry = IssuerRegistry()
        registry.register(
            issuer=COMPANY_ISSUER,
            algorithms=COMPANY_ALGORITHMS,
            audience=COMPANY_AUDIENCE,
            jwks_client=jwks_client,
        )

        token = jwt.encode(
            _claims("https://unknown.example", COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )

        with pytest.raises(UnregisteredIssuerError):
            registry.decode(token)

        jwks_client.get_signing_key_from_jwt.assert_not_called()
        jwks_client.get_signing_key.assert_not_called()

    def test_unregistered_issuer_does_not_fetch_jwks(self) -> None:
        with mock.patch("urllib.request.build_opener") as build_opener:
            registry = IssuerRegistry()
            registry.register(
                issuer=COMPANY_ISSUER,
                algorithms=COMPANY_ALGORITHMS,
                audience=COMPANY_AUDIENCE,
                jwks_uri="https://idp.example.com/.well-known/jwks.json",
            )

            token = jwt.encode(
                _claims("https://unknown.example", COMPANY_AUDIENCE),
                "a" * 64,
                algorithm="HS256",
            )

            with pytest.raises(UnregisteredIssuerError):
                registry.decode(token)

        build_opener.assert_not_called()

    def test_each_config_queries_only_its_own_jwks_client(self) -> None:
        company_client = mock.Mock(spec=PyJWKClient)
        partner_client = mock.Mock(spec=PyJWKClient)
        company_private_key = _read_key("testkey_rsa.priv")
        partner_private_key = _read_key("testkey_ec.priv")

        company_key = jwt.PyJWK.from_dict(
            _public_jwk("testkey_rsa.priv", "RS256"), algorithm="RS256"
        )
        partner_key = jwt.PyJWK.from_dict(
            _public_jwk("testkey_ec.priv", "ES256"), algorithm="ES256"
        )
        company_client.get_signing_key_from_jwt.return_value = company_key
        partner_client.get_signing_key_from_jwt.return_value = partner_key

        registry = IssuerRegistry()
        registry.register(
            issuer=COMPANY_ISSUER,
            algorithms=COMPANY_ALGORITHMS,
            audience=COMPANY_AUDIENCE,
            jwks_client=company_client,
        )
        registry.register(
            issuer=PARTNER_ISSUER,
            algorithms=PARTNER_ALGORITHMS,
            audience=PARTNER_AUDIENCE,
            jwks_client=partner_client,
        )

        company_token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )
        partner_token = jwt.encode(
            _claims(PARTNER_ISSUER, PARTNER_AUDIENCE),
            partner_private_key,
            algorithm="ES256",
        )

        assert registry.decode(company_token).issuer == COMPANY_ISSUER
        assert registry.decode(partner_token).issuer == PARTNER_ISSUER

        company_client.get_signing_key_from_jwt.assert_called_once_with(company_token)
        partner_client.get_signing_key_from_jwt.assert_called_once_with(partner_token)

    def test_registry_does_not_touch_key_source_before_routing(
        self, company_private_key: bytes
    ) -> None:
        jwks_client = mock.Mock(spec=PyJWKClient)
        registry = IssuerRegistry()
        registry.register(
            issuer=COMPANY_ISSUER,
            algorithms=COMPANY_ALGORITHMS,
            audience=COMPANY_AUDIENCE,
            jwks_client=jwks_client,
        )

        # Malformed input fails during routing, before any key selection.
        with pytest.raises(jwt.DecodeError):
            registry.decode(b"not-a-jwt")

        jwks_client.get_signing_key_from_jwt.assert_not_called()


@crypto_required
class TestIssuerRegistryIsolation:
    def test_company_token_fails_under_partner_audience_only(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        # The signature and issuer are valid for the company config, but the
        # token carries the partner audience.  The company config may only
        # accept the company audience and must not borrow the other's.
        token = jwt.encode(
            _claims(COMPANY_ISSUER, PARTNER_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )

        with pytest.raises(InvalidAudienceError):
            registry.decode(token)

    def test_company_audience_is_not_borrowed_by_partner(
        self, registry: IssuerRegistry, partner_private_key: bytes
    ) -> None:
        token = jwt.encode(
            _claims(PARTNER_ISSUER, COMPANY_AUDIENCE),
            partner_private_key,
            algorithm="ES256",
        )

        with pytest.raises(InvalidAudienceError):
            registry.decode(token)

    def test_company_token_cannot_claim_partner_issuer_and_signature(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        # Correct issuer for the partner, signed with the company's key
        # using the company's algorithm.  The partner configuration may only
        # use ES256 with the partner key, so this must not verify.
        token = jwt.encode(
            _claims(PARTNER_ISSUER, PARTNER_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )

        with pytest.raises(InvalidAlgorithmError):
            registry.decode(token)

    def test_same_algorithm_same_audience_configs_still_keep_keys_separate(
        self,
    ) -> None:
        # Both issuers share RS256 and an audience, so only the key source
        # can distinguish them.  The other issuer's key must never be tried.
        with open(key_path("jwk_rsa_key.json")) as key_file:
            partner_jwk = json.load(key_file)
        partner_private_key = jwt.PyJWK.from_dict(partner_jwk)
        registry = IssuerRegistry()
        registry.register(
            issuer=COMPANY_ISSUER,
            algorithms=["RS256"],
            audience=COMPANY_AUDIENCE,
            key=_public_from_private("testkey_rsa.priv", "RS256"),
        )
        registry.register(
            issuer=PARTNER_ISSUER,
            algorithms=["RS256"],
            audience=COMPANY_AUDIENCE,
            key=jwt.PyJWK.from_dict(
                {
                    "kty": partner_jwk["kty"],
                    "n": partner_jwk["n"],
                    "e": partner_jwk["e"],
                }
            ),
        )

        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            partner_private_key.Algorithm.prepare_key(partner_private_key.key),
            algorithm="RS256",
        )
        # Signed with the partner's key material but claiming the company
        # issuer; only the company's key may be used, so this fails.
        with pytest.raises(InvalidSignatureError):
            registry.decode(token)

    def test_partner_key_cannot_verify_company_token(
        self, registry: IssuerRegistry, partner_private_key: bytes
    ) -> None:
        # Signed by partner's EC key but claiming the company issuer and
        # using RS256 in the header.  The company config must not use the
        # partner key, and RS256 over an EC key is rejected.
        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            partner_private_key,
            algorithm="ES256",
        )

        with pytest.raises(InvalidAlgorithmError):
            registry.decode(token)

    def test_same_algorithm_configs_still_keep_keys_separate(self) -> None:
        # Both issuers use RS256, so the algorithm allowlist cannot
        # distinguish them.  Only the per-issuer key may verify the token.
        company_private_key = _read_key("testkey_rsa.priv")
        with open(key_path("jwk_rsa_key.json")) as key_file:
            partner_jwk = json.load(key_file)
        partner_private_key = jwt.PyJWK.from_dict(partner_jwk)
        registry = IssuerRegistry()
        registry.register(
            issuer=COMPANY_ISSUER,
            algorithms=["RS256"],
            audience=COMPANY_AUDIENCE,
            key=_public_from_private("testkey_rsa.priv", "RS256"),
        )
        registry.register(
            issuer=PARTNER_ISSUER,
            algorithms=["RS256"],
            audience=PARTNER_AUDIENCE,
            key=jwt.PyJWK.from_dict(
                {
                    "kty": partner_jwk["kty"],
                    "n": partner_jwk["n"],
                    "e": partner_jwk["e"],
                }
            ),
        )

        company_token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )
        assert registry.decode(company_token).issuer == COMPANY_ISSUER

        partner_token = jwt.encode(
            _claims(PARTNER_ISSUER, PARTNER_AUDIENCE),
            partner_private_key,
            algorithm="RS256",
        )
        assert registry.decode(partner_token).issuer == PARTNER_ISSUER

        # Company key material signed under the partner issuer must not
        # verify with the partner's key.
        cross_signed = jwt.encode(
            _claims(PARTNER_ISSUER, PARTNER_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )
        with pytest.raises(InvalidSignatureError):
            registry.decode(cross_signed)

    def test_algorithm_header_cannot_select_other_configs_algorithm(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        # ES256 is allowed for the partner config only.  A company-issued
        # token cannot switch to it.
        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )
        header_segment, payload_segment, signature_segment = token.split(".")
        tampered_header = jwt.utils.base64url_encode(
            json.dumps({"alg": "ES256", "typ": "JWT"}).encode()
        ).decode()

        with pytest.raises(InvalidAlgorithmError):
            registry.decode(
                ".".join([tampered_header, payload_segment, signature_segment])
            )

    def test_signed_token_cannot_be_replayed_against_other_issuer(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        # Rewriting the iss claim to the partner issuer invalidates the
        # signature; routing must not let the partner config accept it.
        company_token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )
        header_segment, _, signature_segment = company_token.split(".")
        forged_payload = jwt.utils.base64url_encode(
            json.dumps(_claims(PARTNER_ISSUER, PARTNER_AUDIENCE)).encode()
        ).decode()

        with pytest.raises(
            (InvalidAlgorithmError, InvalidSignatureError, jwt.DecodeError)
        ):
            registry.decode(
                ".".join([header_segment, forged_payload, signature_segment])
            )


@crypto_required
class TestIssuerRegistryConfiguration:
    def test_duplicate_registration_rejected(self, company_public_key: bytes) -> None:
        registry = IssuerRegistry()
        registry.register(
            issuer=COMPANY_ISSUER,
            algorithms=COMPANY_ALGORITHMS,
            audience=COMPANY_AUDIENCE,
            key=company_public_key,
        )

        with pytest.raises(IssuerConfigurationError):
            registry.register(
                issuer=COMPANY_ISSUER,
                algorithms=["RS512"],
                audience="other",
                key=company_public_key,
            )

    def test_registration_requires_exactly_one_key_source(
        self, company_public_key: bytes
    ) -> None:
        with pytest.raises(IssuerConfigurationError):
            IssuerConfig(
                issuer=COMPANY_ISSUER,
                algorithms=COMPANY_ALGORITHMS,
                audience=COMPANY_AUDIENCE,
            )

        with pytest.raises(IssuerConfigurationError):
            IssuerConfig(
                issuer=COMPANY_ISSUER,
                algorithms=COMPANY_ALGORITHMS,
                audience=COMPANY_AUDIENCE,
                key=company_public_key,
                jwks_uri="https://idp.example.com/.well-known/jwks.json",
            )

    def test_none_algorithm_cannot_be_registered(
        self, company_public_key: bytes
    ) -> None:
        with pytest.raises(IssuerConfigurationError):
            IssuerConfig(
                issuer=COMPANY_ISSUER,
                algorithms=["none"],
                audience=COMPANY_AUDIENCE,
                key=company_public_key,
            )

    def test_cannot_disable_signature_verification(
        self, company_public_key: bytes
    ) -> None:
        with pytest.raises(IssuerConfigurationError):
            IssuerConfig(
                issuer=COMPANY_ISSUER,
                algorithms=COMPANY_ALGORITHMS,
                audience=COMPANY_AUDIENCE,
                key=company_public_key,
                options={"verify_signature": False},
            )

    def test_cannot_disable_audience_check_with_audience(
        self, company_public_key: bytes
    ) -> None:
        with pytest.raises(IssuerConfigurationError):
            IssuerConfig(
                issuer=COMPANY_ISSUER,
                algorithms=COMPANY_ALGORITHMS,
                audience=COMPANY_AUDIENCE,
                key=company_public_key,
                options={"verify_aud": False},
            )

    def test_registry_requires_iss_claim(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        token = jwt.encode(
            {"aud": COMPANY_AUDIENCE},
            company_private_key,
            algorithm="RS256",
        )
        with pytest.raises(MissingRequiredClaimError):
            registry.decode(token)

    def test_unregister_removes_issuer(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )

        assert registry.unregister(COMPANY_ISSUER) is True
        with pytest.raises(UnregisteredIssuerError):
            registry.decode(token)
        assert registry.unregister(COMPANY_ISSUER) is False

    def test_issuer_listing(self, registry: IssuerRegistry) -> None:
        assert registry.issuers == (COMPANY_ISSUER, PARTNER_ISSUER)
        assert COMPANY_ISSUER in registry
        assert len(registry) == 2

    def test_constructor_accepts_prepared_configs(
        self, company_private_key: bytes
    ) -> None:
        company_public_key = _public_from_private("testkey_rsa.priv", "RS256")
        config = IssuerConfig(
            issuer=COMPANY_ISSUER,
            algorithms=COMPANY_ALGORITHMS,
            audience=COMPANY_AUDIENCE,
            key=company_public_key,
        )
        registry = IssuerRegistry([config])

        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )

        assert registry.decode(token).issuer == COMPANY_ISSUER

    def test_optional_claims_are_verified_per_issuer(
        self, registry: IssuerRegistry, company_private_key: bytes
    ) -> None:
        token = jwt.encode(
            _claims(COMPANY_ISSUER, COMPANY_AUDIENCE),
            company_private_key,
            algorithm="RS256",
        )
        header_segment, payload_segment, signature_segment = token.split(".")
        claims = _claims(COMPANY_ISSUER, COMPANY_AUDIENCE)
        claims["exp"] = utc_timestamp() - 1
        expired_payload = jwt.utils.base64url_encode(
            json.dumps(claims).encode()
        ).decode()

        with pytest.raises(InvalidSignatureError):
            # Tampering invalidates the signature, so expiry alone is never
            # enough to change the result.
            registry.decode(
                ".".join([header_segment, expired_payload, signature_segment])
            )

        expired_token = jwt.encode(claims, company_private_key, algorithm="RS256")
        with pytest.raises(jwt.ExpiredSignatureError):
            registry.decode(expired_token)
