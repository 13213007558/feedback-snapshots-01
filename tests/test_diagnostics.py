import time

import pytest

import jwt
from jwt import diagnostics
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKClientConnectionError,
    PyJWKClientError,
)

SECRET = "synthetic-test-secret"
OTHER_SECRET = "a-different-synthetic-secret"
CLAIM_VALUES = {"sub": "user-12345", "aud": "billing-api"}


@pytest.fixture(autouse=True)
def reset_diagnostics_mode():
    diagnostics.set_diagnostics_enabled(False)
    yield
    diagnostics.set_diagnostics_enabled(False)


def make_token(**overrides):
    payload = {"exp": int(time.time()) + 3600, **CLAIM_VALUES, **overrides}
    return jwt.encode(payload, SECRET, algorithm="HS256")


class FakeKeyService:
    """Stand-in for the JWKS directory service."""

    def __init__(self, key=None, error=None):
        self._key = key
        self._error = error

    def get_signing_key(self, token):
        if self._error is not None:
            raise self._error
        return self._key


class TestClassification:
    def test_signature_failure_from_tampered_token(self):
        token = make_token()
        tampered = token.rsplit(".", 1)[0] + ".invalidsignature"
        with pytest.raises(InvalidSignatureError) as exc_info:
            jwt.decode(tampered, SECRET, algorithms=["HS256"])
        assert (
            diagnostics.classify_exception(exc_info.value)
            == diagnostics.CATEGORY_SIGNATURE
        )

    def test_claims_failure_from_expired_token(self):
        token = make_token(exp=int(time.time()) - 10)
        with pytest.raises(ExpiredSignatureError) as exc_info:
            jwt.decode(token, SECRET, algorithms=["HS256"])
        assert (
            diagnostics.classify_exception(exc_info.value)
            == diagnostics.CATEGORY_CLAIMS
        )

    def test_token_type_failure_from_malformed_input(self):
        with pytest.raises(DecodeError) as exc_info:
            jwt.decode("not-a-jwt", SECRET, algorithms=["HS256"])
        assert (
            diagnostics.classify_exception(exc_info.value)
            == diagnostics.CATEGORY_TOKEN_TYPE
        )

    def test_key_service_failure_from_fake_directory(self):
        token = make_token()
        service = FakeKeyService(
            error=PyJWKClientConnectionError("directory service unreachable")
        )
        with pytest.raises(PyJWKClientConnectionError) as exc_info:
            service.get_signing_key(token)
        assert (
            diagnostics.classify_exception(exc_info.value)
            == diagnostics.CATEGORY_KEY_SERVICE
        )
        # subclasses keep the key-service classification
        assert (
            diagnostics.classify_exception(PyJWKClientError("fetch failed"))
            == diagnostics.CATEGORY_KEY_SERVICE
        )

    def test_signature_failure_with_wrong_key_from_fake_service(self):
        token = make_token()
        service = FakeKeyService(key=OTHER_SECRET)
        with pytest.raises(InvalidSignatureError) as exc_info:
            jwt.decode(token, service.get_signing_key(token), algorithms=["HS256"])
        assert (
            diagnostics.classify_exception(exc_info.value)
            == diagnostics.CATEGORY_SIGNATURE
        )

    def test_unknown_failure(self):
        assert diagnostics.classify_exception(ValueError("x")) == (
            diagnostics.CATEGORY_UNKNOWN
        )


class TestDiagnosticMode:
    def test_production_default_record_has_no_category(self):
        token = make_token(exp=int(time.time()) - 10)
        with pytest.raises(ExpiredSignatureError) as exc_info:
            jwt.decode(token, SECRET, algorithms=["HS256"])
        record = diagnostics.describe_exception(exc_info.value)
        assert record == {"error_type": "ExpiredSignatureError"}
        assert "category" not in record

    def test_enabled_record_exposes_category(self):
        diagnostics.set_diagnostics_enabled(True)
        token = make_token(exp=int(time.time()) - 10)
        with pytest.raises(ExpiredSignatureError) as exc_info:
            jwt.decode(token, SECRET, algorithms=["HS256"])
        record = diagnostics.describe_exception(exc_info.value)
        assert record == {
            "error_type": "ExpiredSignatureError",
            "category": diagnostics.CATEGORY_CLAIMS,
        }

    @pytest.mark.parametrize("enabled", [False, True])
    def test_record_never_leaks_token_or_claim_values(self, enabled):
        diagnostics.set_diagnostics_enabled(enabled)
        token = make_token(exp=int(time.time()) - 10)
        with pytest.raises(ExpiredSignatureError) as exc_info:
            jwt.decode(token, SECRET, algorithms=["HS256"])
        rendered = repr(diagnostics.describe_exception(exc_info.value))
        assert token not in rendered
        for value in CLAIM_VALUES.values():
            assert value not in rendered
        assert str(exc_info.value) not in rendered


class TestExceptionCompatibility:
    def test_subclasses_still_caught_as_before(self):
        token = make_token(exp=int(time.time()) - 10)
        # specific subclass catch
        with pytest.raises(ExpiredSignatureError):
            jwt.decode(token, SECRET, algorithms=["HS256"])
        # base-class catch
        with pytest.raises(InvalidTokenError):
            jwt.decode(token, SECRET, algorithms=["HS256"])

    def test_key_service_error_caught_via_base_class(self):
        service = FakeKeyService(error=PyJWKClientConnectionError("down"))
        with pytest.raises(PyJWKClientError):
            service.get_signing_key(make_token())

    def test_enabling_diagnostics_does_not_change_raised_types(self):
        diagnostics.set_diagnostics_enabled(True)
        token = make_token()
        tampered = token.rsplit(".", 1)[0] + ".invalidsignature"
        with pytest.raises(InvalidSignatureError):
            jwt.decode(tampered, SECRET, algorithms=["HS256"])
