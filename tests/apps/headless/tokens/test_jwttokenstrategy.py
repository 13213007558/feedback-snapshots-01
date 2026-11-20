from http import HTTPStatus
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth import HASH_SESSION_KEY
from django.test.client import Client, RequestFactory
from django.urls import reverse, reverse_lazy

import jwt
import pytest

from allauth.headless.constants import Client as HeadlessClient
from allauth.headless.internal.decorators import mark_request_as_headless
from allauth.headless.tokens.strategies.jwt import JWTTokenStrategy, internal
from allauth.headless.tokens.strategies.jwt.internal import (
    create_access_token,
    decode_token,
    get_token_session,
)


class CustomJWTTokenStrategy(JWTTokenStrategy):
    def get_claims(self, user):
        return {"email": user.email}


class RichClaimsJWTTokenStrategy(JWTTokenStrategy):
    def get_claims(self, user):
        return {
            "roles": ["staff", "editor"],
            "email": user.email,
            "phone": "+31612345678",
        }


LOCAL_SIGNING_KEY = "local-test-signing-key-0123456789abcdef"


def _decode_local(access_token):
    return jwt.decode(
        access_token,
        key=LOCAL_SIGNING_KEY,
        algorithms=["HS256"],
        options={"verify_signature": True, "verify_iss": False, "verify_aud": False},
    )


def _assert_mandatory_claims(payload, user):
    assert payload["sub"] == str(user.pk)
    assert payload["token_use"] == "access"
    for claim in ("sid", "jti", "iat", "exp"):
        assert claim in payload


def test_jwt_config_is_cached(settings):
    settings.HEADLESS_JWT_ALGORITHM = "RS256"
    settings.HEADLESS_JWT_PRIVATE_KEY = "key-1"
    signing_key = MagicMock()
    internal._get_jwt_config_cached.cache_clear()
    with patch.object(
        internal.jwkkit,
        "load_jwk_from_pem",
        return_value=({}, signing_key),
    ) as load_jwk:
        internal._get_jwt_config()
        internal._get_jwt_config()
        load_jwk.assert_called_once_with("key-1")

        settings.HEADLESS_JWT_PRIVATE_KEY = "key-2"
        internal._get_jwt_config()
        assert load_jwk.call_count == 2


@pytest.fixture
def custom_jwt_token_strategy(settings):
    settings.HEADLESS_TOKEN_STRATEGY = (
        "tests.apps.headless.tokens.test_jwttokenstrategy.CustomJWTTokenStrategy"
    )


@pytest.fixture
def obtain_tokens(user, user_password, headless_reverse):
    def f(client):
        # Let's sign in
        resp = client.post(
            headless_reverse("headless:account:login"),
            data={
                "username": user.username,
                "password": user_password,
            },
            content_type="application/json",
        )
        assert resp.status_code == HTTPStatus.OK

        # On sign in, we receive an access/refresh token pair.
        meta = resp.json()["meta"]
        assert meta["is_authenticated"]
        access_token = meta.get("access_token")
        refresh_token = meta.get("refresh_token")
        return access_token, refresh_token

    return f


@pytest.fixture
def enable_jwt(settings):
    def f(*, stateful):
        settings.HEADLESS_TOKEN_STRATEGY = (
            "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
        )
        settings.HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED = stateful

    return f


def _assert_bearer_resource(access_token, status_code):
    for url in (
        reverse("headless_rest_framework_jwt_resource"),
        reverse("headless_ninja:jwt_resource"),
    ):
        resp = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}").get(url)
        assert resp.status_code == status_code


@pytest.mark.parametrize("rotate", [False, True])
def test_rotate_refresh_token(
    headless_client,
    headless_reverse,
    client,
    user,
    rotate,
    settings,
    obtain_tokens,
    custom_jwt_token_strategy,
):
    if headless_client == "browser":
        return
    settings.HEADLESS_JWT_ROTATE_REFRESH_TOKEN = rotate

    access_token, refresh_token = obtain_tokens(client)

    # Check our custom claim
    access_token_data = jwt.decode(
        access_token, algorithms=["RS256"], options={"verify_signature": False}
    )
    assert access_token_data["email"] == user.email

    # Let's refresh
    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]

    # Check our custom claim in the new access token
    access_token = data["access_token"]
    access_token_data = jwt.decode(
        access_token, algorithms=["RS256"], options={"verify_signature": False}
    )
    assert access_token_data["email"] == user.email

    new_refresh_token = data.get("refresh_token")
    assert bool(new_refresh_token) == rotate

    # Let's refresh, again using the previous refresh token
    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == (HTTPStatus.BAD_REQUEST if rotate else HTTPStatus.OK)

    # Let's refresh, using the new refresh token
    if new_refresh_token:
        resp = Client().post(
            headless_reverse("headless:tokens:refresh"),
            data={"refresh_token": new_refresh_token},
            content_type="application/json",
        )
        assert resp.status_code == HTTPStatus.OK


@pytest.mark.parametrize("stateful_validation_enabled", [False, True])
def test_flow(
    headless_client,
    headless_reverse,
    client,
    user,
    settings,
    stateful_validation_enabled,
    obtain_tokens,
):
    settings.HEADLESS_JWT_ROTATE_REFRESH_TOKEN = False
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )
    settings.HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED = stateful_validation_enabled

    access_token, refresh_token = obtain_tokens(client)

    # On sign in, we receive an access/refresh token pair.
    if headless_client == "browser":
        assert not access_token
        assert not refresh_token
        return

    # With the access token, we can reach out to the allauth API.
    at_client = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    resp = at_client.get(headless_reverse("headless:account:current_session"))
    assert resp.status_code == HTTPStatus.OK

    # Also check validity with DRF & Ninja endpoints
    for url in [
        reverse("headless_rest_framework_jwt_resource"),
        reverse("headless_ninja:jwt_resource"),
    ]:
        resp = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}").get(
            f"{url}?userinfo"
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp.json() == {"resource": "ok", "user_email": user.email}

    # With the refresh token, we can retrieve a new access token.
    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    new_access_token = resp.json()["data"]["access_token"]
    assert new_access_token != access_token

    # And, of course, that new access token is valid.
    at_client = Client(HTTP_AUTHORIZATION=f"Bearer {new_access_token}")
    resp = at_client.get(headless_reverse("headless:account:current_session"))
    assert resp.status_code == HTTPStatus.OK

    # Also check validity with DRF & Ninja endpoints
    for url in [
        reverse("headless_rest_framework_jwt_resource"),
        reverse("headless_ninja:jwt_resource"),
    ]:
        resp = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}").get(
            f"{url}?userinfo"
        )
        assert resp.status_code == HTTPStatus.OK
        assert resp.json() == {"resource": "ok", "user_email": user.email}

    # But, when we logout...
    resp = at_client.delete(headless_reverse("headless:account:current_session"))
    assert resp.status_code == HTTPStatus.UNAUTHORIZED

    # ... the refresh token no longer works.
    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST

    # And, the access token no longer functions...
    at_client = Client(HTTP_AUTHORIZATION=f"Bearer {new_access_token}")
    resp = at_client.get(headless_reverse("headless:account:current_session"))
    assert resp.status_code == (
        HTTPStatus.UNAUTHORIZED if stateful_validation_enabled else HTTPStatus.GONE
    )

    # Also check validity with DRF & Ninja endpoints
    for url in [
        reverse("headless_rest_framework_jwt_resource"),
        reverse("headless_ninja:jwt_resource"),
    ]:
        resp = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}").get(url)
        assert resp.status_code == (
            HTTPStatus.UNAUTHORIZED if stateful_validation_enabled else HTTPStatus.OK
        )


@pytest.mark.parametrize(
    "url,stateful,query_count",
    [
        # NOTE: 1 because of permission_classes which fetches user.
        (reverse_lazy("headless_rest_framework_jwt_resource"), False, 1),
        (reverse_lazy("headless_rest_framework_jwt_resource"), True, 2),
        (reverse_lazy("headless_ninja:jwt_resource"), False, 0),
        (reverse_lazy("headless_ninja:jwt_resource"), True, 2),
    ],
)
def test_access_token_query_counts(
    headless_client,
    headless_reverse,
    client,
    settings,
    obtain_tokens,
    django_assert_num_queries,
    stateful,
    query_count,
    url,
):
    if headless_client == "browser":
        return
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )
    settings.HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED = stateful
    access_token, _ = obtain_tokens(client)
    with django_assert_num_queries(query_count):
        resp = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}").get(url)
        assert resp.status_code == (HTTPStatus.OK)


@pytest.mark.parametrize("settings_scheme", ["Bearer", "Token", "JWT"])
@pytest.mark.parametrize("request_scheme", ["Bearer", "Token", "JWT"])
def test_custom_authorization_header_scheme(
    headless_client,
    headless_reverse,
    client,
    settings,
    obtain_tokens,
    settings_scheme,
    request_scheme,
):
    """Test that JWT_AUTHORIZATION_HEADER_SCHEME setting is respected."""
    if headless_client == "browser":
        return

    # Set authorization header scheme in settings
    settings.HEADLESS_JWT_AUTHORIZATION_HEADER_SCHEME = settings_scheme
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )

    access_token, _ = obtain_tokens(client)

    # Make request with the specified scheme
    at_client = Client(HTTP_AUTHORIZATION=f"{request_scheme} {access_token}")
    resp = at_client.get(headless_reverse("headless:account:current_session"))

    # Should succeed only when request scheme matches settings scheme
    if settings_scheme == request_scheme:
        assert resp.status_code == HTTPStatus.OK
    else:
        assert resp.status_code == HTTPStatus.UNAUTHORIZED


def test_hs256_algorithm(
    headless_client,
    headless_reverse,
    client,
    settings,
    user,
    obtain_tokens,
):
    if headless_client == "browser":
        return
    settings.HEADLESS_JWT_ALGORITHM = "HS256"
    settings.HEADLESS_JWT_PRIVATE_KEY = "super-secret"
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )

    access_token, _ = obtain_tokens(client)

    header = jwt.get_unverified_header(access_token)
    assert header["alg"] == "HS256"
    assert "kid" not in header

    payload = jwt.decode(
        access_token,
        key="super-secret",
        algorithms=["HS256"],
        options={"verify_signature": True, "verify_iss": False, "verify_aud": False},
    )
    assert payload["sub"] == str(user.pk)

    at_client = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    resp = at_client.get(headless_reverse("headless:account:current_session"))
    assert resp.status_code == HTTPStatus.OK


def test_hs256_fallback_to_secret_key(
    headless_client,
    headless_reverse,
    client,
    settings,
    user,
    obtain_tokens,
):
    if headless_client == "browser":
        return
    settings.HEADLESS_JWT_ALGORITHM = "HS256"
    settings.HEADLESS_JWT_PRIVATE_KEY = ""  # Empty
    settings.SECRET_KEY = "django-secret-fallback"
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )

    access_token, _ = obtain_tokens(client)

    payload = jwt.decode(
        access_token,
        key="django-secret-fallback",
        algorithms=["HS256"],
        options={"verify_signature": True, "verify_iss": False, "verify_aud": False},
    )
    assert payload["sub"] == str(user.pk)


@pytest.mark.parametrize(
    "stateful,access_status",
    [(False, HTTPStatus.OK), (True, HTTPStatus.UNAUTHORIZED)],
)
def test_tokens_after_password_changed_outside_allauth(
    headless_client,
    headless_reverse,
    client,
    user,
    settings,
    obtain_tokens,
    enable_jwt,
    password_factory,
    stateful,
    access_status,
):
    if headless_client == "browser":
        return
    enable_jwt(stateful=stateful)
    settings.HEADLESS_JWT_ROTATE_REFRESH_TOKEN = False

    access_token, refresh_token = obtain_tokens(client)

    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK

    user.set_password(password_factory())
    user.save()

    _assert_bearer_resource(access_token, access_status)

    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_stateful_password_change_keeps_current_session(
    headless_client,
    headless_reverse,
    client,
    user_password,
    password_factory,
    settings,
    obtain_tokens,
    enable_jwt,
):
    if headless_client == "browser":
        return
    enable_jwt(stateful=True)
    settings.ACCOUNT_LOGOUT_ON_PASSWORD_CHANGE = False

    access_token, _ = obtain_tokens(client)
    resp = Client(HTTP_AUTHORIZATION=f"Bearer {access_token}").post(
        headless_reverse("headless:account:change_password"),
        data={
            "current_password": user_password,
            "new_password": password_factory(),
        },
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    meta = resp.json()["meta"]
    assert meta["is_authenticated"]
    # Django cycles the session key, so the JWT sid is stale; the new
    # session token is what keeps this device signed in.
    resp = Client(HTTP_X_SESSION_TOKEN=meta["session_token"]).get(
        headless_reverse("headless:account:current_session")
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()["meta"]["is_authenticated"]


def test_stateful_access_token_survives_session_auth_hash_update(
    headless_client,
    client,
    user,
    obtain_tokens,
    enable_jwt,
    password_factory,
):
    if headless_client == "browser":
        return
    enable_jwt(stateful=True)
    access_token, _ = obtain_tokens(client)
    payload = decode_token(access_token, "access")
    session = get_token_session(payload)
    assert payload is not None
    assert session is not None
    user.set_password(password_factory())
    user.save()
    session[HASH_SESSION_KEY] = user.get_session_auth_hash()
    session.save()
    _assert_bearer_resource(access_token, HTTPStatus.OK)


def test_stateful_access_token_with_unusable_password(
    headless_client,
    client,
    user,
    enable_jwt,
):
    if headless_client == "browser":
        return
    enable_jwt(stateful=True)
    user.set_unusable_password()
    user.save(update_fields=["password"])
    client.force_login(user)
    access_token = create_access_token(user, client.session, {})
    _assert_bearer_resource(access_token, HTTPStatus.OK)


@pytest.fixture
def rich_claims_jwt(settings):
    settings.HEADLESS_TOKEN_STRATEGY = (
        "tests.apps.headless.tokens.test_jwttokenstrategy.RichClaimsJWTTokenStrategy"
    )
    settings.HEADLESS_JWT_ALGORITHM = "HS256"
    settings.HEADLESS_JWT_PRIVATE_KEY = LOCAL_SIGNING_KEY
    settings.HEADLESS_JWT_EXTRA_CLAIMS_ALLOWED = {
        "app": ("roles", "email"),
        "browser": ("roles",),
    }


def test_extra_claims_allowed_at_issue_and_refresh(
    headless_client,
    headless_reverse,
    client,
    user,
    obtain_tokens,
    rich_claims_jwt,
):
    if headless_client == "browser":
        return
    access_token, refresh_token = obtain_tokens(client)

    # On first issuance, only the claims approved for the app client are
    # signed into the token; the mandatory claims are present as well.
    payload = _decode_local(access_token)
    _assert_mandatory_claims(payload, user)
    assert payload["roles"] == ["staff", "editor"]
    assert payload["email"] == user.email
    assert "phone" not in payload

    # On refresh, the allowlist is checked again.
    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK
    payload = _decode_local(resp.json()["data"]["access_token"])
    _assert_mandatory_claims(payload, user)
    assert payload["roles"] == ["staff", "editor"]
    assert payload["email"] == user.email
    assert "phone" not in payload


def test_extra_claims_config_update_keeps_session(
    headless_client,
    headless_reverse,
    client,
    user,
    settings,
    obtain_tokens,
    rich_claims_jwt,
):
    if headless_client == "browser":
        return
    access_token, refresh_token = obtain_tokens(client)
    assert _decode_local(access_token)["email"] == user.email

    # Tighten the disclosure configuration: email is no longer approved.
    settings.HEADLESS_JWT_EXTRA_CLAIMS_ALLOWED = {"app": ("roles",)}

    # The still-valid session/refresh token does not need to be cleared...
    resp = Client().post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh_token},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK

    # ...yet the refreshed access token reflects the updated configuration.
    payload = _decode_local(resp.json()["data"]["access_token"])
    _assert_mandatory_claims(payload, user)
    assert payload["roles"] == ["staff", "editor"]
    assert "email" not in payload
    assert "phone" not in payload


def test_extra_claims_unrestricted_by_default(
    headless_client,
    client,
    user,
    settings,
    obtain_tokens,
    rich_claims_jwt,
):
    if headless_client == "browser":
        return
    settings.HEADLESS_JWT_EXTRA_CLAIMS_ALLOWED = None
    access_token, _ = obtain_tokens(client)
    payload = _decode_local(access_token)
    _assert_mandatory_claims(payload, user)
    assert payload["roles"] == ["staff", "editor"]
    assert payload["email"] == user.email
    assert payload["phone"] == "+31612345678"


@pytest.mark.parametrize(
    "client,expected_claims",
    [
        (HeadlessClient.APP, {"roles", "email"}),
        (HeadlessClient.BROWSER, {"roles"}),
        (None, set()),
    ],
)
def test_get_allowed_claims_per_client(rich_claims_jwt, client, expected_claims):
    request = RequestFactory().get("/")
    request.allauth = SimpleNamespace()
    if client is not None:
        mark_request_as_headless(request, client)
    claims = RichClaimsJWTTokenStrategy().get_allowed_claims(
        {"roles": ["staff"], "email": "a@b.c", "phone": "+316"}, request
    )
    assert set(claims.keys()) == expected_claims
