import time
from http import HTTPStatus

from django.conf import settings
from django.urls import reverse

import pytest

from allauth.mfa import app_settings
from allauth.mfa.internal.flows import trust


def test_encode_decode(rf):
    request = rf.get("/")
    value = trust.encode_trust_cookie(
        [
            trust.IssuedTrust(fingerprint="dated", at=2024),
            trust.IssuedTrust(fingerprint="good", at=time.time()),
        ]
    )
    request.COOKIES[app_settings.TRUST_COOKIE_NAME] = value
    trusts = trust.decode_trust_cookie(request)
    assert len(trusts) == 1
    assert trusts[0].fingerprint == "good"


def test_decode_invalid_value(rf):
    request = rf.get("/")
    request.COOKIES[app_settings.TRUST_COOKIE_NAME] = "bad"
    trusts = trust.decode_trust_cookie(request)
    assert len(trusts) == 0


@pytest.mark.parametrize("action", ["", "trust"])
def test_trust_flow(
    client,
    user_with_totp,
    user_password,
    totp_validation_bypass,
    settings_impacting_urls,
    action,
):
    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        # Login
        resp = client.post(
            reverse("account_login"),
            {"login": user_with_totp.username, "password": user_password},
        )
        assert resp.status_code == HTTPStatus.FOUND

        # Complete TOTP
        assert resp["location"] == reverse("mfa_authenticate")
        with totp_validation_bypass():
            resp = client.post(
                reverse("mfa_authenticate"),
                {"code": "123"},
            )
        assert resp.status_code == HTTPStatus.FOUND

        # Indicate trust
        assert resp["location"] == reverse("mfa_trust")
        resp = client.post(
            reverse("mfa_trust"),
            {"action": action},
        )
        assert resp["location"] == settings.LOGIN_REDIRECT_URL

        # Sign out
        resp = client.post(
            reverse("account_logout"),
        )
        assert resp.status_code == HTTPStatus.FOUND

        # Sign in
        resp = client.post(
            reverse("account_login"),
            {"login": user_with_totp.username, "password": user_password},
        )
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == (
            settings.LOGIN_REDIRECT_URL
            if action == "trust"
            else reverse("mfa_authenticate")
        )


def _complete_login_with_trust(
    client, user_with_totp, user_password, totp_validation_bypass, *, trust
):
    resp = client.post(
        reverse("account_login"),
        {"login": user_with_totp.username, "password": user_password},
        HTTP_USER_AGENT="test-browser/1.0",
    )
    assert resp.status_code == HTTPStatus.FOUND
    with totp_validation_bypass():
        resp = client.post(reverse("mfa_authenticate"), {"code": "123"})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("mfa_trust")
    resp = client.post(
        reverse("mfa_trust"),
        {"action": "trust" if trust else ""},
        HTTP_USER_AGENT="test-browser/1.0",
    )
    assert resp["location"] == settings.LOGIN_REDIRECT_URL


def test_trust_creates_scoped_browser_device(
    client,
    user_with_totp,
    user_password,
    totp_validation_bypass,
    settings_impacting_urls,
):
    from allauth.mfa.models import TrustedDevice

    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        _complete_login_with_trust(
            client,
            user_with_totp,
            user_password,
            totp_validation_bypass,
            trust=True,
        )
        device = TrustedDevice.objects.get(
            user=user_with_totp, scope=TrustedDevice.Scope.BROWSER
        )
        assert not TrustedDevice.objects.filter(
            user=user_with_totp, scope=TrustedDevice.Scope.APP
        ).exists()
        assert client.cookies[app_settings.TRUST_COOKIE_NAME].value
        assert device.identifier == "test-browser/1.0"
        assert device.user_agent == "test-browser/1.0"


def test_revoked_browser_trust_requires_reverification(
    client,
    user_with_totp,
    user_password,
    totp_validation_bypass,
    settings_impacting_urls,
):
    from allauth.mfa.internal.flows import trust as trust_flow
    from allauth.mfa.models import TrustedDevice

    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        _complete_login_with_trust(
            client,
            user_with_totp,
            user_password,
            totp_validation_bypass,
            trust=True,
        )
        device = TrustedDevice.objects.get(
            user=user_with_totp, scope=TrustedDevice.Scope.BROWSER
        )

        # The session established above is still active. Revoking trust does
        # not end it.
        resp = client.post(
            reverse("mfa_index"),
            {"devices": [device.pk]},
            HTTP_USER_AGENT="test-browser/1.0",
        )
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == reverse("mfa_index")
        assert not TrustedDevice.objects.filter(pk=device.pk).exists()

        # Sign out, then sign in again: the cookie is still present, but the
        # revoked server side record forces re-verification.
        client.post(reverse("account_logout"))
        resp = client.post(
            reverse("account_login"),
            {"login": user_with_totp.username, "password": user_password},
            HTTP_USER_AGENT="test-browser/1.0",
        )
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == reverse("mfa_authenticate")
        assert not trust_flow.is_trusted_browser(resp.wsgi_request, user_with_totp)


def test_revocation_keeps_other_scoped_devices(
    client,
    user_with_totp,
    user_password,
    totp_validation_bypass,
    settings_impacting_urls,
):
    from allauth.mfa.models import TrustedDevice

    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        _complete_login_with_trust(
            client,
            user_with_totp,
            user_password,
            totp_validation_bypass,
            trust=True,
        )
        browser = TrustedDevice.objects.get(scope=TrustedDevice.Scope.BROWSER)
        app = TrustedDevice.objects.create(
            user=user_with_totp,
            scope=TrustedDevice.Scope.APP,
            fingerprint=browser.fingerprint,
            identifier="mobile-app/1.0",
        )
        client.post(
            reverse("mfa_index"),
            {"devices": [browser.pk]},
            HTTP_USER_AGENT="test-browser/1.0",
        )
        assert not TrustedDevice.objects.filter(pk=browser.pk).exists()
        assert TrustedDevice.objects.filter(pk=app.pk).exists()
