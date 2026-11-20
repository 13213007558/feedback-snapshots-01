from http import HTTPStatus

import pytest

from allauth.headless.constants import Client, Flow
from allauth.mfa.models import TrustedDevice


def _login_and_trust(
    client, headless_reverse, user_with_totp, user_password, totp_validation_bypass
):
    resp = client.post(
        headless_reverse("headless:account:login"),
        data={"username": user_with_totp.username, "password": user_password},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    with totp_validation_bypass():
        client.post(
            headless_reverse("headless:mfa:authenticate"),
            data={"code": "bad"},
            content_type="application/json",
        )
    resp = client.post(
        headless_reverse("headless:mfa:trust"),
        data={"trust": True},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.OK


def _logout(client, headless_reverse):
    client.delete(headless_reverse("headless:account:current_session"))
    client.session_token = None


@pytest.mark.parametrize("trust", [False, True])
def test_auth_unverified_email_and_mfa(
    client,
    user_with_totp,
    user_password,
    settings_impacting_urls,
    totp_validation_bypass,
    headless_reverse,
    headless_client,
    trust,
):
    with settings_impacting_urls(
        ACCOUNT_LOGIN_METHODS={"email"},
        ACCOUNT_EMAIL_VERIFICATION="mandatory",
        ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION=True,
        MFA_TRUST_ENABLED=True,
    ):
        # Login
        resp = client.post(
            headless_reverse("headless:account:login"),
            data={
                "email": user_with_totp.email,
                "password": user_password,
            },
            content_type="application/json",
        )

        # TOTP is the next stage
        assert resp.status_code == HTTPStatus.UNAUTHORIZED
        data = resp.json()
        assert [f for f in data["data"]["flows"] if f["id"] == Flow.MFA_AUTHENTICATE][
            0
        ]["is_pending"]
        with totp_validation_bypass():
            resp = client.post(
                headless_reverse("headless:mfa:authenticate"),
                data={"code": "bad"},
                content_type="application/json",
            )

        # Both browser and app clients get a trust stage, each with its own
        # trust scope.
        assert resp.status_code == HTTPStatus.UNAUTHORIZED
        data = resp.json()
        assert [f for f in data["data"]["flows"] if f["id"] == Flow.MFA_TRUST][0][
            "is_pending"
        ]

        # Indicate trust Y/N
        resp = client.post(
            headless_reverse("headless:mfa:trust"),
            data={"trust": trust},
            content_type="application/json",
        )

        # Logout
        assert resp.status_code == HTTPStatus.OK
        _logout(client, headless_reverse)

        expected_scope = (
            TrustedDevice.Scope.APP
            if headless_client == Client.APP
            else TrustedDevice.Scope.BROWSER
        )
        devices = TrustedDevice.objects.filter(
            user=user_with_totp, scope=expected_scope
        )
        assert devices.exists() is trust

        # Login
        resp = client.post(
            headless_reverse("headless:account:login"),
            data={
                "email": user_with_totp.email,
                "password": user_password,
            },
            content_type="application/json",
        )

        # Trust used?
        assert resp.status_code == (HTTPStatus.OK if trust else HTTPStatus.UNAUTHORIZED)


def test_app_trust_is_independent_from_browser_trust(
    client,
    user_with_totp,
    user_password,
    settings_impacting_urls,
    totp_validation_bypass,
    headless_reverse,
    headless_client,
):
    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        _login_and_trust(
            client,
            headless_reverse,
            user_with_totp,
            user_password,
            totp_validation_bypass,
        )

        expected_scope = (
            TrustedDevice.Scope.APP
            if headless_client == Client.APP
            else TrustedDevice.Scope.BROWSER
        )
        other_scope = (
            TrustedDevice.Scope.BROWSER
            if headless_client == Client.APP
            else TrustedDevice.Scope.APP
        )
        assert TrustedDevice.objects.filter(
            user=user_with_totp, scope=expected_scope
        ).exists()
        assert not TrustedDevice.objects.filter(
            user=user_with_totp, scope=other_scope
        ).exists()

        # Logout and login again: trusted scope skips MFA.
        _logout(client, headless_reverse)
        resp = client.post(
            headless_reverse("headless:account:login"),
            data={"username": user_with_totp.username, "password": user_password},
            content_type="application/json",
        )
        assert resp.status_code == HTTPStatus.OK


def test_revoked_trust_requires_reverification(
    client,
    user_with_totp,
    user_password,
    settings_impacting_urls,
    totp_validation_bypass,
    headless_reverse,
    headless_client,
):
    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        _login_and_trust(
            client,
            headless_reverse,
            user_with_totp,
            user_password,
            totp_validation_bypass,
        )

        # List and revoke trusted devices.
        resp = client.get(headless_reverse("headless:mfa:trusted_devices"))
        assert resp.status_code == HTTPStatus.OK
        devices = resp.json()["data"]
        assert len(devices) == 1
        expected_scope = (
            TrustedDevice.Scope.APP
            if headless_client == Client.APP
            else TrustedDevice.Scope.BROWSER
        )
        assert devices[0]["scope"] == expected_scope
        resp = client.delete(
            headless_reverse("headless:mfa:trusted_devices"),
            data={"devices": [devices[0]["id"]]},
            content_type="application/json",
        )
        assert resp.status_code == HTTPStatus.OK
        assert not TrustedDevice.objects.filter(user=user_with_totp).exists()

        # The current session is still authenticated.
        resp = client.get(headless_reverse("headless:account:current_session"))
        assert resp.status_code == HTTPStatus.OK

        # But the next login must verify again.
        _logout(client, headless_reverse)
        resp = client.post(
            headless_reverse("headless:account:login"),
            data={"username": user_with_totp.username, "password": user_password},
            content_type="application/json",
        )
        assert resp.status_code == HTTPStatus.UNAUTHORIZED
        data = resp.json()
        assert [f for f in data["data"]["flows"] if f["id"] == Flow.MFA_AUTHENTICATE][
            0
        ]["is_pending"]


def test_untrusted_device_must_always_verify(
    client,
    user_with_totp,
    user_password,
    settings_impacting_urls,
    headless_reverse,
):
    with settings_impacting_urls(MFA_TRUST_ENABLED=True):
        # Never indicated trust: every login is challenged.
        for _ in range(2):
            resp = client.post(
                headless_reverse("headless:account:login"),
                data={
                    "username": user_with_totp.username,
                    "password": user_password,
                },
                content_type="application/json",
            )
            assert resp.status_code == HTTPStatus.UNAUTHORIZED
            assert not TrustedDevice.objects.filter(user=user_with_totp).exists()
            client.session_token = None
