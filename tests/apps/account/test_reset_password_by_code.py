from http import HTTPStatus
from unittest.mock import patch

from django.test import Client
from django.urls import reverse

import pytest

from allauth.account.models import EmailAddress


@pytest.fixture(autouse=True)
def prbc_settings(settings_impacting_urls):
    with settings_impacting_urls(ACCOUNT_PASSWORD_RESET_BY_CODE_ENABLED=True):
        yield


@pytest.mark.parametrize("login_on_password_reset", [False, True])
def test_flow(
    user,
    client,
    mailoutbox,
    get_last_password_reset_code,
    password_factory,
    login_on_password_reset,
    settings,
):
    settings.ACCOUNT_LOGIN_ON_PASSWORD_RESET = login_on_password_reset
    new_password = password_factory()
    assert not user.check_password(new_password)
    resp = client.post(reverse("account_reset_password"), {"email": user.email})
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_confirm_password_reset_code")

    # Test wrong code
    with patch(
        "allauth.account.signals.password_reset_code_rejected"
    ) as code_rejected_signal:
        resp = client.post(
            reverse("account_confirm_password_reset_code"),
            {"code": "WRONG"},
        )
        assert resp.status_code == HTTPStatus.OK
        assert code_rejected_signal.send.called
        signal_kwargs = code_rejected_signal.send.call_args[1]
        assert signal_kwargs["user"] == user
        assert signal_kwargs["last_attempt"] is False

    # Test right code
    resp = client.post(
        reverse("account_confirm_password_reset_code"),
        {"code": get_last_password_reset_code(client, mailoutbox)},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_complete_password_reset")
    resp = client.post(
        reverse("account_complete_password_reset"),
        {"password1": new_password, "password2": new_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert (
        resp["location"] == settings.LOGIN_REDIRECT_URL
        if login_on_password_reset
        else reverse("account_password_reset_completed")
    )
    user.refresh_from_db()
    assert user.check_password(new_password)


@pytest.mark.parametrize(
    "reset_at,password_reset",
    [
        (1011, True),
        (1020, False),
    ],
)
def test_timeout_restarts_after_code_confirmation(
    user,
    client,
    mailoutbox,
    get_last_password_reset_code,
    password_factory,
    settings,
    reset_at,
    password_reset,
):
    settings.ACCOUNT_PASSWORD_RESET_BY_CODE_TIMEOUT = 10
    new_password = password_factory()
    time_path = "allauth.account.internal.flows.code_verification.time.time"
    with patch(time_path) as now:
        now.return_value = 1000
        client.post(reverse("account_reset_password"), {"email": user.email})

        now.return_value = 1009
        client.post(
            reverse("account_confirm_password_reset_code"),
            {"code": get_last_password_reset_code(client, mailoutbox)},
        )

        now.return_value = reset_at
        resp = client.post(
            reverse("account_complete_password_reset"),
            {"password1": new_password, "password2": new_password},
        )

    assert resp.status_code == HTTPStatus.FOUND
    expected_url = (
        "account_password_reset_completed"
        if password_reset
        else "account_reset_password"
    )
    assert resp["location"] == reverse(expected_url)
    user.refresh_from_db()
    assert user.check_password(new_password) is password_reset


def test_prevent_enumeration(db, client, mailoutbox):
    resp = client.post(
        reverse("account_reset_password"), {"email": "unknown@account.org"}
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_confirm_password_reset_code")
    assert mailoutbox[0].subject == "[example.com] Unknown Account"
    resp = client.post(
        reverse("account_confirm_password_reset_code"),
        {"code": "none?"},
    )
    assert resp.status_code == HTTPStatus.OK


def test_indirect_email_verification(
    db, client, mailoutbox, user_factory, get_last_password_reset_code
):
    user = user_factory(email_verified=False)
    address = EmailAddress.objects.get(user=user, email=user.email, verified=False)
    resp = client.post(reverse("account_reset_password"), {"email": address.email})
    assert resp.status_code == HTTPStatus.FOUND
    resp = client.post(
        reverse("account_confirm_password_reset_code"),
        {"code": get_last_password_reset_code(client, mailoutbox)},
    )
    assert resp.status_code == HTTPStatus.FOUND
    address.refresh_from_db()
    assert address.verified


@pytest.mark.parametrize("code_confirmed_first", [False, True])
def test_password_changed_while_reset_pending(
    user,
    client,
    mailoutbox,
    user_password,
    password_factory,
    get_last_password_reset_code,
    code_confirmed_first,
):
    """A reset that is pending when the user changes the password through the
    security settings must not undo that change at the time of final
    submission. The pending process is dropped, and the client can request a
    new reset as usual.
    """
    changed_password = password_factory()
    reset_password = password_factory()

    resp = client.post(reverse("account_reset_password"), {"email": user.email})
    assert resp.status_code == HTTPStatus.FOUND
    code = get_last_password_reset_code(client, mailoutbox)
    if code_confirmed_first:
        # The user already went through the "enter your code" step.
        resp = client.post(
            reverse("account_confirm_password_reset_code"), {"code": code}
        )
        assert resp.status_code == HTTPStatus.FOUND

    # Meanwhile, the user actively changes the password in another client.
    other = Client()
    other.force_login(user)
    resp = other.post(
        reverse("account_change_password"),
        {
            "oldpassword": user_password,
            "password1": changed_password,
            "password2": changed_password,
        },
    )
    assert resp.status_code == HTTPStatus.FOUND
    user.refresh_from_db()
    assert user.check_password(changed_password)

    # The pending reset no longer overwrites the new password.
    if not code_confirmed_first:
        resp = client.post(
            reverse("account_confirm_password_reset_code"), {"code": code}
        )
        assert resp.status_code == HTTPStatus.FOUND
        assert resp["location"] == reverse("account_complete_password_reset")
    resp = client.post(
        reverse("account_complete_password_reset"),
        {"password1": reset_password, "password2": reset_password},
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.context_data["token_fail"]
    user.refresh_from_db()
    assert user.check_password(changed_password)
    assert not user.check_password(reset_password)

    # The client can request a new reset through the normal flow, and that one
    # does complete.
    resp = client.post(reverse("account_reset_password"), {"email": user.email})
    assert resp.status_code == HTTPStatus.FOUND
    resp = client.post(
        reverse("account_confirm_password_reset_code"),
        {"code": get_last_password_reset_code(client, mailoutbox)},
    )
    assert resp.status_code == HTTPStatus.FOUND
    resp = client.post(
        reverse("account_complete_password_reset"),
        {"password1": reset_password, "password2": reset_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_password_reset_completed")
    user.refresh_from_db()
    assert user.check_password(reset_password)


def test_password_reset_code_success_with_two_clients(
    user, client, mailoutbox, password_factory, get_last_password_reset_code
):
    """A reset-by-code completes normally while the user is logged in elsewhere,
    as long as the password was not changed in the meantime.
    """
    new_password = password_factory()

    resp = client.post(reverse("account_reset_password"), {"email": user.email})
    assert resp.status_code == HTTPStatus.FOUND
    code = get_last_password_reset_code(client, mailoutbox)

    other = Client()
    other.force_login(user)

    resp = client.post(reverse("account_confirm_password_reset_code"), {"code": code})
    assert resp.status_code == HTTPStatus.FOUND
    resp = client.post(
        reverse("account_complete_password_reset"),
        {"password1": new_password, "password2": new_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_password_reset_completed")
    user.refresh_from_db()
    assert user.check_password(new_password)
