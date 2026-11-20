from http import HTTPStatus
from unittest.mock import patch

from django.urls import reverse

import pytest

from allauth.account import app_settings
from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.delivery import EmailVerificationDeliveryEvent
from allauth.core import context


class OrganizationAccountAdapter(DefaultAccountAdapter):
    def get_email_verification_delivery_organization(self, request, email):
        return request.headers.get("X-Organization")


class ShouldNotSendAccountAdapter(DefaultAccountAdapter):
    def should_send_confirmation_mail(self, request, email_address, signup):
        return False


@pytest.fixture
def delivery_records():
    records = []

    def receiver(sender, **kwargs):
        assert set(kwargs) == {
            "signal",
            "delivery",
            "event",
            "organization",
            "reference",
        }
        assert "request" not in kwargs
        records.append(kwargs["delivery"])

    from allauth.account import signals

    signals.email_verification_delivery.connect(receiver, weak=False)
    yield records
    signals.email_verification_delivery.disconnect(receiver)


def _signup(client, email, username="johndoe"):
    return client.post(
        reverse("account_signup"),
        {
            "username": username,
            "email": email,
            "password1": "johndoe",
            "password2": "johndoe",
        },
    )


def test_delivery_statistics_do_not_leak_email_or_confirmation(
    db, client, settings, enable_cache, mailoutbox, delivery_records
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    settings.ACCOUNT_ADAPTER = (
        "tests.apps.account.test_email_verification_delivery"
        ".OrganizationAccountAdapter"
    )
    resp = client.post(
        reverse("account_signup"),
        {
            "username": "johndoe",
            "email": "john@example.org",
            "password1": "johndoe",
            "password2": "johndoe",
        },
        headers={"X-Organization": "acme"},
    )
    assert resp.status_code == HTTPStatus.FOUND
    # The regular delivery still contains the address and confirmation link.
    assert len(mailoutbox) == 1
    message = mailoutbox[0]
    assert message.to == ["john@example.org"]
    assert "http://testserver/accounts/confirm-email/" in message.body

    assert len(delivery_records) == 1
    record = delivery_records[0]
    assert record.event == EmailVerificationDeliveryEvent.VERIFICATION_SENT
    assert record.organization == "acme"
    assert record.reference
    serialized = str(record.as_dict())
    assert "john@example.org" not in serialized
    assert "acme" in serialized
    assert "confirm-email" not in serialized
    assert "key" not in record.as_dict()


def test_delivery_statistics_are_per_address(
    db, client, settings, enable_cache, mailoutbox, delivery_records
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    _signup(client, "john@example.org", username="john")
    client.logout()
    _signup(client, "other@example.org", username="other")
    assert len(delivery_records) == 2
    assert len(mailoutbox) == 2
    references = [record.reference for record in delivery_records]
    # Different addresses are counted separately.
    assert references[0] != references[1]


def test_rate_limited_verification_is_not_delivered(
    db, client, settings, enable_cache, mailoutbox, delivery_records
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    resp = _signup(client, "john@example.org")
    assert resp.status_code == HTTPStatus.FOUND
    assert len(mailoutbox) == 1
    # Requesting another verification mail within the cool-down window is
    # silently skipped...
    from allauth.account.internal.flows.email_verification import (
        send_verification_email_for_user,
    )
    from allauth.account.models import EmailAddress

    user = EmailAddress.objects.get(email="john@example.org").user
    client.logout()
    sent = send_verification_email_for_user(resp.wsgi_request, user)
    assert sent is False
    # ...but the statistics clearly show it was rate limited, not delivered.
    assert len(mailoutbox) == 1
    assert [record.event for record in delivery_records] == [
        EmailVerificationDeliveryEvent.VERIFICATION_SENT,
        EmailVerificationDeliveryEvent.VERIFICATION_RATE_LIMITED,
    ]


def test_fake_login_reports_account_already_exists(
    db, client, settings, enable_cache, mailoutbox, delivery_records, user
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    settings.ACCOUNT_PREVENT_ENUMERATION = True
    resp = _signup(client, user.email)
    # The outside response is identical to a regular signup...
    assert resp.status_code == HTTPStatus.FOUND
    assert resp["location"] == reverse("account_email_verification_sent")
    # ...and the regular alternate mail was delivered to the address.
    assert len(mailoutbox) == 1
    assert mailoutbox[0].to == [user.email]
    # The statistics classify it as an account-already-exists event, without
    # exposing the address.
    assert [record.event for record in delivery_records] == [
        EmailVerificationDeliveryEvent.ACCOUNT_ALREADY_EXISTS_SENT
    ]
    assert user.email not in str(delivery_records[0].as_dict())


def test_fake_login_rate_limited(
    db, client, settings, enable_cache, mailoutbox, delivery_records, user
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    settings.ACCOUNT_PREVENT_ENUMERATION = True
    _signup(client, user.email)
    assert len(mailoutbox) == 1
    resp = _signup(client, user.email)
    assert resp.status_code == HTTPStatus.FOUND
    assert len(mailoutbox) == 1
    assert [record.event for record in delivery_records] == [
        EmailVerificationDeliveryEvent.ACCOUNT_ALREADY_EXISTS_SENT,
        EmailVerificationDeliveryEvent.ACCOUNT_ALREADY_EXISTS_RATE_LIMITED,
    ]


def test_unknown_account_mail_is_reported(
    db, client, settings, enable_cache, mailoutbox, delivery_records
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    from allauth.account.internal.flows.email_verification import (
        send_verification_email_to_address,
    )
    from allauth.account.models import EmailAddress

    request = client.get(reverse("account_login")).wsgi_request
    with context.request_context(request):
        sent = send_verification_email_to_address(
            request, EmailAddress(email="nobody@example.org")
        )
    assert sent
    assert [record.event for record in delivery_records] == [
        EmailVerificationDeliveryEvent.UNKNOWN_ACCOUNT_SENT
    ]
    assert len(mailoutbox) == 1


def test_should_send_confirmation_mail_suppression_is_reported(
    db, client, settings, enable_cache, mailoutbox, delivery_records
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    settings.ACCOUNT_ADAPTER = (
        "tests.apps.account.test_email_verification_delivery"
        ".ShouldNotSendAccountAdapter"
    )
    _signup(client, "john@example.org")
    assert not mailoutbox
    assert [record.event for record in delivery_records] == [
        EmailVerificationDeliveryEvent.VERIFICATION_SUPPRESSED
    ]


def test_code_based_verification_is_reported(
    db, client, settings, enable_cache, mailoutbox, delivery_records
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = True
    resp = _signup(client, "john@example.org")
    assert resp.status_code == HTTPStatus.FOUND
    assert len(mailoutbox) == 1
    assert [record.event for record in delivery_records] == [
        EmailVerificationDeliveryEvent.VERIFICATION_SENT
    ]
    assert "john@example.org" not in str(delivery_records[0].as_dict())


def test_email_confirmation_sent_still_carries_confirmation(
    db, client, settings, enable_cache, mailoutbox
):
    settings.ACCOUNT_EMAIL_VERIFICATION = app_settings.EmailVerificationMethod.MANDATORY
    settings.ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = False
    with patch("allauth.account.signals.email_confirmation_sent") as sent_signal:
        _signup(client, "john@example.org")
    assert sent_signal.send.called
    confirmation = sent_signal.send.call_args[1]["confirmation"]
    assert confirmation.email_address.email == "john@example.org"
    assert confirmation.key
