from http import HTTPStatus
import importlib
from unittest.mock import Mock

from django.core.management import call_command
from django.test import Client
from django.urls import reverse

import pytest

from allauth.usersessions.adapter import get_adapter
from allauth.usersessions.internal import clientkit
from allauth.usersessions.models import UserSession


def test_mask_client_ipv4():
    assert clientkit.mask_client_ip("192.0.2.123") == "192.0.2.0"


def test_mask_client_ipv6():
    assert clientkit.mask_client_ip("2001:db8:1234:5678::1") == "2001:db8:1234::"


def test_mask_invalid_ip():
    assert clientkit.mask_client_ip("not-an-ip") is None
    assert clientkit.mask_client_ip(None) is None


@pytest.mark.parametrize(
    "user_agent,category",
    [
        ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "mobile"),
        ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit Mobile", "mobile"),
        ("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)", "tablet"),
        ("Mozilla/5.0 (Linux; Android 14; SM-X900) AppleWebKit", "tablet"),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "desktop",
        ),
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "desktop"),
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://google.com/bot.html)",
            "crawler",
        ),
        ("Some Weird Custom Agent/1.0", "unknown"),
        ("", "unknown"),
    ],
)
def test_device_category(user_agent, category):
    assert clientkit.device_category(user_agent) == category


@pytest.mark.parametrize(
    "policy,raw_ip,expected",
    [
        ("full", "192.0.2.123", "192.0.2.123"),
        ("masked", "192.0.2.123", "192.0.2.0"),
        ("none", "192.0.2.123", None),
    ],
)
def test_ip_policy(settings, policy, raw_ip, expected):
    settings.USERSESSIONS_CLIENT_IP_POLICY = policy
    assert get_adapter().redact_client_ip(raw_ip) == expected


@pytest.mark.parametrize(
    "policy,raw_ua,expected",
    [
        ("full", "Mozilla/5.0 (Windows NT 10.0)", "Mozilla/5.0 (Windows NT 10.0)"),
        ("device", "Mozilla/5.0 (Windows NT 10.0)", "Desktop"),
        ("device", "", "Unknown"),
        ("none", "Mozilla/5.0 (Windows NT 10.0)", ""),
    ],
)
def test_user_agent_policy(settings, policy, raw_ua, expected):
    settings.USERSESSIONS_USER_AGENT_POLICY = policy
    assert get_adapter().redact_user_agent(raw_ua) == expected


def test_invalid_policy_raises(settings):
    settings.USERSESSIONS_CLIENT_IP_POLICY = "bogus"
    with pytest.raises(ValueError):
        get_adapter().redact_client_ip("192.0.2.1")


@pytest.mark.parametrize(
    "ip_policy,ua_policy,expected_ip,expected_ua",
    [
        ("masked", "device", "192.0.2.0", "Desktop"),
        ("none", "none", None, ""),
        ("full", "full", "192.0.2.123", "Mozilla/5.0 (Windows NT 10.0)"),
    ],
)
def test_login_persists_only_allowed_client_data(
    settings,
    db,
    user_factory,
    user_password,
    ip_policy,
    ua_policy,
    expected_ip,
    expected_ua,
):
    settings.USERSESSIONS_CLIENT_IP_POLICY = ip_policy
    settings.USERSESSIONS_USER_AGENT_POLICY = ua_policy
    user = user_factory()
    client = Client(
        HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0)",
        REMOTE_ADDR="192.0.2.123",
    )
    resp = client.post(
        reverse("account_login"),
        {"login": user.username, "password": user_password},
    )
    assert resp.status_code == HTTPStatus.FOUND
    session = UserSession.objects.get(user=user)
    assert session.ip == expected_ip
    assert session.user_agent == expected_ua


def test_strict_policy_renders_list_and_keeps_sessions_distinguishable(
    settings, user, user_password
):
    settings.USERSESSIONS_CLIENT_IP_POLICY = "none"
    settings.USERSESSIONS_USER_AGENT_POLICY = "device"
    desktop = Client(
        HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0)", REMOTE_ADDR="192.0.2.1"
    )
    mobile = Client(
        HTTP_USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        REMOTE_ADDR="198.51.100.7",
    )
    for client in (desktop, mobile):
        resp = client.post(
            reverse("account_login"),
            {"login": user.username, "password": user_password},
        )
        assert resp.status_code == HTTPStatus.FOUND

    sessions = list(UserSession.objects.filter(user=user).order_by("pk"))
    assert {s.ip for s in sessions} == {None}
    assert {s.user_agent for s in sessions} == {"Desktop", "Mobile"}

    resp = desktop.get(reverse("usersessions_list"))
    assert resp.status_code == HTTPStatus.OK
    content = resp.content.decode()
    assert "192.0.2.1" not in content
    assert "198.51.100.7" not in content
    assert "iPhone" not in content
    assert "Desktop" in content
    assert "Mobile" in content

    # Ending "other sessions" still works without any raw client data.
    resp = desktop.post(reverse("usersessions_list"))
    assert resp.status_code == HTTPStatus.FOUND
    assert UserSession.objects.filter(user=user).count() == 1
    assert not UserSession.objects.filter(pk=sessions[1].pk).exists()


def test_redaction_command_and_migration_apply_policy_to_history(settings, user):
    settings.USERSESSIONS_CLIENT_IP_POLICY = "masked"
    settings.USERSESSIONS_USER_AGENT_POLICY = "device"
    legacy = UserSession.objects.create(
        user=user,
        session_key="legacy-session",
        ip="203.0.113.77",
        user_agent="Mozilla/5.0 (Linux; Android 14; Pixel) Mobile Safari",
    )

    call_command("usersessions_redact_clients")
    legacy.refresh_from_db()
    assert legacy.ip == "203.0.113.0"
    assert legacy.user_agent == "Mobile"

    # Re-running after tightening the policy removes everything disallowed.
    settings.USERSESSIONS_CLIENT_IP_POLICY = "none"
    settings.USERSESSIONS_USER_AGENT_POLICY = "none"
    call_command("usersessions_redact_clients")
    legacy.refresh_from_db()
    assert legacy.ip is None
    assert legacy.user_agent == ""


def test_migration_function_redacts_history(settings, user):
    from django.apps import apps

    settings.USERSESSIONS_CLIENT_IP_POLICY = "masked"
    settings.USERSESSIONS_USER_AGENT_POLICY = "device"
    UserSession.objects.create(
        user=user,
        session_key="history-session",
        ip="198.51.100.42",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    )
    historical_model = apps.get_model("usersessions", "UserSession")
    migration = importlib.import_module(
        "allauth.usersessions.migrations.0002_client_redaction"
    )

    migration.redact_existing_sessions(apps, None)
    record = historical_model.objects.get(session_key="history-session")
    assert record.ip == "198.51.100.0"
    assert record.user_agent == "Desktop"


def test_migration_function_none_policy_clears_history(settings, user):
    from django.apps import apps

    settings.USERSESSIONS_CLIENT_IP_POLICY = "none"
    settings.USERSESSIONS_USER_AGENT_POLICY = "none"
    UserSession.objects.create(
        user=user,
        session_key="strict-history-session",
        ip="198.51.100.42",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    )
    migration = importlib.import_module(
        "allauth.usersessions.migrations.0002_client_redaction"
    )

    migration.redact_existing_sessions(apps, None)
    record = UserSession.objects.get(session_key="strict-history-session")
    assert record.ip is None
    assert record.user_agent == ""


def test_masked_policy_keeps_signal_coarse_grained(rf, db, user, settings):
    from allauth.usersessions.middleware import UserSessionsMiddleware
    from allauth.usersessions.signals import session_client_changed

    settings.USERSESSIONS_TRACK_ACTIVITY = True
    settings.USERSESSIONS_CLIENT_IP_POLICY = "masked"
    mw = UserSessionsMiddleware(lambda request: None)

    request1 = rf.get("/")
    request1.user = user
    request1.session = Mock()
    request1.session.session_key = "sess-coarse"
    request1.META["HTTP_USER_AGENT"] = "Old User Agent"
    request1.META["REMOTE_ADDR"] = "192.0.2.10"
    mw(request1)

    request2 = rf.get("/")
    request2.user = user
    request2.session = Mock()
    request2.session.session_key = "sess-coarse"
    request2.META["HTTP_USER_AGENT"] = "Old User Agent"
    request2.META["REMOTE_ADDR"] = "192.0.2.99"

    signal_received = []

    def signal_handler(sender, **kwargs):
        signal_received.append(kwargs)

    session_client_changed.connect(signal_handler)
    try:
        mw(request2)
    finally:
        session_client_changed.disconnect(signal_handler)

    session = UserSession.objects.get(session_key="sess-coarse", user=user)
    assert session.ip == "192.0.2.0"
    assert signal_received == []
