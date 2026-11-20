from http import HTTPStatus

from allauth.usersessions.models import UserSession


def test_sessions_api_returns_only_redacted_data(
    client, user, user_password, headless_reverse, settings
):
    settings.USERSESSIONS_CLIENT_IP_POLICY = "masked"
    settings.USERSESSIONS_USER_AGENT_POLICY = "device"
    resp = client.post(
        headless_reverse("headless:account:login"),
        data={"username": user.username, "password": user_password},
        content_type="application/json",
        HTTP_USER_AGENT="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        REMOTE_ADDR="192.0.2.123",
    )
    assert resp.status_code == HTTPStatus.OK, resp.content

    resp = client.get(headless_reverse("headless:usersessions:sessions"))
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()["data"]
    assert len(data) == 1
    entry = data[0]
    assert entry["ip"] == "192.0.2.0"
    assert entry["user_agent"] == "Mobile"
    assert "iPhone" not in str(entry)
    assert "192.0.2.123" not in str(entry)

    stored = UserSession.objects.get(pk=entry["id"])
    assert stored.ip == "192.0.2.0"
    assert stored.user_agent == "Mobile"


def test_sessions_api_strict_policy_and_targeted_delete(
    client, user, user_password, headless_reverse, settings
):
    settings.USERSESSIONS_CLIENT_IP_POLICY = "none"
    settings.USERSESSIONS_USER_AGENT_POLICY = "none"
    client.post(
        headless_reverse("headless:account:login"),
        data={"username": user.username, "password": user_password},
        content_type="application/json",
        HTTP_USER_AGENT="Mozilla/5.0 (Windows NT 10.0)",
        REMOTE_ADDR="203.0.113.9",
    )
    resp = client.get(headless_reverse("headless:usersessions:sessions"))
    entry = resp.json()["data"][0]
    assert entry["ip"] is None
    assert entry["user_agent"] == ""

    # The stable session id is independent of client data: deleting it ends
    # exactly the requested session even with all client data redacted.
    resp = client.delete(
        headless_reverse("headless:usersessions:sessions"),
        data={"sessions": [entry["id"]]},
        content_type="application/json",
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert not UserSession.objects.filter(pk=entry["id"]).exists()


def test_config_exposes_redaction_policies(auth_client, headless_reverse, settings):
    settings.USERSESSIONS_CLIENT_IP_POLICY = "masked"
    settings.USERSESSIONS_USER_AGENT_POLICY = "device"
    resp = auth_client.get(headless_reverse("headless:config"))
    assert resp.status_code == HTTPStatus.OK
    config = resp.json()["data"]["usersessions"]
    assert config["client_ip_policy"] == "masked"
    assert config["user_agent_policy"] == "device"
