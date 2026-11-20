"""
Runnable end-to-end demonstration of the configurable user session client
data policy.

Run with:
    python examples/usersession-redaction/demo_redaction.py

The script:
  * configures the strict, privacy preserving policies (masked IP, device
    category only),
  * logs in two different clients,
  * lists sessions through both the browser page and the headless API,
  * ends one specific session over the headless API and verifies that the
    targeted session -- and only that one -- is removed,
  * asserts that neither the database nor the API responses ever contain the
    raw IP address or the full user agent string.
"""

from __future__ import annotations

import os
import sys
import tempfile

import django


def configure() -> str:
    tmp_dir = tempfile.mkdtemp(prefix="allauth-usersession-demo-")
    db_path = os.path.join(tmp_dir, "demo.sqlite3")
    settings_module = "tests.projects.regular.settings"
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    sys.path.insert(
        0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    )
    django.setup()

    from django.conf import settings

    settings.DATABASES["default"]["NAME"] = db_path
    # Coarse geographic clue + device category only; no raw IP / full UA.
    settings.USERSESSIONS_CLIENT_IP_POLICY = "masked"
    settings.USERSESSIONS_USER_AGENT_POLICY = "device"
    settings.USERSESSIONS_TRACK_ACTIVITY = True
    return db_path


def main() -> int:
    db_path = configure()
    from django.core.management import call_command
    from django.test import Client
    from django.urls import reverse
    from django.contrib.auth import get_user_model

    from allauth.usersessions.models import UserSession

    def headless_reverse(viewname: str) -> str:
        return reverse(viewname.replace("headless:", "headless:browser:", 1))

    call_command("migrate", verbosity=0, run_syncdb=True)

    user = get_user_model().objects.create_user(
        username="alice", password="s3cret-pass", email="alice@example.com"
    )

    desktop = Client(
        HTTP_USER_AGENT=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "Chrome/120.0 Safari/537.36"
        ),
        REMOTE_ADDR="192.0.2.123",
    )
    mobile = Client(
        HTTP_USER_AGENT=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
            "Mobile/15E148 Safari/604.1"
        ),
        REMOTE_ADDR="198.51.100.42",
    )

    for client in (desktop, mobile):
        resp = client.post(
            reverse("account_login"),
            {"login": "alice", "password": "s3cret-pass"},
        )
        assert resp.status_code == 302, resp.content

    print("== Database rows ==")
    for session in UserSession.objects.filter(user=user).order_by("pk"):
        print(f"  id={session.pk} ip={session.ip!r} user_agent={session.user_agent!r}")

    raw_values = ["192.0.2.123", "198.51.100.42", "iPhone", "Windows NT", "Chrome"]
    stored_text = " ".join(
        f"{s.ip or ''} {s.user_agent}" for s in UserSession.objects.filter(user=user)
    )
    for raw in raw_values:
        assert raw not in stored_text, f"raw value leaked into DB: {raw}"

    print("\n== Browser session list page ==")
    page = desktop.get(reverse("usersessions_list"))
    assert page.status_code == 200
    body = page.content.decode()
    for raw in raw_values:
        assert raw not in body, f"raw value leaked into page: {raw}"
    print("  page contains only: 'Desktop', 'Mobile' and masked/empty location data")

    print("\n== Headless API: list sessions ==")
    api_url = headless_reverse("headless:usersessions:sessions")
    listing = desktop.get(api_url).json()["data"]
    for entry in listing:
        print(f"  {entry}")
        serialized = str(entry)
        for raw in raw_values:
            assert raw not in serialized, f"raw value leaked into API: {raw}"
    assert sorted(e["user_agent"] for e in listing) == ["Desktop", "Mobile"]
    assert sorted(e["ip"] for e in listing) == ["192.0.2.0", "198.51.100.0"]

    target = next(e for e in listing if e["user_agent"] == "Mobile")
    target_id = target["id"]
    print(f"\n== Ending the Mobile session (id={target_id}) ==")
    resp = desktop.delete(
        api_url, data={"sessions": [target_id]}, content_type="application/json"
    )
    assert resp.status_code == 200, resp.content
    assert not UserSession.objects.filter(pk=target_id).exists()
    remaining = UserSession.objects.filter(user=user)
    assert remaining.count() == 1
    assert remaining.first().user_agent == "Desktop"
    print("  mobile session deleted; desktop session still alive")

    print("\n== Browser 'Sign Out Other Sessions' still works ==")
    extra = Client(
        HTTP_USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari",
        REMOTE_ADDR="203.0.113.9",
    )
    extra.post(reverse("account_login"), {"login": "alice", "password": "s3cret-pass"})
    assert UserSession.objects.filter(user=user).count() == 2
    desktop.post(reverse("usersessions_list"))
    assert UserSession.objects.filter(user=user).count() == 1

    print(f"\nAll checks passed. SQLite database left at: {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
