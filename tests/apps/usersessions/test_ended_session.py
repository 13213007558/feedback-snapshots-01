from datetime import timedelta
from http import HTTPStatus
from unittest.mock import patch

from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import Client
from django.urls import reverse
from django.utils import timezone

import pytest

from allauth.usersessions.internal import usersessionkit
from allauth.usersessions.models import UserSession


def resurrect_session(session_key, data):
    """Re-insert a session row under an existing key, mimicking a slow request
    whose session middleware writes its (already deleted) session back."""
    store = SessionStore()
    Session.objects.create(
        session_key=session_key,
        session_data=store.encode(data),
        expire_date=timezone.now() + timedelta(days=1),
    )


class ControllableClock:
    """A manually advancing clock. ``timezone.now`` is patched to return it so
    that ``last_seen_at`` updates are fully deterministic."""

    def __init__(self, start) -> None:
        self.current = start

    def now(self, tz=None):
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


@pytest.fixture
def clock():
    controllable = ControllableClock(timezone.now())
    with patch("allauth.usersessions.models.timezone") as models_timezone:
        models_timezone.now.side_effect = controllable.now
        yield controllable


@pytest.fixture
def usersessions_settings(settings):
    settings.USERSESSIONS_TRACK_ACTIVITY = True
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    settings.MIDDLEWARE = [
        *settings.MIDDLEWARE,
        "allauth.usersessions.middleware.UserSessionsMiddleware",
    ]
    return settings


def _login(client, user, user_password):
    response = client.post(
        reverse("account_login"),
        {"login": user.username, "password": user_password},
    )
    assert response.status_code == HTTPStatus.FOUND
    return client.session.session_key


def test_ended_session_is_not_resurrected_by_late_activity(
    usersessions_settings, user, user_password, clock
):
    victim = Client(HTTP_USER_AGENT="Victim Browser")
    survivor = Client(HTTP_USER_AGENT="Survivor Browser")
    victim_key = _login(victim, user, user_password)
    survivor_key = _login(survivor, user, user_password)

    assert UserSession.objects.filter(user=user).count() == 2
    survivor_session = UserSession.objects.get(session_key=survivor_key)

    # A slow request from the victim is in flight: it still holds the (about to
    # be ended) session data and key, the way a real request would until the
    # response is written.
    in_flight = SessionStore(session_key=victim_key)
    in_flight_data = dict(in_flight)

    # Step 1: the survivor ends all other sessions.
    clock.advance(timedelta(minutes=5))
    response = survivor.post(reverse("usersessions_list"))
    assert response.status_code == HTTPStatus.FOUND

    # The ended activity record is gone; only the survivor remains and a
    # tombstone keeps remembering the ended session.
    assert not UserSession.objects.filter(session_key=victim_key).exists()
    assert list(
        UserSession.objects.filter(user=user).values_list("session_key", flat=True)
    ) == [survivor_key]
    assert usersessionkit.is_session_ended(victim_key)

    # The slow request returns and the session middleware writes its session
    # back, resurrecting the Django session row under the same key.
    resurrect_session(victim_key, in_flight_data)
    assert SessionStore().exists(victim_key)

    # Step 2: a follow-up request arrives carrying the resurrected session
    # cookie. Without the precedence handling this would bring the activity
    # record back and show the victim as online again.
    late_request = Client()
    late_request.cookies["sessionid"] = victim_key
    response = late_request.get(reverse("usersessions_list"))

    # The middleware rejects the ended session: the request is anonymous and
    # redirected to the login page, and the record stays gone.
    assert response.status_code == HTTPStatus.FOUND
    assert response["location"].startswith(reverse("account_login"))
    assert not UserSession.objects.filter(session_key=victim_key).exists()
    assert usersessionkit.is_session_ended(victim_key)

    # Step 3: yet another request with the same cookie stays unauthenticated.
    response = late_request.get(reverse("usersessions_list"))
    assert response.status_code == HTTPStatus.FOUND
    assert response["location"].startswith(reverse("account_login"))
    assert not UserSession.objects.filter(session_key=victim_key).exists()

    # The survivor keeps working, and its last seen timestamp keeps advancing.
    clock.advance(timedelta(minutes=10))
    old_seen = survivor_session.last_seen_at
    response = survivor.get(reverse("usersessions_list"))
    assert response.status_code == HTTPStatus.OK
    survivor_session.refresh_from_db()
    assert survivor_session.last_seen_at > old_seen
    assert UserSession.objects.filter(user=user).count() == 1


def test_surviving_session_keeps_updating_activity(
    usersessions_settings, user, user_password, clock
):
    first = Client(HTTP_USER_AGENT="First Browser")
    second = Client(HTTP_USER_AGENT="Second Browser")
    first_key = _login(first, user, user_password)
    second_key = _login(second, user, user_password)

    clock.advance(timedelta(minutes=1))
    response = second.post(reverse("usersessions_list"))
    assert response.status_code == HTTPStatus.FOUND
    assert not UserSession.objects.filter(session_key=first_key).exists()

    seen_values = []
    for _ in range(2):
        clock.advance(timedelta(minutes=2))
        response = second.get(reverse("usersessions_list"))
        assert response.status_code == HTTPStatus.OK
        seen_values.append(UserSession.objects.get(session_key=second_key).last_seen_at)

    assert seen_values[1] > seen_values[0]
    assert not UserSession.objects.filter(session_key=first_key).exists()
    assert usersessionkit.is_session_ended(first_key)
