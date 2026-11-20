from datetime import timedelta
from http import HTTPStatus
from unittest.mock import patch

from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import Client
from django.utils import timezone

import jwt
import pytest

from allauth.headless.internal.sessionkit import session_store
from allauth.headless.tokens.strategies.jwt.internal import (
    create_access_token,
    create_refresh_token,
)
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


@pytest.fixture
def headless_client():
    return "app"


@pytest.fixture(autouse=True)
def activity_settings(settings):
    settings.USERSESSIONS_TRACK_ACTIVITY = True
    settings.HEADLESS_TOKEN_STRATEGY = (
        "allauth.headless.tokens.strategies.jwt.JWTTokenStrategy"
    )
    settings.HEADLESS_JWT_STATEFUL_VALIDATION_ENABLED = True
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }


class ControllableClock:
    def __init__(self, start) -> None:
        self.current = start

    def now(self, tz=None):
        return self.current

    def advance(self, delta):
        self.current += delta


@pytest.fixture
def clock():
    controllable = ControllableClock(timezone.now())
    with patch("allauth.usersessions.models.timezone") as models_timezone:
        models_timezone.now.side_effect = controllable.now
        yield controllable


def _login(client, user, user_password, headless_reverse):
    response = client.post(
        headless_reverse("headless:account:login"),
        data={"username": user.username, "password": user_password},
        content_type="application/json",
    )
    assert response.status_code == HTTPStatus.OK, response.content
    return response.json()["meta"]["session_token"]


def _delete_other_session(actor, target_pk, headless_reverse):
    response = actor.delete(
        headless_reverse("headless:usersessions:sessions"),
        data={"sessions": [target_pk]},
        content_type="application/json",
    )
    return response


def test_ended_session_token_is_rejected_after_late_request(
    client, app_client, user, user_password, headless_reverse, clock
):
    victim = app_client
    survivor = client
    victim_token = _login(victim, user, user_password, headless_reverse)
    survivor_token = _login(survivor, user, user_password, headless_reverse)

    assert UserSession.objects.filter(user=user).count() == 2
    victim_pk = UserSession.objects.get(session_key=victim_token).pk
    survivor_session = UserSession.objects.get(session_key=survivor_token)

    # The victim has a slow request in flight holding its session data and key,
    # resolved before the session is ended.
    in_flight_data = dict(session_store(victim_token))

    # Step 1: the survivor ends the victim's session.
    clock.advance(timedelta(minutes=5))
    response = _delete_other_session(survivor, victim_pk, headless_reverse)
    assert response.status_code == HTTPStatus.OK
    assert not UserSession.objects.filter(session_key=victim_token).exists()
    assert usersessionkit.is_session_ended(victim_token)

    # The slow request returns and re-saves the (deleted) session row, the way
    # the session middleware would when writing the response.
    resurrect_session(victim_token, in_flight_data)
    assert SessionStore().exists(victim_token)

    # Step 2: a request carrying the resurrected session token must be rejected
    # and must not bring the activity record back.
    response = victim.get(headless_reverse("headless:usersessions:sessions"))
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert not UserSession.objects.filter(session_key=victim_token).exists()
    assert usersessionkit.is_session_ended(victim_token)

    # Step 3: the survivor stays authenticated and its activity keeps advancing.
    clock.advance(timedelta(minutes=10))
    old_seen = survivor_session.last_seen_at
    response = survivor.get(headless_reverse("headless:usersessions:sessions"))
    assert response.status_code == HTTPStatus.OK
    survivor_session.refresh_from_db()
    assert survivor_session.last_seen_at > old_seen
    assert UserSession.objects.filter(user=user).count() == 1


def test_ninja_session_token_rejects_resurrected_ended_session(
    app_client, user, headless_reverse, settings
):
    settings.USERSESSIONS_TRACK_ACTIVITY = True
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    victim = app_client
    victim.force_login(user)
    token = victim.session_token
    tracked = UserSession.objects.create(
        user=user, session_key=token, ip="127.0.0.1", user_agent="agent"
    )
    in_flight_data = dict(session_store(token))

    tracked.end()
    assert usersessionkit.is_session_ended(token)

    # A slow request re-creates the Django session row under the same key.
    resurrect_session(token, in_flight_data)
    assert SessionStore().exists(token)

    # The Django Ninja integration must reject the resurrected, ended session
    # itself rather than authenticating it.
    ninja_client = Client()
    response = ninja_client.get(
        headless_reverse("headless_ninja:session_resource"),
        data={"userinfo": "1"},
        HTTP_X_SESSION_TOKEN=token,
    )
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert not UserSession.objects.filter(session_key=token).exists()


def test_drf_session_token_rejects_resurrected_ended_session(
    app_client, user, headless_reverse, settings
):
    settings.USERSESSIONS_TRACK_ACTIVITY = True
    settings.CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    }
    victim = app_client
    victim.force_login(user)
    token = victim.session_token
    tracked = UserSession.objects.create(
        user=user, session_key=token, ip="127.0.0.1", user_agent="agent"
    )
    in_flight_data = dict(session_store(token))

    tracked.end()
    assert usersessionkit.is_session_ended(token)

    # A slow request re-creates the Django session row under the same key.
    resurrect_session(token, in_flight_data)
    assert SessionStore().exists(token)

    # The Django REST framework integration must reject the resurrected, ended
    # session itself rather than authenticating it.
    drf_client = Client()
    response = drf_client.get(
        headless_reverse("headless_rest_framework_session_resource"),
        data={"userinfo": "1"},
        HTTP_X_SESSION_TOKEN=token,
    )
    assert response.status_code in (
        HTTPStatus.UNAUTHORIZED,
        HTTPStatus.FORBIDDEN,
    )
    assert not UserSession.objects.filter(session_key=token).exists()


def test_jwt_access_and_refresh_rejected_for_ended_session(
    app_client, user, headless_reverse
):
    victim = app_client
    victim.force_login(user)
    token = victim.headless_session().session_key
    tracked = UserSession.objects.create(
        user=user,
        session_key=token,
        ip="127.0.0.1",
        user_agent="agent",
        last_seen_at=timezone.now(),
    )
    session = session_store(token)
    access = create_access_token(user, session, {})
    refresh = create_refresh_token(user, session)
    session.save()

    # The token itself is structurally valid and still names this session, so
    # that any rejection below is caused by the session being ended.
    assert jwt.decode(access, options={"verify_signature": False})["sub"] == str(
        user.pk
    )

    tracked.end()
    assert usersessionkit.is_session_ended(token)

    # A slow request that resolved its session before the end now writes the
    # response, re-creating the Django session row under the same key.
    resurrect_session(token, dict(session))
    assert SessionStore().exists(token)

    # Stateful access token validation must fail: the session is ended.
    response = app_client.get(
        headless_reverse("headless_rest_framework_jwt_resource"),
        HTTP_AUTHORIZATION=f"Bearer {access}",
    )
    assert response.status_code in (
        HTTPStatus.UNAUTHORIZED,
        HTTPStatus.FORBIDDEN,
    )
    assert not UserSession.objects.filter(session_key=token).exists()

    # Refreshing using the ended session's refresh token must fail too.
    response = app_client.post(
        headless_reverse("headless:tokens:refresh"),
        data={"refresh_token": refresh},
        content_type="application/json",
    )
    assert response.status_code in (
        HTTPStatus.BAD_REQUEST,
        HTTPStatus.UNAUTHORIZED,
    )
    assert not UserSession.objects.filter(session_key=token).exists()
