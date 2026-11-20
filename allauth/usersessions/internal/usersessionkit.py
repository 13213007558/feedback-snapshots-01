from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, cast

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest

from allauth import app_settings as allauth_settings
from allauth.usersessions import app_settings


if TYPE_CHECKING:
    from django.contrib.auth.base_user import AbstractBaseUser
    from django.contrib.auth.models import AnonymousUser
    from django.contrib.sessions.backends.base import SessionBase


_ENDED_SESSIONS_CACHE_KEY = "allauth.usersessions.ended"


def _ended_sessions_cache_key(session_key: str) -> str:
    # Session keys can be long signed blobs (e.g. signed cookie sessions), so
    # hash them to keep the cache key within the limits of every backend.
    digest = hashlib.sha256(session_key.encode()).hexdigest()
    return f"{_ENDED_SESSIONS_CACHE_KEY}.{digest}"


def mark_session_ended(session_key: str) -> None:
    """Register that the session identified by ``session_key`` has been ended.

    Ending a session takes precedence over activity tracking: a slow request
    that is still in flight when its session gets ended must never be able to
    resurrect the session, nor bring back its activity record, when it returns.
    The marker is kept around for as long as the session could otherwise have
    remained valid, so that late (and even future) requests keep failing.
    """
    timeout = getattr(settings, "SESSION_COOKIE_AGE", None)
    cache.set(_ended_sessions_cache_key(session_key), True, timeout=timeout)


def is_session_ended(session_key: str | None) -> bool:
    if not session_key:
        return False
    return bool(cache.get(_ended_sessions_cache_key(session_key)))


def track_activity(
    request: HttpRequest | None,
    *,
    user: AbstractBaseUser | AnonymousUser | None,
    session: SessionBase | None,
) -> bool:
    """Track activity for the given request's session.

    Returns ``True`` if the activity was (or already was) tracked, ``False`` if
    the session should no longer be tracked -- in particular, when the session
    was ended. Ending a session always wins over activity tracking.
    """
    if (
        request is None
        or not allauth_settings.USERSESSIONS_ENABLED
        or not app_settings.TRACK_ACTIVITY
    ):
        return False
    if session is None:
        return False
    if user is None or not user.is_authenticated:
        return False
    if not session.session_key:
        return False
    if is_session_ended(session.session_key):
        return False
    tracked: set[str] = getattr(request, "_allauth_usersessions_tracked", set())
    if session.session_key in tracked:
        return True

    from allauth.usersessions.models import UserSession

    UserSession.objects.create_from_request(
        request, user=cast("AbstractBaseUser", user), session=session
    )
    tracked.add(session.session_key)
    setattr(request, "_allauth_usersessions_tracked", tracked)
    return True
