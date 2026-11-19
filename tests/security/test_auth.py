from importlib import import_module
from unittest import mock

import pytest
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    get_user_model,
    user_logged_in,
    user_logged_out,
)
from django.contrib.auth.models import AnonymousUser
from django.test import override_settings

from channels.auth import AuthFailureReason, AuthMiddleware, get_user, login, logout
from channels.db import database_sync_to_async

MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"
OTHER_BACKEND = "django.contrib.auth.backends.AllowAllUsersModelBackend"


class CatchSignal:
    """
    Capture (and detect) a django signal event.
    This should be used as a Contextmanager.

    :Example:

    with CatchSignal(user_logged_in) as handler:
        # do the django action here that will create the signal
        assert handler.called


    :Async Example:

    async with CatchSignal(user_logged_in) as handler:
        await ... # the django action the creates the signal
         assert handler.called
    """

    def __init__(self, signal):
        self.handler = mock.Mock()
        self.signal = signal

    async def __aenter__(self):
        await sync_to_async(self.signal.connect)(self.handler)
        return self.handler

    async def __aexit__(self, exc_type, exc, tb):
        await sync_to_async(self.signal.disconnect)(self.handler)

    def __enter__(self):
        self.signal.connect(self.handler)
        return self.handler

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.signal.disconnect(self.handler)


@pytest.fixture
def user_bob():
    return get_user_model().objects.create(username="bob", email="bob@example.com")


@pytest.fixture
def user_bill():
    return get_user_model().objects.create(username="bill", email="bill@example.com")


@pytest.fixture
def session():
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    session = SessionStore()
    session.create()
    return session


async def assert_is_logged_in(scope, user):
    """
    Assert that the provided user is logged in to the session contained within
    the scope.
    """
    assert "user" in scope
    assert scope["user"] == user
    session = scope["session"]

    # logged in!
    assert SESSION_KEY in session
    assert BACKEND_SESSION_KEY in session
    assert HASH_SESSION_KEY in session

    assert isinstance(
        await get_user(scope), await database_sync_to_async(get_user_model)()
    )
    assert await get_user(scope) == user


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_no_session_in_scope():
    """
    Test to ensure that a `ValueError` is raised if when tying to login a user
    to a scope that has no session.
    """

    msg = (
        "Cannot find session in scope. You should wrap your consumer in "
        "SessionMiddleware."
    )
    with pytest.raises(ValueError, match=msg):
        await login(scope={}, user=None)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_no_user_in_scope(session):
    """
    Test the login method to ensure it raises a `ValueError` if no user is
    passed and is no user in the scope.
    """
    scope = {"session": session}

    with pytest.raises(
        ValueError,
        match="User must be passed as an argument or must be present in the scope.",
    ):
        await login(scope, user=None)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_user_as_argument(session, user_bob):
    """
    Test that one can login to a scope that has a session by passing the scope
    and user as arguments to the login function.
    """
    scope = {"session": session}

    assert isinstance(await get_user(scope), AnonymousUser)
    # not logged in
    assert SESSION_KEY not in session

    async with CatchSignal(user_logged_in) as handler:
        assert not handler.called
        await login(scope, user=user_bob)
        assert handler.called

    await assert_is_logged_in(scope, user_bob)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_user_on_scope(session, user_bob):
    """
    Test that in the absence of a user being passed to the `login` function the
    function will use the user set on the scope.
    """
    scope = {"session": session, "user": user_bob}

    # check that we are not logged in on the session
    assert isinstance(await get_user(scope), AnonymousUser)

    async with CatchSignal(user_logged_in) as handler:
        assert not handler.called
        await login(scope, user=None)
        assert handler.called

    await assert_is_logged_in(scope, user_bob)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_change_user(session, user_bob, user_bill):
    """
    Test logging in a second user into a scope were another user is already logged in.
    """
    scope = {"session": session}

    # check that we are not logged in on the session
    assert isinstance(await get_user(scope), AnonymousUser)

    async with CatchSignal(user_logged_in) as handler:
        assert not handler.called
        await login(scope, user=user_bob)
        assert handler.called

    await assert_is_logged_in(scope, user_bob)

    session_key = session[SESSION_KEY]
    assert session_key

    async with CatchSignal(user_logged_in) as handler:
        assert not handler.called
        await login(scope, user=user_bill)
        assert handler.called

    await assert_is_logged_in(scope, user_bill)

    assert session_key != session[SESSION_KEY]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_logout(session, user_bob):
    """
    Test that one can logout a user from a logged in session.
    """
    scope = {"session": session}

    # check that we are not logged in on the session
    assert isinstance(await get_user(scope), AnonymousUser)

    async with CatchSignal(user_logged_in) as handler:
        assert not handler.called
        await login(scope, user=user_bob)
        assert handler.called

    await assert_is_logged_in(scope, user_bob)

    assert SESSION_KEY in session
    session_key = session[SESSION_KEY]
    assert session_key

    async with CatchSignal(user_logged_out) as handler:
        assert not handler.called
        await logout(scope)
        assert handler.called

    assert isinstance(await get_user(scope), AnonymousUser)
    assert isinstance(scope["user"], AnonymousUser)

    assert SESSION_KEY not in session


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_logout_not_logged_in(session):
    """
    Test that the `logout` function does nothing in the case were there is no
    user logged in.
    """
    scope = {"session": session}

    # check that we are not logged in on the session
    assert isinstance(await get_user(scope), AnonymousUser)

    async with CatchSignal(user_logged_out) as handler:
        assert not handler.called
        await logout(scope)
        assert not handler.called

    assert "user" not in scope
    assert isinstance(await get_user(scope), AnonymousUser)


@database_sync_to_async
def reload_session_keys(session_key):
    """
    Load a fresh session store instance for the given key, simulating the
    next session load (e.g. a subsequent connection), and return its keys.
    """
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    return set(SessionStore(session_key=session_key).keys())


async def run_auth_middleware(scope):
    """
    Run a scope through AuthMiddleware and return the scope the inner
    application received.
    """
    received = {}

    async def app(scope, receive, send):
        received.update(scope)

    await AuthMiddleware(app)(scope, None, None)
    return received


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_get_user_backend_removed(session, user_bob):
    """
    When the backend that authenticated the session is no longer configured,
    the user resolves to anonymous, the reason is exposed on the scope, and
    the session is flushed so the cleanup persists to the next session load.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)
    session_key = session.session_key

    with override_settings(AUTHENTICATION_BACKENDS=[OTHER_BACKEND]):
        user = await get_user(scope)

    assert isinstance(user, AnonymousUser)
    assert scope["auth_failure_reason"] == AuthFailureReason.BACKEND_REMOVED
    assert SESSION_KEY not in session
    # The cleanup must survive the next load of the session.
    reloaded_keys = await reload_session_keys(session_key)
    assert SESSION_KEY not in reloaded_keys
    assert BACKEND_SESSION_KEY not in reloaded_keys


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_get_user_backend_removed_invalidation_disabled(session, user_bob):
    """
    Session cleanup on backend removal is configurable; when disabled the
    session is left untouched but the reason is still reported.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)

    with override_settings(
        AUTHENTICATION_BACKENDS=[OTHER_BACKEND],
        CHANNELS_AUTH_INVALIDATE_STALE_SESSIONS=False,
    ):
        user = await get_user(scope)

    assert isinstance(user, AnonymousUser)
    assert scope["auth_failure_reason"] == AuthFailureReason.BACKEND_REMOVED
    assert SESSION_KEY in session


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_get_user_backend_removed_relogin_on_supported_backend(
    session, user_bob
):
    """
    After a stale session is cleaned up, the user can log in again on a
    backend that is still supported.
    """
    scope = {"session": session}
    await login(scope, user=user_bob, backend=MODEL_BACKEND)

    with override_settings(AUTHENTICATION_BACKENDS=[OTHER_BACKEND]):
        assert isinstance(await get_user(scope), AnonymousUser)
        assert scope["auth_failure_reason"] == AuthFailureReason.BACKEND_REMOVED

        await login(scope, user=user_bob, backend=OTHER_BACKEND)
        user = await get_user(scope)

    assert user == user_bob
    assert scope["auth_failure_reason"] is None


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_get_user_user_not_found(session, user_bob):
    """
    A normal user miss (the account no longer exists) is reported with its
    own reason and the stale auth keys are removed from the session while
    the session itself is kept.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)
    session_key = session.session_key

    await database_sync_to_async(user_bob.delete)()
    user = await get_user(scope)

    assert isinstance(user, AnonymousUser)
    assert scope["auth_failure_reason"] == AuthFailureReason.USER_NOT_FOUND
    assert SESSION_KEY not in session
    # The session itself survives (same key) but the auth keys are gone for
    # good on the next load.
    assert session.session_key == session_key
    reloaded_keys = await reload_session_keys(session_key)
    assert SESSION_KEY not in reloaded_keys
    assert BACKEND_SESSION_KEY not in reloaded_keys


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_get_user_backend_error(session, user_bob):
    """
    A transient storage failure during the user lookup must not be treated
    as a successful authentication, and must not invalidate the session.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)

    backend = mock.Mock()
    backend.get_user.side_effect = RuntimeError("storage is down")

    with mock.patch("channels.auth.load_backend", return_value=backend):
        user = await get_user(scope)

    assert isinstance(user, AnonymousUser)
    assert scope["auth_failure_reason"] == AuthFailureReason.BACKEND_ERROR
    # The session is left intact so the user is still logged in once the
    # backend recovers.
    assert SESSION_KEY in session
    assert BACKEND_SESSION_KEY in session
    assert await get_user(scope) == user_bob
    assert scope["auth_failure_reason"] is None


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_auth_middleware_backend_removed_new_connection(session, user_bob):
    """
    A fresh connection through AuthMiddleware sees an anonymous user and the
    failure reason once the session's backend has been removed.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)

    with override_settings(AUTHENTICATION_BACKENDS=[OTHER_BACKEND]):
        resolved = await run_auth_middleware({"session": session})

    assert isinstance(resolved["user"], AnonymousUser)
    assert resolved["auth_failure_reason"] == AuthFailureReason.BACKEND_REMOVED


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_auth_middleware_backend_removed_cached_scope(session, user_bob):
    """
    A connection reusing a scope whose user was already resolved by a
    previous connection must not keep the stale identity: re-resolution
    replaces it with the anonymous user and reports the reason.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)

    # First connection resolves and caches the user in the scope.
    cached_scope = await run_auth_middleware({"session": session})
    assert cached_scope["user"] == user_bob

    with override_settings(AUTHENTICATION_BACKENDS=[OTHER_BACKEND]):
        resolved = await run_auth_middleware(cached_scope)

    assert isinstance(resolved["user"], AnonymousUser)
    assert resolved["auth_failure_reason"] == AuthFailureReason.BACKEND_REMOVED


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_auth_middleware_replaces_cached_concrete_user(session, user_bob):
    """
    A scope carrying a concrete cached user object (not a lazy one) has it
    replaced on re-resolution rather than keeping the stale identity.
    """
    scope = {"session": session}
    await login(scope, user=user_bob)
    scope["user"] = user_bob

    with override_settings(AUTHENTICATION_BACKENDS=[OTHER_BACKEND]):
        resolved = await run_auth_middleware(scope)

    assert isinstance(resolved["user"], AnonymousUser)
    assert resolved["auth_failure_reason"] == AuthFailureReason.BACKEND_REMOVED
