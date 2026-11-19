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
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import AnonymousUser

from channels.auth import get_user, login, logout
from channels.db import database_sync_to_async

MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"
OTHER_BACKEND = "tests.security.test_auth.OtherBackend"


class OtherBackend(ModelBackend):
    """A second authentication backend, used to exercise backend selection."""


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


async def get_persisted_session(session_key):
    """
    Load the session data stored under ``session_key`` from the session backend.
    Returns an empty dict if the session no longer exists.
    """
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    return await database_sync_to_async(SessionStore(session_key).load)()


async def save_session(session):
    await database_sync_to_async(session.save)()



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


async def assert_anonymous_login_unchanged(scope, session_key, persisted):
    """
    Assert that a failed login left the anonymous session, its persisted data
    and scope["user"] alone.
    """
    session = scope["session"]
    assert session.session_key == session_key
    assert dict(session) == persisted
    assert SESSION_KEY not in session
    assert BACKEND_SESSION_KEY not in session
    assert HASH_SESSION_KEY not in session
    # The persisted data is still there, under the same key.
    assert await get_persisted_session(session_key) == persisted
    # The scope user was not replaced by the attempted login.
    assert scope["user"].is_authenticated is False
    assert isinstance(await get_user(scope), AnonymousUser)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_ambiguous_backend_keeps_anonymous_progress(
    session, settings, user_bob
):
    """
    Test that an ambiguous backend (multiple configured, none provided) raises
    without rotating the session key, dropping anonymous data, updating
    scope["user"] or sending user_logged_in.
    """
    settings.AUTHENTICATION_BACKENDS = [MODEL_BACKEND, OTHER_BACKEND]
    session["anonymous_progress"] = "keep-me"
    await save_session(session)
    session_key = session.session_key
    persisted = await get_persisted_session(session_key)
    scope = {"session": session, "user": AnonymousUser()}

    async with CatchSignal(user_logged_in) as handler:
        with pytest.raises(
            ValueError,
            match="You have multiple authentication backends configured",
        ):
            await login(scope, user=user_bob)
        assert not handler.called

    await assert_anonymous_login_unchanged(scope, session_key, persisted)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_ambiguous_backend_keeps_existing_login(
    session, settings, user_bob, user_bill
):
    """
    Test that an ambiguous backend failure does not log out or rotate the
    session of an already authenticated user.
    """
    settings.AUTHENTICATION_BACKENDS = [MODEL_BACKEND, OTHER_BACKEND]
    scope = {"session": session}
    await login(scope, user=user_bob, backend=MODEL_BACKEND)
    await save_session(session)
    session_key = session.session_key
    persisted = await get_persisted_session(session_key)
    session_key_in_session = session[SESSION_KEY]

    async with CatchSignal(user_logged_in) as handler:
        with pytest.raises(
            ValueError,
            match="You have multiple authentication backends configured",
        ):
            await login(scope, user=user_bill)
        assert not handler.called

    assert session.session_key == session_key
    assert session[SESSION_KEY] == session_key_in_session
    assert await get_persisted_session(session_key) == persisted
    assert scope["user"] == user_bob
    assert await get_user(scope) == user_bob


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_invalid_backend_keeps_anonymous_progress(session, user_bob):
    """
    Test that a backend which is not configured in AUTHENTICATION_BACKENDS is
    rejected without changing the session, persisted data or scope["user"].
    """
    session["anonymous_progress"] = "keep-me"
    await save_session(session)
    session_key = session.session_key
    persisted = await get_persisted_session(session_key)
    scope = {"session": session, "user": AnonymousUser()}

    async with CatchSignal(user_logged_in) as handler:
        with pytest.raises(
            ValueError,
            match="is not configured in settings.AUTHENTICATION_BACKENDS",
        ):
            await login(scope, user=user_bob, backend="tests.security.NoSuchBackend")
        assert not handler.called

    await assert_anonymous_login_unchanged(scope, session_key, persisted)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_non_string_backend_keeps_anonymous_progress(session, user_bob):
    """
    Test that a non-string backend is rejected before the session is modified.
    """
    session["anonymous_progress"] = "keep-me"
    await save_session(session)
    session_key = session.session_key
    persisted = await get_persisted_session(session_key)
    scope = {"session": session, "user": AnonymousUser()}

    async with CatchSignal(user_logged_in) as handler:
        with pytest.raises(
            TypeError, match="backend must be a dotted import path string"
        ):
            await login(scope, user=user_bob, backend=object())
        assert not handler.called

    await assert_anonymous_login_unchanged(scope, session_key, persisted)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_switch_user_with_backend(session, settings, user_bob, user_bill):
    """
    Test that a successful login with an explicit backend flushes the previous
    user's session, persists the new login, updates scope["user"] and sends
    exactly one user_logged_in signal.
    """
    settings.AUTHENTICATION_BACKENDS = [MODEL_BACKEND, OTHER_BACKEND]
    scope = {"session": session}
    await login(scope, user=user_bob, backend=MODEL_BACKEND)
    await save_session(session)
    old_session_key = session.session_key

    async with CatchSignal(user_logged_in) as handler:
        await login(scope, user=user_bill, backend=OTHER_BACKEND)
        assert handler.call_count == 1
        assert handler.call_args.kwargs["user"] == user_bill

    await save_session(session)
    new_session_key = session.session_key
    assert new_session_key != old_session_key
    # The old session was flushed: its data (including the old login) is gone.
    assert await get_persisted_session(old_session_key) == {}
    persisted = await get_persisted_session(new_session_key)
    assert persisted[SESSION_KEY] == str(user_bill.pk)
    assert persisted[BACKEND_SESSION_KEY] == OTHER_BACKEND
    await assert_is_logged_in(scope, user_bill)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_login_success_preserves_anonymous_data_once(session, user_bob):
    """
    Test that a successful first login cycles the session key but keeps
    anonymous data, and that only this success emits user_logged_in.
    """
    session["anonymous_progress"] = "keep-me"
    await save_session(session)
    old_session_key = session.session_key
    scope = {"session": session}

    async with CatchSignal(user_logged_in) as handler:
        await login(scope, user=user_bob, backend=MODEL_BACKEND)
        assert handler.call_count == 1
        assert handler.call_args.kwargs["user"] == user_bob

    await save_session(session)
    assert session.session_key != old_session_key
    persisted = await get_persisted_session(session.session_key)
    assert persisted["anonymous_progress"] == "keep-me"
    assert persisted[SESSION_KEY] == str(user_bob.pk)
    assert persisted[BACKEND_SESSION_KEY] == MODEL_BACKEND
    await assert_is_logged_in(scope, user_bob)
