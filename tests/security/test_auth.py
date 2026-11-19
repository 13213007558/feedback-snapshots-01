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

from channels.auth import get_user, login, logout
from channels.db import database_sync_to_async


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
def user_ada():
    user = get_user_model().objects.create(username="ada", email="ada@example.com")
    user.set_password("initial-password")
    user.save()
    return user


@pytest.fixture
def session():
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    session = SessionStore()
    session.create()
    return session


async def make_logged_in_scope(user):
    """
    Build a client scope with a persisted, logged-in session, simulating a
    client that connected, logged in, and had its session saved by the
    SessionMiddleware on the way out.
    """
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    session = SessionStore()
    await database_sync_to_async(session.create)()
    scope = {"session": session}
    await login(scope, user=user)
    await database_sync_to_async(session.save)()
    return scope


async def change_password(user, session, new_password):
    """
    Change the user's password and refresh the given session's auth hash,
    like django.contrib.auth.update_session_auth_hash does for the client
    that initiated the password change.
    """
    user.set_password(new_password)
    await database_sync_to_async(user.save)()
    session[HASH_SESSION_KEY] = user.get_session_auth_hash()
    await database_sync_to_async(session.save)()


@database_sync_to_async
def session_exists(session_key):
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    return SessionStore().exists(session_key)


@database_sync_to_async
def load_session(session_key):
    """
    Load a session from the store by key, as a reconnecting client would,
    returning the session and a plain dict of its persisted data.
    """
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    session = SessionStore(session_key=session_key)
    return session, {key: session[key] for key in session.keys()}


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


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_password_change_get_user_on_long_lived_scope(user_ada):
    """
    A long-lived connection keeps its scope (and cached scope user) after
    the account password is changed from another client. Re-fetching the
    user through `get_user` must reject the stale session hash, flush the
    old session and return AnonymousUser, while the session that was
    updated with the new credentials keeps authenticating.
    """
    long_lived_scope = await make_logged_in_scope(user_ada)
    changer_scope = await make_logged_in_scope(user_ada)
    long_lived_session = long_lived_scope["session"]
    old_session_key = long_lived_session.session_key

    # The second client changes the password; its own session is refreshed
    # with the new session auth hash.
    await change_password(user_ada, changer_scope["session"], "new-password")

    # Entry point 1: re-fetching the user on the long-lived scope.
    assert isinstance(await get_user(long_lived_scope), AnonymousUser)

    # The old session is cleaned up, not just ignored.
    assert SESSION_KEY not in long_lived_session
    assert HASH_SESSION_KEY not in long_lived_session
    assert not await session_exists(old_session_key)

    # The cached scope user is not refreshed implicitly; the connection
    # only observes the invalidation when it re-resolves the user.
    assert long_lived_scope["user"] == user_ada

    # The session carrying the new credentials is still valid.
    assert await get_user(changer_scope) == user_ada


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_password_change_reconnect(user_ada):
    """
    Reconnecting after a password change: presenting the old (cleaned up)
    session yields an anonymous connection, presenting the session updated
    with the new credentials yields the authenticated user, and a brand new
    session is a normal anonymous connection.
    """
    long_lived_scope = await make_logged_in_scope(user_ada)
    changer_scope = await make_logged_in_scope(user_ada)
    old_session_key = long_lived_scope["session"].session_key
    new_session_key = changer_scope["session"].session_key

    await change_password(user_ada, changer_scope["session"], "new-password")

    # The long-lived connection re-resolves its user, which invalidates
    # and cleans up its old session.
    assert isinstance(await get_user(long_lived_scope), AnonymousUser)

    # Entry point 2: reconnecting.
    # A client presenting the old session key finds it cleaned up and
    # connects anonymously.
    old_session, old_data = await load_session(old_session_key)
    assert SESSION_KEY not in old_data
    assert isinstance(await get_user({"session": old_session}), AnonymousUser)

    # A client presenting the session with the new credentials is still
    # authenticated.
    new_session, new_data = await load_session(new_session_key)
    assert new_data[SESSION_KEY] == str(user_ada.pk)
    reconnected_user = await get_user({"session": new_session})
    assert reconnected_user == user_ada
    assert reconnected_user.is_authenticated

    # A client with a brand new session connects anonymously, as usual.
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    anonymous_session = SessionStore()
    await database_sync_to_async(anonymous_session.create)()
    assert isinstance(await get_user({"session": anonymous_session}), AnonymousUser)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_password_change_logout_on_long_lived_scope(user_ada):
    """
    Explicitly logging out from a long-lived connection whose session was
    invalidated by a password change resets the scope to an anonymous one
    and cleans up the session. The `user_logged_out` signal firing alone
    would not prove any of that, so the persisted state is asserted too.
    """
    long_lived_scope = await make_logged_in_scope(user_ada)
    changer_scope = await make_logged_in_scope(user_ada)
    long_lived_session = long_lived_scope["session"]
    old_session_key = long_lived_session.session_key

    await change_password(user_ada, changer_scope["session"], "new-password")

    # Entry point 3: explicit logout on the long-lived scope.
    async with CatchSignal(user_logged_out) as handler:
        assert not handler.called
        await logout(long_lived_scope)
        assert handler.called

    # The signal firing is not the contract; the resulting state is.
    assert isinstance(long_lived_scope["user"], AnonymousUser)
    assert SESSION_KEY not in long_lived_session
    assert isinstance(await get_user(long_lived_scope), AnonymousUser)
    assert not await session_exists(old_session_key)
