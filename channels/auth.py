import logging

from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    _get_backends,
    get_user_model,
    load_backend,
    user_logged_in,
    user_logged_out,
)
from django.utils.crypto import constant_time_compare
from django.utils.functional import LazyObject

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from channels.sessions import CookieMiddleware, SessionMiddleware

logger = logging.getLogger(__name__)


class AuthFailureReason:
    """
    Concise, application-consumable reasons why session authentication
    resolution did not yield a user. Exposed as
    ``scope["auth_failure_reason"]`` after ``get_user`` runs.
    """

    # The backend that authenticated the session is no longer in
    # settings.AUTHENTICATION_BACKENDS (e.g. it was decommissioned).
    BACKEND_REMOVED = "backend_removed"
    # The backend is configured but no user matches the session's user id
    # (e.g. the account was deleted).
    USER_NOT_FOUND = "user_not_found"
    # The user lookup itself failed (e.g. a transient storage outage). The
    # session is left untouched so the user stays logged in once the
    # backend recovers.
    BACKEND_ERROR = "backend_error"
    # The session auth hash did not match the user's current hash.
    SESSION_HASH_MISMATCH = "session_hash_mismatch"


def _invalidate_stale_sessions():
    """
    Whether stale authentication state should be cleaned from the session
    when it is detected. Controlled by the
    ``CHANNELS_AUTH_INVALIDATE_STALE_SESSIONS`` setting (default ``True``).
    """
    return getattr(settings, "CHANNELS_AUTH_INVALIDATE_STALE_SESSIONS", True)


def _clear_auth_session_data(session):
    """
    Remove the authentication keys from the session and persist the change
    so it survives the next session load. Other session data is kept.
    """
    for key in (SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY):
        session.pop(key, None)
    session.save()


def _get_session_user(session):
    """
    Resolve the user for a session, returning a ``(user, failure_reason)``
    tuple. ``failure_reason`` is ``None`` on success or when the session
    holds no authentication state at all, otherwise one of the
    ``AuthFailureReason`` values.
    """
    try:
        user_id = _get_user_session_key(session)
        backend_path = session[BACKEND_SESSION_KEY]
    except KeyError:
        return None, None
    if backend_path not in settings.AUTHENTICATION_BACKENDS:
        # The backend that authenticated this session is no longer
        # configured, so the session cannot be trusted anymore. Flush it so
        # the user can re-login cleanly on a still-supported backend.
        if _invalidate_stale_sessions():
            session.flush()
        return None, AuthFailureReason.BACKEND_REMOVED
    backend = load_backend(backend_path)
    try:
        user = backend.get_user(user_id)
    except Exception:
        logger.exception(
            "Authentication backend %r failed while resolving the session "
            "user; treating the request as anonymous without invalidating "
            "the session.",
            backend_path,
        )
        return None, AuthFailureReason.BACKEND_ERROR
    if user is None:
        if _invalidate_stale_sessions():
            _clear_auth_session_data(session)
        return None, AuthFailureReason.USER_NOT_FOUND
    # Verify the session
    if hasattr(user, "get_session_auth_hash"):
        session_hash = session.get(HASH_SESSION_KEY)
        session_hash_verified = session_hash and constant_time_compare(
            session_hash, user.get_session_auth_hash()
        )
        if not session_hash_verified:
            session.flush()
            return None, AuthFailureReason.SESSION_HASH_MISMATCH
    return user, None


@database_sync_to_async
def get_user(scope):
    """
    Return the user model instance associated with the given scope.
    If no user is retrieved, return an instance of `AnonymousUser`.

    Sets ``scope["auth_failure_reason"]`` to ``None`` on success, or to one
    of the ``AuthFailureReason`` values when the session held authentication
    state that could not be resolved to a user.
    """
    # postpone model import to avoid ImproperlyConfigured error before Django
    # setup is complete.
    from django.contrib.auth.models import AnonymousUser

    if "session" not in scope:
        raise ValueError(
            "Cannot find session in scope. You should wrap your consumer in "
            "SessionMiddleware."
        )
    user, reason = _get_session_user(scope["session"])
    scope["auth_failure_reason"] = reason
    return user or AnonymousUser()


@database_sync_to_async
def login(scope, user, backend=None):
    """
    Persist a user id and a backend in the request.
    This way a user doesn't have to re-authenticate on every request.
    Note that data set during the anonymous session is retained when the user
    logs in.
    """
    if "session" not in scope:
        raise ValueError(
            "Cannot find session in scope. You should wrap your consumer in "
            "SessionMiddleware."
        )
    session = scope["session"]
    session_auth_hash = ""
    if user is None:
        user = scope.get("user", None)
    if user is None:
        raise ValueError(
            "User must be passed as an argument or must be present in the scope."
        )
    if hasattr(user, "get_session_auth_hash"):
        session_auth_hash = user.get_session_auth_hash()
    if SESSION_KEY in session:
        if _get_user_session_key(session) != user.pk or (
            session_auth_hash
            and not constant_time_compare(
                session.get(HASH_SESSION_KEY, ""), session_auth_hash
            )
        ):
            # To avoid reusing another user's session, create a new, empty
            # session if the existing session corresponds to a different
            # authenticated user.
            session.flush()
    else:
        session.cycle_key()
    try:
        backend = backend or user.backend
    except AttributeError:
        backends = _get_backends(return_tuples=True)
        if len(backends) == 1:
            _, backend = backends[0]
        else:
            raise ValueError(
                "You have multiple authentication backends configured and "
                "therefore must provide the `backend` "
                "argument or set the `backend` attribute on the user."
            )
    session[SESSION_KEY] = user._meta.pk.value_to_string(user)
    session[BACKEND_SESSION_KEY] = backend
    session[HASH_SESSION_KEY] = session_auth_hash
    scope["user"] = user
    # note this does not reset the CSRF_COOKIE/Token
    user_logged_in.send(sender=user.__class__, request=None, user=user)


@database_sync_to_async
def logout(scope):
    """
    Remove the authenticated user's ID from the request and flush their session
    data.
    """
    # postpone model import to avoid ImproperlyConfigured error before Django
    # setup is complete.
    from django.contrib.auth.models import AnonymousUser

    if "session" not in scope:
        raise ValueError(
            "Login cannot find session in scope. You should wrap your "
            "consumer in SessionMiddleware."
        )
    session = scope["session"]
    # Dispatch the signal before the user is logged out so the receivers have a
    # chance to find out *who* logged out.
    user = scope.get("user", None)
    if hasattr(user, "is_authenticated") and not user.is_authenticated:
        user = None
    if user is not None:
        user_logged_out.send(sender=user.__class__, request=None, user=user)
    session.flush()
    if "user" in scope:
        scope["user"] = AnonymousUser()


def _get_user_session_key(session):
    # This value in the session is always serialized to a string, so we need
    # to convert it back to Python whenever we access it.
    return get_user_model()._meta.pk.to_python(session[SESSION_KEY])


class UserLazyObject(LazyObject):
    """
    Throw a more useful error message when scope['user'] is accessed before
    it's resolved
    """

    def _setup(self):
        raise ValueError("Accessing scope user before it is ready.")


class AuthMiddleware(BaseMiddleware):
    """
    Middleware which populates scope["user"] from a Django session.
    Requires SessionMiddleware to function.
    """

    def populate_scope(self, scope):
        # Make sure we have a session
        if "session" not in scope:
            raise ValueError(
                "AuthMiddleware cannot find session in scope. "
                "SessionMiddleware must be above it."
            )
        # Add it to the scope if it's not there already
        if "user" not in scope:
            scope["user"] = UserLazyObject()

    async def resolve_scope(self, scope):
        user = await get_user(scope)
        if isinstance(scope["user"], UserLazyObject):
            scope["user"]._wrapped = user
        else:
            # The scope already carries a resolved user cached by a previous
            # resolution; replace it so a stale identity cannot survive.
            scope["user"] = user

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        # Scope injection/mutation per this middleware's needs.
        self.populate_scope(scope)
        # Grab the finalized/resolved scope
        await self.resolve_scope(scope)

        return await super().__call__(scope, receive, send)


# Handy shortcut for applying all three layers at once
def AuthMiddlewareStack(inner):
    return CookieMiddleware(SessionMiddleware(AuthMiddleware(inner)))
