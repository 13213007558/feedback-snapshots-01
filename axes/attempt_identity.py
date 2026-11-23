"""
Stable identity for a single real authentication attempt.

A login request can be observed by more than one layer of the Django
authentication stack. For example a project can have a form layer and a
separate view level call to :func:`django.contrib.auth.authenticate`, both
of which end up emitting ``user_login_failed`` for the very same password
check. Without a shared identity each observation would be counted as a
separate failure and a single wrong password could consume several lockout
score points.

The identity is stored in a :class:`contextvars.ContextVar`, so it follows
the authentication flow through backends, signal receivers and handlers
without having to be threaded through every function signature, and is also
mirrored on the request for code that only has the request available.

Each *real* authentication attempt gets a fresh identifier. Two explicit
``authenticate`` calls on the same request therefore produce two different
identifiers and are counted separately, while duplicate reports of one and
the same attempt share an identifier and are only counted once.
"""

from contextvars import ContextVar
from typing import Optional
from uuid import uuid4

from django.http import HttpRequest

#: Name of the request attribute that mirrors the active attempt identity.
REQUEST_ATTRIBUTE = "axes_attempt_identifier"

#: Request attribute holding the identities already reported through
#: ``user_login_failed`` for this request.
OBSERVED_REQUEST_ATTRIBUTE = "_axes_observed_attempts"

#: Context variable holding the identity of the in-flight authentication
#: attempt. ``None`` means that no attempt has been explicitly started, in
#: which case the legacy behaviour of trusting every failure signal is kept.
_attempt_identifier: ContextVar[Optional[str]] = ContextVar(
    "axes_attempt_identifier", default=None
)


def begin_attempt_identifier() -> str:
    """
    Generate a fresh identity for a real authentication attempt.

    Called by the Axes authentication backend every time Django runs an
    ``authenticate`` call. The identifier replaces any previously active
    identity, so two explicit authentication attempts on the same request
    receive two distinct identities.
    """

    identifier = uuid4().hex
    _attempt_identifier.set(identifier)
    return identifier


def get_attempt_identifier(
    request: Optional[HttpRequest] = None,
) -> Optional[str]:
    """
    Return the identity of the current authentication attempt.

    The context variable is preferred because it works even when the same
    request object is reused by nested authentication calls. The request
    attribute is used as a fallback for callers that report failures through
    signals outside of an Axes-backed ``authenticate`` call. When neither is
    set, ``None`` is returned and the caller keeps the legacy behaviour.
    """

    identifier = _attempt_identifier.get()
    if identifier is not None:
        return identifier

    if request is not None:
        return getattr(request, REQUEST_ATTRIBUTE, None)

    return None


def set_attempt_identifier(
    identifier: str, request: Optional[HttpRequest] = None
) -> None:
    """
    Bind an existing attempt identity to the current context and request.

    Useful for login entry points that want to reuse an identity created
    elsewhere instead of generating a new one.
    """

    _attempt_identifier.set(identifier)
    if request is not None:
        setattr(request, REQUEST_ATTRIBUTE, identifier)


def mark_attempt_non_countable(
    request: Optional[HttpRequest], reason: str
) -> None:
    """
    Record that the current attempt was rejected by a business rule rather
    than a failed password check.

    The failure is still observable through ``user_login_failed`` but the
    Axes handlers skip lockout scoring for it, keeping business rule
    rejections separate from credential failures. The reason is stored on the
    request for the view layer and for lockout responses.
    """

    if request is not None:
        request.axes_non_countable_reason = reason


def reset_attempt_identifier() -> None:
    """
    Clear the active attempt identity.

    Mainly useful in tests and for entry points that manage the identity
    lifecycle manually.
    """

    _attempt_identifier.set(None)
