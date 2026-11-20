from __future__ import annotations

import time
from typing import Any, Callable

from django.core.exceptions import PermissionDenied
from django.http import HttpRequest

from allauth.socialaccount.adapter import get_adapter


STATE_ID_LENGTH = 16
MAX_STATES = 10
STATE_TTL = 600
STATES_SESSION_KEY = "socialaccount_states"

# (state, timestamp, provider_id, app_id). The ``app_id`` records which social
# app ("connector") configuration initiated the flow. States stashed by older
# allauth versions do not have it, hence it is optional.
StashedState = tuple[dict[str, Any], float, str, str | None]

StateMatcher = Callable[[dict[str, Any]], bool]


def _unpack(stashed_state: Any) -> tuple[dict[str, Any], float, str, str | None] | None:
    if not isinstance(stashed_state, (tuple, list)):
        return None
    if len(stashed_state) == 4:
        state, ts, provider_id, app_id = stashed_state
    elif len(stashed_state) == 3:
        state, ts, provider_id = stashed_state
        app_id = None
    else:
        return None
    if not isinstance(state, dict) or not isinstance(ts, (int, float)):
        return None
    return state, ts, provider_id, app_id


def _matches(
    stashed_state: Any,
    *,
    provider_id: str | None,
    app_id: str | None,
    matcher: StateMatcher | None,
) -> tuple[dict[str, Any], float, str, str | None] | None:
    parts = _unpack(stashed_state)
    if parts is None:
        return None
    state, ts, state_provider_id, state_app_id = parts
    if provider_id is not None and state_provider_id != provider_id:
        return None
    if app_id is not None and state_app_id is not None and state_app_id != app_id:
        # A state that records an app must match that app. States stashed by
        # older allauth versions carry no app; they can only be redeemed when
        # the callback resolves to one unambiguous app configuration.
        return None
    if matcher is not None and not matcher(state):
        return None
    return state, ts, state_provider_id, state_app_id


def get_oldest_state(
    states: dict[str, StashedState],
    *,
    provider_id: str | None = None,
    app_id: str | None = None,
) -> str | None:
    oldest_ts = None
    oldest_id = None
    for state_id, stashed_state in states.items():
        parts = _matches(
            stashed_state, provider_id=provider_id, app_id=app_id, matcher=None
        )
        if parts is None:
            continue
        ts = parts[1]
        if oldest_ts is None or oldest_ts > ts:
            oldest_ts = ts
            oldest_id = state_id
    return oldest_id


def find_state_id(
    states: dict[str, StashedState],
    *,
    provider_id: str | None = None,
    app_id: str | None = None,
    matcher: StateMatcher | None = None,
    unique: bool = False,
) -> str | None:
    """Returns the ID of the most recently stashed (non-expired) state that
    matches the given criteria, without consuming it.

    Callbacks of providers that do not round-trip a ``state`` parameter cannot
    look a state up by ID. They must match on information the callback *does*
    carry. When that information is not enough to identify exactly one pending
    flow, ``unique`` makes the lookup fail rather than consume the state of
    another (legitimate) flow.
    """
    now = time.time()
    state_id = None
    newest_ts = None
    candidates = 0
    for sid, stashed_state in states.items():
        parts = _matches(
            stashed_state,
            provider_id=provider_id,
            app_id=app_id,
            matcher=matcher,
        )
        if parts is None:
            continue
        ts = parts[1]
        if is_expired(ts, now=now):
            continue
        candidates += 1
        if newest_ts is None or ts > newest_ts:
            newest_ts = ts
            state_id = sid
    if unique and candidates != 1:
        return None
    return state_id


def is_expired(ts: float, *, now: float | None = None) -> bool:
    if now is None:
        now = time.time()
    return now - ts > STATE_TTL


def peek_state(
    request: HttpRequest, *, state_id: str
) -> tuple[dict[str, Any], float, str, str | None] | None:
    """Looks up a stashed state without consuming it.

    Callbacks need to know which app configuration initiated the flow before
    they can validate and consume the state. Peeking makes it possible to
    reject a callback without consuming another flow's state.
    """
    return _unpack(get_states(request).get(state_id))


def get_state_app_id(request: HttpRequest, *, state_id: str) -> str | None:
    """Returns the app ("connector") configuration a stashed state belongs to.

    Returns ``None`` when the state is unknown, expired, or was stashed by an
    older allauth version without app information. Callers must treat that as
    "unknown" and stay conservative, not as "any app will do".
    """
    peeked = peek_state(request, state_id=state_id)
    if peeked is None:
        return None
    state, ts, _, app_id = peeked
    if is_expired(ts):
        return None
    return app_id


def drop_state(request: HttpRequest, *, state_id: str) -> None:
    """Removes a single stashed state, if present. Used to reclaim expired
    states without touching any other pending state.
    """
    states = get_states(request)
    if state_id not in states:
        return
    del states[state_id]
    request.session[STATES_SESSION_KEY] = states
    _save_session(request)


def gc_states(states: dict[str, StashedState]) -> bool:
    """Drops expired states (and the oldest ones when over the limit).
    Returns whether the given mapping was modified.
    """
    now = time.time()
    modified = False
    expired_sids = []
    for sid, stashed_state in states.items():
        parts = _unpack(stashed_state)
        if parts is None or is_expired(parts[1], now=now):
            expired_sids.append(sid)
    for sid in expired_sids:
        del states[sid]
        modified = True
    while len(states) > MAX_STATES:
        oldest_id = get_oldest_state(states)
        if not oldest_id:
            break
        del states[oldest_id]
        modified = True
    return modified


def get_states(request: HttpRequest) -> dict[str, StashedState]:
    states = request.session.get(STATES_SESSION_KEY)
    if not isinstance(states, dict):
        states = {}
    return states


def _save_session(request: HttpRequest) -> None:
    """Persist state changes and reload the session lazily."""
    request.session.save()
    session_key = request.session.session_key
    if session_key is not None:
        request.session = request.session.__class__(session_key)
        # Ensure that cookie based sessions write the state back, and that
        # SessionMiddleware saves the latest state at the end of the request.
        request.session.modified = True


def stash_state(
    request: HttpRequest,
    *,
    provider_id: str,
    state: dict[str, Any],
    state_id: str | None = None,
    app_id: str | None = None,
) -> str:
    states = get_states(request)
    gc_states(states)
    if state_id is None:
        state_id = get_adapter().generate_state_param(state)
    states[state_id] = (state, time.time(), provider_id, app_id)
    request.session[STATES_SESSION_KEY] = states
    _save_session(request)
    return state_id


def unstash_state(
    request: HttpRequest,
    *,
    state_id: str,
    provider_id: str,
    app_id: str | None = None,
    raises: bool = False,
) -> dict[str, Any] | None:
    state: dict[str, Any] | None = None
    states = get_states(request)
    parts = _matches(
        states.get(state_id),
        provider_id=provider_id,
        app_id=app_id,
        matcher=None,
    )
    if parts is not None:
        state, ts, _, _ = parts
        if is_expired(ts):
            state = None
        del states[state_id]
        request.session[STATES_SESSION_KEY] = states
        # OAuth callbacks can take a while. Persist the consumed state now and
        # reload the session lazily so changes made by parallel tabs while the
        # callback is running are not overwritten at the end of this request.
        _save_session(request)
    if state is None and raises:
        raise PermissionDenied()
    return state


def unstash_last_state(
    request: HttpRequest,
    *,
    provider_id: str,
    app_id: str | None = None,
    matcher: StateMatcher | None = None,
    unique: bool = False,
    raises: bool = False,
) -> dict[str, Any] | None:
    states = get_states(request)
    if gc_states(states):
        request.session[STATES_SESSION_KEY] = states
        _save_session(request)
    state_id = find_state_id(
        states,
        provider_id=provider_id,
        app_id=app_id,
        matcher=matcher,
        unique=unique,
    )
    if state_id:
        return unstash_state(
            request,
            state_id=state_id,
            provider_id=provider_id,
            app_id=app_id,
            raises=raises,
        )
    if raises:
        raise PermissionDenied()
    return None
