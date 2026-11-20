import time

from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse

import pytest

from allauth.socialaccount.internal import statekit


def test_get_oldest_state():
    states = {
        "new": [{"id": "new"}, 300, "provider"],
        "mid": [{"id": "mid"}, 200, "provider"],
        "old": [{"id": "old"}, 100, "provider"],
    }
    state_id = statekit.get_oldest_state(states)
    assert state_id == "old"


def test_get_oldest_state_empty():
    state_id = statekit.get_oldest_state({})
    assert state_id is None


def test_gc_states():
    now = time.time()
    states = {}
    for i in range(statekit.MAX_STATES + 1):
        states[f"state-{i}"] = [{"i": i}, now + i, "provider"]
    assert len(states) == statekit.MAX_STATES + 1
    statekit.gc_states(states)
    assert len(states) == statekit.MAX_STATES
    assert "state-0" not in states


def test_gc_states_expires():
    now = time.time()
    states = {
        "fresh": [{"id": "fresh"}, now, "provider"],
        "expired": [
            {"id": "expired"},
            now - statekit.STATE_TTL - 1,
            "provider",
        ],
    }
    statekit.gc_states(states)
    assert "fresh" in states
    assert "expired" not in states


@pytest.mark.django_db
def test_stashing(request_factory):
    request = request_factory.get("/")
    provider_id = "provider"

    # Stash states with a small delay
    state_id = statekit.stash_state(
        request, provider_id=provider_id, state={"foo": "bar"}
    )
    time.sleep(0.001)  # delay for microseconds
    state2_id = statekit.stash_state(
        request, provider_id=provider_id, state={"foo2": "bar2"}
    )
    time.sleep(0.001)  # delay for microseconds
    state3_id = statekit.stash_state(
        request, provider_id=provider_id, state={"foo3": "bar3"}
    )

    # Unstash last state and check order
    state = statekit.unstash_last_state(request, provider_id=provider_id)
    assert state == {"foo3": "bar3"}

    state = statekit.unstash_state(request, provider_id=provider_id, state_id=state3_id)
    assert state is None
    state = statekit.unstash_state(request, provider_id=provider_id, state_id=state2_id)
    assert state == {"foo2": "bar2"}
    state = statekit.unstash_state(request, provider_id=provider_id, state_id=state2_id)
    assert state is None
    state = statekit.unstash_state(request, provider_id=provider_id, state_id=state_id)
    assert state == {"foo": "bar"}
    state = statekit.unstash_state(request, provider_id=provider_id, state_id=state_id)
    assert state is None


@pytest.mark.django_db
def test_stashing_persists_session(request_factory):
    request = request_factory.get("/")
    session = request.session
    state_id = statekit.stash_state(
        request, provider_id="provider", state={"foo": "bar"}
    )

    assert request.session is not session
    assert request.session.modified
    stored_session = request.session.__class__(request.session.session_key)
    assert state_id in stored_session[statekit.STATES_SESSION_KEY]


@pytest.mark.django_db
def test_stashing_does_not_overwrite_parallel_state_on_response(request_factory):
    request = request_factory.get("/")
    state_id = statekit.stash_state(
        request, provider_id="provider", state={"foo": "bar"}
    )

    parallel_request = request_factory.get("/")
    parallel_request.session = request.session.__class__(request.session.session_key)
    parallel_state_id = statekit.stash_state(
        parallel_request, provider_id="provider", state={"parallel": True}
    )

    middleware = SessionMiddleware(lambda request: HttpResponse())
    middleware.process_response(request, HttpResponse())

    stored_session = request.session.__class__(request.session.session_key)
    assert set(stored_session[statekit.STATES_SESSION_KEY]) == {
        state_id,
        parallel_state_id,
    }


@pytest.mark.django_db
def test_unstashing_persists_and_reloads_session(request_factory):
    request = request_factory.get("/")
    state_id = statekit.stash_state(
        request, provider_id="provider", state={"foo": "bar"}
    )
    session = request.session

    state = statekit.unstash_state(request, provider_id="provider", state_id=state_id)

    assert state == {"foo": "bar"}
    assert request.session is not session
    assert request.session.modified
    stored_session = request.session.__class__(request.session.session_key)
    assert state_id not in stored_session[statekit.STATES_SESSION_KEY]


@pytest.mark.django_db
def test_unstash_expired_state(request_factory):
    request = request_factory.get("/")
    provider_id = "provider"
    state_id = statekit.stash_state(
        request, provider_id=provider_id, state={"foo": "bar"}
    )
    # Backdate the timestamp to simulate expiry
    states = statekit.get_states(request)
    states[state_id] = (
        states[state_id][0],
        time.time() - statekit.STATE_TTL - 1,
        provider_id,
    )
    request.session[statekit.STATES_SESSION_KEY] = states
    state = statekit.unstash_state(request, provider_id=provider_id, state_id=state_id)
    assert state is None


@pytest.mark.django_db
def test_unstash_state_raises(request_factory):
    request = request_factory.get("/")
    state_id = statekit.stash_state(
        request, provider_id="provider", state={"foo": "bar"}
    )

    with pytest.raises(PermissionDenied):
        statekit.unstash_state(
            request, provider_id="other-provider", state_id=state_id, raises=True
        )


@pytest.mark.django_db
def test_stash_state_binds_app_configuration(request_factory):
    request = request_factory.get("/")
    state_id = statekit.stash_state(
        request,
        provider_id="provider",
        app_id="app-a",
        state={"foo": "bar"},
    )
    peeked = statekit.peek_state(request, state_id=state_id)
    assert peeked is not None
    assert peeked[2] == "provider"
    assert peeked[3] == "app-a"
    assert statekit.get_state_app_id(request, state_id=state_id) == "app-a"


@pytest.mark.django_db
def test_unstash_state_app_mismatch_keeps_other_state(request_factory):
    request = request_factory.get("/")
    state_a = statekit.stash_state(
        request, provider_id="provider", app_id="app-a", state={"a": True}
    )
    state_b = statekit.stash_state(
        request, provider_id="provider", app_id="app-b", state={"b": True}
    )

    # Redeeming A's state through B's app must not succeed, and must not
    # consume A's state either.
    assert (
        statekit.unstash_state(
            request,
            provider_id="provider",
            app_id="app-b",
            state_id=state_a,
        )
        is None
    )
    assert set(statekit.get_states(request)) == {state_a, state_b}

    assert statekit.unstash_state(
        request, provider_id="provider", app_id="app-a", state_id=state_a
    ) == {"a": True}
    assert set(statekit.get_states(request)) == {state_b}


@pytest.mark.django_db
def test_unstash_state_without_app_accepts_legacy_and_current_state(request_factory):
    """States stashed before app binding existed remain redeemable.

    The app is only enforced when the caller knows it; a callback that cannot
    determine the app must not claim a state belongs to (or not to) an app.
    """
    request = request_factory.get("/")
    legacy_id = "legacy-state"
    statekit.stash_state(
        request,
        provider_id="provider",
        state={"old": True},
        state_id=legacy_id,
    )
    states = statekit.get_states(request)
    # Simulate a state stashed by an older allauth version (3-tuple).
    states[legacy_id] = (states[legacy_id][0], time.time(), "provider")
    request.session[statekit.STATES_SESSION_KEY] = states

    state = statekit.unstash_state(request, provider_id="provider", state_id=legacy_id)
    assert state == {"old": True}

    app_id = statekit.stash_state(
        request, provider_id="provider", app_id="app-a", state={"new": True}
    )
    assert statekit.unstash_state(request, provider_id="provider", state_id=app_id) == {
        "new": True
    }


@pytest.mark.django_db
def test_unstash_last_state_is_app_scoped(request_factory):
    request = request_factory.get("/")
    state_a = statekit.stash_state(
        request, provider_id="provider", app_id="app-a", state={"a": True}
    )
    statekit.stash_state(
        request, provider_id="provider", app_id="app-b", state={"b": True}
    )
    assert statekit.unstash_last_state(
        request, provider_id="provider", app_id="app-b"
    ) == {"b": True}
    assert set(statekit.get_states(request)) == {state_a}
    assert statekit.unstash_last_state(
        request, provider_id="provider", app_id="app-a"
    ) == {"a": True}


@pytest.mark.django_db
def test_unstash_last_state_unique_requires_unambiguous_match(request_factory):
    request = request_factory.get("/")
    state_a = statekit.stash_state(request, provider_id="provider", state={"a": True})
    state_b = statekit.stash_state(request, provider_id="provider", state={"b": True})

    # Two eligible states: matching one of them would be a guess.
    assert (
        statekit.unstash_last_state(request, provider_id="provider", unique=True)
        is None
    )
    with pytest.raises(PermissionDenied):
        statekit.unstash_last_state(
            request, provider_id="provider", unique=True, raises=True
        )
    assert set(statekit.get_states(request)) == {state_a, state_b}

    # With a matcher narrowing down to exactly one state, it is consumable.
    assert statekit.unstash_last_state(
        request,
        provider_id="provider",
        matcher=lambda state: state == {"b": True},
        unique=True,
    ) == {"b": True}
    assert set(statekit.get_states(request)) == {state_a}


@pytest.mark.django_db
def test_unstash_last_state_ignores_expired_states(request_factory):
    request = request_factory.get("/")
    expired_id = statekit.stash_state(
        request, provider_id="provider", state={"expired": True}
    )
    request.session[statekit.STATES_SESSION_KEY] = {
        expired_id: ({"expired": True}, 0.0, "provider", None)
    }
    request.session.save()
    assert statekit.unstash_last_state(request, provider_id="provider") is None
    # Reclaimed as part of the lookup.
    assert statekit.get_states(request) == {}


@pytest.mark.django_db
def test_gc_states_drops_malformed_entries():
    now = time.time()
    states = {
        "ok": ({"id": "ok"}, now, "provider", None),
        "legacy": ({"id": "legacy"}, now, "provider"),
        "broken": ("nope",),
    }
    statekit.gc_states(states)
    assert set(states) == {"ok", "legacy"}


@pytest.mark.django_db
def test_drop_state_only_removes_given_state(request_factory):
    request = request_factory.get("/")
    state_a = statekit.stash_state(request, provider_id="provider", state={"a": True})
    state_b = statekit.stash_state(request, provider_id="provider", state={"b": True})
    statekit.drop_state(request, state_id=state_a)
    assert set(statekit.get_states(request)) == {state_b}
    statekit.drop_state(request, state_id=state_a)
    assert set(statekit.get_states(request)) == {state_b}
