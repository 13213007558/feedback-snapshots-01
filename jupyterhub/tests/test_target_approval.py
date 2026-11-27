"""Tests for explicit target approval during Hub authentication.

These tests use a recording transport and reserved TEST-NET addresses so no
real network traffic is produced:

- ``192.0.2.10`` (TEST-NET-1) is the approved origin
- ``198.51.100.20`` (TEST-NET-2) is a health-check-only candidate
"""

import json

import pytest
from tornado.web import HTTPError

from ..services.auth import (
    AUTH_CATEGORY_SERVICE,
    AUTH_CATEGORY_USER,
    HubAuth,
)
from ..services.targets import (
    TargetNotApproved,
    TargetPolicy,
    TargetUnavailable,
    normalize_target,
    replace_origin,
)

APPROVED = "http://192.0.2.10:8081"
CANDIDATE = "http://198.51.100.20:8081"


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status = status
        self._payload = payload if payload is not None else {"name": "alice"}

    async def text(self):
        return json.dumps(self._payload)


class RecordingTransport:
    """Record every request that actually reaches a target."""

    def __init__(self, fail_targets=()):
        self.calls = []
        self.fail_targets = set(fail_targets)

    async def __call__(self, url, *, method="GET", raise_for_status=True, **kwargs):
        from aiohttp import ClientConnectionError

        target = normalize_target(url)
        self.calls.append(
            {
                "target": target,
                "url": url,
                "method": method,
                "authorization": kwargs.get("headers", {}).get("Authorization"),
            }
        )
        if target in self.fail_targets:
            self.fail_targets.discard(target)
            raise ClientConnectionError("connection reset by peer")
        return FakeResponse()

    @property
    def targets(self):
        return [call["target"] for call in self.calls]


@pytest.fixture
def make_hub_auth():
    created = []

    def _make(approved, candidates, transport):
        auth = HubAuth(
            approved_api_urls=approved,
            candidate_api_urls=candidates,
            transport=transport,
            cache_max_age=300,
        )
        created.append(auth)
        return auth

    yield _make
    for auth in created:
        auth.clear_instance()


def test_normalize_target():
    assert normalize_target("HTTP://Example.COM:80/path?x=1") == "http://example.com"
    assert normalize_target("https://example.com:443/") == "https://example.com"
    assert normalize_target("https://example.com:8443/") == "https://example.com:8443"
    assert normalize_target("http+unix://%2Ftmp%2Fhub.sock/x") == (
        "http+unix://%2Ftmp%2Fhub.sock"
    )
    with pytest.raises(ValueError):
        normalize_target("not-a-url")


def test_replace_origin_keeps_endpoint():
    assert replace_origin(f"{APPROVED}/hub/api/user", CANDIDATE) == (
        f"{CANDIDATE}/hub/api/user"
    )


def test_policy_cache_invalidated_on_config_change():
    policy = TargetPolicy()
    policy.set_config([APPROVED], [APPROVED, CANDIDATE])
    assert policy.select() == APPROVED
    assert policy.cached_target == APPROVED

    # unrelated rewrite keeps the cached selection
    assert policy.set_config([APPROVED], [APPROVED, CANDIDATE]) is False
    assert policy.cached_target == APPROVED

    # removing the approval must drop the cached selection
    policy.set_config([CANDIDATE], [APPROVED, CANDIDATE])
    assert policy.cached_target is None
    assert policy.select() == CANDIDATE


def test_policy_skips_unapproved_candidate():
    policy = TargetPolicy()
    policy.set_config([APPROVED], [CANDIDATE, APPROVED])
    assert policy.select() == APPROVED
    assert policy.last_skipped == (CANDIDATE,)
    assert policy.health_check_targets() == [CANDIDATE]


def test_policy_no_approved_target():
    policy = TargetPolicy()
    policy.set_config([], [CANDIDATE])
    with pytest.raises(TargetNotApproved):
        policy.select()


async def test_first_connection_uses_approved_target(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [APPROVED, CANDIDATE], transport)

    user = await auth.user_for_token("tok-1", use_cache=False, sync=False)
    assert user == {"name": "alice"}
    assert transport.targets == [APPROVED]
    assert transport.calls[0]["authorization"] == "token tok-1"
    assert transport.calls[0]["url"] == f"{APPROVED}/hub/api/user"

    categories = [(r.category, r.target, r.outcome) for r in auth.auth_records]
    assert categories == [(AUTH_CATEGORY_USER, APPROVED, "success")]


async def test_unapproved_candidate_never_receives_identity(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [CANDIDATE, APPROVED], transport)

    await auth.user_for_token("tok-secret", use_cache=False, sync=False)

    # the unapproved candidate is never contacted ...
    assert CANDIDATE not in transport.targets
    # ... but the skipped attempt is recorded
    skipped = [r for r in auth.auth_records if r.outcome == "not-approved"]
    assert [(r.target, r.approval) for r in skipped] == [(CANDIDATE, "unapproved")]


async def test_cached_identity_reused(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [APPROVED, CANDIDATE], transport)

    first = await auth.user_for_token("tok-1", sync=False)
    second = await auth.user_for_token("tok-1", sync=False)
    assert first == second
    # only one authenticated call was made
    assert transport.targets == [APPROVED]


async def test_trust_change_clears_cache_and_switches_target(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [APPROVED, CANDIDATE], transport)

    await auth.user_for_token("tok-1", sync=False)
    assert transport.targets == [APPROVED]

    # approval moves to the candidate; the old cached response must not be
    # reused and the old target must not receive identity again
    auth.approved_api_urls = [CANDIDATE]
    auth.candidate_api_urls = [CANDIDATE, APPROVED]

    await auth.user_for_token("tok-1", sync=False)
    assert transport.targets == [APPROVED, CANDIDATE]
    assert all(
        call["target"] == CANDIDATE for call in transport.calls[1:]
    )


async def test_retry_rotates_to_next_approved_target(make_hub_auth):
    transport = RecordingTransport(fail_targets=[APPROVED])
    auth = make_hub_auth([APPROVED, CANDIDATE], [APPROVED, CANDIDATE], transport)

    user = await auth.user_for_token("tok-2", use_cache=False, sync=False)
    assert user == {"name": "alice"}
    assert transport.targets == [APPROVED, CANDIDATE]
    assert transport.calls[1]["authorization"] == "token tok-2"

    outcomes = [(r.target, r.outcome) for r in auth.auth_records]
    assert outcomes == [(APPROVED, "network-error"), (CANDIDATE, "success")]


async def test_retry_never_falls_back_to_unapproved(make_hub_auth):
    transport = RecordingTransport(fail_targets=[APPROVED])
    auth = make_hub_auth([APPROVED], [APPROVED, CANDIDATE], transport)

    with pytest.raises(TargetUnavailable) as excinfo:
        await auth.user_for_token("tok-3", use_cache=False, sync=False)

    assert excinfo.value.status_code == 503
    assert transport.targets == [APPROVED]
    assert CANDIDATE not in transport.targets
    # unapproved target is only recorded as skipped, never called
    assert {r.outcome for r in auth.auth_records} == {
        "network-error",
        "not-approved",
    }


async def test_no_approved_target_is_forbidden(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([], [CANDIDATE], transport)

    with pytest.raises(TargetNotApproved) as excinfo:
        await auth.user_for_token("tok-4", use_cache=False, sync=False)

    assert excinfo.value.status_code == 403
    assert transport.calls == []


async def test_network_failure_and_approval_failure_are_distinct(make_hub_auth):
    transport = RecordingTransport(fail_targets=[APPROVED, CANDIDATE])
    auth = make_hub_auth([APPROVED, CANDIDATE], [APPROVED, CANDIDATE], transport)
    with pytest.raises(TargetUnavailable) as network_error:
        await auth.user_for_token("tok-5", use_cache=False, sync=False)

    transport2 = RecordingTransport()
    auth2 = make_hub_auth([], [CANDIDATE], transport2)
    with pytest.raises(TargetNotApproved) as approval_error:
        await auth2.user_for_token("tok-5", use_cache=False, sync=False)

    assert network_error.value.status_code == 503
    assert approval_error.value.status_code == 403
    assert network_error.value.status_code != approval_error.value.status_code


async def test_service_and_user_categories_recorded(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [APPROVED], transport)

    # user token path
    await auth.user_for_token("user-token", use_cache=False, sync=False)
    # explicit service-token call
    await auth._api_request(
        "GET",
        f"{APPROVED}/hub/api/user",
        category=AUTH_CATEGORY_SERVICE,
        headers={"Authorization": "token service-token"},
    )

    categories = [r.category for r in auth.auth_records]
    assert categories == [AUTH_CATEGORY_USER, AUTH_CATEGORY_SERVICE]


async def test_http_error_does_not_retry_other_target(make_hub_auth):
    """An HTTP error is not a transport failure and must not select a new target."""

    class ErrorTransport(RecordingTransport):
        async def __call__(self, url, *, method="GET", **kwargs):
            await super().__call__(url, method=method, **kwargs)
            response = FakeResponse()
            response.status = 500
            return response

    transport = ErrorTransport()
    auth = make_hub_auth([APPROVED, CANDIDATE], [APPROVED, CANDIDATE], transport)

    with pytest.raises(HTTPError):
        await auth._api_request("GET", f"{APPROVED}/hub/api/user")

    assert transport.targets == [APPROVED]
    assert [r.outcome for r in auth.auth_records] == ["http-error"]


async def test_health_check_probes_only_unapproved_without_credentials(make_hub_auth):
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [APPROVED, CANDIDATE], transport)

    recovered = await auth.probe_health_targets()

    assert recovered == {CANDIDATE: "success"}
    # health check contacted the candidate, but never sent an Authorization header
    assert transport.targets == [CANDIDATE]
    assert transport.calls[0]["authorization"] is None
    assert transport.calls[0]["url"] == f"{CANDIDATE}/hub/health"
    health_records = [
        r for r in auth.auth_records if r.category == AUTH_CATEGORY_SERVICE
    ]
    assert health_records == []
    assert all(r.category == "health-check" for r in auth.auth_records)
    assert all(r.approval == "unapproved" for r in auth.auth_records)


async def test_stale_cached_target_not_reused_after_approval_change(make_hub_auth):
    """A cached selection must not lend approval to a newly configured target."""
    transport = RecordingTransport()
    auth = make_hub_auth([APPROVED], [APPROVED], transport)

    # establish a cached connection to the approved target
    await auth.user_for_token("tok-1", sync=False)
    assert auth._target_policy.cached_target == APPROVED

    # trust configuration changes: old target removed, a new one approved
    auth.approved_api_urls = [CANDIDATE]
    auth.candidate_api_urls = [APPROVED, CANDIDATE]

    # the cached selection is cleared immediately on config change, so the
    # next identity request can only go to the newly approved target
    assert auth._target_policy.cached_target is None
    await auth.user_for_token("tok-1", sync=False)

    assert transport.targets == [APPROVED, CANDIDATE]
    assert transport.calls[-1]["target"] == CANDIDATE
    # the removed target never receives identity material after the change
    assert all(c["target"] == CANDIDATE for c in transport.calls[1:])
