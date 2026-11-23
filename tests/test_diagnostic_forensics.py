"""Forensic, independently re-runnable tests for MSAL diagnostic headers.

Background
----------
MSAL emits three diagnostic headers on token requests:

``client-request-id``
    Identity of *this* invocation. It is what an operator quotes to the
    service owner, so the forensic question is always "which identity read
    this evidence".

``x-client-current-telemetry``
    ``4|<api_id>,<cache_refresh>|`` for the call in flight.

``x-client-last-telemetry``
    Offline buffer of *prior* activity, as ``4|<success_count>|<api>,<corr>,...|<err>,...|``.
    It is written by earlier calls on the same app object and read by the
    next *wire* call. This is the header colleagues misread: a failure that
    happened somewhere else shows up here, so it can be mistaken for the
    failure of the current request.

The hazard
----------
A local cache hit is a success, but it is never sent on the wire. A local
cache miss is not a failure, and is never sent either. When the next real
request is sent, the offline buffer describes the *previous* call(s). An
operator who only reads ``x-client-last-telemetry`` can therefore attribute
a stale record to the current identity.

How these tests collect evidence
--------------------------------
Each test uses a local HTTP double that records every request verbatim.
Nothing leaves the process: OIDC discovery is patched, and no GET reaches
the recorder. Every file is standalone (``python -m pytest -q
tests/test_diagnostic_forensics.py``), needs no network, no lab secrets and
no ordering relative to other test modules.

Privacy contract
----------------
Tests assert only correlation identifiers and diagnostic categories
(api id, cache-refresh reason, success count). Temporary authentication
material (access token, refresh token, device code, error description)
lives in the double only, never in an assertion message or in test output.
"""

import json
import unittest
from unittest.mock import patch

from msal import PublicClientApplication
from msal.telemetry import (
    CLIENT_CURRENT_TELEMETRY, CLIENT_LAST_TELEMETRY, CLIENT_REQUEST_ID,
    NON_SILENT_CALL, FORCE_REFRESH,
)
from tests.http_client import MinimalResponse
from tests.test_token_cache import build_response


# ---------------------------------------------------------------------------
# Test doubles: every value below is temporary and appears only inside them.
# ---------------------------------------------------------------------------

_AUTHORITY = "https://login.microsoftonline.com/forensic-tenant"
_OIDC = {
    "authorization_endpoint": _AUTHORITY + "/oauth2/v2.0/authorize",
    "token_endpoint": _AUTHORITY + "/oauth2/v2.0/token",
    "device_authorization_endpoint": _AUTHORITY + "/oauth2/v2.0/devicecode",
    "issuer": _AUTHORITY + "/v2.0",
}
_CLIENT_ID = "forensic-client-id"
_SCOPE = ["api://forensic-resource/.default"]
_HOME_ACCOUNT_ID = "forensic-uid.forensic-utid"

# Temporary material. It must never appear in an assertion message.
_TEMP_AT = "TEMP-ACCESS-TOKEN-DO-NOT-PRINT"
_TEMP_RT = "TEMP-REFRESH-TOKEN-DO-NOT-PRINT"
_TEMP_DEVICE_CODE = "TEMP-DEVICE-CODE-DO-NOT-PRINT"
_TEMP_ERROR_DESCRIPTION = "TEMP-ERROR-DESCRIPTION-DO-NOT-PRINT"

# Correlation identities are the only per-call values asserted by name.
_ID_LOCAL_FAILURE = "00000000-0000-0000-0000-0000000000a1"
_ID_CACHE_HIT = "00000000-0000-0000-0000-0000000000a2"
_ID_ACTUAL_RETRY = "00000000-0000-0000-0000-0000000000a3"
_ID_ACTUAL_REQUEST = "00000000-0000-0000-0000-0000000000a4"


class _RecordingHttpClient(object):
    """Records every request verbatim and serves queued responses.

    OIDC discovery is patched in ``setUp``, so no ``get`` is expected at all.
    Any ``get`` here means a test is not offline: fail loudly instead of
    silently reaching a network that may not exist.
    """

    def __init__(self, token_responses):
        self._token_responses = list(token_responses)
        self.posts = []  # Evidence: list of {"url", "params", "data", "headers"}

    def get(self, url, params=None, headers=None, **kwargs):
        raise AssertionError(
            "Unexpected GET; OIDC discovery is patched, so this suite is offline: %s"
            % url)

    def post(self, url, params=None, data=None, headers=None, **kwargs):
        self.posts.append({
            "url": url,
            "params": params,
            "data": dict(data or {}),
            "headers": dict(headers or {}),
        })
        return self._token_responses.pop(0)

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Evidence readers. They expose identifiers and categories only.
# ---------------------------------------------------------------------------

def _current(header):
    """Parse ``4|<api_id>,<cache_refresh>|`` into (api_id, cache_refresh)."""
    version, payload, _ = header.split("|")
    assert version == "4"
    api_id, cache_refresh = payload.split(",")
    return api_id, int(cache_refresh)


def _last(header):
    """Parse ``4|<success>|<pairs>|<errors>|`` into (success, pairs, errors)."""
    version, success, failed_pairs, errors, _ = header.split("|")
    assert version == "4"
    pairs = []
    if failed_pairs:
        parts = failed_pairs.split(",")
        pairs = [
            (parts[i], parts[i + 1]) for i in range(0, len(parts), 2)
        ]
    error_categories = [e for e in errors.split(",") if e] if errors else []
    return int(success), pairs, error_categories


def _evidence(call):
    """Return (request_id, current, last) from one recorded wire call."""
    headers = call["headers"]
    return (
        headers.get(CLIENT_REQUEST_ID),
        _current(headers[CLIENT_CURRENT_TELEMETRY]),
        _last(headers[CLIENT_LAST_TELEMETRY]),
    )


class _ForensicTestCase(unittest.TestCase):
    """Builds an app whose HTTP and OIDC discovery are fully local."""

    def setUp(self):
        self._discovery = patch("msal.authority.tenant_discovery", return_value=_OIDC)
        self._discovery.start()
        self.addCleanup(self._discovery.stop)

    def new_app(self, token_responses=()):
        http = _RecordingHttpClient(token_responses)
        app = PublicClientApplication(
            _CLIENT_ID,
            authority=_AUTHORITY,
            instance_discovery=False,
            http_client=http,
        )
        return app, http

    def seed_cache(self, app, *, expires_in=3600, with_refresh_token=True,
                   access_token=_TEMP_AT):
        """Populate one account. Returns the account dict for silent calls."""
        response = build_response(
            uid="forensic-uid",
            utid="forensic-utid",
            access_token=access_token,
            expires_in=expires_in,
            **({"refresh_token": _TEMP_RT} if with_refresh_token else {})
        )
        app.token_cache.add({
            "client_id": _CLIENT_ID,
            "scope": _SCOPE,
            "token_endpoint": _AUTHORITY + "/oauth2/v2.0/token",
            "response": response,
        })
        return {"home_account_id": _HOME_ACCOUNT_ID}

    def device_flow(self, correlation_id):
        return {
            "device_code": _TEMP_DEVICE_CODE,
            "interval": 0,
            PublicClientApplication.DEVICE_FLOW_CORRELATION_ID: correlation_id,
        }

    def actual_request(self, app, http, correlation_id, *, error=None):
        """Perform one real (wire) device-flow call with a fixed identity."""
        body = ({"error": error, "error_description": _TEMP_ERROR_DESCRIPTION}
                if error else {"access_token": _TEMP_AT})
        http._token_responses = [MinimalResponse(
            status_code=400 if error else 200, text=json.dumps(body))]
        return app.acquire_token_by_device_flow(
            self.device_flow(correlation_id), post=http.post)


# ---------------------------------------------------------------------------
# Class 1: silent cache evidence
# ---------------------------------------------------------------------------

class SilentCacheEvidenceTest(_ForensicTestCase):
    """A cache hit succeeds locally, yet never becomes wire evidence."""

    def test_cache_hit_sends_nothing_but_counts_one_success(self):
        app, http = self.new_app()
        account = self.seed_cache(app)

        result = app.acquire_token_silent(_SCOPE, account)

        self.assertEqual("cache", result[app._TOKEN_SOURCE])
        self.assertEqual([], http.posts, "A cache hit must not produce a POST")
        # Read what the next request would transmit, without sending it.
        last = _last(app._build_telemetry_context(-1)
                     .generate_headers()[CLIENT_LAST_TELEMETRY])
        self.assertEqual((1, [], []), last,
            "A cache hit is one success, never a failed request or error")

    def test_next_real_request_attributes_the_hit_to_its_own_identity(self):
        """The hit is counted, but read under the *retry's* identity, not its own."""
        app, http = self.new_app([MinimalResponse(
            status_code=200, text=json.dumps({"access_token": _TEMP_AT}))])
        account = self.seed_cache(app)

        app.acquire_token_silent(_SCOPE, account)  # Local hit; no wire
        self.assertEqual([], http.posts)

        with patch("msal.telemetry._get_new_correlation_id",
                   return_value=_ID_ACTUAL_RETRY):
            app.acquire_token_silent(
                _SCOPE, account, force_refresh=True, post=http.post)

        self.assertEqual(1, len(http.posts), "Only the forced refresh goes on the wire")
        request_id, current, last = _evidence(http.posts[0])

        self.assertEqual(_ID_ACTUAL_RETRY, request_id,
            "The wire identity belongs to the refresh, not to the cache hit")
        self.assertEqual((app.ACQUIRE_TOKEN_SILENT_ID, FORCE_REFRESH), current)
        self.assertEqual(1, last[0], "The local hit is the only counted success")
        self.assertEqual([], last[1], "A cache hit is not a failed request")
        self.assertEqual([], last[2], "A cache hit is not an error")

    def test_local_cache_miss_is_not_a_failure_and_not_transmitted(self):
        """A miss returns None locally; the next request reports zero activity."""
        app, http = self.new_app()

        result = app.acquire_token_silent(_SCOPE, {"home_account_id": _HOME_ACCOUNT_ID})

        self.assertIsNone(result, "An empty cache is a local None, not an error")
        self.assertEqual([], http.posts, "A local miss must not produce a POST")

        self.actual_request(app, http, _ID_ACTUAL_REQUEST)

        self.assertEqual(1, len(http.posts))
        request_id, current, last = _evidence(http.posts[0])
        self.assertEqual(_ID_ACTUAL_REQUEST, request_id)
        self.assertEqual((app.ACQUIRE_TOKEN_BY_DEVICE_FLOW_ID, NON_SILENT_CALL), current)
        self.assertEqual((0, [], []), last,
            "The local miss left no success counter and no error record")


# ---------------------------------------------------------------------------
# Class 2: real-request evidence
# ---------------------------------------------------------------------------

class RealRequestEvidenceTest(_ForensicTestCase):
    """A genuine wire failure is recorded under the identity that sent it."""

    def test_wire_failure_is_read_under_the_identity_that_sent_it(self):
        app, http = self.new_app()

        result = self.actual_request(
            app, http, _ID_ACTUAL_REQUEST, error="invalid_grant")

        self.assertEqual("invalid_grant", result.get("error"))
        self.assertEqual(1, len(http.posts))

        request_id, current, last = _evidence(http.posts[0])
        self.assertEqual(_ID_ACTUAL_REQUEST, request_id)
        self.assertEqual((app.ACQUIRE_TOKEN_BY_DEVICE_FLOW_ID, NON_SILENT_CALL), current)
        # The failing request carried the *prior* buffer (empty); it is only
        # recorded for the next transmission. This is the stale-read hazard.
        self.assertEqual((0, [], []), last,
            "The current failure is not visible to the current request")

    def test_diagnostic_headers_carry_no_authentication_material(self):
        app, http = self.new_app()

        self.actual_request(app, http, _ID_ACTUAL_REQUEST, error="invalid_grant")

        serialized_headers = json.dumps(
            {key.lower(): value for key, value in http.posts[0]["headers"].items()})
        for secret in (_TEMP_AT, _TEMP_RT, _TEMP_DEVICE_CODE,
                       _TEMP_ERROR_DESCRIPTION):
            self.assertNotIn(secret, serialized_headers)

        _evidence(http.posts[0])  # Parses cleanly, i.e. only ids and categories


# ---------------------------------------------------------------------------
# Class 3: one failure, then a retry
# ---------------------------------------------------------------------------

class FailureThenRetryEvidenceTest(_ForensicTestCase):
    """After one failure, the next wire call reads that failure under its own id.

    Timeline for the retry test:
        F  real wire failure, identity ``_ID_LOCAL_FAILURE``
        R  actual retry, identity ``_ID_ACTUAL_RETRY``

    The decisive evidence: R's ``x-client-last-telemetry`` names F's api id and
    F's correlation id, while R's ``client-request-id`` is R itself. Even
    though F did reach the wire, no request ever carries its own failure:
    F observed an empty buffer, and only R reads F.
    """

    def test_retry_reads_the_single_prior_failure_under_its_own_identity(self):
        app, http = self.new_app()

        first = self.actual_request(
            app, http, _ID_LOCAL_FAILURE, error="invalid_grant")
        self.assertEqual("invalid_grant", first.get("error"))

        retry = self.actual_request(app, http, _ID_ACTUAL_RETRY)
        self.assertEqual("identity_provider", retry[app._TOKEN_SOURCE])

        self.assertEqual(2, len(http.posts), "A 400 is not cached; the retry hits the wire")

        fail_id, _, fail_last = _evidence(http.posts[0])
        retry_id, retry_current, retry_last = _evidence(http.posts[1])

        self.assertEqual(_ID_LOCAL_FAILURE, fail_id)
        self.assertEqual((0, [], []), fail_last,
            "The first failure cannot observe itself")

        self.assertEqual(_ID_ACTUAL_RETRY, retry_id)
        self.assertEqual((app.ACQUIRE_TOKEN_BY_DEVICE_FLOW_ID, NON_SILENT_CALL),
                         retry_current)
        self.assertEqual(
            (0, [(app.ACQUIRE_TOKEN_BY_DEVICE_FLOW_ID, _ID_LOCAL_FAILURE)],
             ["invalid_grant"]),
            retry_last,
            "The retry reads the earlier failure by api id and correlation id")

    def test_local_failure_then_cache_hit_then_actual_retry(self):
        """L (local failure) -> H (cache hit, unsent) -> R (actual retry).

        Identities injected:
            L: silent with an expired AT and no RT -> local None
            H: silent with a fresh AT -> local cache hit
            R: silent with force_refresh -> the only wire call

        Proof obligations:
            * R reads the offline buffer as one success (H) and zero errors;
              neither L nor H produced a wire request.
            * R's own identity is R, never H; H's identity never reaches the
              wire at all.
        """
        app, http = self.new_app([MinimalResponse(
            status_code=200, text=json.dumps({"access_token": _TEMP_AT}))])

        # L: expired access token only, so there is no RT to refresh with.
        account = self.seed_cache(app, expires_in=-1, with_refresh_token=False)
        with patch("msal.telemetry._get_new_correlation_id",
                   return_value=_ID_LOCAL_FAILURE):
            local = app.acquire_token_silent(_SCOPE, account)
        self.assertIsNone(local, "Expired cache without RT fails locally")
        self.assertEqual([], http.posts, "L never reaches the wire")

        # H: a fresh access token plus an RT, so silent lookup succeeds locally.
        account = self.seed_cache(app, expires_in=3600, with_refresh_token=True)
        with patch("msal.telemetry._get_new_correlation_id",
                   return_value=_ID_CACHE_HIT):
            hit = app.acquire_token_silent(_SCOPE, account)
        self.assertEqual("cache", hit[app._TOKEN_SOURCE], "H is a local cache hit")
        self.assertEqual([], http.posts, "H never reaches the wire")

        # R: force a refresh so exactly one real request is sent.
        with patch("msal.telemetry._get_new_correlation_id",
                   return_value=_ID_ACTUAL_RETRY):
            retried = app.acquire_token_silent(
                _SCOPE, account, force_refresh=True, post=http.post)

        self.assertEqual("identity_provider", retried[app._TOKEN_SOURCE])
        self.assertEqual(1, len(http.posts))

        request_id, current, last = _evidence(http.posts[0])
        self.assertEqual(_ID_ACTUAL_RETRY, request_id,
            "The retry is read under its own identity, not the cache hit's")
        self.assertNotEqual(_ID_CACHE_HIT, request_id,
            "The cache hit's identity was never transmitted")
        self.assertEqual((app.ACQUIRE_TOKEN_SILENT_ID, FORCE_REFRESH), current)
        self.assertEqual(1, last[0],
            "H contributed the only success; L contributed no wire activity")
        self.assertEqual([], last[1], "Neither L nor H was a failed request")
        self.assertEqual([], last[2], "Neither L nor H produced an error category")


if __name__ == "__main__":
    unittest.main()
