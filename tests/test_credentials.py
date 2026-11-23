# Copyright 2016 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import os
import threading
from unittest import mock


import pytest  # type: ignore

from google.auth import _helpers
from google.auth import credentials
from google.auth import environment_vars
from google.auth import exceptions
from google.oauth2 import _client


class CredentialsImpl(credentials.CredentialsWithTrustBoundary):
    def _perform_refresh_token(self, request):
        self.token = "refreshed-token"
        self.expiry = (
            datetime.datetime.utcnow()
            + _helpers.REFRESH_THRESHOLD
            + datetime.timedelta(seconds=5)
        )

    def with_quota_project(self, quota_project_id):
        raise NotImplementedError()

    def _build_trust_boundary_lookup_url(self):
        # Using self.token here to make the URL dynamic for testing purposes
        return "http://mock.url/lookup_for_{}".format(self.token)


class CredentialsImplWithMetrics(credentials.Credentials):
    def refresh(self, request):
        self.token = request

    def _metric_header_for_usage(self):
        return "foo"


def test_credentials_constructor():
    credentials = CredentialsImpl()
    assert not credentials.token
    assert not credentials.expiry
    assert not credentials.expired
    assert not credentials.valid
    assert credentials.universe_domain == "googleapis.com"
    assert not credentials._use_non_blocking_refresh


def test_credentials_get_cred_info():
    credentials = CredentialsImpl()
    assert not credentials.get_cred_info()


def test_with_non_blocking_refresh():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()
    assert c._use_non_blocking_refresh


def test_expired_and_valid():
    credentials = CredentialsImpl()
    credentials.token = "token"

    assert credentials.valid
    assert not credentials.expired

    # Set the expiration to one second more than now plus the clock skew
    # accomodation. These credentials should be valid.
    credentials.expiry = (
        _helpers.utcnow() + _helpers.REFRESH_THRESHOLD + datetime.timedelta(seconds=1)
    )

    assert credentials.valid
    assert not credentials.expired

    # Set the credentials expiration to now. Because of the clock skew
    # accomodation, these credentials should report as expired.
    credentials.expiry = _helpers.utcnow()

    assert not credentials.valid
    assert credentials.expired


def test_before_request():
    credentials = CredentialsImpl()
    request = mock.Mock()
    headers = {}

    # First call should call refresh, setting the token.
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert "x-allowed-locations" not in headers

    request = mock.Mock()
    headers = {}

    # Second call shouldn't call refresh.
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert "x-allowed-locations" not in headers


def test_before_request_with_trust_boundary():
    DUMMY_BOUNDARY = "0xA30"
    credentials = CredentialsImpl()
    credentials._trust_boundary = {"locations": [], "encodedLocations": DUMMY_BOUNDARY}
    request = mock.Mock()
    headers = {}

    # First call should call refresh, setting the token.
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert headers["x-allowed-locations"] == DUMMY_BOUNDARY

    request = mock.Mock()
    headers = {}

    # Second call shouldn't call refresh.
    credentials.before_request(request, "http://example.com", "GET", headers)
    assert credentials.valid
    assert credentials.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert headers["x-allowed-locations"] == DUMMY_BOUNDARY


def test_before_request_metrics():
    credentials = CredentialsImplWithMetrics()
    request = "token"
    headers = {}

    credentials.before_request(request, "http://example.com", "GET", headers)
    assert headers["x-goog-api-client"] == "foo"


def test_anonymous_credentials_ctor():
    anon = credentials.AnonymousCredentials()
    assert anon.token is None
    assert anon.expiry is None
    assert not anon.expired
    assert anon.valid


def test_anonymous_credentials_refresh():
    anon = credentials.AnonymousCredentials()
    request = object()
    with pytest.raises(ValueError):
        anon.refresh(request)


def test_anonymous_credentials_apply_default():
    anon = credentials.AnonymousCredentials()
    headers = {}
    anon.apply(headers)
    assert headers == {}
    with pytest.raises(ValueError):
        anon.apply(headers, token="TOKEN")


def test_anonymous_credentials_before_request():
    anon = credentials.AnonymousCredentials()
    request = object()
    method = "GET"
    url = "https://example.com/api/endpoint"
    headers = {}
    anon.before_request(request, method, url, headers)
    assert headers == {}


class ReadOnlyScopedCredentialsImpl(credentials.ReadOnlyScoped, CredentialsImpl):
    @property
    def requires_scopes(self):
        return super(ReadOnlyScopedCredentialsImpl, self).requires_scopes


def test_readonly_scoped_credentials_constructor():
    credentials = ReadOnlyScopedCredentialsImpl()
    assert credentials._scopes is None


def test_readonly_scoped_credentials_scopes():
    credentials = ReadOnlyScopedCredentialsImpl()
    credentials._scopes = ["one", "two"]
    assert credentials.scopes == ["one", "two"]
    assert credentials.has_scopes(["one"])
    assert credentials.has_scopes(["two"])
    assert credentials.has_scopes(["one", "two"])
    assert not credentials.has_scopes(["three"])

    # Test with default scopes
    credentials_with_default = ReadOnlyScopedCredentialsImpl()
    credentials_with_default._default_scopes = ["one", "two"]
    assert credentials_with_default.has_scopes(["one", "two"])
    assert not credentials_with_default.has_scopes(["three"])

    # Test with no scopes
    credentials_no_scopes = ReadOnlyScopedCredentialsImpl()
    assert not credentials_no_scopes.has_scopes(["one"])

    assert credentials_no_scopes.has_scopes([])


def test_readonly_scoped_credentials_requires_scopes():
    credentials = ReadOnlyScopedCredentialsImpl()
    assert not credentials.requires_scopes


class RequiresScopedCredentialsImpl(credentials.Scoped, CredentialsImpl):
    def __init__(self, scopes=None, default_scopes=None):
        super(RequiresScopedCredentialsImpl, self).__init__()
        self._scopes = scopes
        self._default_scopes = default_scopes

    @property
    def requires_scopes(self):
        return not self.scopes

    def with_scopes(self, scopes, default_scopes=None):
        return RequiresScopedCredentialsImpl(
            scopes=scopes, default_scopes=default_scopes
        )


def test_create_scoped_if_required_scoped():
    unscoped_credentials = RequiresScopedCredentialsImpl()
    scoped_credentials = credentials.with_scopes_if_required(
        unscoped_credentials, ["one", "two"]
    )

    assert scoped_credentials is not unscoped_credentials
    assert not scoped_credentials.requires_scopes
    assert scoped_credentials.has_scopes(["one", "two"])


def test_create_scoped_if_required_not_scopes():
    unscoped_credentials = CredentialsImpl()
    scoped_credentials = credentials.with_scopes_if_required(
        unscoped_credentials, ["one", "two"]
    )

    assert scoped_credentials is unscoped_credentials


def test_nonblocking_refresh_fresh_credentials():
    c = CredentialsImpl()

    c._refresh_worker = mock.MagicMock()

    request = mock.Mock()

    c.refresh(request)
    assert c.token_state == credentials.TokenState.FRESH

    c.with_non_blocking_refresh()
    c.before_request(request, "http://example.com", "GET", {})


def test_nonblocking_refresh_invalid_credentials():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()

    request = mock.Mock()
    headers = {}

    assert c.token_state == credentials.TokenState.INVALID

    c.before_request(request, "http://example.com", "GET", headers)
    assert c.token_state == credentials.TokenState.FRESH
    assert c.valid
    assert c.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert "x-identity-trust-boundary" not in headers


def test_nonblocking_refresh_stale_credentials():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()

    request = mock.Mock()
    headers = {}

    # Invalid credentials MUST require a blocking refresh.
    c.before_request(request, "http://example.com", "GET", headers)
    assert c.token_state == credentials.TokenState.FRESH
    assert not c._refresh_worker._worker

    c.expiry = (
        datetime.datetime.utcnow()
        + _helpers.REFRESH_THRESHOLD
        - datetime.timedelta(seconds=1)
    )

    # STALE credentials SHOULD spawn a non-blocking worker
    assert c.token_state == credentials.TokenState.STALE
    c.before_request(request, "http://example.com", "GET", headers)
    assert c._refresh_worker._worker is not None

    assert c.token_state == credentials.TokenState.FRESH
    assert c.valid
    assert c.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert "x-identity-trust-boundary" not in headers


def test_nonblocking_refresh_failed_credentials():
    c = CredentialsImpl()
    c.with_non_blocking_refresh()

    request = mock.Mock()
    headers = {}

    # Invalid credentials MUST require a blocking refresh.
    c.before_request(request, "http://example.com", "GET", headers)
    assert c.token_state == credentials.TokenState.FRESH
    assert not c._refresh_worker._worker

    c.expiry = (
        datetime.datetime.utcnow()
        + _helpers.REFRESH_THRESHOLD
        - datetime.timedelta(seconds=1)
    )

    # STALE credentials SHOULD spawn a non-blocking worker
    assert c.token_state == credentials.TokenState.STALE
    c._refresh_worker._worker = mock.MagicMock()
    c._refresh_worker._worker._error_info = "Some Error"
    c.before_request(request, "http://example.com", "GET", headers)
    assert c._refresh_worker._worker is not None

    assert c.token_state == credentials.TokenState.FRESH
    assert c.valid
    assert c.token == "refreshed-token"
    assert headers["authorization"] == "Bearer refreshed-token"
    assert "x-identity-trust-boundary" not in headers


def test_token_state_no_expiry():
    c = CredentialsImpl()

    request = mock.Mock()
    c.refresh(request)

    c.expiry = None
    assert c.token_state == credentials.TokenState.FRESH

    c.before_request(request, "http://example.com", "GET", {})


class TestCredentialsWithTrustBoundary(object):
    @mock.patch.object(_client, "_lookup_trust_boundary")
    def test_lookup_trust_boundary_env_var_not_true(self, mock_lookup_tb):
        creds = CredentialsImpl()
        request = mock.Mock()

        # Ensure env var is not "true"
        with mock.patch.dict(
            os.environ, {environment_vars.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED: "false"}
        ):
            result = creds._refresh_trust_boundary(request)

        assert result is None
        mock_lookup_tb.assert_not_called()

    @mock.patch.object(_client, "_lookup_trust_boundary")
    def test_lookup_trust_boundary_env_var_missing(self, mock_lookup_tb):
        creds = CredentialsImpl()
        request = mock.Mock()

        # Ensure env var is missing
        with mock.patch.dict(os.environ, clear=True):
            result = creds._refresh_trust_boundary(request)

        assert result is None
        mock_lookup_tb.assert_not_called()

    @mock.patch.object(_client, "_lookup_trust_boundary")
    def test_lookup_trust_boundary_non_default_universe(self, mock_lookup_tb):
        creds = CredentialsImpl()
        creds._universe_domain = "my.universe.com"  # Non-GDU
        request = mock.Mock()

        with mock.patch.dict(
            os.environ, {environment_vars.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED: "true"}
        ):
            result = creds._refresh_trust_boundary(request)

        assert result is None
        mock_lookup_tb.assert_not_called()

    @mock.patch.object(_client, "_lookup_trust_boundary")
    def test_lookup_trust_boundary_calls_client_and_build_url(self, mock_lookup_tb):
        creds = CredentialsImpl()
        creds.token = "test_token"  # For _build_trust_boundary_lookup_url
        request = mock.Mock()
        expected_url = "http://mock.url/lookup_for_test_token"
        expected_boundary_info = {"encodedLocations": "0xABC"}
        mock_lookup_tb.return_value = expected_boundary_info

        # Mock _build_trust_boundary_lookup_url to ensure it's called.
        mock_build_url = mock.Mock(return_value=expected_url)
        creds._build_trust_boundary_lookup_url = mock_build_url

        with mock.patch.dict(
            os.environ, {environment_vars.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED: "true"}
        ):
            result = creds._lookup_trust_boundary(request)

        assert result == expected_boundary_info
        mock_build_url.assert_called_once()
        expected_headers = {"authorization": "Bearer test_token"}
        mock_lookup_tb.assert_called_once_with(
            request, expected_url, headers=expected_headers
        )

    @mock.patch.object(_client, "_lookup_trust_boundary")
    def test_lookup_trust_boundary_build_url_returns_none(self, mock_lookup_tb):
        creds = CredentialsImpl()
        request = mock.Mock()

        # Mock _build_trust_boundary_lookup_url to return None
        mock_build_url = mock.Mock(return_value=None)
        creds._build_trust_boundary_lookup_url = mock_build_url

        with mock.patch.dict(
            os.environ, {environment_vars.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED: "true"}
        ):
            with pytest.raises(
                exceptions.InvalidValue,
                match="Failed to build trust boundary lookup URL.",
            ):
                creds._lookup_trust_boundary(request)

        mock_build_url.assert_called_once()  # Ensure _build_trust_boundary_lookup_url was called
        mock_lookup_tb.assert_not_called()  # Ensure _client.lookup_trust_boundary was not called

    @mock.patch("google.auth.credentials._LOGGER")
    @mock.patch("google.auth._helpers.is_logging_enabled", return_value=True)
    @mock.patch.object(_client, "_lookup_trust_boundary")
    def test_refresh_trust_boundary_fails_with_cached_data_and_logging(
        self, mock_lookup_tb, mock_is_logging_enabled, mock_logger
    ):
        creds = CredentialsImpl()
        creds._trust_boundary = {"encodedLocations": "0xABC"}
        request = mock.Mock()

        refresh_error = exceptions.RefreshError("Lookup failed")
        mock_lookup_tb.side_effect = refresh_error

        with mock.patch.dict(
            os.environ, {environment_vars.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED: "true"}
        ):
            creds.refresh(request)

        mock_lookup_tb.assert_called_once()
        mock_is_logging_enabled.assert_called_once_with(mock_logger)
        mock_logger.debug.assert_called_once_with(
            "Using cached trust boundary due to refresh error: %s", refresh_error
        )


class BlockingBoundaryTransport:
    """Test transport that pauses the first trust boundary lookup.

    The lookup blocks on an event until :meth:`release` is called, letting a
    test simulate concurrent business requests while a synchronized refresh
    is still in flight. Every outbound call is recorded so tests can assert
    on what the transport layer actually observed.
    """

    def __init__(self, boundary):
        self._boundary = boundary
        self._lookup_started = threading.Event()
        self._release = threading.Event()
        self.calls = []
        self.business_requests = []

    def lookup(self, request, url, headers=None):
        self.calls.append(("lookup", url, dict(headers or {})))
        self._lookup_started.set()
        # Pause here until the test releases the boundary query.
        if not self._release.wait(timeout=5):
            raise exceptions.RefreshError("Timed out waiting for test release.")
        return self._boundary

    def business(self, method, url, headers=None, **kwargs):
        record = (method, url, dict(headers or {}))
        self.calls.append(("business", url, dict(headers or {})))
        self.business_requests.append(record)
        response = mock.Mock()
        response.status = 200
        response.data = b"{}"
        return response

    def wait_until_lookup_started(self):
        assert self._lookup_started.wait(timeout=5)

    def release(self):
        self._release.set()


class SynchronizedTrustBoundaryCredentials(
    credentials.CredentialsWithTrustBoundary
):
    """Credentials whose refresh publishes distinct token/boundary pairs."""

    def __init__(self):
        super(SynchronizedTrustBoundaryCredentials, self).__init__()
        self.publication = 0

    def _perform_refresh_token(self, request):
        self.publication += 1
        self.token = "token-{}".format(self.publication)
        self.expiry = _helpers.utcnow() + datetime.timedelta(hours=1)

    def with_quota_project(self, quota_project_id):
        raise NotImplementedError()

    def _build_trust_boundary_lookup_url(self):
        return "http://mock.url/lookup"


class TestSynchronizedIdentityPublication(object):
    ENABLED = {environment_vars.GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED: "true"}

    def _make_credentials(self):
        creds = SynchronizedTrustBoundaryCredentials()
        return creds

    def test_refresh_publishes_token_and_boundary_together(self):
        creds = self._make_credentials()
        boundary = {"locations": ["us-central1"], "encodedLocations": "0xA30"}
        request = mock.Mock()

        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client, "_lookup_trust_boundary", return_value=boundary
        ) as mock_lookup:
            creds.refresh(request)

        assert creds.token == "token-1"
        assert creds._trust_boundary == boundary
        mock_lookup.assert_called_once()

    def test_failed_boundary_lookup_rolls_back_staged_token(self):
        creds = self._make_credentials()
        request = mock.Mock()

        # No cached boundary: a lookup failure must surface and the staged
        # token must not remain visible.
        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client,
            "_lookup_trust_boundary",
            side_effect=exceptions.RefreshError("boundary revoked"),
        ):
            with pytest.raises(exceptions.RefreshError):
                creds.refresh(request)

        # The staged token is discarded; no token/boundary pair is published.
        assert creds.token is None
        assert creds._trust_boundary is None
        assert creds.publication == 1

    def test_failed_lookup_keeps_cached_pair_within_window(self):
        creds = self._make_credentials()
        original_boundary = {"encodedLocations": "0xABC"}
        creds.token = "previous-token"
        creds.expiry = _helpers.utcnow() + datetime.timedelta(hours=1)
        creds._trust_boundary = original_boundary
        request = mock.Mock()

        # A cached boundary exists: a lookup failure is tolerated. The
        # refreshed token is published together with the still-valid cached
        # boundary as a single paired identity.
        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client,
            "_lookup_trust_boundary",
            side_effect=exceptions.RefreshError("temporary lookup failure"),
        ):
            creds.refresh(request)

        assert creds.token == "token-1"
        assert creds._trust_boundary == original_boundary

    def test_apply_uses_matching_token_and_boundary(self):
        creds = self._make_credentials()
        boundary = {"encodedLocations": "0xA30"}
        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client, "_lookup_trust_boundary", return_value=boundary
        ):
            creds.refresh(mock.Mock())

        headers = {}
        creds.apply(headers)
        assert headers["authorization"] == "Bearer token-1"
        assert headers["x-allowed-locations"] == "0xA30"

    def test_request_blocked_when_window_ends_before_refresh_completes(self):
        creds = self._make_credentials()
        boundary = {"encodedLocations": "0xA30"}
        transport = BlockingBoundaryTransport(boundary)

        # Start from an already approved but soon-to-expire identity pair.
        creds.token = "old-token"
        creds.expiry = _helpers.utcnow() + datetime.timedelta(seconds=30)
        creds._trust_boundary = {"encodedLocations": "0xOLD"}

        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client, "_lookup_trust_boundary", side_effect=transport.lookup
        ):
            # A synchronized refresh starts in the background. The token is
            # refreshed but the boundary query is paused by the transport.
            refresh_thread = threading.Thread(
                target=creds._refresh_synchronized, args=(mock.Mock(), True),
            )
            refresh_thread.start()
            transport.wait_until_lookup_started()

            # Simulate the old approval window ending while the lookup is
            # still paused. The second business call must not reach the
            # transport until the synchronized refresh publishes.
            creds.expiry = _helpers.utcnow() - datetime.timedelta(seconds=1)
            business_result = {}

            def make_business_call():
                try:
                    headers = {}
                    creds.before_request(
                        mock.Mock(), "GET", "http://business/api", headers
                    )
                    transport.business("GET", "http://business/api", headers)
                    business_result["status"] = "sent"
                    business_result["headers"] = headers
                except exceptions.GoogleAuthError as error:
                    business_result["status"] = "blocked"
                    business_result["error"] = error

            caller = threading.Thread(target=make_business_call)
            caller.start()
            # Give the caller time to reach the in-flight refresh and wait.
            caller.join(timeout=1)

            # The transport must not observe a new business request while the
            # boundary query is paused.
            assert transport.business_requests == []
            assert caller.is_alive()

            # Resume the boundary query; the token and boundary are then
            # published as one identity pair and the waiting call proceeds.
            transport.release()
            refresh_thread.join(timeout=5)
            caller.join(timeout=5)

        assert business_result["status"] == "sent"
        assert len(transport.business_requests) == 1

        # Both identity pieces must come from the same new publication.
        assert creds.token == "token-1"
        assert creds._trust_boundary == boundary
        sent_headers = business_result["headers"]
        assert sent_headers["authorization"] == "Bearer token-1"
        assert sent_headers["x-allowed-locations"] == "0xA30"

    def test_old_pair_usable_within_window_while_refresh_in_flight(self):
        creds = self._make_credentials()
        old_boundary = {"encodedLocations": "0x111"}
        creds.token = "old-token"
        creds.expiry = _helpers.utcnow() + datetime.timedelta(hours=1)
        creds._trust_boundary = old_boundary

        transport = BlockingBoundaryTransport({"encodedLocations": "0x222"})

        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client, "_lookup_trust_boundary", side_effect=transport.lookup
        ):
            refresh_thread = threading.Thread(
                target=creds._refresh_synchronized, args=(mock.Mock(), True),
            )
            refresh_thread.start()
            transport.wait_until_lookup_started()

            # The old pair is still inside its window, so a business call may
            # proceed using exactly that approved combination.
            headers = {}
            creds._validate_request_identity()
            creds.apply(headers)
            transport.business("GET", "http://business/api", headers)

            transport.release()
            refresh_thread.join(timeout=5)

        assert len(transport.business_requests) == 1
        sent_headers = transport.business_requests[0][2]
        assert sent_headers["authorization"] == "Bearer old-token"
        assert sent_headers["x-allowed-locations"] == "0x111"

        # After publication both identities come from the same new approval.
        assert creds.token == "token-1"
        assert creds._trust_boundary == {"encodedLocations": "0x222"}

    def test_concurrent_callers_coalesce_to_single_refresh(self):
        creds = self._make_credentials()
        boundary = {"encodedLocations": "0xA30"}
        transport = BlockingBoundaryTransport(boundary)

        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client, "_lookup_trust_boundary", side_effect=transport.lookup
        ):
            first = threading.Thread(target=creds._refresh_synchronized, args=(mock.Mock(), True),)
            first.start()
            transport.wait_until_lookup_started()

            results = []

            def waiting_caller():
                try:
                    creds._refresh_synchronized(mock.Mock())
                    results.append("refreshed")
                except Exception as error:  # pragma: NO COVER
                    results.append(("error", error))

            waiters = [threading.Thread(target=waiting_caller) for _ in range(3)]
            for waiter in waiters:
                waiter.start()
            # Give waiters time to block on the in-flight refresh.
            transport.release()
            first.join(timeout=5)
            for waiter in waiters:
                waiter.join(timeout=5)

        assert results == ["refreshed", "refreshed", "refreshed"]
        # Only one token publication and one boundary lookup happened.
        assert creds.token == "token-1"
        assert creds.publication == 1
        lookup_calls = [call for call in transport.calls if call[0] == "lookup"]
        assert len(lookup_calls) == 1

    def test_validate_identity_raises_when_no_token(self):
        creds = self._make_credentials()
        with mock.patch.dict(os.environ, self.ENABLED):
            with pytest.raises(exceptions.TrustBoundaryError):
                creds._validate_request_identity()

    def test_validate_identity_raises_when_window_ended(self):
        creds = self._make_credentials()
        creds.token = "token-1"
        creds.expiry = _helpers.utcnow() - datetime.timedelta(seconds=1)
        creds._trust_boundary = {"encodedLocations": "0xA30"}
        with mock.patch.dict(os.environ, self.ENABLED):
            with pytest.raises(exceptions.TrustBoundaryError):
                creds._validate_request_identity()

    def test_dynamic_lookup_disabled_keeps_original_semantics(self):
        creds = self._make_credentials()
        # No env var enabling the feature: validation is a no-op even with no
        # token and an ended window, preserving historical behavior.
        creds.expiry = _helpers.utcnow() - datetime.timedelta(seconds=1)
        with mock.patch.dict(os.environ, clear=True):
            assert creds._validate_request_identity() is None

    def test_boundary_revocation_blocks_before_business_request(self):
        # Admin revocation: the boundary lookup denies access and there is no
        # cached boundary to fall back to, so no usable pair can be published.
        creds = self._make_credentials()
        creds.expiry = _helpers.utcnow() - datetime.timedelta(seconds=1)

        transport = BlockingBoundaryTransport({"encodedLocations": "0x222"})
        transport.release()

        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            _client,
            "_lookup_trust_boundary",
            side_effect=exceptions.RefreshError("boundary revoked"),
        ):
            with pytest.raises(exceptions.RefreshError):
                creds.before_request(
                    mock.Mock(), "GET", "http://business/api", {}
                )

        # Nothing was staged and no business request reached the transport.
        assert creds.token is None
        assert creds._trust_boundary is None
        assert transport.business_requests == []

    def test_ended_window_with_failing_refresh_blocks_request(self):
        # When the approval window has ended and no replacement pair can be
        # produced, the request must stop before reaching the transport.
        creds = self._make_credentials()
        creds.token = "old-token"
        creds.expiry = _helpers.utcnow() - datetime.timedelta(seconds=1)
        creds._trust_boundary = {"encodedLocations": "0x111"}

        transport = BlockingBoundaryTransport({"encodedLocations": "0x222"})
        transport.release()

        with mock.patch.dict(os.environ, self.ENABLED), mock.patch.object(
            creds,
            "_perform_refresh_token",
            side_effect=exceptions.RefreshError("token endpoint unavailable"),
        ):
            with pytest.raises(exceptions.RefreshError):
                creds.before_request(
                    mock.Mock(), "GET", "http://business/api", {}
                )

        # The expired pair is retained but no business request is sent.
        assert creds.token == "old-token"
        assert creds._trust_boundary == {"encodedLocations": "0x111"}
        assert transport.business_requests == []
