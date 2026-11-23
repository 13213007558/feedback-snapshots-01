# Copyright 2026 Google LLC
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

"""Tests for call-scoped client certificate authorizations.

The central scenario uses a pausable HTTP double: a call is stopped right
before its authentication retry, a new certificate is published, and a second
call is started. The assertions show which authorization each connection and
each authentication attempt actually used, and when the older generation is
released.
"""

import http.client as http_client
import threading
from unittest import mock

import pytest  # type: ignore

from google.auth import _certificate_context
from google.auth import exceptions
import google.auth.credentials
import google.auth.transport._certificate_authorization as certificate_authorization
import google.auth.transport.requests

CERT_ONE = b"-----BEGIN CERTIFICATE-----\nONE\n-----END CERTIFICATE-----\n"
KEY_ONE = b"-----BEGIN PRIVATE KEY-----\nONE\n-----END PRIVATE KEY-----\n"
CERT_TWO = b"-----BEGIN CERTIFICATE-----\nTWO\n-----END CERTIFICATE-----\n"
KEY_TWO = b"-----BEGIN PRIVATE KEY-----\nTWO\n-----END PRIVATE KEY-----\n"

TEST_URL = "https://api.example.com/v1/items"

_sessions_to_close = []


@pytest.fixture(autouse=True)
def _close_sessions():
    yield
    while _sessions_to_close:
        _sessions_to_close.pop().close()


class AdapterHandle:
    """A stand-in for a TLS adapter that records its own lifetime."""

    def __init__(self, cert, key):
        self.cert = cert
        self.key = key
        self.closed = False

    def close(self):
        self.closed = True


class RecordingCredentials(google.auth.credentials.Credentials):
    """Credentials that record the authorization active during each refresh."""

    def __init__(self):
        super(RecordingCredentials, self).__init__()
        self.before_request_authorizations = []
        self.refresh_authorizations = []
        self.token = "token"

    def before_request(self, request, method, url, headers):
        authorization = _certificate_context.get_active()
        self.before_request_authorizations.append(
            authorization.generation if authorization is not None else None
        )
        headers["authorization"] = "Bearer {}".format(self.token)

    def refresh(self, request):
        authorization = _certificate_context.get_active()
        self.refresh_authorizations.append(
            authorization.generation if authorization is not None else None
        )
        self.token = "token-refreshed"


def make_response(status):
    response = mock.Mock(spec=["status_code", "headers", "content", "request"])
    response.status_code = status
    response.headers = {}
    response.content = b""
    return response


class SessionUnderTest(google.auth.transport.requests.AuthorizedSession):
    """AuthorizedSession whose sends and adapter construction are observable."""

    def __init__(self, *args, **kwargs):
        super(SessionUnderTest, self).__init__(*args, **kwargs)
        self.handles = []
        self.send_count = 0
        self.responses = []
        self.sent_authorizations = []
        self.used_adapters = []
        self.rotation_checks = []

    def _publish_rotated_certificate(self, authorization):
        # The pausable double publishes certificates explicitly from the test.
        self.rotation_checks.append(
            authorization.generation if authorization is not None else None
        )

    def _make_tls_adapter(self, cert, key):
        handle = AdapterHandle(cert, key)
        self.handles.append(handle)
        return handle

    def _send_with_authorization(self, authorization, *args, **kwargs):
        self.send_count += 1
        self.sent_authorizations.append(
            authorization.generation if authorization is not None else None
        )
        self.used_adapters.append(
            authorization.adapter if authorization is not None else None
        )
        index = min(len(self.responses) - 1, self.send_count - 1)
        return make_response(self.responses[index])


class Gate:
    """Lets a test pause a call at a chosen point."""

    def __init__(self):
        self.reached = threading.Event()
        self.resume = threading.Event()

    def wait(self):
        self.reached.set()
        assert self.resume.wait(timeout=10), "test gate was never opened"


class PausableSession(SessionUnderTest):
    """Session whose send can be paused right before the authentication retry.

    ``send_count`` is 1 for the first attempt and 2 for the retry that happens
    after the 401 refresh. The gate is entered while the call is still inside
    its own authorization lease.
    """

    def __init__(self, *args, **kwargs):
        super(PausableSession, self).__init__(*args, **kwargs)
        self.send_count = 0
        self.before_send_gate = None
        self.gate_on_send = None

    def _send_with_authorization(self, authorization, *args, **kwargs):
        self.send_count += 1
        self.sent_authorizations.append(
            authorization.generation if authorization is not None else None
        )
        self.used_adapters.append(
            authorization.adapter if authorization is not None else None
        )
        if self.gate_on_send == self.send_count:
            self.before_send_gate = Gate()
            self.before_send_gate.wait()
        index = min(len(self.responses) - 1, self.send_count - 1)
        return make_response(self.responses[index])


@pytest.fixture
def authority():
    value = certificate_authorization.CertificateAuthority()
    yield value
    value.close()


class TestCertificateAuthority(object):
    def _authority(self, authority):
        return authority

    def test_publish_and_acquire(self, authority):
        first = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        assert first.generation == 1
        assert first.active_leases == 0
        lease = authority.acquire()
        assert lease.generation == 1
        assert first.active_leases == 1
        lease.release()
        assert first.active_leases == 0

    def test_same_material_is_not_republished(self, authority):
        first = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        again = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        assert again is first
        assert authority.current.generation == 1

    def test_no_lease_without_published_certificate(self, authority):
        assert authority.acquire() is None

    def test_old_generation_survives_until_last_lease(self, authority):
        first = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        lease_a = authority.acquire()
        lease_b = authority.acquire()

        second = authority.publish(CERT_TWO, KEY_TWO, AdapterHandle)
        assert second.generation == 2
        assert first.retired is True
        assert first.released is False
        # New calls pin the newly published certificate.
        lease_c = authority.acquire()
        assert lease_c.generation == 2

        lease_a.release()
        assert first.released is False
        lease_b.release()
        # The last in-flight call on the old generation released it.
        assert first.released is True
        lease_c.release()

    def test_retiring_an_unused_generation_releases_it_immediately(self, authority):
        first = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        second = authority.publish(CERT_TWO, KEY_TWO, AdapterHandle)
        assert first.released is True
        assert second.released is False

    def test_adapter_is_built_lazily_once(self, authority):
        builds = []

        def factory(cert, key):
            builds.append((cert, key))
            return AdapterHandle(cert, key)

        authorization = authority.publish(CERT_ONE, KEY_ONE, factory)
        assert builds == []
        first_adapter = authorization.adapter
        second_adapter = authorization.adapter
        assert first_adapter is second_adapter
        assert builds == [(CERT_ONE, KEY_ONE)]

    def test_release_closes_adapter_and_removes_temp_files(self, authority):
        authorization = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        adapter = authorization.adapter
        cert_path, key_path = authorization.mtls_cert_and_key_paths()
        import os

        assert os.path.exists(cert_path) and os.path.exists(key_path)
        authority.close()
        assert adapter.closed is True
        assert not os.path.exists(cert_path)
        assert not os.path.exists(key_path)

    def test_released_material_cannot_be_used(self, authority):
        authorization = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        authority.close()
        with pytest.raises(exceptions.MutualTLSChannelError):
            _ = authorization.cert
        with pytest.raises(exceptions.MutualTLSChannelError):
            _ = authorization.adapter


class TestCallScopedAuthorization(object):
    def _session(self, credentials):
        session = SessionUnderTest(credentials)
        _sessions_to_close.append(session)
        return session

    def _publish(self, session, cert=CERT_ONE, key=KEY_ONE):
        session._certificate_authority.publish(cert, key, session._make_tls_adapter)
        session._is_mtls = True
        session._cached_cert = cert

    def test_call_pins_authorization_through_refresh_and_retry(self):
        credentials = RecordingCredentials()
        session = self._session(credentials)
        session.responses = [http_client.UNAUTHORIZED, http_client.OK]
        self._publish(session)

        response = session.request("GET", TEST_URL)

        assert response.status_code == http_client.OK
        # One generation was pinned, used for authentication, both connections
        # and the retry after the 401-triggered refresh.
        authorization = session.certificate_authorization
        assert authorization.generation == 1
        assert credentials.before_request_authorizations == [1, 1]
        assert credentials.refresh_authorizations == [1]
        assert session.sent_authorizations == [1, 1]
        # The very same adapter (and therefore the same TLS contexts) served
        # both connections of the call.
        assert session.used_adapters == [authorization.adapter, authorization.adapter]

    def test_call_without_mtls_has_no_authorization(self):
        credentials = RecordingCredentials()
        session = self._session(credentials)
        session.responses = [http_client.UNAUTHORIZED]
        response = session.request("GET", TEST_URL)
        assert response.status_code == http_client.UNAUTHORIZED
        # No authorization was published, so every attempt and retry ran with
        # no certificate pinned.
        assert credentials.before_request_authorizations == [None, None, None]
        assert credentials.refresh_authorizations == [None, None]

    def test_each_call_releases_its_lease(self):
        credentials = RecordingCredentials()
        session = self._session(credentials)
        session.responses = [http_client.OK]
        self._publish(session)
        session.request("GET", TEST_URL)
        authorization = session.certificate_authorization
        assert authorization.active_leases == 0

    def test_lease_released_when_call_raises(self):
        credentials = RecordingCredentials()
        session = self._session(credentials)
        self._publish(session)

        with mock.patch.object(
            session, "_send_with_authorization", side_effect=RuntimeError("boom")
        ):
            with pytest.raises(RuntimeError):
                session.request("GET", TEST_URL)

        assert session.certificate_authorization.active_leases == 0


class TestRotationDuringInFlightCall(object):
    """The pausable-double acceptance scenario."""

    def _session(self, credentials):
        session = PausableSession(credentials)
        _sessions_to_close.append(session)
        return session

    def test_rotation_between_authentication_retry_and_retry(self):
        credentials = RecordingCredentials()
        session = self._session(credentials)
        session.responses = [http_client.UNAUTHORIZED, http_client.OK]

        # Publish generation 1 exactly like configure_mtls_channel does.
        session._cached_cert = CERT_ONE
        session._is_mtls = True
        first_generation = session._certificate_authority.publish(
            CERT_ONE, KEY_ONE, session._make_tls_adapter
        )
        first_adapter = first_generation.adapter

        # Park the first call just before its post-refresh (second) send.
        session.gate_on_send = 2
        first_call = {}

        def run_first_call():
            first_call["response"] = session.request("GET", TEST_URL)

        worker = threading.Thread(target=run_first_call)
        worker.start()
        while session.before_send_gate is None:
            threading.Event().wait(0.01)

        # The first call is stopped right before its retry connection. Its
        # authentication, first (401) connection and refreshed authentication
        # all happened on generation 1.
        assert first_generation.generation == 1
        assert credentials.before_request_authorizations == [1, 1]
        assert credentials.refresh_authorizations == [1]
        assert session.sent_authorizations == [1, 1]
        assert all(adapter is first_adapter for adapter in session.used_adapters)

        # Publish a new certificate and start a second call while the first is
        # still parked before its retry.
        second_generation = session._certificate_authority.publish(
            CERT_TWO, KEY_TWO, session._make_tls_adapter
        )
        session._cached_cert = CERT_TWO
        assert second_generation.generation == 2
        assert first_generation.retired is True
        assert first_generation.released is False

        session.gate_on_send = None
        second_response = session.request("GET", TEST_URL)
        assert second_response.status_code == http_client.OK

        # The second call authenticated and connected under generation 2. Only
        # the first call needed an authentication refresh so far.
        assert session.sent_authorizations == [1, 1, 2]
        assert credentials.before_request_authorizations == [1, 1, 2]
        assert credentials.refresh_authorizations == [1]

        # Resume the first call. Its retry must stay on generation 1 even
        # though generation 2 has already been published.
        session.before_send_gate.resume.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
        assert first_call["response"].status_code == http_client.OK

        # The resumed retry is the same send that was parked, so it is the
        # second recorded send and it used generation 1's adapter.
        assert session.sent_authorizations == [1, 1, 2]
        assert session.used_adapters[0] is first_adapter
        assert session.used_adapters[1] is first_adapter
        assert session.used_adapters[2] is second_generation.adapter
        assert credentials.refresh_authorizations == [1]
        # The old generation stayed alive while its call was in flight and was
        # released once that call finished.
        assert first_generation.active_leases == 0
        assert first_generation.released is True

    def test_old_generation_released_only_after_in_flight_call_finishes(self):
        credentials = RecordingCredentials()
        session = self._session(credentials)
        session.responses = [http_client.UNAUTHORIZED, http_client.OK]
        session._cached_cert = CERT_ONE
        session._is_mtls = True
        session._certificate_authority.publish(
            CERT_ONE, KEY_ONE, session._make_tls_adapter
        )
        old_authorization = session.certificate_authorization

        session.gate_on_send = 2
        first_call = {}
        worker = threading.Thread(
            target=lambda: first_call.update(response=session.request("GET", TEST_URL))
        )
        worker.start()
        while session.before_send_gate is None:
            threading.Event().wait(0.01)

        assert old_authorization.active_leases == 1
        old_adapter = old_authorization.adapter
        session._certificate_authority.publish(
            CERT_TWO, KEY_TWO, session._make_tls_adapter
        )
        assert old_authorization.retired is True
        assert old_authorization.released is False
        assert old_adapter.closed is False

        session.before_send_gate.resume.set()
        worker.join(timeout=10)
        assert not worker.is_alive()

        # The old generation was released as soon as its last call finished.
        assert old_authorization.active_leases == 0
        assert old_authorization.released is True
        assert old_adapter.closed is True


class TestCredentialBinding(object):
    """Credential refreshes bind to the certificate pinned by the call."""

    def test_identity_pool_binds_pinned_fingerprint(self):
        from google.auth import identity_pool

        credentials = object.__new__(identity_pool.Credentials)
        credentials._credential_source_certificate = {
            "certificate_config_location": "x"
        }
        captured = {}

        def fake_perform_refresh_token(request, cert_fingerprint=None):
            captured["fingerprint"] = cert_fingerprint

        credentials._perform_refresh_token = fake_perform_refresh_token
        credentials._handle_trust_boundary = lambda request: None

        authority = certificate_authorization.CertificateAuthority()
        authorization = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)
        # The source on disk now holds a different certificate; the pinned
        # authorization must still win so the token matches the TLS connection.
        credentials._get_cert_bytes = lambda: CERT_TWO

        with mock.patch(
            "google.auth._agent_identity_utils.parse_certificate",
            return_value=mock.sentinel.cert,
        ), mock.patch(
            "google.auth._agent_identity_utils.should_request_bound_token",
            return_value=True,
        ), mock.patch(
            "google.auth._agent_identity_utils.calculate_certificate_fingerprint",
            return_value="unpinned-fingerprint",
        ) as mock_calculate:
            with certificate_authorization.activate(authorization):
                credentials.refresh(None)

        assert captured["fingerprint"] == authorization.fingerprint
        assert captured["fingerprint"] != "unpinned-fingerprint"
        # The pinned path does not need to re-fingerprint the source.
        mock_calculate.assert_not_called()
        authority.close()

    def test_identity_pool_uses_pinned_mtls_paths(self):
        from google.auth import identity_pool

        credentials = object.__new__(identity_pool.Credentials)
        credentials._credential_source_certificate = {
            "certificate_config_location": "x"
        }
        authority = certificate_authorization.CertificateAuthority()
        authorization = authority.publish(CERT_ONE, KEY_ONE, AdapterHandle)

        with certificate_authorization.activate(authorization):
            cert_path, key_path = credentials._get_mtls_cert_and_key_paths()
            with open(cert_path, "rb") as cert_file:
                assert cert_file.read() == CERT_ONE
            with open(key_path, "rb") as key_file:
                assert key_file.read() == KEY_ONE

        authority.close()


class TestSessionClose(object):
    def test_close_does_not_close_adapter_with_in_flight_call(self):
        credentials = RecordingCredentials()
        session = PausableSession(credentials)
        session.responses = [http_client.UNAUTHORIZED, http_client.OK]
        session._is_mtls = True
        generation = session._certificate_authority.publish(
            CERT_ONE, KEY_ONE, session._make_tls_adapter
        )
        adapter = generation.adapter

        session.gate_on_send = 2
        worker = threading.Thread(target=lambda: session.request("GET", TEST_URL))
        worker.start()
        while session.before_send_gate is None:
            threading.Event().wait(0.01)

        # Closing the session while a call is in flight must not tear down the
        # TLS pools that call is using. The generation owns the adapter.
        session.close()
        assert adapter.closed is False
        assert generation.released is False

        session.before_send_gate.resume.set()
        worker.join(timeout=10)
        assert not worker.is_alive()
        # Once the in-flight call finished, the adapter is released.
        assert generation.released is True
        assert adapter.closed is True

    def test_close_releases_unused_generation(self):
        credentials = RecordingCredentials()
        session = PausableSession(credentials)
        session._is_mtls = True
        generation = session._certificate_authority.publish(
            CERT_ONE, KEY_ONE, session._make_tls_adapter
        )
        adapter = generation.adapter
        session.close()
        assert adapter.closed is True
        assert generation.released is True


class TestDirectAndProxyPaths(object):
    """The adapter builds separate TLS contexts for direct and proxy paths."""

    def _adapter(self):
        return google.auth.transport.requests._MutualTlsAdapter(
            pytest.public_cert_bytes, pytest.private_key_bytes
        )

    @mock.patch.object(
        google.auth.transport.requests.requests.adapters.HTTPAdapter,
        "proxy_manager_for",
    )
    @mock.patch.object(
        google.auth.transport.requests.requests.adapters.HTTPAdapter,
        "init_poolmanager",
    )
    def test_direct_and_proxy_contexts_are_distinct(
        self, mock_init_poolmanager, mock_proxy_manager_for
    ):
        adapter = self._adapter()
        adapter.init_poolmanager()
        adapter.proxy_manager_for("http://proxy.example")
        direct = mock_init_poolmanager.call_args.kwargs["ssl_context"]
        through_proxy = mock_proxy_manager_for.call_args.kwargs["ssl_context"]
        assert direct is adapter._ctx_poolmanager
        assert through_proxy is adapter._ctx_proxymanager
        assert direct is not through_proxy

    @mock.patch.object(
        google.auth.transport.requests.requests.adapters.HTTPAdapter,
        "proxy_manager_for",
    )
    @mock.patch.object(
        google.auth.transport.requests.requests.adapters.HTTPAdapter,
        "init_poolmanager",
    )
    def test_proxy_context_is_built_lazily_on_first_proxied_connection(
        self, mock_init_poolmanager, mock_proxy_manager_for
    ):
        adapter = self._adapter()
        # ``requests`` builds the direct pool manager eagerly, but the proxy
        # TLS context is only created when an existing proxy is actually used.
        assert adapter._ctx_proxymanager is None
        assert mock_proxy_manager_for.call_count == 0

        adapter.proxy_manager_for("http://proxy.example")
        assert mock_proxy_manager_for.call_count == 1
        proxy_context = mock_proxy_manager_for.call_args.kwargs["ssl_context"]
        assert proxy_context is adapter._ctx_proxymanager

        # A second proxied connection reuses the same context.
        adapter.proxy_manager_for("http://proxy.example")
        assert mock_proxy_manager_for.call_count == 2
        assert mock_proxy_manager_for.call_args.kwargs["ssl_context"] is proxy_context
