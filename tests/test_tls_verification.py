# SPDX-FileCopyrightText: 2026
#
# SPDX-License-Identifier: Apache-2.0

"""
Protected-mode behavior with respect to the TLS peer-verification setting.

The HTTPS transport is entirely fake. The cache adapter still runs its real
caching and response-building flow; only the connection pool's ``urlopen``
(which would open a socket) is replaced. The ``verify`` argument is captured at
the adapter's TLS-context hook, so it can be asserted directly.
"""

from email.utils import formatdate
from io import BytesIO
from unittest.mock import patch

import msgpack
import pytest
import requests
from urllib3 import HTTPResponse

from cachecontrol import CacheController
from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.cache import DictCache
from cachecontrol.serialize import SERDE_PREFIX, VERIFY_PEER_ATTR, Serializer

URL = "https://api.internal.example/resource"
ETAG = '"v1"'
# An existing path is sufficient: cert_verify() only checks that the CA bundle
# path exists; it never reads it because the pool call is faked.
CA_BUNDLE = __file__


class StopSend(Exception):
    """Raised to stop a faked request before any network connection opens."""


class SelfClosingBytesIO(BytesIO):
    """A body stream that closes once exhausted.

    Real ``http.client`` response objects drop their file pointer when the
    body is fully consumed; CacheControl's file wrapper uses that signal to
    fire the cache-write callback. A plain ``BytesIO`` stays open, so it is
    closed here to match the real behavior.
    """

    def read(self, amt=None):
        data = super().read(amt)
        if not data:
            self.close()
        return data


class FakeHTTPSTransport:
    """Serves an ETagged resource and records the peer-verification setting."""

    def __init__(self):
        self.verify_calls = []

    def response_for(self, request):
        if "If-None-Match" in request.headers:
            return HTTPResponse(
                body=SelfClosingBytesIO(b""),
                headers={"ETag": ETAG, "Date": formatdate(usegmt=True)},
                status=304,
                reason="Not Modified",
                preload_content=False,
            )
        body = b"payload"
        return HTTPResponse(
            body=SelfClosingBytesIO(body),
            headers={
                "Date": formatdate(usegmt=True),
                "Cache-Control": "max-age=0",
                "ETag": ETAG,
                "Content-Type": "text/plain",
                "Content-Length": str(len(body)),
            },
            status=200,
            reason="OK",
            preload_content=False,
        )


class FakeTransportAdapter(CacheControlAdapter):
    """CacheControl adapter whose pool network call is faked."""

    def __init__(self, transport, *args, **kwargs):
        self.fake_transport = transport
        super().__init__(*args, **kwargs)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        self.fake_transport.verify_calls.append(verify)
        connection = super().get_connection_with_tls_context(
            request, verify, proxies=proxies, cert=cert
        )
        connection.urlopen = lambda *args, **kwargs: self.fake_transport.response_for(
            request
        )
        return connection


def make_session(cache, transport, protected):
    session = requests.Session()
    session.mount(
        "https://",
        FakeTransportAdapter(
            transport,
            cache=cache,
            protected=protected,
        ),
    )
    return session


def cache_key():
    return CacheController.cache_url(URL)


def stored_entry(cache):
    return msgpack.loads(
        cache.get(cache_key())[len(SERDE_PREFIX) :],
        raw=False,
    )


def make_legacy_entry(cache):
    """Write an entry in the current format but without verification info."""
    serializer = Serializer()
    request = requests.Request("GET", URL).prepare()
    setattr(request, VERIFY_PEER_ATTR, True)
    body = b"payload"
    raw = HTTPResponse(
        body=BytesIO(body),
        headers={
            "Date": formatdate(usegmt=True),
            "Cache-Control": "max-age=3600",
            "ETag": ETAG,
            "Content-Length": str(len(body)),
        },
        status=200,
        reason="OK",
        preload_content=False,
    )
    payload = serializer.dumps(request, raw, body)
    legacy = msgpack.loads(payload[len(SERDE_PREFIX) :], raw=False)
    legacy.pop("verified", None)
    cache.set(cache_key(), SERDE_PREFIX + msgpack.dumps(legacy, use_bin_type=True))


@pytest.fixture()
def transport():
    return FakeHTTPSTransport()


class TestProtectedTLSVerification:
    def test_strict_call_bypasses_debug_cache_and_revalidates_strictly(self, transport):
        cache = DictCache()

        # Debug configuration: peer identity is not verified.
        debug_session = make_session(cache, transport, protected=True)
        debug_response = debug_session.get(URL, verify=False)

        assert not debug_response.from_cache
        assert transport.verify_calls == [False]
        assert stored_entry(cache)["verified"] is False

        # Strict configuration against the same address: the unverified entry
        # cannot be served, so the request goes back to the origin without
        # borrowing a conditional validator from it.
        strict_session = make_session(cache, transport, protected=True)
        strict_response = strict_session.get(URL, verify=True)

        assert not strict_response.from_cache
        assert transport.verify_calls[-1] is True
        assert "If-None-Match" not in strict_response.request.headers
        assert stored_entry(cache)["verified"] is True

        # A later strict call revalidates the now-verified entry; the
        # conditional request must keep the strict verification setting.
        revalidated = strict_session.get(URL, verify=True)

        assert transport.verify_calls[-1] is True
        assert revalidated.request.headers["If-None-Match"] == ETAG
        assert revalidated.from_cache

    def test_ca_bundle_verification_matches_strict_verification(self, transport):
        cache = DictCache()
        session = make_session(cache, transport, protected=True)

        first = session.get(URL, verify=CA_BUNDLE)
        second = session.get(URL, verify=True)

        # Both requests require peer verification, so the second one may reuse
        # the first entry for its conditional revalidation.
        assert not first.from_cache
        assert transport.verify_calls == [CA_BUNDLE, True]
        assert second.request.headers["If-None-Match"] == ETAG

    def test_legacy_entry_without_verification_info_is_rejected(self, transport):
        cache = DictCache()
        make_legacy_entry(cache)
        session = make_session(cache, transport, protected=True)

        response = session.get(URL, verify=True)

        # Fail closed: the legacy entry is ignored and the origin is contacted
        # with no conditional validator taken from the untrusted entry.
        assert not response.from_cache
        assert transport.verify_calls == [True]
        assert "If-None-Match" not in response.request.headers

        # The replacement entry now records explicit verification provenance.
        assert stored_entry(cache)["verified"] is True

    def test_legacy_entry_remains_usable_without_protection(self):
        cache = DictCache()
        make_legacy_entry(cache)
        transport = FakeHTTPSTransport()
        session = make_session(cache, transport, protected=False)

        response = session.get(URL, verify=True)

        assert response.from_cache
        assert transport.verify_calls == []


class TestVerificationProvenance:
    def test_serializer_records_peer_verification(self):
        serializer = Serializer()
        request = requests.Request("GET", URL).prepare()

        setattr(request, VERIFY_PEER_ATTR, True)
        verified = serializer.loads(
            request,
            serializer.dumps(
                request,
                HTTPResponse(
                    body=BytesIO(b"x"),
                    headers={"Date": formatdate(usegmt=True)},
                    status=200,
                    preload_content=False,
                ),
            ),
        )
        assert getattr(verified, VERIFY_PEER_ATTR) is True

        setattr(request, VERIFY_PEER_ATTR, False)
        unverified = serializer.loads(
            request,
            serializer.dumps(
                request,
                HTTPResponse(
                    body=BytesIO(b"x"),
                    headers={"Date": formatdate(usegmt=True)},
                    status=200,
                    preload_content=False,
                ),
            ),
        )
        assert getattr(unverified, VERIFY_PEER_ATTR) is False

    def test_serializer_treats_missing_field_as_unverified(self):
        serializer = Serializer()
        request = requests.Request("GET", URL).prepare()
        raw = HTTPResponse(
            body=BytesIO(b"payload"),
            headers={"Date": formatdate(usegmt=True)},
            status=200,
            preload_content=False,
        )

        payload = serializer.dumps(request, raw, b"payload")
        data = msgpack.loads(payload[len(SERDE_PREFIX) :], raw=False)
        data.pop("verified", None)
        legacy = SERDE_PREFIX + msgpack.dumps(data, use_bin_type=True)

        loaded = serializer.loads(request, legacy)
        assert getattr(loaded, VERIFY_PEER_ATTR) is False

    def test_controller_gate_uses_recorded_provenance(self):
        strict_request = requests.Request("GET", URL).prepare()
        setattr(strict_request, VERIFY_PEER_ATTR, True)

        cache = DictCache()
        controller = CacheController(cache, protected=True)

        verifying_request = requests.Request("GET", URL).prepare()
        setattr(verifying_request, VERIFY_PEER_ATTR, True)
        verified_response = HTTPResponse(
            body=BytesIO(b"payload"),
            headers={"Date": formatdate(usegmt=True), "Cache-Control": "max-age=3600"},
            status=200,
            preload_content=False,
        )
        cache.set(
            cache_key(),
            Serializer().dumps(verifying_request, verified_response, b"payload"),
        )
        assert controller._load_from_cache(strict_request) is not None

        unverified_request = requests.Request("GET", URL).prepare()
        setattr(unverified_request, VERIFY_PEER_ATTR, False)
        unverified_response = HTTPResponse(
            body=BytesIO(b"payload"),
            headers={"Date": formatdate(usegmt=True), "Cache-Control": "max-age=3600"},
            status=200,
            preload_content=False,
        )
        cache.set(
            cache_key(),
            Serializer().dumps(unverified_request, unverified_response, b"payload"),
        )
        assert controller._load_from_cache(strict_request) is None

        permissive = CacheController(DictCache(dict(cache.data)), protected=False)
        assert permissive._load_from_cache(strict_request) is not None

    def test_non_verifying_request_is_not_restricted(self):
        request = requests.Request("GET", URL).prepare()
        setattr(request, VERIFY_PEER_ATTR, False)

        unverified_response = HTTPResponse(
            body=BytesIO(b"payload"),
            headers={"Date": formatdate(usegmt=True), "Cache-Control": "max-age=3600"},
            status=200,
            preload_content=False,
        )
        cache = DictCache()
        cache.set(
            cache_key(),
            Serializer().dumps(request, unverified_response, b"payload"),
        )

        controller = CacheController(cache, protected=True)
        assert controller._load_from_cache(request) is not None

    def test_adapter_tags_request_with_verify_requirement(self, transport):
        adapter = CacheControlAdapter(DictCache(), protected=True)

        def stop_at_connection(request, verify, proxies=None, cert=None):
            raise StopSend

        with patch.object(
            adapter, "get_connection_with_tls_context", side_effect=stop_at_connection
        ):
            request = requests.Request("GET", URL).prepare()
            with pytest.raises(StopSend):
                adapter.send(request, verify=False)
            assert getattr(request, VERIFY_PEER_ATTR) is False

            request = requests.Request("GET", URL).prepare()
            with pytest.raises(StopSend):
                adapter.send(request, verify=True)
            assert getattr(request, VERIFY_PEER_ATTR) is True
