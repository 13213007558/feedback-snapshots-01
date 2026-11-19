# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""Cache invalidation after unsafe requests.

RFC 9111 section 4.4 requires a cache to invalidate the target URI and any
same-origin URI named by ``Location`` or ``Content-Location`` after a
successful unsafe request.  These tests drive two in-process stub origins so
that no network access is required.
"""

from __future__ import annotations

import io
from email.utils import formatdate
from urllib.parse import urlsplit

import pytest
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3 import HTTPResponse

from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.cache import DictCache


class _Body(io.BytesIO):
    """A body that looks closed once exhausted, like a socket file.

    ``CallbackFileWrapper`` only invokes its cache callback when the
    underlying file reports ``fp is None``, so the stub bodies need to
    emulate that behavior.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.fp = self

    def read(self, amt: int | None = None) -> bytes:
        data = super().read(amt)
        if not data:
            self.fp = None
        return data


class StubOrigin:
    """A local stand-in for an origin server."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.responses: dict[tuple[str, str], tuple[int, dict[str, str], bytes]] = {}
        self.requests: list[tuple[str, str]] = []

    def add(
        self,
        method: str,
        path: str,
        body: bytes,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        all_headers = {
            "Cache-Control": "max-age=60",
            "Date": formatdate(usegmt=True),
            "Content-Length": str(len(body)),
            "Content-Type": "text/plain",
        }
        all_headers.update(headers or {})
        self.responses[(method, path)] = (status, all_headers, body)

    def respond(self, request) -> HTTPResponse:
        path = urlsplit(request.url).path
        self.requests.append((request.method, path))
        status, headers, body = self.responses[(request.method, path)]
        return HTTPResponse(
            body=_Body(body),
            status=status,
            headers=headers,
            preload_content=False,
        )


@pytest.fixture()
def origins(monkeypatch):
    origin_a = StubOrigin("origin-a.test")
    origin_b = StubOrigin("origin-b.test")
    by_host = {origin_a.host: origin_a, origin_b.host: origin_b}

    def send(
        self,
        request,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
    ):
        raw = by_host[urlsplit(request.url).hostname].respond(request)
        return self.build_response(request, raw)  # type: ignore[attr-defined]

    monkeypatch.setattr(HTTPAdapter, "send", send)
    return origin_a, origin_b


@pytest.fixture()
def session(origins):
    cache = DictCache()
    sess = Session()
    sess.mount("http://", CacheControlAdapter(cache))
    yield sess, cache
    sess.close()


def key(url: str) -> str:
    return CacheControlAdapter().controller.cache_url(url)


def all_cached(cache: DictCache) -> set[str]:
    return set(cache.data)


def test_successful_write_purges_target_and_relative_location(origins, session):
    origin_a, _ = origins
    sess, cache = session

    origin_a.add("GET", "/api/contracts/42", b"contract v1")
    origin_a.add("GET", "/api/summaries/42", b"summary v1")
    origin_a.add(
        "PUT",
        "/api/contracts/42",
        b"",
        headers={"Location": "/api/summaries/42"},
    )

    sess.get("http://origin-a.test/api/contracts/42")
    sess.get("http://origin-a.test/api/summaries/42")
    before = all_cached(cache)
    assert before == {
        "http://origin-a.test/api/contracts/42",
        "http://origin-a.test/api/summaries/42",
    }

    origin_a.add("GET", "/api/summaries/42", b"summary v2")
    sess.put("http://origin-a.test/api/contracts/42")

    assert all_cached(cache) == set()

    refreshed = sess.get("http://origin-a.test/api/summaries/42")
    assert refreshed.from_cache is False
    assert refreshed.content == b"summary v2"


def test_successful_write_purges_relative_content_location(origins, session):
    origin_a, _ = origins
    sess, cache = session

    origin_a.add("GET", "/api/contracts/42", b"contract v1")
    origin_a.add("GET", "/api/contracts/42/summary", b"summary v1")
    origin_a.add(
        "PATCH",
        "/api/contracts/42",
        b"",
        headers={"Content-Location": "42/summary"},
    )

    sess.get("http://origin-a.test/api/contracts/42")
    sess.get("http://origin-a.test/api/contracts/42/summary")
    assert len(all_cached(cache)) == 2

    sess.patch("http://origin-a.test/api/contracts/42")

    assert all_cached(cache) == set()


def test_failed_write_keeps_everything_cached(origins, session):
    origin_a, _ = origins
    sess, cache = session

    origin_a.add("GET", "/api/contracts/42", b"contract v1")
    origin_a.add("GET", "/api/summaries/42", b"summary v1")
    origin_a.add(
        "PUT",
        "/api/contracts/42",
        b"nope",
        status=500,
        headers={"Location": "/api/summaries/42"},
    )

    sess.get("http://origin-a.test/api/contracts/42")
    sess.get("http://origin-a.test/api/summaries/42")
    before = all_cached(cache)

    failed = sess.put("http://origin-a.test/api/contracts/42")

    assert failed.status_code == 500
    assert all_cached(cache) == before
    assert sess.get("http://origin-a.test/api/summaries/42").from_cache is True


def test_cross_origin_location_is_not_invalidated(origins, session):
    origin_a, origin_b = origins
    sess, cache = session

    origin_a.add("GET", "/api/contracts/42", b"contract v1")
    origin_a.add("GET", "/api/summaries/42", b"origin-a summary")
    origin_b.add("GET", "/api/summaries/42", b"origin-b summary")
    origin_a.add(
        "PUT",
        "/api/contracts/42",
        b"",
        headers={"Location": "http://origin-b.test/api/summaries/42"},
    )

    sess.get("http://origin-a.test/api/contracts/42")
    sess.get("http://origin-a.test/api/summaries/42")
    sess.get("http://origin-b.test/api/summaries/42")

    sess.put("http://origin-a.test/api/contracts/42")

    # The target URI is invalidated, but the other-origin reference is not.
    assert all_cached(cache) == {
        "http://origin-a.test/api/summaries/42",
        "http://origin-b.test/api/summaries/42",
    }
    assert sess.get("http://origin-b.test/api/summaries/42").from_cache is True


@pytest.mark.parametrize(
    "location",
    [
        "http://origin-b.test/api/summaries/42",
        "//origin-b.test/api/summaries/42",
        "https://origin-a.test/api/summaries/42",
        "http://origin-a.test:8080/api/summaries/42",
    ],
)
def test_only_same_origin_references_are_purged(origins, session, location):
    origin_a, _ = origins
    sess, cache = session

    origin_a.add("GET", "/api/contracts/42", b"contract v1")
    origin_a.add("GET", "/api/summaries/42", b"summary v1")
    origin_a.add("PUT", "/api/contracts/42", b"", headers={"Location": location})

    sess.get("http://origin-a.test/api/contracts/42")
    sess.get("http://origin-a.test/api/summaries/42")

    sess.put("http://origin-a.test/api/contracts/42")

    assert all_cached(cache) == {"http://origin-a.test/api/summaries/42"}


def test_unparseable_reference_does_not_break_the_update(origins, session):
    origin_a, _ = origins
    sess, cache = session

    origin_a.add("GET", "/api/summaries/42", b"summary v1")
    origin_a.add(
        "PUT",
        "/api/contracts/42",
        b"",
        headers={"Location": "http://origin-a.test:notaport/x"},
    )

    sess.get("http://origin-a.test/api/summaries/42")
    response = sess.put("http://origin-a.test/api/contracts/42")

    assert response.status_code == 200
    assert all_cached(cache) == {"http://origin-a.test/api/summaries/42"}
