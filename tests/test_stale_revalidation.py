# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end stale/revalidation behavior with a fake clock and transport."""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from email.utils import formatdate

import pytest
import requests
import urllib3

import cachecontrol.controller as controller
from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.cache import DictCache
from cachecontrol.heuristics import OneDayCache


class FakeClock:
    def __init__(self, now: int) -> None:
        self.now = float(now)

    def time(self) -> float:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


class _TrackingBody(io.BytesIO):
    """A fake socket body that reports EOF so CallbackFileWrapper caches it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self._exhausted = False

    @property
    def closed(self) -> bool:
        return self._exhausted or super().closed

    def read(self, amt: int | None = None) -> bytes:
        data = super().read(amt)
        if not data:
            self._exhausted = True
        return data


@dataclass
class OutboundRequest:
    method: str
    url: str
    headers: dict[str, str]


def _http_response(
    status: int, headers: dict[str, str], body: bytes = b""
) -> urllib3.HTTPResponse:
    return urllib3.HTTPResponse(
        body=_TrackingBody(body),
        status=status,
        headers=headers,
        preload_content=False,
        decode_content=False,
        reason="OK",
    )


@dataclass
class Origin:
    """A transport double that records every outbound request."""

    clock: FakeClock
    cache_control: str
    etag: str = '"v1"'
    body: bytes = b"public asset"
    available: bool = True
    requests: list[OutboundRequest] = field(default_factory=list)

    def urlopen(
        self,
        method: str,
        url: str,
        body: object = None,
        headers: dict[str, str] | None = None,
        **kwargs: object,
    ) -> urllib3.HTTPResponse:
        request_headers = dict(headers or {})
        self.requests.append(OutboundRequest(method, url, request_headers))

        if not self.available:
            raise OSError("origin is unavailable")

        date = formatdate(int(self.clock.now), usegmt=True)
        if request_headers.get("If-None-Match") == self.etag:
            return _http_response(304, {"Date": date, "ETag": self.etag})

        return _http_response(
            200,
            {
                "Date": date,
                "Cache-Control": self.cache_control,
                "ETag": self.etag,
                "Content-Length": str(len(self.body)),
            },
            self.body,
        )


class RecordingAdapter(CacheControlAdapter):
    """CacheControlAdapter wired to an in-process recording transport."""

    def __init__(self, origin: Origin, **kwargs: object) -> None:
        self.origin = origin
        super().__init__(**kwargs)

    def get_connection_with_tls_context(
        self,
        request: object,
        verify: object,
        proxies: object = None,
        cert: object = None,
    ) -> Origin:
        return self.origin

    def cert_verify(
        self, conn: object, url: str, verify: object, cert: object
    ) -> None:
        return None


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    clock = FakeClock(1_700_000_000)
    monkeypatch.setattr(controller, "time", clock)
    return clock


def _session(origin: Origin, **kwargs: object) -> requests.Session:
    session = requests.Session()
    session.mount(
        "http://",
        RecordingAdapter(origin, cache=DictCache(), **kwargs),
    )
    return session


def test_fresh_response_is_served_without_an_outbound_request(clock: FakeClock) -> None:
    origin = Origin(clock, "public, max-age=60, must-revalidate")
    session = _session(origin)

    first = session.get("http://cdn.example/asset")
    assert first.status_code == 200
    assert not first.from_cache
    assert first.content == origin.body

    clock.advance(30)
    second = session.get("http://cdn.example/asset")
    assert second.from_cache
    assert second.content == origin.body
    assert len(origin.requests) == 1


def test_stale_must_revalidate_revalidates_conditionally_when_online(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, max-age=60, must-revalidate")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)

    revalidated = session.get("http://cdn.example/asset")

    assert len(origin.requests) == 2
    assert origin.requests[1].headers.get("If-None-Match") == origin.etag
    assert revalidated.status_code == 200
    assert revalidated.content == origin.body
    # A 304 reuses the stored body, but only after the origin confirmed it.
    assert revalidated.from_cache


def test_stale_must_revalidate_raises_when_origin_is_unavailable(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, max-age=60, must-revalidate")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)
    origin.available = False

    with pytest.raises(requests.ConnectionError):
        session.get("http://cdn.example/asset")


def test_public_stale_response_can_be_reused_by_request_policy(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, max-age=60")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)

    stale = session.get(
        "http://cdn.example/asset", headers={"Cache-Control": "max-stale"}
    )

    assert stale.from_cache
    assert stale.content == origin.body
    assert len(origin.requests) == 1


def test_request_max_stale_limit_is_enforced(clock: FakeClock) -> None:
    origin = Origin(clock, "public, max-age=60")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)
    origin.available = False

    with pytest.raises(requests.ConnectionError):
        session.get(
            "http://cdn.example/asset", headers={"Cache-Control": "max-stale=30"}
        )


def test_stale_response_is_not_served_without_request_policy(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, max-age=60")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)
    origin.available = False

    with pytest.raises(requests.ConnectionError):
        session.get("http://cdn.example/asset")

    assert len(origin.requests) == 2
    assert origin.requests[1].headers.get("If-None-Match") == origin.etag


def test_must_revalidate_blocks_stale_reuse_even_with_max_stale(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, max-age=60, must-revalidate")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)
    origin.available = False

    with pytest.raises(requests.ConnectionError):
        session.get(
            "http://cdn.example/asset", headers={"Cache-Control": "max-stale"}
        )

    # The origin was asked to confirm the copy, rather than the stale copy
    # being returned as a successful response.
    assert len(origin.requests) == 2
    assert origin.requests[1].headers.get("If-None-Match") == origin.etag


def test_revalidation_keeps_must_revalidate_for_the_next_stale_request(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, max-age=60, must-revalidate")
    session = _session(origin)

    session.get("http://cdn.example/asset")
    clock.advance(120)

    # Online revalidation succeeds, refreshing the stored Date.
    revalidated = session.get("http://cdn.example/asset")
    assert revalidated.from_cache

    # Once the refreshed copy is stale again, it still must be revalidated.
    clock.advance(120)
    origin.available = False
    with pytest.raises(requests.ConnectionError):
        session.get("http://cdn.example/asset")


def test_age_heuristic_keeps_must_revalidate_and_expires_consistently(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, must-revalidate")
    session = _session(origin, heuristic=OneDayCache())

    first = session.get("http://cdn.example/asset")
    assert "must-revalidate" in first.headers["cache-control"]

    # The heuristic adds a one-day Expires; the copy is fresh until then.
    clock.advance(3600)
    fresh = session.get("http://cdn.example/asset")
    assert fresh.from_cache
    assert len(origin.requests) == 1

    clock.advance(24 * 3600 + 3600)
    origin.available = False
    with pytest.raises(requests.ConnectionError):
        session.get("http://cdn.example/asset")


def test_age_heuristic_revalidates_conditionally_when_online(
    clock: FakeClock,
) -> None:
    origin = Origin(clock, "public, must-revalidate")
    session = _session(origin, heuristic=OneDayCache())

    session.get("http://cdn.example/asset")
    clock.advance(24 * 3600 + 3600)

    revalidated = session.get("http://cdn.example/asset")

    assert len(origin.requests) == 2
    assert origin.requests[1].headers.get("If-None-Match") == origin.etag
    assert revalidated.from_cache
    assert revalidated.content == origin.body
