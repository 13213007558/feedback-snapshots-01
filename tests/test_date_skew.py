# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""Freshness must not outlive the configured maximum reusable age.

The upstream Date header is only an observation made by the origin (or an
intermediate proxy).  A fast upstream clock, an existing Age header, or a
local clock that moves backwards must never postpone the final expiration
point of a cached response.
"""

import io
import time
from email.utils import formatdate
from unittest.mock import Mock

import pytest
from requests.structures import CaseInsensitiveDict
from urllib3.response import HTTPResponse

from cachecontrol import CacheControlAdapter, CacheController
from cachecontrol.cache import DictCache
from cachecontrol.heuristics import LastModified
from cachecontrol.metadata import ensure_metadata, response_metadata
from cachecontrol.wrapper import CacheControl

from .utils import NullSerializer


class VirtualClock:
    """A clock whose wall and monotonic readings can be controlled."""

    def __init__(self, now=1_000_000.0):
        self.now = now
        self.monotonic = now

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        self.monotonic += seconds

    def set(self, now):
        self.now = now

    def monotonic_time(self):
        return self.monotonic


def http_date(value):
    return formatdate(value, usegmt=True)


def make_response(status=200, headers=None, body=b"body"):
    return HTTPResponse(
        body=io.BytesIO(body),
        headers=headers or {},
        status=status,
        preload_content=False,
    )


def make_request(url="http://example.com/", headers=None):
    return Mock(url=url, headers=CaseInsensitiveDict(headers or {}))


def make_controller(clock, **kwargs):
    return CacheController(
        DictCache(),
        serializer=NullSerializer(),
        clock=clock.time,
        monotonic=clock.monotonic_time,
        **kwargs,
    )


class TestMaxReusableAge:
    def test_fast_date_does_not_extend_reuse(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now + 500),
                "Cache-Control": "max-age=3600",
            }
        )

        controller.cache_response(request, response, b"body")

        clock.advance(59)
        cached = controller.cached_request(request)
        assert cached
        cached.close()

        clock.advance(2)
        assert controller.cached_request(request) is False

    def test_age_header_counts_toward_the_cap(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now),
                "Age": "30",
                "Cache-Control": "max-age=3600",
            }
        )

        controller.cache_response(request, response, b"body")

        clock.advance(29)
        cached = controller.cached_request(request)
        assert cached
        cached.close()

        clock.advance(2)
        assert controller.cached_request(request) is False

    def test_clock_rollback_does_not_revive_an_expired_entry(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now),
                "Cache-Control": "max-age=3600",
            }
        )

        controller.cache_response(request, response, b"body")
        clock.advance(120)
        assert controller.cached_request(request) is False

        # The wall clock moved back before the expiry point.  The entry must
        # stay stale; its final expiration point does not move.
        clock.set(clock.now - 100)
        assert controller.cached_request(request) is False

    def test_clock_rollback_before_receive_time_is_stale(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now),
                "Cache-Control": "max-age=3600",
            }
        )

        controller.cache_response(request, response, b"body")
        clock.set(clock.now - 1)
        assert controller.cached_request(request) is False

    def test_partial_rollback_keeps_the_highest_observed_time(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now),
                "Cache-Control": "max-age=3600",
            }
        )

        controller.cache_response(request, response, b"body")
        clock.advance(55)
        assert controller.cached_request(request)

        # 55 seconds had already been observed; moving the wall clock back
        # five seconds must not buy another five seconds of reuse.
        clock.set(clock.now - 5)
        clock.advance(5)
        assert controller.cached_request(request) is False

    def test_without_a_cap_the_existing_directives_still_govern(self):
        clock = VirtualClock()
        controller = make_controller(clock)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now),
                "Cache-Control": "max-age=3600",
            }
        )

        controller.cache_response(request, response, b"body")
        clock.advance(3599)
        assert controller.cached_request(request)
        clock.advance(2)
        assert controller.cached_request(request) is False

    def test_cap_is_honored_by_the_adapter_and_wrapper(self):
        adapter = CacheControlAdapter(max_reusable_age=30)
        assert adapter.controller.max_reusable_age == 30

        sess = CacheControl(Mock(), max_reusable_age=45)
        assert sess is not None

    def test_negative_cap_is_rejected(self):
        with pytest.raises(ValueError):
            CacheController(max_reusable_age=-1)


class TestObservability:
    def test_headers_and_receive_time_are_preserved(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        headers = {
            "Date": http_date(clock.now + 500),
            "Age": "7",
            "Cache-Control": "max-age=3600, public",
            "Expires": http_date(clock.now + 4000),
        }
        response = make_response(headers=headers)

        controller.cache_response(request, response, b"body")
        metadata = response_metadata(response)
        assert metadata is not None
        assert metadata.response_time == clock.now
        assert metadata.date == int(clock.now + 500)
        assert metadata.age == 7

        cached = controller.cached_request(request)
        assert cached
        try:
            # Enforcing the cap never rewrites what the upstream sent.
            for name, value in headers.items():
                assert cached.headers[name] == value
            cached_metadata = response_metadata(cached)
            assert cached_metadata is not None
            assert cached_metadata.response_time == clock.now
        finally:
            cached.close()

    def test_cache_age_uses_the_receive_time(self):
        clock = VirtualClock()
        controller = make_controller(clock, max_reusable_age=60)
        request = make_request()
        response = make_response(
            headers={
                "Date": http_date(clock.now + 500),
                "Age": "10",
                "Cache-Control": "max-age=3600",
            }
        )
        controller.cache_response(request, response, b"body")

        clock.advance(20)
        cached = controller.cached_request(request)
        assert cached
        try:
            assert controller.cache_age(cached) == 30
        finally:
            cached.close()


class TestMetadataSerialization:
    def test_serializer_round_trips_receive_time(self):
        from cachecontrol.serialize import Serializer

        clock = VirtualClock()
        controller = CacheController(DictCache(), serializer=Serializer())
        request = Mock(url="http://example.com/", headers=CaseInsensitiveDict())
        response = make_response(
            headers={
                "Date": http_date(clock.now + 500),
                "Age": "12",
                "Cache-Control": "max-age=3600",
            }
        )
        ensure_metadata(response, clock.now)

        controller.cache_response(request, response, b"body")
        loaded = controller._load_from_cache(request)
        assert loaded is not None
        try:
            metadata = response_metadata(loaded)
            assert metadata is not None
            assert metadata.response_time == clock.now
            assert metadata.corrected_initial_age == 12
        finally:
            loaded.close()


class TestLastModifiedHeuristic:
    def test_fast_date_does_not_push_the_heuristic_expiry_later(self):
        clock = VirtualClock()
        heuristic = LastModified()
        response = make_response(
            headers={
                "Date": http_date(clock.now + 500),
                "Last-Modified": http_date(clock.now - 500),
                "Content-Type": "text/plain",
            }
        )
        ensure_metadata(response, clock.now)

        original_time = time.time
        try:
            time.time = clock.time
            headers = heuristic.update_headers(response)
        finally:
            time.time = original_time

        assert "expires" in headers
        from email.utils import parsedate_tz
        import calendar

        expires = calendar.timegm(parsedate_tz(headers["expires"])[:6])
        # The 100-second heuristic lifetime is measured from the local
        # receive time, not from the upstream's 500-second-fast Date.
        assert expires <= clock.now + 100


class _ClosingBody:
    """A small file-like object that reports EOF as a closed file."""

    def __init__(self, data):
        self._data = data
        self._read = False
        self.closed = False

    def read(self, amt=None):
        if self._read:
            self.closed = True
            return b""
        self._read = True
        return self._data

    def close(self):
        self.closed = True


class TestAdapterIntegration:
    def test_adapter_reuses_until_the_cap_even_with_a_fast_date(self):
        import requests

        clock = VirtualClock()
        adapter = CacheControlAdapter(
            DictCache(), max_reusable_age=60, controller_class=None
        )
        adapter.controller._clock = clock.time
        adapter.controller._monotonic = clock.monotonic_time

        request = requests.Request("GET", "http://example.com/resource").prepare()
        raw = HTTPResponse(
            body=_ClosingBody(b"payload"),
            headers={
                "Date": http_date(clock.now + 4000),
                "Cache-Control": "max-age=86400",
            },
            status=200,
            preload_content=False,
        )
        adapter.build_response(request, raw).content

        assert adapter.cache.get("http://example.com/resource") is not None

        clock.advance(59)
        cached = adapter.controller.cached_request(request)
        assert cached
        cached.close()

        clock.advance(2)
        assert adapter.controller.cached_request(request) is False

    def test_unmodified_headers_and_reported_age(self):
        import requests

        clock = VirtualClock()
        adapter = CacheControlAdapter(DictCache(), max_reusable_age=60)
        adapter.controller._clock = clock.time
        adapter.controller._monotonic = clock.monotonic_time

        request = requests.Request("GET", "http://example.com/headers").prepare()
        headers = {
            "Date": http_date(clock.now + 4000),
            "Age": "5",
            "Cache-Control": "max-age=86400",
        }
        raw = HTTPResponse(
            body=_ClosingBody(b"payload"),
            headers=headers,
            status=200,
            preload_content=False,
        )
        adapter.build_response(request, raw).content

        clock.advance(10)
        cached = adapter.controller.cached_request(request)
        assert cached
        try:
            for name, value in headers.items():
                assert cached.headers[name] == value
            assert adapter.controller.cache_age(cached) == 15
        finally:
            cached.close()
