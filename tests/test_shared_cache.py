# SPDX-FileCopyrightText: 2026
#
# SPDX-License-Identifier: Apache-2.0

"""
Shared-cache handling of the ``Cache-Control: private`` directive, including
its field-list form (``private="Set-Cookie, ..."``).

A shared cache must not store responses that are private in their entirety,
and must store only the explicitly shareable remainder of a response that
names specific private fields. Ambiguous directives resolve conservatively.
"""

import io
import time
from urllib3 import HTTPResponse

import pytest

from cachecontrol.cache import DictCache
from cachecontrol.caches import FileCache, SeparateBodyFileCache
from cachecontrol.controller import (
    CacheController,
    _strip_private_headers,
)

from .utils import DummyRequest

TIME_FMT = "%a, %d %b %Y %H:%M:%S GMT"
URL = "http://api.example.com/resource"
BODY = b'{"public": "ok", "secret": "shh"}'


def make_response(cache_control, extra_headers=None):
    headers = {
        "Cache-Control": cache_control,
        "Date": time.strftime(TIME_FMT, time.gmtime()),
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    return HTTPResponse(
        body=io.BytesIO(BODY),
        headers=headers,
        status=200,
        preload_content=False,
    )


def cache_response(controller, response, url=URL):
    request = DummyRequest(url=url, headers={})
    body = response.read(decode_content=False)
    controller.cache_response(request, response, body)
    return request


class TestPrivateDirectiveParsing:
    def setup_method(self):
        self.cc = CacheController()

    @pytest.mark.parametrize(
        "header",
        [
            "max-age=60, public",
            "no-store",
            "",
        ],
    )
    def test_no_private_directive(self, header):
        present, fields = self.cc._private_fields({"cache-control": header})
        assert present is False
        assert fields is None

    def test_bare_private_is_fully_private(self):
        assert self.cc._private_fields({"cache-control": "private"}) == (True, None)

    def test_quoted_field_list(self):
        present, fields = self.cc._private_fields(
            {"cache-control": 'private="Set-Cookie, X-Secret", max-age=60'}
        )
        assert present is True
        assert fields == ["Set-Cookie", "X-Secret"]

    def test_unquoted_field_list(self):
        assert self.cc._private_fields(
            {"cache-control": "private=Set-Cookie"}
        ) == (True, ["Set-Cookie"])

    @pytest.mark.parametrize(
        "header",
        [
            'private=""',
            'private="bad field"',
            'private="unterminated',
            "private=,",
        ],
    )
    def test_ambiguous_directive_is_conservative(self, header):
        assert self.cc._private_fields({"cache-control": header}) == (True, None)

    def test_directive_names_are_case_insensitive(self):
        assert self.cc._private_fields(
            {"cache-control": 'PRIVATE="Set-Cookie"'}
        ) == (True, ["Set-Cookie"])


class TestStripPrivateHeaders:
    def test_named_fields_are_removed_case_insensitively(self):
        from requests.structures import CaseInsensitiveDict

        headers = CaseInsensitiveDict(
            {
                "Cache-Control": 'private="Set-Cookie, X-Secret", max-age=60',
                "set-cookie": "sid=1",
                "x-secret": "topsecret",
                "X-Public": "visible",
            }
        )
        _strip_private_headers(headers, ["Set-Cookie", "X-Secret"])
        assert "Set-Cookie" not in headers
        assert "X-Secret" not in headers
        assert headers["X-Public"] == "visible"
        assert headers["Cache-Control"] == "max-age=60"

    def test_private_only_directive_removes_cache_control(self):
        from requests.structures import CaseInsensitiveDict

        headers = CaseInsensitiveDict(
            {"Cache-Control": 'private="Set-Cookie"', "Set-Cookie": "sid=1"}
        )
        _strip_private_headers(headers, ["Set-Cookie"])
        assert "Cache-Control" not in headers
        assert "Set-Cookie" not in headers


class TestSharedCacheController:
    def test_private_cache_mode_still_caches_fully_private(self):
        # Default behavior: CacheControl is a private cache, so a bare
        # "private" response remains cacheable.
        cc = CacheController(DictCache())
        response = make_response("private, max-age=3600", {"Set-Cookie": "sid=1"})
        request = cache_response(cc, response)

        assert cc.cached_request(request) is not False
        cached = cc.cached_request(request)
        assert cached.headers["Set-Cookie"] == "sid=1"
        cached.close()

    def test_shared_cache_skips_fully_private_response(self):
        cc = CacheController(DictCache(), shared_cache=True)
        response = make_response("private", {"Set-Cookie": "sid=1"})
        request = cache_response(cc, response)

        assert cc.cached_request(request) is False
        assert cc.cache.get(cc.cache_url(URL)) is None

    def test_shared_cache_purges_existing_fully_private_entry(self):
        cc = CacheController(DictCache(), shared_cache=True)
        public = make_response("max-age=3600")
        request = cache_response(cc, public)
        assert cc.cache.get(cc.cache_url(URL)) is not None

        private = make_response("private", {"Set-Cookie": "sid=1"})
        cache_response(cc, private)
        assert cc.cache.get(cc.cache_url(URL)) is None
        assert cc.cached_request(request) is False

    def test_shared_cache_strips_named_private_fields(self):
        cc = CacheController(DictCache(), shared_cache=True)
        response = make_response(
            'private="Set-Cookie, X-Secret", max-age=3600',
            {"Set-Cookie": "sid=1", "X-Secret": "topsecret", "X-Public": "ok"},
        )
        request = cache_response(cc, response)
        cached = cc.cached_request(request)

        assert cached is not False
        assert "Set-Cookie" not in cached.headers
        assert "X-Secret" not in cached.headers
        assert cached.headers["X-Public"] == "ok"
        assert "private" not in cached.headers["Cache-Control"].lower()
        assert cached.headers["Cache-Control"] == "max-age=3600"
        cached.close()

    def test_shared_cache_keeps_fully_public_response_intact(self):
        cc = CacheController(DictCache(), shared_cache=True)
        response = make_response("max-age=3600", {"X-Public": "all-good"})
        request = cache_response(cc, response)
        cached = cc.cached_request(request)

        assert cached is not False
        assert cached.headers["X-Public"] == "all-good"
        assert cached.headers["Cache-Control"] == "max-age=3600"
        cached.close()

    @pytest.mark.parametrize(
        "directive",
        ['private=""', 'private="bad field"', 'private="unterminated'],
    )
    def test_ambiguous_directive_results_in_no_storage(self, directive):
        cc = CacheController(DictCache(), shared_cache=True)
        response = make_response(
            f"{directive}, max-age=3600", {"Set-Cookie": "sid=1"}
        )
        request = cache_response(cc, response)

        assert cc.cached_request(request) is False
        assert cc.cache.get(cc.cache_url(URL)) is None

    def test_live_response_headers_are_not_mutated(self):
        cc = CacheController(DictCache(), shared_cache=True)
        original_cache_control = 'private="Set-Cookie, X-Secret", max-age=3600'
        response = make_response(
            original_cache_control,
            {"Set-Cookie": "sid=1", "X-Secret": "topsecret"},
        )
        cache_response(cc, response)

        # The online caller must still see the response exactly as received.
        assert response.headers["Cache-Control"] == original_cache_control
        assert response.headers["Set-Cookie"] == "sid=1"
        assert response.headers["X-Secret"] == "topsecret"


class TestSharedCacheRevalidation:
    def _seed_cached_entry(self, cc, url):
        etag = '"v1"'
        seeded = make_response(
            'private="Set-Cookie", max-age=0',
            {"ETag": etag, "Set-Cookie": "sid=1"},
        )
        request = DummyRequest(url=url, headers={})
        cc.cache_response(request, seeded, seeded.read(decode_content=False))
        return request, etag

    def test_304_with_field_list_stays_sanitized(self):
        cc = CacheController(DictCache(), shared_cache=True)
        request, etag = self._seed_cached_entry(cc, URL)

        not_modified = make_response(
            'private="Set-Cookie", max-age=3600',
            {"ETag": etag, "Set-Cookie": "sid=2"},
        )
        not_modified.status = 304
        result = cc.update_cached_response(request, not_modified)

        assert "Set-Cookie" not in result.headers
        assert result.headers["Cache-Control"] == "max-age=3600"
        replayed = cc.cached_request(request)
        assert replayed is not False
        assert "Set-Cookie" not in replayed.headers
        replayed.close()

    def test_304_turning_fully_private_purges_the_entry(self):
        cc = CacheController(DictCache(), shared_cache=True)
        request, etag = self._seed_cached_entry(cc, URL)

        not_modified = make_response(
            "private, max-age=3600", {"ETag": etag, "Set-Cookie": "sid=2"}
        )
        not_modified.status = 304
        result = cc.update_cached_response(request, not_modified)

        # The online 304 response itself is returned untouched.
        assert result is not_modified
        assert cc.cache.get(cc.cache_url(URL)) is None
        assert cc.cached_request(request) is False


@pytest.mark.parametrize(
    "cache_factory",
    [
        lambda tmp: DictCache(),
        lambda tmp: FileCache(str(tmp)),
        lambda tmp: SeparateBodyFileCache(str(tmp)),
    ],
    ids=["dict", "file", "separate-body-file"],
)
class TestPersistentReplay:
    def test_three_samples_round_trip(self, tmp_path, cache_factory):
        cache = cache_factory(tmp_path)
        cc = CacheController(cache, shared_cache=True)

        samples = {
            "fully-private": (
                "private",
                {"Set-Cookie": "sid=1", "X-Secret": "topsecret"},
            ),
            "field-limited": (
                'private="Set-Cookie, X-Secret", max-age=3600',
                {"Set-Cookie": "sid=1", "X-Secret": "topsecret"},
            ),
            "fully-public": ("max-age=3600", {"X-Public": "all-good"}),
        }

        live_headers = {}
        for name, (cache_control, extra) in samples.items():
            url = f"{URL}/{name}"
            response = make_response(cache_control, extra)
            live_headers[name] = dict(response.headers)
            cache_response(cc, response, url=url)
            # Storing must not alter what the online call received.
            assert dict(response.headers) == live_headers[name]

        # Replay through a brand-new controller. File-backed caches are
        # reopened from disk; the in-memory cache reuses the same instance.
        replay_cache = cache if isinstance(cache, DictCache) else cache_factory(tmp_path)
        replay = CacheController(replay_cache, shared_cache=True)

        private_request = DummyRequest(url=f"{URL}/fully-private", headers={})
        assert replay.cached_request(private_request) is False

        limited_request = DummyRequest(url=f"{URL}/field-limited", headers={})
        limited = replay.cached_request(limited_request)
        assert limited is not False
        assert "Set-Cookie" not in limited.headers
        assert "X-Secret" not in limited.headers
        assert limited.headers["Cache-Control"] == "max-age=3600"
        assert limited.read() == BODY
        limited.close()

        public_request = DummyRequest(url=f"{URL}/fully-public", headers={})
        public = replay.cached_request(public_request)
        assert public is not False
        assert public.headers["X-Public"] == "all-good"
        assert public.headers["Cache-Control"] == "max-age=3600"
        assert public.read() == BODY
        public.close()
