# SPDX-FileCopyrightText: 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Shared-cache mode tests.

These tests exercise a cache store that is shared by more than one worker
(session). A recording adapter counts origin fetches separately for public
resources, explicitly shareable authenticated responses and private
authenticated responses, without needing a live HTTP server.
"""

import time

import pytest
import requests

from cachecontrol import CacheControl
from cachecontrol.cache import DictCache
from cachecontrol.caches import SeparateBodyFileCache
from cachecontrol.controller import CacheController
from tests.utils import (
    DummyRequest,
    DummyResponse,
    ROUTE_PRIVATE,
    ROUTE_PUBLIC,
    ROUTE_SHAREABLE,
    RecordingCacheControlAdapter,
)

TIME_FMT = "%a, %d %b %Y %H:%M:%S GMT"
BASE_URL = "http://shared.example.test/"
AUTH = {"Authorization": "Bearer worker-token"}


def _http_date() -> str:
    return time.strftime(TIME_FMT, time.gmtime())


def _make_session(cache, shared):
    adapter = RecordingCacheControlAdapter(cache=cache, shared=shared).start()
    session = requests.Session()
    session.mount("http://", adapter)
    return session, adapter


@pytest.fixture()
def shared_cache(tmp_path):
    return SeparateBodyFileCache(str(tmp_path / "shared-cache"))


class TestSharedCacheMode:
    def test_public_resource_is_shared_between_workers(self, shared_cache):
        session_one, adapter_one = _make_session(shared_cache, shared=True)
        session_two, adapter_two = _make_session(shared_cache, shared=True)
        url = BASE_URL + ROUTE_PUBLIC
        try:
            first = session_one.get(url)
            second = session_two.get(url)
        finally:
            session_one.close()
            session_two.close()

        assert first.from_cache is False
        assert second.from_cache is True
        assert adapter_one.origin_fetch_counts[ROUTE_PUBLIC] == 1
        assert adapter_two.origin_fetch_counts[ROUTE_PUBLIC] == 0

    def test_shareable_authenticated_response_is_shared(self, shared_cache):
        session_one, adapter_one = _make_session(shared_cache, shared=True)
        session_two, adapter_two = _make_session(shared_cache, shared=True)
        url = BASE_URL + ROUTE_SHAREABLE
        try:
            first = session_one.get(url, headers=AUTH)
            second = session_two.get(url, headers=AUTH)
        finally:
            session_one.close()
            session_two.close()

        assert first.from_cache is False
        assert second.from_cache is True
        assert adapter_one.origin_fetch_counts[ROUTE_SHAREABLE] == 1
        assert adapter_two.origin_fetch_counts[ROUTE_SHAREABLE] == 0

    @pytest.mark.parametrize(
        "directive",
        ["public, max-age=60", "s-maxage=60, max-age=60"],
    )
    def test_only_explicit_sharing_permission_is_accepted(
        self, shared_cache, directive
    ):
        controller = CacheController(shared_cache, shared=True)
        request = DummyRequest(BASE_URL + "granted", AUTH)
        response = DummyResponse(
            200, {"cache-control": directive, "date": _http_date()}
        )

        controller.cache_response(request, response, b"body")

        loaded = controller._load_from_cache(
            DummyRequest(BASE_URL + "granted", AUTH)
        )
        assert loaded is not None

    def test_private_authenticated_response_is_never_stored(self, shared_cache):
        session_one, adapter_one = _make_session(shared_cache, shared=True)
        session_two, adapter_two = _make_session(shared_cache, shared=True)
        url = BASE_URL + ROUTE_PRIVATE
        try:
            first = session_one.get(url, headers=AUTH)
            second = session_two.get(url, headers=AUTH)
        finally:
            session_one.close()
            session_two.close()

        assert first.from_cache is False
        assert second.from_cache is False
        assert adapter_one.origin_fetch_counts[ROUTE_PRIVATE] == 1
        assert adapter_two.origin_fetch_counts[ROUTE_PRIVATE] == 1
        assert shared_cache.get(CacheController.cache_url(url)) is None

    def test_private_response_removes_previously_shared_entry(self):
        cache = DictCache()
        controller = CacheController(cache, shared=True)
        url = BASE_URL + "downgraded"
        request = DummyRequest(url, AUTH)

        # The origin first explicitly allows sharing, then later stops.
        controller.cache_response(
            request,
            DummyResponse(
                200,
                {"cache-control": "public, max-age=60", "date": _http_date()},
            ),
            b"shared",
        )
        assert cache.get(url) is not None

        controller.cache_response(
            request,
            DummyResponse(
                200, {"cache-control": "max-age=60", "date": _http_date()}
            ),
            b"private",
        )
        assert cache.get(url) is None

    def test_legacy_entry_without_provenance_is_a_miss(self, shared_cache):
        controller = CacheController(shared_cache, shared=True)
        url = BASE_URL + "legacy"
        request = DummyRequest(url, AUTH)

        # An entry written without the shareability provenance record, as an
        # older CacheControl version (or a foreign writer) would leave behind.
        legacy = DummyResponse(
            200,
            {
                "cache-control": "public, max-age=60",
                "date": _http_date(),
            },
        )
        shared_cache.set(url, controller.serializer.dumps(request, legacy, b"old"))

        assert controller._load_from_cache(DummyRequest(url, AUTH)) is None

    def test_legacy_entry_miss_does_not_count_as_origin_hit(self, shared_cache):
        session, adapter = _make_session(shared_cache, shared=True)
        url = BASE_URL + ROUTE_PUBLIC
        # Pre-populate the cache directly, bypassing the provenance marking.
        legacy = DummyResponse(
            200,
            {"cache-control": "max-age=60", "date": _http_date()},
        )
        shared_cache.set(
            CacheController.cache_url(url),
            CacheController().serializer.dumps(
                DummyRequest(url, {}), legacy, b"old"
            ),
        )
        try:
            response = session.get(url)
        finally:
            session.close()

        assert response.from_cache is False
        assert adapter.origin_fetch_counts[ROUTE_PUBLIC] == 1


class TestPrivateCacheUnchanged:
    """The default (non-shared) cache keeps its historical behavior."""

    def test_private_mode_caches_authenticated_response(self):
        cache = DictCache()
        session, adapter = _make_session(cache, shared=False)
        url = BASE_URL + ROUTE_PRIVATE
        try:
            first = session.get(url, headers=AUTH)
            second = session.get(url, headers=AUTH)
        finally:
            session.close()

        assert first.from_cache is False
        assert second.from_cache is True
        assert adapter.origin_fetch_counts[ROUTE_PRIVATE] == 1

    def test_private_mode_serves_legacy_entries(self):
        cache = DictCache()
        controller = CacheController(cache)
        url = BASE_URL + "legacy"
        legacy = DummyResponse(
            200, {"cache-control": "max-age=60", "date": _http_date()}
        )
        cache.set(
            url,
            controller.serializer.dumps(DummyRequest(url, {}), legacy, b"old"),
        )

        assert controller._load_from_cache(DummyRequest(url, {})) is not None


class TestWrapperConstruction:
    def test_wrapper_enables_shared_mode(self):
        cache = DictCache()
        session = CacheControl(requests.Session(), cache=cache, shared=True)
        adapter = session.adapters["http://"]
        assert adapter.controller.shared is True
        session.close()

    def test_wrapper_defaults_to_private_mode(self):
        cache = DictCache()
        session = CacheControl(requests.Session(), cache=cache)
        adapter = session.adapters["http://"]
        assert adapter.controller.shared is False
        session.close()


class TestSharingPermissionDirectives:
    def test_public_or_smaxage_grant_sharing(self):
        controller = CacheController(shared=True)
        assert controller._allows_shared({"Cache-Control": "public"})
        assert controller._allows_shared({"Cache-Control": "s-maxage=60"})
        assert controller._allows_shared(
            {"Cache-Control": "public, s-maxage=60, max-age=0"}
        )

    def test_private_directives_do_not_grant_sharing(self):
        controller = CacheController(shared=True)
        assert not controller._allows_shared({"Cache-Control": "max-age=60"})
        assert not controller._allows_shared({"Cache-Control": "private, max-age=60"})
        assert not controller._allows_shared({"Cache-Control": "no-cache"})
        assert not controller._allows_shared({})

    def test_authorization_header_detection_is_case_insensitive(self):
        lower = DummyRequest(BASE_URL, {"authorization": "Bearer t"})
        upper = DummyRequest(BASE_URL, {"Authorization": "Bearer t"})
        missing = DummyRequest(BASE_URL, {})
        assert CacheController._is_authenticated(lower)
        assert CacheController._is_authenticated(upper)
        assert not CacheController._is_authenticated(missing)
