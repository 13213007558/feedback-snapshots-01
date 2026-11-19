# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the configurable authorization-redirect caching policy.

A file service may redirect a stable download entry point to a short-lived
authorized URL (for example a presigned object-store link). Such redirects
must still be delivered to the online caller, but they must never be stored
as reusable cache entries. Redirects explicitly marked ``Cache-Control:
public`` are exempt and keep being cached normally.
"""

import os
from email.utils import formatdate
from unittest import mock

from urllib3 import HTTPResponse

import cachecontrol.adapter as adapter_module
from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.cache import DictCache
from cachecontrol.caches import FileCache
from cachecontrol.controller import CacheController

from .utils import DummyRequest, DummyResponse

ENTRY_URL = "http://files.example.com/download/report"
# A fresh, single-use signed address is synthesized on every response.
SIGNED_URL = "http://files.example.com/signed/report?token=SECRET&expires=123"
PUBLIC_URL = "http://files.example.com/permalink/report"
DATE = formatdate(usegmt=True)


def points_at_authorized_url(request, response):
    """Application-defined rule: signed download URLs carry a ``token``."""
    return "token=" in response.headers.get("Location", "")


def make_redirect(headers):
    return DummyResponse(301, {"Location": SIGNED_URL, **headers})


class TestAuthorizationRedirectPolicy:
    def setup_method(self):
        self.cache = DictCache()
        self.controller = CacheController(
            self.cache, authorization_redirect=points_at_authorized_url
        )
        self.request = DummyRequest(ENTRY_URL, {})

    def test_authorization_redirect_is_not_cached(self):
        # The redirect is still handed back to the caller unchanged; only the
        # cache write has to be suppressed.
        self.controller.cache_response(self.request, make_redirect({}))

        assert self.cache.get(self.controller.cache_url(ENTRY_URL)) is None

    def test_public_redirect_is_cached_even_when_rule_matches(self):
        self.controller.cache_response(
            self.request, make_redirect({"Cache-Control": "public"})
        )

        assert self.cache.get(self.controller.cache_url(ENTRY_URL)) is not None

    def test_ordinary_redirect_uses_default_caching_rules(self):
        # No authorization-redirect callback configured: behavior is unchanged.
        controller = CacheController(DictCache())

        controller.cache_response(self.request, make_redirect({}))

        assert controller.cache.get(controller.cache_url(ENTRY_URL)) is not None

    def test_rule_without_location_header_is_ignored(self):
        response = DummyResponse(200, {"Cache-Control": "max-age=3600"})

        assert (
            self.controller.is_authorization_redirect(self.request, response) is False
        )

    def test_existing_entry_is_purged_when_policy_flips_to_authorized(self):
        # Seed a reusable entry for the stable URL, as would exist before the
        # service started issuing signed redirects.
        self.controller.cache_response(
            self.request, DummyResponse(301, {"Location": "/old-permalink"})
        )
        cache_url = self.controller.cache_url(ENTRY_URL)
        assert self.cache.get(cache_url) is not None

        self.controller.cache_response(self.request, make_redirect({}))

        assert self.cache.get(cache_url) is None

    def test_non_redirect_responses_are_unaffected(self):
        # A 200 carrying a Location is not a redirect, so the policy must not
        # interfere with ordinary freshness-based caching.
        cache = DictCache()
        controller = CacheController(
            cache,
            serializer=mock.Mock(),
            authorization_redirect=points_at_authorized_url,
        )
        response = mock.Mock(
            status=200,
            headers={
                "Location": SIGNED_URL,
                "Cache-Control": "max-age=3600",
                "Date": DATE,
            },
        )

        controller.cache_response(self.request, response)

        assert cache.get(controller.cache_url(ENTRY_URL)) is not None


class TestAuthorizationRedirectFileCache:
    """End-to-end check through the adapter and a persistent on-disk cache."""

    def _raw_response(self, url):
        if url == ENTRY_URL:
            return HTTPResponse(
                status=301,
                headers={"Location": SIGNED_URL, "Date": DATE},
                body=b"",
            )
        if url == PUBLIC_URL:
            return HTTPResponse(
                status=301,
                headers={
                    "Location": "http://files.example.com/final",
                    "Cache-Control": "public",
                    "Date": DATE,
                },
                body=b"",
            )
        return HTTPResponse(
            status=200, headers={"Cache-Control": "max-age=5000"}, body=b"ok"
        )

    def test_only_public_redirect_hits_cache_and_disk_has_no_signed_url(self, tmp_path):
        cache = FileCache(str(tmp_path / "cache"))
        adapter = CacheControlAdapter(
            cache=cache, authorization_redirect=points_at_authorized_url
        )

        def prepared(url):
            request = mock.Mock()
            request.url = url
            request.method = "GET"
            request.headers = {}
            return request

        def fake_send(self, request, *args, **kwargs):
            raw = self._raw_response(request.url)
            return self.build_response(request, raw)

        adapter._raw_response = self._raw_response

        with mock.patch.object(adapter_module.HTTPAdapter, "send", fake_send):
            # First contact: follow the synthetic signed redirect once. It must
            # be served online, not from the cache.
            first = adapter.send(prepared(ENTRY_URL))
            assert first.status_code == 301
            assert first.headers["Location"] == SIGNED_URL
            assert first.from_cache is False

            # Second contact through the same persistent cache: the policy
            # forbids reusing the signed redirect, so it goes online again.
            second = adapter.send(prepared(ENTRY_URL))
            assert second.from_cache is False

            # The explicitly public redirect is reusable on the second hit.
            public_first = adapter.send(prepared(PUBLIC_URL))
            public_second = adapter.send(prepared(PUBLIC_URL))
            assert public_first.from_cache is False
            assert public_second.from_cache is True

        auth_path = cache._fn(CacheController.cache_url(ENTRY_URL))
        public_path = cache._fn(CacheController.cache_url(PUBLIC_URL))
        assert not os.path.exists(auth_path)
        assert os.path.exists(public_path)

        # Nothing persisted on disk may contain the short-lived signed address.
        on_disk = b""
        for root, _, files in os.walk(cache.directory):
            for name in files:
                with open(os.path.join(root, name), "rb") as handle:
                    on_disk += handle.read()
        assert b"SECRET" not in on_disk
        assert SIGNED_URL.encode() not in on_disk

        adapter.close()
