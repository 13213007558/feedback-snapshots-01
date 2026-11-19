# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

import calendar
import time
from datetime import datetime, timezone
from email.utils import formatdate, parsedate
from pprint import pprint
from unittest.mock import Mock

from requests import Session, get

from cachecontrol import CacheControl
from cachecontrol.heuristics import (
    TIME_FMT,
    BaseHeuristic,
    ExpiresAfter,
    LastModified,
    OneDayCache,
)

from .utils import DummyResponse


class TestHeuristicWithoutWarning:
    def setup_method(self):
        class NoopHeuristic(BaseHeuristic):
            warning = Mock()

            def update_headers(self, resp):
                return {}

        self.heuristic = NoopHeuristic()
        self.sess = CacheControl(Session(), heuristic=self.heuristic)

    def test_no_header_change_means_no_warning_header(self, url):
        the_url = url + "optional_cacheable_request"
        self.sess.get(the_url)

        assert not self.heuristic.warning.called


class TestHeuristicWith3xxResponse:
    def setup_method(self):
        class DummyHeuristic(BaseHeuristic):
            def update_headers(self, resp):
                return {"x-dummy-header": "foobar"}

        self.sess = CacheControl(Session(), heuristic=DummyHeuristic())

    def test_heuristic_applies_to_301(self, url):
        the_url = url + "permanent_redirect"
        resp = self.sess.get(the_url)
        assert "x-dummy-header" in resp.headers

    def test_heuristic_applies_to_304(self, url):
        the_url = url + "conditional_get"
        resp = self.sess.get(the_url)
        assert "x-dummy-header" in resp.headers


class TestUseExpiresHeuristic:
    def test_expires_heuristic_arg(self):
        sess = Session()
        cached_sess = CacheControl(sess, heuristic=Mock())
        assert cached_sess


class TestOneDayCache:
    def setup_method(self):
        self.sess = Session()
        self.cached_sess = CacheControl(self.sess, heuristic=OneDayCache())

    def test_cache_for_one_day(self, url):
        the_url = url + "optional_cacheable_request"
        r = self.sess.get(the_url)

        assert "expires" in r.headers
        assert "warning" in r.headers

        pprint(dict(r.headers))

        r = self.sess.get(the_url)
        pprint(dict(r.headers))
        assert r.from_cache


class TestExpiresAfter:
    def setup_method(self):
        self.sess = Session()
        self.cache_sess = CacheControl(self.sess, heuristic=ExpiresAfter(days=1))

    def test_expires_after_one_day(self, url):
        the_url = url + "no_cache"
        resp = get(the_url)
        assert resp.headers["cache-control"] == "no-cache"

        r = self.sess.get(the_url)

        assert "expires" in r.headers
        assert "warning" in r.headers
        assert r.headers["cache-control"] == "public"

        r = self.sess.get(the_url)
        assert r.from_cache


class TestLastModified:
    def setup_method(self):
        self.sess = Session()
        self.cached_sess = CacheControl(self.sess, heuristic=LastModified())

    def test_last_modified(self, url):
        the_url = url + "optional_cacheable_request"
        r = self.sess.get(the_url)

        assert "expires" in r.headers
        assert "warning" not in r.headers

        pprint(dict(r.headers))

        r = self.sess.get(the_url)
        pprint(dict(r.headers))
        assert r.from_cache


def datetime_to_header(dt):
    return formatdate(calendar.timegm(dt.timetuple()))


class TestHeuristicPreservesRevalidation:
    def test_heuristic_does_not_drop_must_revalidate(self):
        """A heuristic may synthesize freshness, but not weaken revalidation."""

        class PublicHeuristic(BaseHeuristic):
            def update_headers(self, resp):
                return {"cache-control": "public"}

        resp = DummyResponse(
            200, {"Cache-Control": "public, max-age=1, must-revalidate"}
        )
        updated = PublicHeuristic().apply(resp)

        assert updated.headers["cache-control"] == "public, must-revalidate"

    def test_expires_after_keeps_must_revalidate(self):
        """The bundled ExpiresAfter heuristic replaces Cache-Control; retain it."""
        resp = DummyResponse(200, {"Cache-Control": "must-revalidate"})
        updated = ExpiresAfter(hours=1).apply(resp)

        assert "must-revalidate" in updated.headers["cache-control"]


class TestModifiedUnitTests:
    def last_modified(self, period):
        return time.strftime(TIME_FMT, time.gmtime(self.time_now - period))

    def setup_method(self):
        self.heuristic = LastModified()
        self.time_now = time.time()
        day_in_seconds = 86400
        self.year_ago = self.last_modified(day_in_seconds * 365)
        self.week_ago = self.last_modified(day_in_seconds * 7)
        self.day_ago = self.last_modified(day_in_seconds)
        self.now = self.last_modified(0)

        # NOTE: We pass in a negative to get a positive... Probably
        #       should refactor.
        self.day_ahead = self.last_modified(-day_in_seconds)

    def test_no_expiry_is_inferred_when_no_last_modified_is_present(self):
        assert self.heuristic.update_headers(DummyResponse(200, {})) == {}

    def test_expires_is_not_replaced_when_present(self):
        resp = DummyResponse(200, {"Expires": self.day_ahead})
        assert self.heuristic.update_headers(resp) == {}

    def test_last_modified_is_used(self):
        resp = DummyResponse(200, {"Date": self.now, "Last-Modified": self.week_ago})
        modified = self.heuristic.update_headers(resp)
        assert ["expires"] == list(modified.keys())

        expected = datetime(*parsedate(modified["expires"])[:6], tzinfo=timezone.utc)
        assert expected > datetime.now(timezone.utc)

    def test_last_modified_is_not_used_when_cache_control_present(self):
        resp = DummyResponse(
            200,
            {
                "Date": self.now,
                "Last-Modified": self.week_ago,
                "Cache-Control": "private",
            },
        )
        assert self.heuristic.update_headers(resp) == {}

    def test_last_modified_is_not_used_when_status_is_unknown(self):
        resp = DummyResponse(299, {"Date": self.now, "Last-Modified": self.week_ago})
        assert self.heuristic.update_headers(resp) == {}

    def test_last_modified_is_used_when_cache_control_public(self):
        resp = DummyResponse(
            200,
            {
                "Date": self.now,
                "Last-Modified": self.week_ago,
                "Cache-Control": "public",
            },
        )
        modified = self.heuristic.update_headers(resp)
        assert ["expires"] == list(modified.keys())
        expected = datetime(*parsedate(modified["expires"])[:6], tzinfo=timezone.utc)
        assert expected > datetime.now(timezone.utc)

    def test_last_modified_is_used_when_cache_control_public_must_revalidate(self):
        """must-revalidate does not forbid heuristic freshness on its own."""
        resp = DummyResponse(
            200,
            {
                "Date": self.now,
                "Last-Modified": self.week_ago,
                "Cache-Control": "public, must-revalidate",
            },
        )
        modified = self.heuristic.update_headers(resp)
        assert ["expires"] == list(modified.keys())

    def test_last_modified_is_not_used_when_cache_control_forbids_storage(self):
        resp = DummyResponse(
            200,
            {
                "Date": self.now,
                "Last-Modified": self.week_ago,
                "Cache-Control": "public, no-store",
            },
        )
        assert self.heuristic.update_headers(resp) == {}

    def test_warning_not_added_when_response_more_recent_than_24_hours(self):
        resp = DummyResponse(200, {"Date": self.now, "Last-Modified": self.week_ago})
        assert self.heuristic.warning(resp) is None

    def test_warning_is_not_added_when_heuristic_was_not_used(self):
        resp = DummyResponse(200, {"Date": self.now, "Expires": self.day_ahead})
        assert self.heuristic.warning(resp) is None

    def test_expiry_is_no_more_that_twenty_four_hours(self):
        resp = DummyResponse(200, {"Date": self.now, "Last-Modified": self.year_ago})
        modified = self.heuristic.update_headers(resp)
        assert ["expires"] == list(modified.keys())
        assert self.day_ahead == modified["expires"]
