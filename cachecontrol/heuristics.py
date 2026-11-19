# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import calendar
import time
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, parsedate, parsedate_tz
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from urllib3 import HTTPResponse

TIME_FMT = "%a, %d %b %Y %H:%M:%S GMT"


def expire_after(delta: timedelta, date: datetime | None = None) -> datetime:
    date = date or datetime.now(timezone.utc)
    return date + delta


def datetime_to_header(dt: datetime) -> str:
    return formatdate(calendar.timegm(dt.timetuple()))


class BaseHeuristic:
    def warning(self, response: HTTPResponse) -> str | None:
        """
        Return a valid 1xx warning header value describing the cache
        adjustments.

        The response is provided too allow warnings like 113
        http://tools.ietf.org/html/rfc7234#section-5.5.4 where we need
        to explicitly say response is over 24 hours old.
        """
        return '110 - "Response is Stale"'

    def update_headers(self, response: HTTPResponse) -> dict[str, str]:
        """Update the response headers with any new headers.

        NOTE: This SHOULD always include some Warning header to
              signify that the response was cached by the client, not
              by way of the provided headers.
        """
        return {}

    def apply(self, response: HTTPResponse) -> HTTPResponse:
        # A heuristic may synthesize cache-control headers, but it must not
        # weaken a revalidation requirement set by the origin. Capture the
        # original directive before update_headers() gets a chance to mutate
        # the response's headers in place.
        original_cc = str(response.headers.get("cache-control", ""))
        must_revalidate = "must-revalidate" in original_cc.lower()

        updated_headers = self.update_headers(response)

        for header, value in updated_headers.items():
            if header.lower() != "cache-control" or not must_revalidate:
                continue
            if "must-revalidate" not in str(value).lower():
                updated_headers[header] = f"{value}, must-revalidate"

        if updated_headers:
            response.headers.update(updated_headers)
            warning_header_value = self.warning(response)
            if warning_header_value is not None:
                response.headers.update({"Warning": warning_header_value})

        if must_revalidate:
            current_cc = response.headers.get("cache-control")
            if current_cc is None:
                response.headers["cache-control"] = "must-revalidate"
            elif "must-revalidate" not in str(current_cc).lower():
                response.headers["cache-control"] = f"{current_cc}, must-revalidate"

        return response


class OneDayCache(BaseHeuristic):
    """
    Cache the response by providing an expires 1 day in the
    future.
    """

    def update_headers(self, response: HTTPResponse) -> dict[str, str]:
        headers = {}

        if "expires" not in response.headers:
            date = parsedate(response.headers["date"])
            expires = expire_after(
                timedelta(days=1),
                date=datetime(*date[:6], tzinfo=timezone.utc),  # type: ignore[index,misc]
            )
            headers["expires"] = datetime_to_header(expires)
            headers["cache-control"] = "public"
        return headers


class ExpiresAfter(BaseHeuristic):
    """
    Cache **all** requests for a defined time period.
    """

    def __init__(self, **kw: Any) -> None:
        self.delta = timedelta(**kw)

    def update_headers(self, response: HTTPResponse) -> dict[str, str]:
        expires = expire_after(self.delta)
        return {"expires": datetime_to_header(expires), "cache-control": "public"}

    def warning(self, response: HTTPResponse) -> str | None:
        tmpl = "110 - Automatically cached for %s. Response might be stale"
        return tmpl % self.delta


class LastModified(BaseHeuristic):
    """
    If there is no Expires header already, fall back on Last-Modified
    using the heuristic from
    http://tools.ietf.org/html/rfc7234#section-4.2.2
    to calculate a reasonable value.

    Firefox also does something like this per
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching_FAQ
    http://lxr.mozilla.org/mozilla-release/source/netwerk/protocol/http/nsHttpResponseHead.cpp#397
    Unlike mozilla we limit this to 24-hr.
    """

    cacheable_by_default_statuses = {
        200,
        203,
        204,
        206,
        300,
        301,
        404,
        405,
        410,
        414,
        501,
    }

    def update_headers(self, resp: HTTPResponse) -> dict[str, str]:
        headers: Mapping[str, str] = resp.headers

        if "expires" in headers:
            return {}

        if "cache-control" in headers:
            # Heuristic freshness may only be synthesized when the origin did
            # not provide explicit freshness or forbid caching. A
            # must-revalidate directive does not prevent caching; it only
            # requires revalidation once the heuristic lifetime has elapsed,
            # and apply() makes sure that directive is preserved.
            directives = {
                directive.split("=", 1)[0].strip().lower()
                for directive in headers["cache-control"].split(",")
            }
            if directives - {"public", "must-revalidate"}:
                return {}

        if resp.status not in self.cacheable_by_default_statuses:
            return {}

        if "date" not in headers or "last-modified" not in headers:
            return {}

        time_tuple = parsedate_tz(headers["date"])
        assert time_tuple is not None
        date = calendar.timegm(time_tuple[:6])
        last_modified = parsedate(headers["last-modified"])
        if last_modified is None:
            return {}

        now = time.time()
        current_age = max(0, now - date)
        delta = date - calendar.timegm(last_modified)
        freshness_lifetime = max(0, min(delta / 10, 24 * 3600))
        if freshness_lifetime <= current_age:
            return {}

        expires = date + freshness_lifetime
        return {"expires": time.strftime(TIME_FMT, time.gmtime(expires))}

    def warning(self, resp: HTTPResponse) -> str | None:
        return None
