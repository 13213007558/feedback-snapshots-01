"""
Shared utility classes.
"""

import time
from contextvars import ContextVar
from io import BytesIO
from typing import Any
from unittest.mock import patch

from requests.structures import CaseInsensitiveDict
from urllib3 import HTTPResponse

from cachecontrol.adapter import CacheControlAdapter
from cachecontrol.serialize import Serializer


class NullSerializer(Serializer):
    def dumps(self, request, response, body=None):
        return response

    def loads(self, request, data, body_file=None):
        if data and getattr(data, "chunked", False):
            data.chunked = False
        return data


class DummyResponse:
    """Match a ``urllib3.response.HTTPResponse``."""

    version = "1.1"
    reason = b"Because"
    strict = 0
    decode_content = False

    def __init__(self, status, headers):
        self.status = status
        self.headers = CaseInsensitiveDict(headers)


class DummyRequest:
    """Match a Request."""

    def __init__(self, url, headers):
        self.url = url
        self.headers = CaseInsensitiveDict(headers)


class _ClosingBody:
    """Mimic an ``http.client.HTTPResponse`` body stream.

    The cache writes its entry once the underlying stream reports itself as
    closed after the final read. A plain ``BytesIO`` never does, so this
    wrapper flips ``fp`` to ``None`` on EOF, matching the real transport.
    """

    def __init__(self, data: bytes):
        self._buffer = BytesIO(data)
        self.fp: Any = self

    def read(self, amt: int | None = None) -> bytes:
        data = self._buffer.read(amt)
        if data == b"":
            self.fp = None
        return data

    def readinto(self, buffer: bytearray) -> int:
        data = self.read(len(buffer))
        count = len(data)
        buffer[:count] = data
        return count

    def close(self) -> None:
        self.fp = None


# Route names understood by :class:`RecordingCacheControlAdapter`. Each one
# stands for one of the three sharing categories used by the shared-cache
# tests:
#
# * ``public``    -- a public resource requested without credentials.
# * ``shareable`` -- an authenticated response the origin marks shareable.
# * ``private``   -- an authenticated response with no sharing permission.
ROUTE_PUBLIC = "public"
ROUTE_SHAREABLE = "shareable"
ROUTE_PRIVATE = "private"


def _recording_urlopen(
    pool: Any, method: str, url: str, **kwargs: Any
) -> HTTPResponse:
    adapter = RecordingCacheControlAdapter._active_adapter.get()
    assert adapter is not None, "urlopen called outside a recording adapter"
    return adapter._urlopen(pool, method, url, **kwargs)


class RecordingCacheControlAdapter(CacheControlAdapter):
    """CacheControl adapter that records how often it goes back to the origin.

    The transport is mocked, so no socket or test server is required. Origin
    fetches are counted separately for public resources, explicitly
    shareable authenticated responses and private authenticated responses.

    Because every instance replaces the same
    ``HTTPConnectionPool.urlopen`` method, the active adapter for a given
    request is tracked in a :class:`ContextVar` while ``send`` runs; this
    keeps each adapter's counts independent even when several sessions share
    a cache.
    """

    #: Maps each route to the response headers the "origin" returns.
    route_headers = {
        ROUTE_PUBLIC: {"Cache-Control": "max-age=60"},
        ROUTE_SHAREABLE: {"Cache-Control": "public, max-age=60"},
        ROUTE_PRIVATE: {"Cache-Control": "max-age=60"},
    }

    _active_adapter: ContextVar["RecordingCacheControlAdapter | None"] = ContextVar(
        "recording_adapter", default=None
    )
    _patch_count = 0
    _global_patcher: Any = None

    def __init__(self, *args: Any, body: bytes = b"payload", **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.body = body
        self.origin_fetch_counts = {
            ROUTE_PUBLIC: 0,
            ROUTE_SHAREABLE: 0,
            ROUTE_PRIVATE: 0,
        }

    def start(self) -> "RecordingCacheControlAdapter":
        cls = type(self)
        if cls._patch_count == 0:
            cls._global_patcher = patch(
                "urllib3.connectionpool.HTTPConnectionPool.urlopen",
                _recording_urlopen,
            )
            cls._global_patcher.start()
        cls._patch_count += 1
        return self

    def stop(self) -> None:
        cls = type(self)
        cls._patch_count -= 1
        if cls._patch_count == 0:
            cls._global_patcher.stop()
            cls._global_patcher = None

    def send(self, request: Any, *args: Any, **kwargs: Any) -> Any:
        token = self._active_adapter.set(self)
        try:
            return super().send(request, *args, **kwargs)
        finally:
            self._active_adapter.reset(token)

    def _route_for(self, url: str) -> str:
        for route in self.route_headers:
            if url.rstrip("/").endswith(route):
                return route
        raise KeyError(f"unknown test route in url: {url!r}")

    def _urlopen(
        self, pool: Any, method: str, url: str, **kwargs: Any
    ) -> HTTPResponse:
        route = self._route_for(url)
        self.origin_fetch_counts[route] += 1

        headers = {"Date": self._http_date(), "Content-Type": "text/plain"}
        headers.update(self.route_headers[route])

        return HTTPResponse(
            body=_ClosingBody(self.body),
            headers=headers,
            status=200,
            reason="OK",
            preload_content=False,
        )

    @staticmethod
    def _http_date() -> str:
        return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

    @property
    def total_origin_fetches(self) -> int:
        return sum(self.origin_fetch_counts.values())
