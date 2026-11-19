# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""
Acceptance tests for caching streamed responses behind a swappable HTTP
transport.

The production transport is replaced with a deterministic in-process fake
(no sockets, no network). The fake hands the *real* urllib3
``HTTPResponse`` / cachecontrol read path a controllable body file, so the
tests exercise the same close/EOF/error handling a real socket-backed
response would trigger.

Callers sometimes:

* read only part of a streamed response and then close it, or
* receive an I/O error before the body is fully delivered.

In both cases the cache must not publish a (possibly truncated) response.
These tests pin that contract for the in-memory cache and both persistent
file backends, and verify what is actually stored on disk and what a later
request replays. They deliberately assert on the *body* and on the cache
entry, not just the HTTP status code, so an implementation that commits a
half-read body after seeing ``200 OK`` fails here.

The matrix also covers responses *without* a ``Content-Length`` header
(connection-delimited bodies). That is the case where the serializer's
length sanity check cannot help, so it is the one most likely to expose a
regression while swapping the underlying HTTP transport.
"""

from __future__ import annotations

import io
import os
from email.utils import formatdate
from typing import TYPE_CHECKING

import pytest
import requests
from urllib3 import HTTPResponse

from cachecontrol import CacheControl
from cachecontrol.cache import DictCache
from cachecontrol.caches import FileCache, SeparateBodyFileCache

if TYPE_CHECKING:
    from cachecontrol.cache import BaseCache

URL = "http://127.0.0.1/streaming-resource"

# Larger than any single read chunk requests/urllib3 will issue, so a
# consumer that stops after a couple of chunks is genuinely partial.
BODY = b"0123456789ABCDEF" * 4096  # 64 KiB
PARTIAL_READ_CHUNK = 1024
PARTIAL_READ_CHUNKS = 2
FAIL_AFTER_BYTES = 32


def _cacheable_headers(content_length: bool) -> dict[str, str]:
    headers = {
        "Date": formatdate(usegmt=True),
        "Cache-Control": "max-age=86400",
        "Content-Type": "text/plain",
    }
    if content_length:
        headers["Content-Length"] = str(len(BODY))
    return headers


class FakeBodyFile:
    """Stand-in for the socket file behind ``http.client.HTTPResponse``.

    Models the two behaviours cachecontrol relies on to tell "finished"
    apart from "abandoned":

    * ``isclosed()`` / ``fp is None`` flips once the response is closed, and
    * reading to EOF closes the file just like a real body whose final byte
      has been consumed.

    ``fail_after`` raises an ``OSError`` mid-stream, simulating a broken
    connection before the full body is available.
    """

    def __init__(self, data: bytes, fail_after: int | None = None) -> None:
        self._buf = io.BytesIO(data)
        self._fail_after = fail_after
        self._emitted = 0
        self.closed = False
        self.fp: object | None = object()

    def isclosed(self) -> bool:
        return self.fp is None

    def read(self, amt: int | None = None) -> bytes:
        if self.closed:
            return b""

        data = self._buf.read(amt)

        if data and self._fail_after is not None:
            if self._emitted < self._fail_after < self._emitted + len(data):
                data = data[: self._fail_after - self._emitted]
            self._emitted += len(data)
            if self._emitted >= self._fail_after:
                raise OSError("simulated mid-stream connection failure")

        if not data:
            # A real http.client HTTPResponse closes itself at EOF.
            self.close()
        return data

    def read1(self, amt: int | None = None) -> bytes:
        return self.read(amt)

    def close(self) -> None:
        self.closed = True
        self.fp = None


class FakeConnectionPool:
    """Matches the slice of a urllib3 connection pool requests calls."""

    def __init__(self, script: list[str], content_length: bool) -> None:
        self._script = script
        self._content_length = content_length
        self.urlopen_calls = 0

    def urlopen(self, method: str, url: str, **kwargs: object) -> HTTPResponse:
        outcome = self._script[min(self.urlopen_calls, len(self._script) - 1)]
        self.urlopen_calls += 1

        fail_after = FAIL_AFTER_BYTES if outcome == "error" else None
        body = FakeBodyFile(BODY, fail_after=fail_after)
        return HTTPResponse(
            body=body,
            headers=_cacheable_headers(self._content_length),
            status=200,
            reason="OK",
            version=11,
            preload_content=False,
        )


class FakePoolManager:
    """Replaces ``adapter.poolmanager`` so no real connection is opened."""

    def __init__(self, pool: FakeConnectionPool) -> None:
        self._pool = pool

    def connection_from_host(self, **kwargs: object) -> FakeConnectionPool:
        return self._pool

    def clear(self) -> None:
        pass


def _make_session(
    cache: BaseCache, script: list[str], content_length: bool
) -> tuple[requests.Session, FakeConnectionPool]:
    session = CacheControl(requests.Session(), cache=cache)
    pool = FakeConnectionPool(script, content_length=content_length)
    adapter = session.get_adapter(URL)
    adapter.poolmanager = FakePoolManager(pool)  # type: ignore[attr-defined]
    return session, pool


def _cache_key() -> str:
    from cachecontrol.controller import CacheController

    return CacheController.cache_url(URL)


@pytest.fixture(params=[True, False], ids=["content-length", "connection-delimited"])
def content_length(request: pytest.FixtureRequest) -> bool:
    return bool(request.param)


@pytest.fixture(
    params=[
        pytest.param("dict", id="DictCache"),
        pytest.param("file", id="FileCache"),
        pytest.param("separate-body-file", id="SeparateBodyFileCache"),
    ]
)
def cache_backend(request: pytest.FixtureRequest, tmp_path: object) -> BaseCache:
    kind = request.param
    if kind == "dict":
        return DictCache()
    if kind == "file":
        return FileCache(str(tmp_path))
    return SeparateBodyFileCache(str(tmp_path))


@pytest.fixture()
def cache_paths(
    cache_backend: BaseCache,
) -> tuple[BaseCache, str | None, str | None]:
    """Return the backend and the on-disk metadata/body paths when applicable."""
    if isinstance(cache_backend, (FileCache, SeparateBodyFileCache)):
        metadata_path = cache_backend._fn(  # type: ignore[attr-defined]
            _cache_key()
        )
        body_path = metadata_path + ".body"
    else:
        metadata_path = None
        body_path = None
    return cache_backend, metadata_path, body_path


def _assert_no_persisted_entry(
    cache: BaseCache, metadata_path: str | None, body_path: str | None
) -> None:
    assert cache.get(_cache_key()) is None
    if metadata_path is not None:
        assert not os.path.exists(metadata_path), "metadata must not be persisted"
    if body_path is not None:
        assert not os.path.exists(body_path), "body must not be persisted"


def _read_partial_and_close(
    session: requests.Session,
) -> bytes:
    response = session.get(URL, stream=True)
    chunks: list[bytes] = []
    for index, chunk in enumerate(response.iter_content(PARTIAL_READ_CHUNK)):
        chunks.append(chunk)
        if index == PARTIAL_READ_CHUNKS - 1:
            break
    received = b"".join(chunks)
    assert len(received) == PARTIAL_READ_CHUNK * PARTIAL_READ_CHUNKS
    assert len(received) < len(BODY)
    response.close()
    return received


class TestStreamingCacheIntegrity:
    def test_partial_read_then_close_is_not_cached(
        self,
        cache_paths: tuple[BaseCache, str | None, str | None],
        content_length: bool,
    ) -> None:
        """Reading part of a stream and closing must not publish it."""
        cache, metadata_path, body_path = cache_paths
        session, pool = _make_session(cache, ["ok", "ok"], content_length)

        received = _read_partial_and_close(session)
        assert received == BODY[: len(received)]

        _assert_no_persisted_entry(cache, metadata_path, body_path)

        # The next request must miss the cache and hit the transport again.
        replay = session.get(URL, stream=True)
        try:
            assert replay.from_cache is False
            assert pool.urlopen_calls == 2
        finally:
            replay.close()
        session.close()

    def test_read_error_before_completion_is_not_cached(
        self,
        cache_paths: tuple[BaseCache, str | None, str | None],
        content_length: bool,
    ) -> None:
        """An I/O error mid-body must not publish a truncated response."""
        cache, metadata_path, body_path = cache_paths
        session, pool = _make_session(cache, ["error", "ok"], content_length)

        response = session.get(URL, stream=True)
        assert response.status_code == 200
        try:
            with pytest.raises(requests.RequestException):
                response.content
        finally:
            response.close()

        _assert_no_persisted_entry(cache, metadata_path, body_path)

        # Status code alone looked fine; the contract is that the partial
        # body is not replayable. A retry must re-ask the transport.
        retry = session.get(URL, stream=True)
        try:
            assert retry.from_cache is False
            assert pool.urlopen_calls == 2
            assert retry.content == BODY
        finally:
            retry.close()
        session.close()

    def test_fully_read_response_is_cached_and_replayed_intact(
        self,
        cache_paths: tuple[BaseCache, str | None, str | None],
        content_length: bool,
    ) -> None:
        """Consuming the whole body publishes the complete response."""
        cache, metadata_path, body_path = cache_paths
        session, pool = _make_session(cache, ["ok"], content_length)

        response = session.get(URL, stream=True)
        assert response.content == BODY
        assert response.from_cache is False

        assert cache.get(_cache_key()) is not None
        if metadata_path is not None:
            assert os.path.exists(metadata_path)
        if isinstance(cache, SeparateBodyFileCache):
            assert body_path is not None
            assert open(body_path, "rb").read() == BODY

        replay = session.get(URL)
        assert replay.from_cache is True
        assert replay.content == BODY
        # A cache hit must not invoke the (fake) transport again.
        assert pool.urlopen_calls == 1
        session.close()

    def test_retry_after_failure_caches_and_replays_full_body(
        self,
        cache_backend: BaseCache,
        tmp_path: object,
        content_length: bool,
    ) -> None:
        """A failed first attempt followed by a full retry caches correctly."""
        cache = cache_backend
        session, pool = _make_session(cache, ["error", "ok"], content_length)

        failed = session.get(URL, stream=True)
        try:
            with pytest.raises(requests.RequestException):
                failed.content
        finally:
            failed.close()
        assert cache.get(_cache_key()) is None
        assert pool.urlopen_calls == 1

        retry = session.get(URL, stream=True)
        assert retry.from_cache is False
        assert retry.content == BODY
        assert pool.urlopen_calls == 2
        assert cache.get(_cache_key()) is not None

        # Reopen through a brand new session backed by the same store to
        # prove the replay comes from the persisted entry, not live state.
        if isinstance(cache, (FileCache, SeparateBodyFileCache)):
            replay_cache: BaseCache = type(cache)(str(tmp_path))
        else:
            replay_cache = cache
        replay_session = CacheControl(requests.Session(), cache=replay_cache)
        try:
            cached = replay_session.get(URL)
            assert cached.from_cache is True
            assert cached.content == BODY
        finally:
            replay_session.close()

        # The replay session never had a transport installed, so the body
        # could only have come from the cache.
        assert pool.urlopen_calls == 2
        session.close()
