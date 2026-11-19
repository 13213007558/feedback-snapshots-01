# SPDX-FileCopyrightText: 2015 Eric Larson
#
# SPDX-License-Identifier: Apache-2.0

"""
Consistency guarantees of ``SeparateBodyFileCache``.

A large download is stored as two pieces: a small metadata file and a body
file that holds the full payload. A cache reader must only ever observe a
version that was committed completely -- the headers, the declared body length
and the actual bytes always have to belong to the *same* version. In
particular an interrupted download or two writers updating the same key at
once can never splice old metadata onto a different body.

These tests deliberately drive the storage layer (and, where useful, the
``CacheController``) directly instead of going through a live HTTP server, so
that the interesting write interleavings are fully deterministic.
"""

from __future__ import annotations

import io
import os
import threading
from unittest.mock import Mock

import pytest
from urllib3 import HTTPResponse

from cachecontrol.caches import SeparateBodyFileCache
from cachecontrol.controller import CacheController
from cachecontrol.serialize import Serializer

KEY = "http://example.com/large-file"

# Two clearly distinguishable versions with *different* lengths: pairing the
# headers of one with the body of the other is therefore detectable both via
# the Content-Length header and via the byte contents.
VERSIONS = {
    "v1": (b"".join(bytes([i % 256]) for i in range(4096)), "v1"),
    "v2": (b"".join(bytes([(i + 7) % 256]) for i in range(8192)), "v2"),
}


def make_request() -> Mock:
    request = Mock()
    request.url = KEY
    request.headers = {}
    return request


def make_response(body: bytes, tag: str) -> HTTPResponse:
    """Build a fresh, unread urllib3 response for one version."""
    headers = {
        "Content-Length": str(len(body)),
        "X-Version": tag,
        "Cache-Control": "max-age=60",
    }
    return HTTPResponse(
        body=io.BytesIO(body),
        headers=headers,
        status=200,
        reason="OK",
        preload_content=False,
        decode_content=False,
    )


def serialized_metadata(serializer: Serializer, body: bytes, tag: str) -> bytes:
    return serializer.dumps(make_request(), make_response(body, tag), body)


@pytest.fixture()
def cache(tmp_path) -> SeparateBodyFileCache:
    return SeparateBodyFileCache(str(tmp_path))


@pytest.fixture()
def controller(cache: SeparateBodyFileCache) -> CacheController:
    return CacheController(cache)


def read_full_version(cache: SeparateBodyFileCache) -> tuple[dict[str, str], bytes]:
    """Read a version through the same atomic snapshot a cache hit uses.

    ``get_with_body`` hands back metadata and a body handle that name the
    same immutable body file, so even if a replacement happens while we read,
    the two can never belong to different versions.
    """
    raw_metadata, body_file = cache.get_with_body(KEY)
    assert raw_metadata is not None
    assert body_file is not None
    try:
        response = Serializer().loads(make_request(), raw_metadata, body_file)
        assert response is not None
        # Stream the body back in small chunks, mirroring a streamed hit.
        chunks = list(response.stream(127))
        headers = dict(response.headers)
        response.close()
    finally:
        body_file.close()
    return headers, b"".join(chunks)


def assert_consistent(headers: dict[str, str], body: bytes) -> str:
    """Assert headers, declared length and bytes describe one version."""
    expected_tag = "v1" if body == VERSIONS["v1"][0] else "v2"
    assert body == VERSIONS[expected_tag][0]
    assert headers["X-Version"] == expected_tag
    assert int(headers["Content-Length"]) == len(body)
    return expected_tag


class TestInterruptedDownload:
    def test_failed_body_write_publishes_nothing(self, cache, monkeypatch):
        """A crash while the body is being written leaves no visible entry."""
        serializer = Serializer()
        metadata = serialized_metadata(serializer, *VERSIONS["v1"])
        real_write_file = cache._write_file

        def fail_on_first_body_write(path, body):
            # Simulate the download dying before the body is fully published.
            if cache._is_versioned_body(os.path.basename(path)):
                raise OSError("download interrupted")
            return real_write_file(path, body)

        monkeypatch.setattr(cache, "_write_file", fail_on_first_body_write)

        with pytest.raises(OSError, match="download interrupted"):
            cache.commit(KEY, metadata, VERSIONS["v1"][0])

        # Nothing readable: no metadata version and no resolvable body.
        assert cache.get(KEY) is None
        assert cache.get_body(KEY) is None
        # The unpublished temporary body must not linger where readers look.
        leftovers = [
            name
            for _root, _dirs, files in os.walk(cache.directory)
            for name in files
            if cache._is_versioned_body(name) or name.endswith(".part")
        ]
        assert leftovers == []

    def test_failed_metadata_write_does_not_expose_body(self, cache, monkeypatch):
        """If the metadata cannot be published, the orphaned body is removed."""
        serializer = Serializer()
        body, tag = VERSIONS["v1"]
        metadata = serialized_metadata(serializer, body, tag)
        real_write = cache._write

        def fail_metadata_write(path, data):
            # The metadata file has no ``.body`` suffix; only fail that write,
            # letting the (earlier) body write succeed.
            if not path.endswith(".body"):
                raise OSError("metadata publish failed")
            return real_write(path, data)

        monkeypatch.setattr(cache, "_write", fail_metadata_write)

        with pytest.raises(OSError, match="metadata publish failed"):
            cache.commit(KEY, metadata, body)

        assert cache.get(KEY) is None
        assert cache.get_body(KEY) is None
        versioned = [
            name
            for _root, _dirs, files in os.walk(cache.directory)
            for name in files
            if cache._is_versioned_body(name)
        ]
        assert versioned == []

    def test_retry_after_interruption_commits_cleanly(self, cache, monkeypatch):
        """A later, successful attempt produces a fully consistent version."""
        serializer = Serializer()
        metadata_v1 = serialized_metadata(serializer, *VERSIONS["v1"])

        attempts = {"count": 0}
        real_write_file = cache._write_file

        def flaky_write(path, body):
            if cache._is_versioned_body(os.path.basename(path)):
                attempts["count"] += 1
                if attempts["count"] == 1:
                    raise OSError("download interrupted")
            return real_write_file(path, body)

        monkeypatch.setattr(cache, "_write_file", flaky_write)

        with pytest.raises(OSError):
            cache.commit(KEY, metadata_v1, VERSIONS["v1"][0])
        assert cache.get(KEY) is None

        monkeypatch.undo()
        cache.commit(KEY, metadata_v1, VERSIONS["v1"][0])

        headers, body = read_full_version(cache)
        assert assert_consistent(headers, body) == "v1"

    def test_gc_reclaims_body_from_crashed_publish(self, cache):
        """gc() removes a body that never got referenced by metadata."""
        serializer = Serializer()
        body_v1, tag_v1 = VERSIONS["v1"]
        cache.commit(KEY, serialized_metadata(serializer, body_v1, tag_v1), body_v1)
        referenced = os.path.basename(cache._body_path(KEY))

        # Simulate a crashed second publish: its body exists but no metadata
        # names it.
        orphan_dir = os.path.dirname(cache._fn(KEY))
        orphan_path = os.path.join(
            orphan_dir, f"{cache.encode(KEY)}.{'0' * 32}.body"
        )
        with open(orphan_path, "wb") as handle:
            handle.write(b"orphaned half-written body")

        cache.gc()

        assert os.path.basename(cache._body_path(KEY)) == referenced
        assert not os.path.exists(orphan_path)


class TestSuccessfulReplacement:
    def test_two_commits_never_splice_versions(self, cache):
        serializer = Serializer()
        body_v1, tag_v1 = VERSIONS["v1"]
        body_v2, tag_v2 = VERSIONS["v2"]

        cache.commit(KEY, serialized_metadata(serializer, body_v1, tag_v1), body_v1)
        first_body_path = cache._body_path(KEY)
        headers, body = read_full_version(cache)
        assert assert_consistent(headers, body) == "v1"

        cache.commit(KEY, serialized_metadata(serializer, body_v2, tag_v2), body_v2)
        second_body_path = cache._body_path(KEY)

        # Each version owns an immutable body file; replacing the metadata
        # never mutates the body the old metadata was pointing at.
        assert first_body_path != second_body_path
        with open(first_body_path, "rb") as handle:
            assert handle.read() == body_v1

        headers, body = read_full_version(cache)
        assert assert_consistent(headers, body) == "v2"

    def test_header_only_refresh_keeps_exact_body(self, cache):
        """A 304-style metadata update must keep the previously committed body."""
        serializer = Serializer()
        body, tag = VERSIONS["v2"]
        cache.commit(KEY, serialized_metadata(serializer, body, tag), body)
        committed_body_path = cache._body_path(KEY)

        # Equivalent to CacheController.update_cached_response(): replace the
        # serialized metadata without supplying a new body.
        new_metadata = serializer.dumps(
            make_request(), make_response(body, "v2-refreshed"), body
        )
        cache.set(KEY, new_metadata)

        assert cache._body_path(KEY) == committed_body_path
        headers, read_body = read_full_version(cache)
        assert read_body == body
        assert int(headers["Content-Length"]) == len(body)

    def test_controller_caches_and_serves_consistent_version(self, controller, cache):
        serializer = controller.serializer
        body, tag = VERSIONS["v1"]
        request = make_request()
        controller._cache_set(KEY, request, make_response(body, tag), body)

        response = controller._load_from_cache(request)
        assert response is not None
        try:
            assert response.headers["X-Version"] == tag
            assert int(response.headers["Content-Length"]) == len(body)
            assert response.read() == body
        finally:
            response.close()

    def test_legacy_body_file_is_still_read(self, cache, tmp_path):
        """Entries written by older releases (fixed ``.body`` file) keep working."""
        serializer = Serializer()
        body, tag = VERSIONS["v1"]
        legacy_body = cache._fn(KEY) + ".body"
        os.makedirs(os.path.dirname(legacy_body), exist_ok=True)
        with open(legacy_body, "wb") as handle:
            handle.write(body)
        # Plain metadata, without a body-pointer envelope.
        from cachecontrol.caches.file_cache import _FileCacheMixin

        _FileCacheMixin.set(
            cache, KEY, serializer.dumps(make_request(), make_response(body, tag), body)
        )

        assert cache.get_body(KEY).read() == body
        headers, read_body = read_full_version(cache)
        assert assert_consistent(headers, read_body) == "v1"


class TestConcurrentReads:
    def test_readers_only_see_complete_versions_during_rewrite(
        self, cache, tmp_path
    ):
        serializer = Serializer()
        body_v1, tag_v1 = VERSIONS["v1"]
        body_v2, tag_v2 = VERSIONS["v2"]
        cache.commit(KEY, serialized_metadata(serializer, body_v1, tag_v1), body_v1)

        start = threading.Barrier(2)
        stop = threading.Event()
        failures: list[str] = []
        observed: set[str] = set()
        lock = threading.Lock()

        def reader() -> None:
            start.wait()
            while not stop.is_set():
                try:
                    headers, body = read_full_version(cache)
                    version = assert_consistent(headers, body)
                    with lock:
                        observed.add(version)
                except AssertionError as exc:  # pragma: no cover - failure path
                    with lock:
                        failures.append(str(exc))

        reader_thread = threading.Thread(target=reader)
        reader_thread.start()
        start.wait()

        # Hammer rewrites while the reader runs; every intermediate state a
        # reader can land on still has to be a fully committed version.
        for i in range(25):
            body, tag = VERSIONS["v1"] if i % 2 == 0 else VERSIONS["v2"]
            cache.commit(KEY, serialized_metadata(serializer, body, tag), body)

        stop.set()
        reader_thread.join()

        assert failures == []
        assert observed  # the reader genuinely saw cache hits
        assert observed <= {"v1", "v2"}

    def test_concurrent_writers_never_leave_cross_wired_entry(self, cache):
        serializer = Serializer()
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def writer(tag: str) -> None:
            body, _ = VERSIONS[tag]
            try:
                barrier.wait()
                for _ in range(10):
                    cache.commit(
                        KEY, serialized_metadata(serializer, body, tag), body
                    )
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [
            threading.Thread(target=writer, args=("v1",)),
            threading.Thread(target=writer, args=("v2",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        # Whichever writer won, the visible metadata and body must match.
        headers, body = read_full_version(cache)
        assert_consistent(headers, body)

    def test_snapshot_retries_when_replaced_mid_read(self, cache, monkeypatch):
        """A replacement between the metadata read and the body open must not
        cross-wire versions; the snapshot retries onto the newer version.
        """
        serializer = Serializer()
        body_v1, tag_v1 = VERSIONS["v1"]
        body_v2, tag_v2 = VERSIONS["v2"]
        cache.commit(
            KEY, serialized_metadata(serializer, body_v1, tag_v1), body_v1
        )

        from cachecontrol.caches.file_cache import _FileCacheMixin

        calls = {"count": 0}
        original_get = _FileCacheMixin.get

        def flapping_raw_get(self_inner, key):
            calls["count"] += 1
            value = original_get(self_inner, key)
            if calls["count"] == 1:
                # Publish v2 after the snapshot read v1's metadata, forcing
                # the stability check to reject the first attempt.
                cache.commit(
                    KEY,
                    serialized_metadata(serializer, body_v2, tag_v2),
                    body_v2,
                )
            return value

        monkeypatch.setattr(_FileCacheMixin, "get", flapping_raw_get)

        metadata, body_file = cache.get_with_body(KEY)
        assert metadata is not None and body_file is not None
        try:
            response = serializer.loads(
                make_request(), metadata, body_file
            )
            assert response is not None
            assert response.headers["X-Version"] == "v2"
            assert int(response.headers["Content-Length"]) == len(body_v2)
            assert response.read() == body_v2
            response.close()
        finally:
            body_file.close()
        assert calls["count"] >= 2


class TestLifecycle:
    def test_forever_cache_never_deletes(self, tmp_path):
        cache = SeparateBodyFileCache(str(tmp_path), forever=True)
        serializer = Serializer()
        body, tag = VERSIONS["v1"]
        cache.commit(KEY, serialized_metadata(serializer, body, tag), body)
        body_path = cache._body_path(KEY)

        cache.delete(KEY)

        assert cache.get(KEY) is not None
        assert cache.get_body(KEY) is not None
        assert os.path.exists(body_path)

    def test_empty_body_round_trips(self, cache):
        cache.commit(KEY, b"empty-meta", b"")
        assert cache.get(KEY) == b"empty-meta"
        body_file = cache.get_body(KEY)
        assert body_file is not None
        assert body_file.read() == b""
        body_file.close()


class TestStreamingHit:
    def test_cached_hit_streams_without_splicing(self, cache):
        """A normal cache hit is still returned as a streaming file object."""
        serializer = Serializer()
        body, tag = VERSIONS["v2"]
        cache.commit(KEY, serialized_metadata(serializer, body, tag), body)

        body_file = cache.get_body(KEY)
        assert body_file is not None
        assert not isinstance(body_file, io.BytesIO)
        try:
            response = serializer.loads(make_request(), cache.get(KEY), body_file)
            assert response is not None
            streamed = b"".join(response.stream(512))
            assert streamed == body
            assert int(response.headers["Content-Length"]) == len(body)
            response.close()
        finally:
            body_file.close()
