#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""The optional ``first_request_timeout`` budget on the ASGI worker.

A fresh connection gets one budget for its request preparation phase: from
the moment it commits to HTTP/1 until the first final response starts. Time
is driven by a manual clock, so the reaping boundary, reuse after a completed
request, and an in-flight streaming response are checked without real sleeps.
"""

import asyncio
import sys

import pytest

from gunicorn.config import Config
from gunicorn.asgi.protocol import ASGIProtocol, _ManualClock

from tests.test_asgi_keepalive_background import _Transport, _Log, _spin, _close

BUDGET = 5
KEEPALIVE = 2


class _Worker:
    pass


def _connect(app, http_parser="python", budget=BUDGET, keepalive=KEEPALIVE):
    loop = asyncio.get_event_loop()
    cfg = Config()
    cfg.set("keepalive", keepalive)
    cfg.set("timeout", 30)
    cfg.set("http_parser", http_parser)
    cfg.set("asgi_disconnect_grace_period", 0)
    cfg.set("first_request_timeout", budget)

    worker = _Worker()
    worker.cfg = cfg
    worker.loop = loop
    worker.log = _Log()
    worker.asgi = app
    worker.nr_conns = 0
    worker.nr = 0
    worker.max_requests = 1000
    worker.alive = True

    protocol = ASGIProtocol(worker)
    # Deterministic clock: wall time never moves the timers on their own.
    clock = _ManualClock()
    protocol.clock = clock

    transport = _Transport(loop)
    transport.protocol = protocol
    protocol.connection_made(transport)
    return protocol, transport, clock


def _get(path=b"/", close=False):
    extra = b"Connection: close\r\n" if close else b""
    return (b"GET " + path + b" HTTP/1.1\r\nHost: example.com\r\n"
            + extra + b"\r\n")


@pytest.mark.asyncio
async def test_slow_first_request_is_reaped(http_parser):
    # A connection that never finishes its first request is closed once the
    # ingress budget elapses, and not before.
    async def app(scope, receive, send):  # pragma: no cover - never reached
        raise AssertionError("app must not run before headers are parsed")

    protocol, transport, clock = _connect(app, http_parser)
    try:
        # Only a request line, no headers: the request never becomes ready.
        protocol.data_received(b"GET /slow HTTP/1.1\r\n")
        await _spin()
        assert not transport.closed

        clock.advance(BUDGET - 0.1)
        await _spin()
        assert not transport.closed, "reaped before the budget elapsed"

        clock.advance(0.1)
        await _spin()
        assert transport.closed, "the ingress budget did not reap the connection"
    finally:
        await _close(protocol)


@pytest.mark.asyncio
async def test_completed_first_request_graduates_and_is_reused(http_parser):
    # A request answered within the budget disarms the timer; the connection
    # is then governed by keepalive and serves the next request normally.
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    protocol, transport, clock = _connect(app, http_parser)
    try:
        protocol.data_received(_get(b"/one"))
        await _spin()
        assert transport.written.count(b"HTTP/1.1 200") == 1
        # The preparation phase ended; advancing well past the budget must not
        # close a connection that is now only waiting for the next request.
        clock.advance(BUDGET * 10)
        await _spin()
        assert not transport.closed
        assert protocol._ingress_done
        assert protocol._ingress_handle is None

        # The connection is reused for a second request under ordinary rules.
        protocol.data_received(_get(b"/two"))
        await _spin()
        assert transport.written.count(b"HTTP/1.1 200") == 2
        assert not transport.closed
    finally:
        await _close(protocol)


@pytest.mark.asyncio
async def test_streaming_response_outlives_the_ingress_budget(http_parser):
    # Once the final response starts, an active stream is no longer bounded
    # by the ingress budget even if it runs far longer.
    started = asyncio.Event()

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"transfer-encoding", b"chunked")]})
        await send({"type": "http.response.body", "body": b"a",
                    "more_body": True})
        started.set()
        await asyncio.Event().wait()

    protocol, transport, clock = _connect(app, http_parser)
    try:
        protocol.data_received(_get(b"/stream"))
        await started.wait()
        await _spin()
        assert b"HTTP/1.1 200" in transport.written

        clock.advance(BUDGET * 10)
        await _spin()
        assert not transport.closed, "an active stream was reaped as ingress"
        assert protocol._ingress_done
    finally:
        await _close(protocol)


@pytest.mark.asyncio
async def test_second_request_on_reused_conn_not_timed(http_parser):
    # Only the first request carries the budget. A slow *second* request is
    # left to the ordinary keepalive/timeout rules, not reaped as ingress.
    async def app(scope, receive, send):
        if scope["path"] == "/slow-second":
            await asyncio.Event().wait()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    protocol, transport, clock = _connect(app, http_parser)
    try:
        protocol.data_received(_get(b"/one"))
        await _spin()
        assert protocol._ingress_done

        protocol.data_received(b"GET /slow-second HTTP/1.1\r\n")
        await _spin()
        clock.advance(BUDGET * 10)
        await _spin()
        assert not transport.closed, "a later request was timed as ingress"
    finally:
        await _close(protocol)


@pytest.mark.asyncio
async def test_disabled_by_default_leaves_no_timer(http_parser):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    protocol, transport, clock = _connect(app, http_parser, budget=0)
    try:
        assert protocol._ingress_handle is None
        protocol.data_received(b"GET / HTTP/1.1\r\n")
        await _spin()
        clock.advance(1000)
        await _spin()
        assert not transport.closed
    finally:
        await _close(protocol)


@pytest.mark.asyncio
async def test_slow_request_then_normal_request_on_new_connection(http_parser):
    # Acceptance interleaving: a reaped slow connection does not poison the
    # worker; a brand new connection afterwards is served normally.
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    # First connection: slow, reaped.
    slow, slow_transport, clock = _connect(app, http_parser)
    try:
        slow.data_received(b"GET / HTTP/1.1\r\n")
        clock.advance(BUDGET)
        await _spin()
        assert slow_transport.closed
        await _close(slow)
    finally:
        pass

    # Second connection: fresh budget, answered and kept alive.
    good, good_transport, good_clock = _connect(app, http_parser)
    try:
        good.data_received(_get(b"/ok"))
        await _spin()
        assert good_transport.written.count(b"HTTP/1.1 200") == 1
        assert not good_transport.closed
        good_clock.advance(BUDGET * 10)
        await _spin()
        assert not good_transport.closed
    finally:
        await _close(good)


@pytest.mark.asyncio
async def test_reaping_reuse_and_active_stream_interleave(http_parser):
    # The full acceptance picture under one controllable clock:
    # a slow first request is reaped, a completed one is reused afterwards,
    # and an in-flight stream keeps being served across the same boundary.
    release = asyncio.Event()

    async def app(scope, receive, send):
        if scope["path"] == "/stream":
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"transfer-encoding", b"chunked")]})
            await send({"type": "http.response.body", "body": b"a",
                        "more_body": True})
            await release.wait()
            return
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    # (1) A slow connection is reaped at the budget.
    slow, slow_transport, clock = _connect(app, http_parser)
    slow.data_received(b"GET / HTTP/1.1\r\n")
    clock.advance(BUDGET - 0.5)
    await _spin()
    assert not slow_transport.closed
    clock.advance(0.5)
    await _spin()
    assert slow_transport.closed
    await _close(slow)

    # (2) A fresh connection answers, graduates and is reused well past
    # the budget, while (3) a streaming response stays open alongside.
    reused, reused_transport, _ = _connect(app, http_parser)
    streaming, stream_transport, _ = _connect(app, http_parser)
    try:
        reused.data_received(_get(b"/one"))
        await _spin()
        assert reused_transport.written.count(b"HTTP/1.1 200") == 1

        streaming.data_received(_get(b"/stream"))
        await _spin()
        assert b"HTTP/1.1 200" in stream_transport.written
        assert not stream_transport.closed

        # Well beyond every ingress budget: reuse still works and the
        # active stream is untouched.
        clock.advance(BUDGET * 5)
        await _spin()
        assert not stream_transport.closed
        reused.data_received(_get(b"/two"))
        await _spin()
        assert reused_transport.written.count(b"HTTP/1.1 200") == 2
        assert not reused_transport.closed
    finally:
        release.set()
        await _close(reused)
        await _close(streaming)


if sys.implementation.name == "pypy":  # pragma: no cover
    pytestmark = pytest.mark.skip(reason="fast parser unavailable on PyPy")
