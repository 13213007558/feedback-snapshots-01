#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""What each entry point actually sees with per-listener trust.

Two listeners serve the same peer address. One is the public entry, the
other the internal one behind a load balancer. The WSGI side runs a real
SyncWorker accept over a socketpair; the ASGI side uses the fake transport
the ASGI tests already provide. Both must end up with the scheme and the
peer address the listener's own rule calls for.
"""

import asyncio
from contextlib import contextmanager
import socket
from unittest import mock

import pytest

from gunicorn import trust
from gunicorn.config import Config
from gunicorn.http2 import negotiation
from gunicorn.workers.sync import SyncWorker
from test_asgi_keepalive_smuggling import (
    _FakeTransport, _build_worker, http_parser,  # noqa: F401 (fixture)
)

PUBLIC = ("0.0.0.0", 8000)
INTERNAL = ("10.0.0.5", 8001)
LB_NETWORK = "10.0.0.0/8"


class _Listener:
    """A listening socket stand-in with the identity trust keys on."""

    def __init__(self, address, bind_spec):
        self.address = address
        self.bind_spec = bind_spec

    def getsockname(self):
        return self.address


def _cfg(**settings):
    cfg = Config()
    cfg.set("forwarded_allow_ips", "127.0.0.1,::1")
    for name, value in settings.items():
        cfg.set(name, value)
    return cfg


def _both_entries(**extra):
    settings = dict(
        forwarded_allow_ips_by_bind={INTERNAL[0] + ":8001": LB_NETWORK},
        proxy_allow_ips_by_bind={INTERNAL[0] + ":8001": LB_NETWORK},
        secure_scheme_headers={"X-FORWARDED-PROTO": "https"},
        forwarder_headers="SCRIPT_NAME,PATH_INFO",
    )
    settings.update(extra)
    return _cfg(**settings)


@contextmanager
def _event_loop():
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        yield loop
    finally:
        asyncio.set_event_loop(None)
        loop.close()


class _SyncWorker(SyncWorker):
    """A real SyncWorker that only records what its app was handed."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.nr = 0
        self.max_requests = 1000
        self.alive = True
        self.log = mock.Mock()
        self.environ = None
        self.request = None
        self.error = None
        self.wsgi = self._app

    def _app(self, environ, start_response):
        self.environ = environ
        start_response("200 OK", [("Content-Length", "0")])
        return [b""]

    def handle_request(self, listener, req, client, addr):
        self.request = req
        super().handle_request(listener, req, client, addr)

    def handle_error(self, req, client, addr, exc):
        self.error = exc
        super().handle_error(req, client, addr, exc)


def _run_sync(listener, raw_request, peer):
    """Drive a request through SyncWorker.handle() over a socketpair.

    The accepted side is a UNIX socketpair, so the peer tuple is passed
    explicitly and the listener object carries the trust identity.
    """
    server_end, client_end = socket.socketpair()
    cfg = listener.cfg
    worker = _SyncWorker(cfg)
    listener_sock = mock.Mock()
    listener_sock.getsockname.return_value = listener.address
    listener_sock.bind_spec = listener.bind_spec
    try:
        client_end.sendall(raw_request)
        client_end.shutdown(socket.SHUT_WR)
        worker.handle(listener_sock, server_end, peer)
    finally:
        server_end.close()
        client_end.close()
    return worker, listener_sock


class _TwoEntries:
    """Holds the config plus the two listener identities sharing it."""

    def __init__(self):
        self.cfg = _both_entries()
        self.public = _Listener(PUBLIC, "0.0.0.0:8000")
        self.public.cfg = self.cfg
        self.internal = _Listener(INTERNAL, "10.0.0.5:8001")
        self.internal.cfg = self.cfg


REQUEST = (b"GET / HTTP/1.1\r\n"
           b"Host: app.internal\r\n"
           b"X-Forwarded-Proto: https\r\n"
           b"X-Forwarded-For: 203.0.113.7\r\n"
           b"\r\n")


def _run_asgi(listener, peer, raw=REQUEST, parser="python", cfg=None,
              **extra):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})

    async def drive():
        loop = asyncio.get_running_loop()
        worker = _build_worker(loop, app, parser)
        worker.cfg = cfg if cfg is not None else _TwoEntries().cfg
        for name, value in extra.items():
            worker.cfg.set(name, value)
        from gunicorn.asgi.protocol import ASGIProtocol
        protocol = ASGIProtocol(worker, listener)
        transport = _FakeTransport()
        transport._extra["peername"] = peer
        transport._extra["sockname"] = listener.address
        matcher = _ScopeMatcher()
        original = protocol._build_http_scope
        protocol._build_http_scope = matcher.wrap(original)
        protocol.connection_made(transport)
        protocol.data_received(raw)
        for _ in range(60):
            await asyncio.sleep(0)
        if protocol._task and not protocol._task.done():
            protocol._task.cancel()
            try:
                await protocol._task
            except (asyncio.CancelledError, Exception):
                pass
        return matcher.scope

    with _event_loop() as loop:
        return loop.run_until_complete(drive())


class _ScopeMatcher:
    def __init__(self):
        self.scope = None

    def wrap(self, original):
        def build(*args, **kwargs):
            self.scope = original(*args, **kwargs)
            return self.scope
        return build


def test_wsgi_public_entry_ignores_forwarded_headers():
    entries = _TwoEntries()
    worker, _ = _run_sync(entries.public, REQUEST, ("10.9.9.9", 50000))
    assert worker.environ["wsgi.url_scheme"] == "http"
    assert worker.environ["REMOTE_ADDR"] == "10.9.9.9"
    assert worker.environ["REMOTE_PORT"] == "50000"


def test_wsgi_internal_entry_honours_forwarded_headers():
    entries = _TwoEntries()
    worker, _ = _run_sync(entries.internal, REQUEST, ("10.9.9.9", 50000))
    assert worker.environ["wsgi.url_scheme"] == "https"
    # X-Forwarded-For is data for the app, not a rewrite of REMOTE_ADDR.
    assert worker.environ["REMOTE_ADDR"] == "10.9.9.9"
    assert worker.environ["HTTP_X_FORWARDED_FOR"] == "203.0.113.7"


def test_wsgi_proxy_peer_rewritten_only_on_internal_entry():
    v1 = b"PROXY TCP4 198.51.100.4 10.0.0.5 44321 8001\r\n"
    entries = _TwoEntries()
    entries.cfg.set("proxy_protocol", "v1")

    worker, _ = _run_sync(entries.internal, v1 + REQUEST, ("10.9.9.9", 50000))
    assert worker.environ["REMOTE_ADDR"] == "198.51.100.4"
    assert worker.environ["REMOTE_PORT"] == "44321"
    assert worker.environ["PROXY_PROTOCOL"] == "TCP4"


def test_wsgi_proxy_framing_refused_on_public_entry():
    from gunicorn.http.errors import ForbiddenProxyRequest

    v1 = b"PROXY TCP4 198.51.100.4 10.0.0.5 44321 8000\r\n"
    entries = _TwoEntries()
    entries.cfg.set("proxy_protocol", "v1")

    worker, _ = _run_sync(entries.public, v1 + REQUEST, ("10.9.9.9", 50000))
    assert isinstance(worker.error, ForbiddenProxyRequest)
    assert worker.environ is None


def test_wsgi_underscore_header_policy_follows_listener():
    """header_map=refuse refuses an underscore name unless the listener
    trusts the peer; the public entry must not inherit the internal rule."""
    raw = (b"GET /evil/x HTTP/1.1\r\n"
           b"Host: app.internal\r\n"
           b"Script_Name: /evil\r\n"
           b"\r\n")
    entries = _TwoEntries()
    entries.cfg.set("header_map", "refuse")

    public, _ = _run_sync(entries.public, raw, ("10.9.9.9", 50000))
    assert public.environ is None

    internal, _ = _run_sync(entries.internal, raw, ("10.9.9.9", 50000))
    assert internal.environ["SCRIPT_NAME"] == "/evil"
    assert internal.environ["PATH_INFO"] == "/x"


def test_wsgi_missing_entry_falls_back_to_global():
    cfg = _cfg(forwarded_allow_ips="10.9.0.0/16",
               secure_scheme_headers={"X-FORWARDED-PROTO": "https"})
    public = _Listener(PUBLIC, "0.0.0.0:8000")
    public.cfg = cfg
    worker, _ = _run_sync(public, REQUEST, ("10.9.9.9", 50000))
    assert worker.environ["wsgi.url_scheme"] == "https"


def test_asgi_public_entry_ignores_forwarded_headers(http_parser):
    entries = _TwoEntries()
    scope = _run_asgi(entries.public, ("10.9.9.9", 50000),
                      parser=http_parser, cfg=entries.cfg)
    assert scope["scheme"] == "http"
    assert scope["client"] == ("10.9.9.9", 50000)
    assert scope["server"] == ("0.0.0.0", 8000)


def test_asgi_internal_entry_honours_forwarded_headers(http_parser):
    entries = _TwoEntries()
    scope = _run_asgi(entries.internal, ("10.9.9.9", 50000),
                      parser=http_parser, cfg=entries.cfg)
    assert scope["scheme"] == "https"
    assert scope["client"] == ("10.9.9.9", 50000)
    assert scope["server"] == ("10.0.0.5", 8001)
    headers = dict(scope["headers"])
    assert headers[b"x-forwarded-for"] == b"203.0.113.7"


def test_asgi_forwarder_headers_follow_the_entry(http_parser):
    """SCRIPT_NAME is honoured only where the listener trusts the forwarder."""
    raw = (b"GET /evil/x HTTP/1.1\r\n"
           b"Host: app.internal\r\n"
           b"Script_Name: /evil\r\n"
           b"\r\n")
    entries = _TwoEntries()
    entries.cfg.set("header_map", "refuse")

    public = _run_asgi(entries.public, ("10.9.9.9", 50000), raw=raw,
                       parser=http_parser, cfg=entries.cfg)
    assert public is None

    internal = _run_asgi(entries.internal, ("10.9.9.9", 50000), raw=raw,
                         parser=http_parser, cfg=entries.cfg)
    assert (b"script_name", b"/evil") in internal["headers"]


def _asgi_scope_with_proxy(listener, peer, parser="python",
                           proxy_protocol="v1", cfg=None):
    raw = (b"PROXY TCP4 198.51.100.4 10.0.0.5 44321 8001\r\n" + REQUEST)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"0")]})
        await send({"type": "http.response.body", "body": b""})

    async def drive():
        loop = asyncio.get_running_loop()
        worker = _build_worker(loop, app, parser)
        worker.cfg = cfg if cfg is not None else _TwoEntries().cfg
        worker.cfg.set("proxy_protocol", proxy_protocol)
        from gunicorn.asgi.protocol import ASGIProtocol
        protocol = ASGIProtocol(worker, listener)
        transport = _FakeTransport()
        transport._extra["peername"] = peer
        transport._extra["sockname"] = listener.address
        matcher = _ScopeMatcher()
        protocol._build_http_scope = matcher.wrap(protocol._build_http_scope)
        protocol.connection_made(transport)
        protocol.data_received(raw)
        for _ in range(60):
            await asyncio.sleep(0)
        if protocol._task and not protocol._task.done():
            protocol._task.cancel()
            try:
                await protocol._task
            except (asyncio.CancelledError, Exception):
                pass
        return matcher.scope

    with _event_loop() as loop:
        return loop.run_until_complete(drive())


def test_asgi_proxy_client_address_only_on_internal_entry(http_parser):
    entries = _TwoEntries()
    scope = _asgi_scope_with_proxy(entries.internal, ("10.9.9.9", 50000),
                                   parser=http_parser, cfg=entries.cfg)
    assert scope["client"] == ("198.51.100.4", 44321)


def test_asgi_public_entry_does_not_parse_proxy_framing(http_parser):
    """PROXY framing on the untrusted public entry is not framing: the
    request starts with a malformed method and is refused, never served
    with a rewritten client address."""
    entries = _TwoEntries()
    scope = _asgi_scope_with_proxy(entries.public, ("10.9.9.9", 50000),
                                   parser=http_parser, cfg=entries.cfg)
    assert scope is None


def test_h2c_sniffing_follows_the_entry():
    """Cleartext HTTP/2 prior knowledge reuses the forwarded-header rule of
    the listener: the public entry must not start sniffing just because the
    internal one trusts the load balancer."""
    cfg = _both_entries()
    cfg.set("http_protocols", "h2,h1")
    cfg.set("http2_cleartext", "prior-knowledge")
    public = _Listener(PUBLIC, "0.0.0.0:8000")
    internal = _Listener(INTERNAL, "10.0.0.5:8001")

    public_trust = trust.resolve(cfg, public)
    internal_trust = trust.resolve(cfg, internal)

    assert negotiation.prior_knowledge_allowed(
        cfg, ("10.9.9.9", 50000), public_trust) is False
    assert negotiation.prior_knowledge_allowed(
        cfg, ("10.9.9.9", 50000), internal_trust) is True
