# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Listener-scope rules for cleartext HTTP/2 (h2c).

Cleartext HTTP/2 is an internal facility: it may be offered on the loopback
debugging port or the listener behind a TLS-terminating proxy, but never on a
public listener just because the connecting peer is trusted. These tests pin
that deployment rule for every worker, and confirm that TLS ALPN negotiation
is unaffected.

They reuse the protocol doubles from test_http2_h2c (a gthread TConn over a
socketpair, the AsyncWorker.handle stub and the ASGI fake transport) rather
than binding real ports.
"""

import asyncio
import socket
import ssl
from unittest import mock

import pytest

from gunicorn.config import Config
from gunicorn.http.parser import RequestParser
from gunicorn.http2 import negotiation

from test_http2_h2c import (
    H2_AVAILABLE,
    TRUSTED_ADDR,
    UNTRUSTED_ADDR,
    _FakeTransport,
    _StubAsyncWorker,
    h2c_config,
    make_asgi_protocol,
    make_conn,
)

# A loopback listener: inside the default http2_cleartext_listeners list.
LOOPBACK_LISTENER = ("127.0.0.1", 8000)
# TEST-NET-3 (RFC 5737): a public address, never loopback or private.
PUBLIC_LISTENER = ("203.0.113.10", 8000)
# A private, non-loopback listener.
PRIVATE_LISTENER = ("10.0.0.5", 8000)

HTTP1_REQUEST = b"GET /ping HTTP/1.1\r\nHost: example.com\r\n\r\n"


def scoped_config(mode="prior-knowledge", listeners=None):
    cfg = h2c_config()
    cfg.set("http2_cleartext", mode)
    if listeners is not None:
        cfg.set("http2_cleartext_listeners", listeners)
    return cfg


class TestListenerScopeSetting:
    def test_defaults_to_loopback(self):
        assert Config().http2_cleartext_listeners == ["127.0.0.1", "::1"]

    def test_accepts_addresses_and_networks(self):
        cfg = Config()
        cfg.set("http2_cleartext_listeners", "127.0.0.1,10.0.0.0/8")
        assert cfg.http2_cleartext_listeners == ["127.0.0.1", "10.0.0.0/8"]

    def test_rejects_a_malformed_entry(self):
        cfg = Config()
        with pytest.raises(ValueError):
            cfg.set("http2_cleartext_listeners", "not-an-address")

    def test_wildcard_is_accepted(self):
        cfg = Config()
        cfg.set("http2_cleartext_listeners", "*")
        assert cfg.http2_cleartext_listeners == ["*"]


class TestListenerAllowsH2C:
    """The pure predicate shared by every worker."""

    def test_loopback_listener_allowed_by_default(self):
        cfg = scoped_config()
        assert negotiation.listener_allows_h2c(cfg, LOOPBACK_LISTENER)

    def test_public_listener_refused_by_default(self):
        cfg = scoped_config()
        assert not negotiation.listener_allows_h2c(cfg, PUBLIC_LISTENER)

    def test_private_listener_refused_unless_listed(self):
        cfg = scoped_config()
        assert not negotiation.listener_allows_h2c(cfg, PRIVATE_LISTENER)
        listed = scoped_config(listeners="10.0.0.0/8")
        assert negotiation.listener_allows_h2c(listed, PRIVATE_LISTENER)

    def test_unix_socket_listener_is_always_allowed(self):
        # No IP address: local IPC, not a network interface.
        assert negotiation.listener_allows_h2c(scoped_config(), "/run/g.sock")

    def test_wildcard_permits_any_listener(self):
        cfg = scoped_config(listeners="*")
        assert negotiation.listener_allows_h2c(cfg, PUBLIC_LISTENER)

    def test_ipv6_loopback_allowed(self):
        assert negotiation.listener_allows_h2c(
            scoped_config(), ("::1", 8000))


class TestNegotiationGates:
    """Both the listener and the peer have to permit h2c."""

    def test_authorized_listener_and_trusted_peer_negotiate(self):
        cfg = scoped_config()
        assert negotiation.prior_knowledge_allowed(
            cfg, TRUSTED_ADDR, LOOPBACK_LISTENER)
        assert negotiation.upgrade_allowed(
            scoped_config("upgrade"), TRUSTED_ADDR, LOOPBACK_LISTENER)

    def test_public_listener_blocks_even_a_trusted_peer(self):
        cfg = scoped_config()
        assert not negotiation.prior_knowledge_allowed(
            cfg, TRUSTED_ADDR, PUBLIC_LISTENER)
        assert not negotiation.upgrade_allowed(
            scoped_config("upgrade"), TRUSTED_ADDR, PUBLIC_LISTENER)

    def test_authorized_listener_still_rejects_untrusted_peer(self):
        # The listener rule does not replace the forwarded_allow_ips check.
        cfg = scoped_config()
        assert not negotiation.prior_knowledge_allowed(
            cfg, UNTRUSTED_ADDR, LOOPBACK_LISTENER)

    def test_wildcard_listeners_restore_negotiation(self):
        cfg = scoped_config(listeners="*")
        assert negotiation.prior_knowledge_allowed(
            cfg, TRUSTED_ADDR, PUBLIC_LISTENER)

    def test_tls_negotiation_is_not_gated_by_the_listener_list(self):
        # With TLS the ALPN path is taken before either predicate runs, and
        # _h2c_available() is false, so the cleartext gate stays inert.
        cfg = scoped_config()
        cfg.set("certfile", "/dev/null")
        cfg.set("keyfile", "/dev/null")
        assert cfg.is_ssl
        assert not negotiation.prior_knowledge_allowed(
            cfg, TRUSTED_ADDR, LOOPBACK_LISTENER)


def make_scoped_conn(cfg, client_data, listener, addr=TRUSTED_ADDR):
    """A gthread TConn whose server side reports a given listener address."""
    conn, client = make_conn(cfg, client_data, addr=addr)
    conn.server = listener
    return conn, client


@pytest.mark.skipif(not H2_AVAILABLE, reason="h2 library not available")
class TestGthreadListenerScope:
    """The gthread worker applies the rule when it reads the preface."""

    def test_authorized_listener_negotiates_http2(self):
        from gunicorn.http2.connection import HTTP2ServerConnection

        conn, client = make_scoped_conn(
            scoped_config(), negotiation.H2C_PREFACE, LOOPBACK_LISTENER)
        try:
            conn.init()
            assert conn.is_http2 is True
            assert isinstance(conn.parser, HTTP2ServerConnection)
        finally:
            conn.sock.close()
            client.close()

    def test_public_listener_serves_http1_to_a_preface(self):
        # The preface is not sniffed on a public listener, so it reaches the
        # HTTP/1 parser rather than starting an HTTP/2 connection.
        conn, client = make_scoped_conn(
            scoped_config(), negotiation.H2C_PREFACE, PUBLIC_LISTENER)
        try:
            conn.init()
            assert conn.is_http2 is False
            assert isinstance(conn.parser, RequestParser)
        finally:
            conn.sock.close()
            client.close()

    def test_normal_http1_client_on_authorized_listener_is_refused(self):
        # Prior-knowledge alone: a trusted peer on the h2c port must speak
        # HTTP/2, so an ordinary HTTP/1 request keeps its 400 behaviour.
        from gunicorn.http.errors import InvalidH2CPreface

        conn, client = make_scoped_conn(
            scoped_config(), HTTP1_REQUEST, LOOPBACK_LISTENER)
        try:
            with pytest.raises(InvalidH2CPreface):
                conn.init()
        finally:
            conn.sock.close()
            client.close()

    def test_normal_http1_client_on_public_listener_is_served(self):
        # Outside the h2c scope the same request is plain HTTP/1, no 400.
        conn, client = make_scoped_conn(
            scoped_config("both"), HTTP1_REQUEST, PUBLIC_LISTENER)
        try:
            conn.init()
            assert conn.is_http2 is False
            req = next(conn.parser)
            assert req.method == "GET"
            assert req.path == "/ping"
        finally:
            conn.sock.close()
            client.close()

    def test_unix_listener_negotiates_http2(self):
        from gunicorn.http2.connection import HTTP2ServerConnection

        conn, client = make_scoped_conn(
            scoped_config(), negotiation.H2C_PREFACE, "/run/gunicorn.sock")
        try:
            conn.init()
            assert conn.is_http2 is True
            assert isinstance(conn.parser, HTTP2ServerConnection)
        finally:
            conn.sock.close()
            client.close()


def run_handle_on_listener(cfg, client_data, listener, addr=TRUSTED_ADDR,
                           close_client=True):
    """Drive AsyncWorker.handle with a listener reporting a given address."""
    server_sock, client_sock = socket.socketpair()
    listener_sock = mock.Mock()
    listener_sock.getsockname.return_value = listener
    worker = _StubAsyncWorker(cfg)
    try:
        if client_data:
            client_sock.sendall(client_data)
        if close_client:
            client_sock.close()
        worker.handle(listener_sock, server_sock, addr)
    finally:
        server_sock.close()
        try:
            client_sock.close()
        except OSError:
            pass
    return worker


class TestAsyncWorkerListenerScope:
    """The gevent/async worker enforces the same rule as gthread."""

    def test_authorized_listener_negotiates(self):
        worker = run_handle_on_listener(
            scoped_config(), negotiation.H2C_PREFACE, LOOPBACK_LISTENER)
        assert worker.http2_calls == [negotiation.H2C_PREFACE]
        assert worker.errors == []

    def test_public_listener_does_not_negotiate(self):
        worker = run_handle_on_listener(
            scoped_config(), negotiation.H2C_PREFACE, PUBLIC_LISTENER)
        assert worker.http2_calls == []
        # Not an h2c rejection: the bytes fall through to the HTTP/1 parser.
        from gunicorn.http.errors import InvalidH2CPreface
        assert not any(isinstance(e, InvalidH2CPreface) for e in worker.errors)

    def test_public_listener_still_serves_http1(self):
        worker = run_handle_on_listener(
            scoped_config("both"), HTTP1_REQUEST, PUBLIC_LISTENER)
        assert worker.http2_calls == []
        assert worker.errors == []

    def test_upgrade_blocked_on_public_listener(self):
        from test_http2_h2c import upgrade_request

        cfg = scoped_config("upgrade")
        worker = run_handle_on_listener(
            cfg, upgrade_request() + negotiation.H2C_PREFACE,
            PUBLIC_LISTENER, close_client=False)
        assert worker.upgrades == []
        assert worker.http2_calls == []


class _ScopedTransport(_FakeTransport):
    """A fake transport whose local (sockname) address we can choose."""

    def __init__(self, sockname, peername=TRUSTED_ADDR):
        super().__init__(peername)
        self._sockname = sockname

    def get_extra_info(self, name, default=None):
        if name == "sockname":
            return self._sockname
        return super().get_extra_info(name, default)


class TestASGIListenerScope:
    """The ASGI worker buffers for a preface only on an authorized listener."""

    def _connect(self, cfg, listener, peername=TRUSTED_ADDR):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        proto = make_asgi_protocol(cfg, loop)
        transport = _ScopedTransport(listener, peername)
        proto.connection_made(transport)
        return proto, transport, loop

    def _teardown(self, proto, loop):
        proto._h2c_cancel_timer()
        loop.close()
        asyncio.set_event_loop(None)

    def test_authorized_listener_buffers_the_preface(self):
        proto, transport, loop = self._connect(
            scoped_config(), LOOPBACK_LISTENER)
        try:
            proto.data_received(negotiation.H2C_PREFACE)
            assert proto._h2c_buffer is None
            assert proto.reader is not None
            assert not transport.closed
        finally:
            self._teardown(proto, loop)

    def test_public_listener_skips_sniffing_and_uses_http1(self):
        proto, transport, loop = self._connect(
            scoped_config(), PUBLIC_LISTENER)
        try:
            # No undecided buffer means the sniffer never armed.
            assert proto._h2c_buffer is None
            assert proto._callback_parser is not None
            proto.data_received(HTTP1_REQUEST)
            assert not transport.closed
        finally:
            self._teardown(proto, loop)

    def test_public_listener_does_not_refuse_http1(self):
        # On a public listener prior-knowledge is off, so the 400 path for a
        # non-preface never triggers.
        proto, transport, loop = self._connect(
            scoped_config(), PUBLIC_LISTENER)
        try:
            proto.data_received(HTTP1_REQUEST)
            assert b"400" not in transport.written
            assert not transport.closed
        finally:
            self._teardown(proto, loop)

    def test_upgrade_disabled_on_public_listener(self):
        proto, transport, loop = self._connect(
            scoped_config("upgrade"), PUBLIC_LISTENER)
        try:
            assert proto._h2c_upgrade_ok is False
        finally:
            self._teardown(proto, loop)

    def test_upgrade_enabled_on_authorized_listener(self):
        proto, transport, loop = self._connect(
            scoped_config("upgrade"), LOOPBACK_LISTENER)
        try:
            assert proto._h2c_upgrade_ok is True
        finally:
            self._teardown(proto, loop)

    def test_unix_listener_buffers_the_preface(self):
        proto, transport, loop = self._connect(
            scoped_config(), "/run/gunicorn.sock")
        try:
            proto.data_received(negotiation.H2C_PREFACE)
            assert proto.reader is not None
        finally:
            self._teardown(proto, loop)


class TestTlsNegotiationUnaffected:
    """A connection already negotiated over TLS bypasses the cleartext gate."""

    def test_alpn_h2_is_handled_before_the_cleartext_predicate(self):
        # The workers check is_http2_negotiated() first and return, so the
        # listener list never gets a say. Mirror that ordering with a stub.
        from gunicorn import sock as gunicorn_sock

        ssl_sock = mock.Mock(spec=ssl.SSLSocket)
        ssl_sock.selected_alpn_protocol.return_value = "h2"
        assert gunicorn_sock.is_http2_negotiated(ssl_sock) is True

        cfg = scoped_config()
        # Even a listener outside the cleartext list does not matter: the
        # connection is already HTTP/2 via ALPN.
        assert not negotiation.listener_allows_h2c(cfg, PUBLIC_LISTENER)
        assert gunicorn_sock.is_http2_negotiated(ssl_sock) is True

    def test_gthread_alpn_h2_ignores_the_cleartext_listener_list(self):
        cfg = scoped_config()
        # TLS is configured, so init() takes the ALPN branch and never looks
        # at the cleartext listener list, even on a public listener.
        cfg.set("certfile", "/dev/null")
        cfg.set("keyfile", "/dev/null")
        assert cfg.is_ssl
        conn, client = make_conn(cfg, None)
        conn.server = PUBLIC_LISTENER
        fake_ssl = mock.Mock()
        fake_ssl.selected_alpn_protocol.return_value = "h2"
        try:
            with mock.patch("gunicorn.workers.gthread.sock.ssl_wrap_socket",
                            return_value=fake_ssl), \
                 mock.patch("gunicorn.workers.gthread.sock.is_http2_negotiated",
                            return_value=True), \
                 mock.patch("gunicorn.http.get_parser") as get_parser:
                http2_parser = mock.Mock()
                get_parser.return_value = http2_parser
                conn.init()
            assert conn.is_http2 is True
            http2_parser.initiate_connection.assert_called_once()
        finally:
            conn.sock.close()
            client.close()
