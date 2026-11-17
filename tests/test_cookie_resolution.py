# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import contextlib
import socket
from unittest.mock import patch

import pytest

import dns.asyncbackend
import dns.asyncresolver
import dns.cookie
import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.nameserver
import dns.query
import dns.rcode
import dns.resolver
import dns.rrset

A_ADDRESS = "192.0.2.1"
A_PORT = 5300
B_ADDRESS = "192.0.2.2"
B_PORT = 5301
ERROR_ADDRESS = "203.0.113.9"

A1 = b"A" * 8
A2 = b"B" * 8
B1 = b"C" * 8


def make_response(query, address="192.0.2.10", server_cookie=None, cookie=None):
    r = dns.message.make_response(query)
    r.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", address))
    if cookie is not None:
        r.use_edns(0, 0, 1232, options=[cookie])
    elif server_cookie is not None:
        request_cookie = dns.cookie.get_cookie_option(query)
        assert request_cookie is not None
        r.use_edns(
            0,
            0,
            1232,
            options=[dns.edns.CookieOption(request_cookie.client, server_cookie)],
        )
    return r


class FakeUDP:
    """A deterministic, shared fake UDP transport.

    Responses are scripted by the destination the query was sent to and the
    query name.  The inbox is a real queue of ``(wire, source_address)`` so
    unexpected sources, bad ids, and real responses can be interleaved.
    """

    family = socket.AF_INET

    def __init__(self):
        self.inbox = []
        self.sent = []
        self.counts = {}

    def add(self, wire, source=(ERROR_ADDRESS, 53)):
        self.inbox.append((wire, source))

    def sendto(self, data, where):
        q = dns.message.from_wire(data)
        self.sent.append((where, q))
        key = where[0]
        self.counts[key] = self.counts.get(key, 0) + 1
        self._script(where, q)
        return len(data)

    def recvfrom(self, size):
        if not self.inbox:
            raise dns.exception.Timeout
        return self.inbox.pop(0)

    def _script(self, where, q):
        if where[0] == A_ADDRESS:
            cookie = dns.cookie.get_cookie_option(q)
            assert cookie is not None
            if cookie.server == b"":
                # The first query also gets a forged answer from an unrelated
                # source and a forged answer from the right source with the
                # wrong id before the real response.
                self.add(make_response(q, "203.0.113.66").to_wire())
                wrong_id = make_response(q, "203.0.113.67")
                wrong_id.id ^= 1
                self.add(wrong_id.to_wire(), (A_ADDRESS, A_PORT))
                self.add(
                    make_response(q, "192.0.2.10", server_cookie=A1).to_wire(),
                    (A_ADDRESS, A_PORT),
                )
            else:
                # The stored server cookie is stale.  Tell the client to
                # retry with a rotated server cookie.
                bad = make_response(q, cookie=dns.edns.CookieOption(cookie.client, A2))
                bad.set_rcode(dns.rcode.BADCOOKIE)
                self.add(bad.to_wire(), (A_ADDRESS, A_PORT))
                self.add(
                    make_response(q, "192.0.2.11", server_cookie=A2).to_wire(),
                    (A_ADDRESS, A_PORT),
                )
        elif where[0] == B_ADDRESS:
            # A's address is not a valid source for B's query, and a response
            # with no cookie is accepted opportunistically but not bound.
            self.add(make_response(q, "203.0.113.68").to_wire(), (A_ADDRESS, A_PORT))
            self.add(make_response(q, "192.0.2.12").to_wire(), (B_ADDRESS, B_PORT))


@contextlib.contextmanager
def fake_udp(fake):
    @contextlib.contextmanager
    def make_socket(af, socktype, source=None):
        yield fake

    with patch("dns.query.make_socket", make_socket):
        yield fake


def run_query(ns, q):
    return ns.query(q, timeout=2.0, source=None, source_port=0, max_size=False)


def test_interleaved_upstreams_error_source_and_rotation():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    a = dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)
    b = dns.nameserver.Do53Nameserver(B_ADDRESS, B_PORT, policy)
    fake = FakeUDP()

    with fake_udp(fake):
        q1 = dns.message.make_query("a.example.", "A")
        r1 = run_query(a, q1)
        assert r1.answer[0][0].address == "192.0.2.10"
        assert dns.cookie.validation_for_message(r1).bound is True

        # The client cookie is stable for endpoint A, and the response's
        # server cookie is in the next request.
        q2 = dns.message.make_query("a2.example.", "A")
        r2 = run_query(a, q2)
        assert r2.answer[0][0].address == "192.0.2.11"
        assert dns.cookie.validation_for_message(r2).bound is True

        q3 = dns.message.make_query("b.example.", "A")
        r3 = run_query(b, q3)
        assert r3.answer[0][0].address == "192.0.2.12"
        assert dns.cookie.validation_for_message(r3).bound is False

    a_sent = [q for where, q in fake.sent if where[0] == A_ADDRESS]
    b_sent = [q for where, q in fake.sent if where[0] == B_ADDRESS]
    cookie1 = dns.cookie.get_cookie_option(a_sent[0])
    cookie2 = dns.cookie.get_cookie_option(a_sent[1])
    cookie2_retry = dns.cookie.get_cookie_option(a_sent[2])
    cookie3 = dns.cookie.get_cookie_option(b_sent[0])

    assert cookie1.client == cookie2.client
    assert cookie1.server == b""
    assert cookie2.server == A1
    assert cookie2_retry.client == cookie1.client
    assert cookie2_retry.server == A2
    assert cookie3.client != cookie1.client
    assert cookie3.server == b""

    assert policy.server_cookie(policy.endpoint(A_ADDRESS, A_PORT)) == A2
    assert policy.server_cookie(policy.endpoint(B_ADDRESS, B_PORT)) == b""


def test_use_edns_true_resolver_gets_edns_and_binds():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.use_edns(True)
    resolver.nameservers = [dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)]
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.26", server_cookie=A1).to_wire(),
        (A_ADDRESS, A_PORT),
    )
    with fake_udp(fake):
        answer = resolver.resolve("edns.example.", "A")
    assert answer.cookie_bound is True
    sent = fake.sent[0][1]
    assert sent.edns == 0
    assert dns.cookie.get_cookie_option(sent) is not None


def test_unbound_response_is_not_cached():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)]
    resolver.cache = dns.resolver.Cache()
    fake = FakeUDP()
    # Every response for this test omits a server cookie.
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.20").to_wire(), (A_ADDRESS, A_PORT)
    )

    with fake_udp(fake):
        answer = resolver.resolve("unbound.example.", "A")
        assert answer.cookie_bound is False
        assert len(fake.sent) == 1
        assert len(resolver.cache.data) == 0

        # A cache miss again, because the unbound answer was not cached.
        answer = resolver.resolve("unbound.example.", "A")
        assert answer.cookie_bound is False
        assert len(fake.sent) == 2
        assert len(resolver.cache.data) == 0


def test_bound_response_is_cached():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)]
    resolver.cache = dns.resolver.Cache()
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.21", server_cookie=A1).to_wire(),
        (A_ADDRESS, A_PORT),
    )

    with fake_udp(fake):
        answer = resolver.resolve("bound.example.", "A")
        assert answer.cookie_bound is True
        assert len(fake.sent) == 1
        assert len(resolver.cache.data) == 1

        answer = resolver.resolve("bound.example.", "A")
        assert answer.cookie_bound is True
        assert len(fake.sent) == 1  # cache hit; no query sent


def test_tcp_fallback_keeps_normal_cache_behavior():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)]
    resolver.cache = dns.resolver.Cache()
    fake = FakeUDP()

    def truncate(where, q):
        r = dns.message.make_response(q)
        r.use_edns(None)
        r.flags |= dns.flags.TC
        fake.add(r.to_wire(), (A_ADDRESS, A_PORT))

    fake._script = truncate
    tcp_response = None

    def fake_tcp(request, address, **kwargs):
        nonlocal tcp_response
        # The TCP fallback request has no COOKIE option; the UDP path
        # restored the caller's EDNS state before falling back.
        response = make_response(request, "192.0.2.40")
        # Round-trip through the wire so the response has the normal parsed
        # message indexes, as a real TCP query would.
        tcp_response = dns.message.from_wire(response.to_wire())
        return tcp_response

    with fake_udp(fake), patch("dns.nameserver.dns.query.tcp", fake_tcp):
        answer = resolver.resolve("tcp.example.", "A")
        assert answer.cookie_bound is None
        assert len(resolver.cache.data) == 1
        answer = resolver.resolve("tcp.example.", "A")
        assert answer.cookie_bound is None
        assert len(fake.sent) == 1  # served from cache


def test_badcookie_without_stale_cookie_is_not_retried():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    ns = dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)
    fake = FakeUDP()

    def badcookie(where, q):
        cookie = dns.cookie.get_cookie_option(q)
        r = make_response(q, cookie=dns.edns.CookieOption(cookie.client, b"N" * 8))
        r.set_rcode(dns.rcode.BADCOOKIE)
        fake.add(r.to_wire(), (A_ADDRESS, A_PORT))

    fake._script = badcookie
    with fake_udp(fake):
        response = run_query(ns, dns.message.make_query("bad.example.", "A"))
    assert response.rcode() == dns.rcode.BADCOOKIE
    assert len(fake.sent) == 1
    # The fresh server cookie is still learned for the endpoint.
    assert policy.server_cookie(policy.endpoint(A_ADDRESS, A_PORT)) == b"N" * 8


def test_required_mode_rejects_missing_server_cookie():
    policy = dns.cookie.CookiePolicy(dns.cookie.CookieMode.REQUIRED, secret=b"s" * 32)
    ns = dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.22").to_wire(), (A_ADDRESS, A_PORT)
    )
    with fake_udp(fake), pytest.raises(dns.cookie.CookieError):
        run_query(ns, dns.message.make_query("required.example.", "A"))


def test_wrong_client_cookie_from_correct_source_rejected():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    ns = dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, cookie=dns.edns.CookieOption(b"WRONGcok", A1)).to_wire(),
        (A_ADDRESS, A_PORT),
    )
    with fake_udp(fake), pytest.raises(dns.cookie.CookieError):
        run_query(ns, dns.message.make_query("wrong.example.", "A"))


def test_other_edns_options_are_preserved():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    ns = dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.23", server_cookie=A1).to_wire(),
        (A_ADDRESS, A_PORT),
    )
    q = dns.message.make_query(
        "edns.example.", "A", options=[dns.edns.ECSOption("198.51.100.0", 24)]
    )
    with fake_udp(fake):
        run_query(ns, q)
    sent = fake.sent[0][1]
    types = {option.otype for option in sent.options}
    assert dns.edns.OptionType.COOKIE in types
    assert dns.edns.OptionType.ECS in types
    # The caller's request is restored after the Cookie is removed.
    assert [option.otype for option in q.options] == [dns.edns.OptionType.ECS]


def test_async_resolver_uses_cookie_cache_gate():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)]
    resolver.cache = dns.resolver.Cache()
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.30", server_cookie=A1).to_wire(),
        (A_ADDRESS, A_PORT),
    )
    backend = FakeBackend()
    backend.fake = fake

    async def run():
        return await resolver.resolve("async-cache.example.", "A", backend=backend)

    answer = asyncio.run(run())
    assert answer.cookie_bound is True
    assert len(fake.sent) == 1
    assert len(resolver.cache.data) == 1

    async def run_again():
        return await resolver.resolve("async-cache.example.", "A", backend=backend)

    answer = asyncio.run(run_again())
    assert answer.cookie_bound is True
    assert len(fake.sent) == 1


class FakeAsyncDatagram:
    family = socket.AF_INET

    def __init__(self, fake):
        self.fake = fake

    async def sendto(self, data, where, timeout):
        return self.fake.sendto(data, where)

    async def recvfrom(self, size, timeout):
        return self.fake.recvfrom(size)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass


class FakeBackend:
    name = "fake"

    def datagram_connection_required(self):
        return False

    async def make_socket(self, af, socktype, proto=0, source=None, destination=None):
        return FakeAsyncDatagram(self.fake)

    async def sleep(self, interval):
        pass


def test_response_without_edns_is_unbound_and_not_cached():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)]
    resolver.cache = dns.resolver.Cache()
    fake = FakeUDP()

    def no_edns(where, q):
        r = dns.message.make_response(q)
        r.use_edns(None)
        r.answer.append(
            dns.rrset.from_text(q.question[0].name, 60, "IN", "A", "192.0.2.25")
        )
        fake.add(r.to_wire(), (A_ADDRESS, A_PORT))

    fake._script = no_edns
    with fake_udp(fake):
        answer = resolver.resolve("noedns.example.", "A")
        assert answer.cookie_bound is False
        assert answer.response.cookie_validation.used_edns is False
        assert len(resolver.cache.data) == 0


def test_async_cookie_path():
    policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
    ns = dns.nameserver.Do53Nameserver(A_ADDRESS, A_PORT, policy)
    fake = FakeUDP()
    fake._script = lambda where, q: fake.add(
        make_response(q, "192.0.2.24", server_cookie=A1).to_wire(),
        (A_ADDRESS, A_PORT),
    )
    backend = FakeBackend()
    backend.fake = fake

    async def run():
        return await ns.async_query(
            dns.message.make_query("async.example.", "A"),
            timeout=2.0,
            source=None,
            source_port=0,
            max_size=False,
            backend=backend,
        )

    response = asyncio.run(run())
    assert response.answer[0][0].address == "192.0.2.24"
    assert dns.cookie.validation_for_message(response).bound is True
    assert policy.server_cookie(policy.endpoint(A_ADDRESS, A_PORT)) == A1
