# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio

import pytest

import dns.asyncbackend
import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.nameserver
import dns.rcode
import dns.rdata
import dns.resolver


class RecordingNameserver(dns.nameserver.Nameserver):
    """A nameserver/transport stand-in that records every attempt made
    to it and replays scripted outcomes.

    Each outcome is either an exception instance, which is raised, or a
    callable taking the request and returning a response message.  If
    the outcomes are exhausted, *default* is used if provided.
    """

    def __init__(self, name, outcomes=(), kind="Do53", port=53, default=None):
        super().__init__()
        self.name = name
        self._kind = kind
        self._port = port
        self.outcomes = list(outcomes)
        self.default = default
        self.attempts = []

    def __str__(self):
        return self.name

    def kind(self):
        return self._kind

    def is_always_max_size(self):
        return False

    def answer_nameserver(self):
        return self.name

    def answer_port(self):
        return self._port

    def _attempt(self, request, max_size):
        self.attempts.append((request, max_size))
        if self.outcomes:
            outcome = self.outcomes.pop(0)
        elif self.default is not None:
            outcome = self.default
        else:
            raise AssertionError(f"{self.name}: unexpected query")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome(request)

    def query(
        self,
        request,
        timeout,
        source,
        source_port,
        max_size,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    ):
        return self._attempt(request, max_size)

    async def async_query(
        self,
        request,
        timeout,
        source,
        source_port,
        max_size,
        backend,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    ):
        return self._attempt(request, max_size)


def make_answer(address="192.0.2.1"):
    def respond(request):
        response = dns.message.make_response(request)
        qname = request.question[0].name
        rrset = response.find_rrset(response.answer, qname, "IN", "A", create=True)
        rrset.add(dns.rdata.from_text("IN", "A", address), 300)
        return response

    return respond


def make_nxdomain(request):
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.NXDOMAIN)
    return response


def tls_failure():
    return OSError("TLS handshake failed")


def make_resolver(plain, *policies, async_=False):
    if async_:
        resolver = dns.asyncresolver.Resolver(configure=False)
    else:
        resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = plain
    for name, policy in policies:
        resolver.add_transport_policy(name, policy)
    return resolver


def test_protected_query_never_falls_back_to_plaintext():
    plain = RecordingNameserver("plain", [make_answer()])
    tls = RecordingNameserver("tls", [tls_failure()], kind="DoT", port=853)
    resolver = make_resolver(
        [plain], ("secure.example.", dns.resolver.TransportPolicy([tls]))
    )
    with pytest.raises(dns.resolver.TransportPolicyViolation) as excinfo:
        resolver.resolve("www.secure.example.", "A")
    assert "transport policy" in str(excinfo.value)
    assert len(tls.attempts) == 1
    assert plain.attempts == []


def test_unprotected_query_keeps_normal_fallback():
    failing = RecordingNameserver("plain1", [OSError("boom")])
    working = RecordingNameserver("plain2", [make_answer()])
    tls = RecordingNameserver("tls", [tls_failure()], kind="DoT", port=853)
    resolver = make_resolver(
        [failing, working], ("secure.example.", dns.resolver.TransportPolicy([tls]))
    )
    answer = resolver.resolve("www.other.example.", "A")
    assert answer[0].address == "192.0.2.1"
    assert len(failing.attempts) == 1
    assert len(working.attempts) == 1
    assert tls.attempts == []


def test_policy_is_snapshot_when_resolution_starts():
    plain = RecordingNameserver("plain", [make_answer()])
    resolver = make_resolver([plain])

    def fail_and_unpin(request):
        # Simulate external reconfiguration while the query is running.
        resolver.transport_policies.clear()
        raise OSError("TLS handshake failed")

    tls1 = RecordingNameserver("tls1", [fail_and_unpin], kind="DoT", port=853)
    tls2 = RecordingNameserver("tls2", [make_answer("192.0.2.2")], kind="DoT", port=853)
    resolver.add_transport_policy(
        "secure.example.", dns.resolver.TransportPolicy([tls1, tls2])
    )
    answer = resolver.resolve("www.secure.example.", "A")
    assert answer[0].address == "192.0.2.2"
    assert len(tls1.attempts) == 1
    assert len(tls2.attempts) == 1
    assert plain.attempts == []
    # The cleared configuration applies to the next resolution.
    answer = resolver.resolve("www.secure.example.", "A")
    assert len(plain.attempts) == 1


def test_tc_retry_stays_within_policy():
    plain = RecordingNameserver("plain", [make_answer()])
    tls = RecordingNameserver(
        "tls", [dns.message.Truncated(), make_answer()], kind="DoT", port=853
    )
    resolver = make_resolver(
        [plain], ("secure.example.", dns.resolver.TransportPolicy([tls]))
    )
    answer = resolver.resolve("www.secure.example.", "A")
    assert answer[0].address == "192.0.2.1"
    # The truncation retry used the same pinned transport, not plaintext.
    assert [max_size for _, max_size in tls.attempts] == [False, True]
    assert plain.attempts == []


def test_lifetime_still_applies_to_protected_query():
    plain = RecordingNameserver("plain", [make_answer()])
    tls = RecordingNameserver(
        "tls", kind="DoT", port=853, default=dns.exception.Timeout("timed out")
    )
    resolver = make_resolver(
        [plain], ("secure.example.", dns.resolver.TransportPolicy([tls]))
    )
    with pytest.raises(dns.resolver.LifetimeTimeout):
        resolver.resolve("www.secure.example.", "A", lifetime=0.5)
    assert len(tls.attempts) > 0
    assert plain.attempts == []


def test_protected_nxdomain_does_not_fall_back():
    plain = RecordingNameserver("plain", [make_answer()])
    tls = RecordingNameserver("tls", [make_nxdomain], kind="DoT", port=853)
    resolver = make_resolver(
        [plain], ("secure.example.", dns.resolver.TransportPolicy([tls]))
    )
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("www.secure.example.", "A")
    assert len(tls.attempts) == 1
    assert plain.attempts == []


def test_most_specific_policy_wins():
    plain = RecordingNameserver("plain", [make_answer()])
    tls_wide = RecordingNameserver(
        "tls-wide", [make_answer("192.0.2.10")], kind="DoT", port=853
    )
    tls_specific = RecordingNameserver(
        "tls-specific", [make_answer("192.0.2.11")], kind="DoT", port=853
    )
    resolver = make_resolver(
        [plain],
        ("example.", dns.resolver.TransportPolicy([tls_wide])),
        ("secure.example.", dns.resolver.TransportPolicy([tls_specific])),
    )
    answer = resolver.resolve("www.secure.example.", "A")
    assert answer[0].address == "192.0.2.11"
    answer = resolver.resolve("www.other.example.", "A")
    assert answer[0].address == "192.0.2.10"
    assert plain.attempts == []


def test_async_protected_query_never_falls_back():
    plain = RecordingNameserver("plain", [make_answer()])
    tls = RecordingNameserver("tls", [tls_failure()], kind="DoT", port=853)
    resolver = make_resolver(
        [plain],
        ("secure.example.", dns.resolver.TransportPolicy([tls])),
        async_=True,
    )

    async def run():
        with pytest.raises(dns.resolver.TransportPolicyViolation):
            await resolver.resolve("www.secure.example.", "A")
        # An unprotected query still uses the regular nameservers.
        return await resolver.resolve("www.other.example.", "A")

    dns.asyncbackend.set_default_backend("asyncio")
    answer = asyncio.run(run())
    assert answer[0].address == "192.0.2.1"
    assert len(tls.attempts) == 1
    assert len(plain.attempts) == 1


def test_tls_constructor():
    policy = dns.resolver.TransportPolicy.tls(
        ["192.0.2.53", "192.0.2.54"], server_hostname="dot.example", verify=False
    )
    assert len(policy.nameservers) == 2
    nameserver = policy.nameservers[0]
    assert isinstance(nameserver, dns.nameserver.DoTNameserver)
    assert nameserver.address == "192.0.2.53"
    assert nameserver.port == 853
    assert nameserver.hostname == "dot.example"
    assert nameserver.verify is False


def test_policy_snapshots_nameserver_sequence():
    tls = RecordingNameserver("tls", kind="DoT", port=853)
    plain = RecordingNameserver("plain")
    source = [tls]
    policy = dns.resolver.TransportPolicy(source)
    source.append(plain)
    assert policy.nameservers == (tls,)


def test_policy_requires_nameservers():
    with pytest.raises(ValueError):
        dns.resolver.TransportPolicy([])
