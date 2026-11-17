# -*- coding: utf-8
# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import ipaddress
import unittest

import dns.edns
import dns.ecscache
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
from dns.ecscache import (
    ECSCache,
    ECSError,
    ECSEvent,
    ECSMalformed,
    ECSResolver,
    NoECSPolicy,
    WiderScopePolicy,
    client_subnet,
    extract_ecs,
    make_ecs_option,
    parse_ecs_wire,
)

QNAME = dns.name.from_text("example.com.")
QKEY = (QNAME, dns.rdatatype.A, dns.rdataclass.IN)


def _response(answer_ip, ecs_option=None, rcode=dns.rcode.NOERROR):
    """Build a synthetic A response with an optional ECS option."""
    q = dns.message.make_query(QNAME, dns.rdatatype.A)
    response = dns.message.make_response(q)
    if rcode == dns.rcode.NOERROR:
        rrset = response.find_rrset(
            response.answer,
            QNAME,
            dns.rdataclass.IN,
            dns.rdatatype.A,
            create=True,
        )
        rrset.ttl = 300
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, answer_ip))
    else:
        response.set_rcode(rcode)
    if ecs_option is not None:
        response.use_edns(options=[ecs_option])
    return response


def _answer(answer_ip, ecs_option=None, rcode=dns.rcode.NOERROR):
    response = _response(answer_ip, ecs_option, rcode)
    return dns.resolver.Answer(QNAME, dns.rdatatype.A, dns.rdataclass.IN, response)


def _ecs(option):
    """Return the single ECS option held by a message."""
    found = [o for o in option.options if o.otype == dns.edns.OptionType.ECS]
    return found[0]


def _raw_ecs(family, srclen, scopelen, address):
    """Build a raw ECS GenericOption so source and scope can differ."""
    network = client_subnet(address, srclen)
    nbytes = (srclen + 7) // 8
    # Wire order is FAMILY, SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH.
    payload = (
        family.to_bytes(2, "big")
        + bytes((srclen, scopelen))
        + network.network_address.packed[:nbytes]
    )
    return dns.edns.GenericOption(dns.edns.ECS, payload)


def _subnet(address, prefix):
    return client_subnet(address, prefix)


class ClientSubnetTestCase(unittest.TestCase):
    def test_masks_host_bits(self):
        network = client_subnet("192.0.2.137", 24)
        self.assertEqual(network, ipaddress.ip_network("192.0.2.0/24"))
        self.assertEqual(network.network_address, ipaddress.ip_address("192.0.2.0"))

    def test_default_prefixes(self):
        self.assertEqual(client_subnet("192.0.2.137").prefixlen, 24)
        self.assertEqual(client_subnet("2001:db8::dead").prefixlen, 56)

    def test_non_octet_boundary_mask(self):
        network = client_subnet("10.0.0.255", 25)
        self.assertEqual(network, ipaddress.ip_network("10.0.0.128/25"))

    def test_full_address_never_retained(self):
        network = client_subnet("198.51.100.77", 28)
        self.assertNotIn("77", str(network.network_address))
        self.assertEqual(network.network_address, ipaddress.ip_address("198.51.100.64"))

    def test_bad_prefix(self):
        with self.assertRaises(ValueError):
            client_subnet("192.0.2.1", 33)


class ParseWireTestCase(unittest.TestCase):
    def test_valid_ipv4(self):
        data = b"\x00\x01\x18\x18\xc0\x00\x02"
        result = parse_ecs_wire(data)
        self.assertEqual(result.family, dns.ecscache.FAMILY_IPV4)
        self.assertEqual(result.srclen, 24)
        self.assertEqual(result.scopelen, 24)
        self.assertEqual(result.network, ipaddress.ip_network("192.0.2.0/24"))

    def test_preserves_distinct_source_and_scope(self):
        # Source /24 in the query, scope /20 asserted by the response.
        result = parse_ecs_wire(b"\x00\x01\x18\x14\xc0\x00\x02")
        self.assertEqual(result.srclen, 24)
        self.assertEqual(result.scopelen, 20)
        self.assertEqual(result.source().prefixlen, 24)

    def test_masks_invalid_host_bits(self):
        # srclen 25, last byte has the 7 low bits set; they must be masked.
        data = b"\x00\x01\x19\x19\x0a\x00\x00\xff"
        result = parse_ecs_wire(data)
        self.assertEqual(result.network, ipaddress.ip_network("10.0.0.128/25"))

    def test_zero_prefix_needs_no_address(self):
        result = parse_ecs_wire(b"\x00\x01\x00\x00")
        self.assertEqual(result.network, ipaddress.ip_network("0.0.0.0/0"))

    def test_ipv6(self):
        addr = ipaddress.ip_address("2001:db8::").packed[:7]
        result = parse_ecs_wire(b"\x00\x02\x38\x38" + addr)
        self.assertEqual(result.family, dns.ecscache.FAMILY_IPV6)
        self.assertEqual(result.srclen, 56)
        self.assertEqual(result.network, ipaddress.ip_network("2001:db8::/56"))

    def test_unknown_family(self):
        with self.assertRaises(ECSMalformed):
            parse_ecs_wire(b"\x00\x09\x18\x00\x0a\x00\x00")

    def test_prefix_too_long(self):
        with self.assertRaises(ECSMalformed):
            parse_ecs_wire(b"\x00\x01\x21\x00\x0a\x00\x00\x00")

    def test_truncated_header(self):
        with self.assertRaises(ECSMalformed):
            parse_ecs_wire(b"\x00\x01\x18")

    def test_address_length_mismatch(self):
        with self.assertRaises(ECSMalformed):
            parse_ecs_wire(b"\x00\x01\x18\x00\x0a")

    def test_scope_length_checked(self):
        with self.assertRaises(ECSMalformed):
            parse_ecs_wire(b"\x00\x01\x18\x81\x0a\x00\x00")


class ExtractTestCase(unittest.TestCase):
    def test_no_ecs_returns_none(self):
        response = _response("192.0.2.1")
        self.assertIsNone(extract_ecs(response))

    def test_extracts_generic_option(self):
        response = _response(
            "192.0.2.1",
            dns.edns.GenericOption(dns.edns.ECS, b"\x00\x01\x18\x18\xc0\x00\x02"),
        )
        result = extract_ecs(response)
        self.assertEqual(result.network, ipaddress.ip_network("192.0.2.0/24"))

    def test_host_bits_event(self):
        response = _response(
            "192.0.2.1",
            dns.edns.GenericOption(dns.edns.ECS, b"\x00\x01\x19\x19\x0a\x00\x00\xff"),
        )
        events = []
        result = extract_ecs(response, events.append)
        self.assertEqual(result.network, ipaddress.ip_network("10.0.0.128/25"))
        self.assertIn(ECSEvent.QUERY_HOST_BITS_MASKED, events)

    def test_response_host_bits_event(self):
        response = _response(
            "192.0.2.1",
            dns.edns.GenericOption(dns.edns.ECS, b"\x00\x01\x19\x19\x0a\x00\x00\xff"),
        )
        events = []
        extract_ecs(
            response,
            events.append,
            host_bits_event=ECSEvent.RESPONSE_HOST_BITS_MASKED,
        )
        self.assertIn(ECSEvent.RESPONSE_HOST_BITS_MASKED, events)

    def test_malformed_raises(self):
        response = _response(
            "192.0.2.1",
            dns.edns.GenericOption(dns.edns.ECS, b"\x00\x01\x18\x00\x0a"),
        )
        with self.assertRaises(ECSMalformed):
            extract_ecs(response)

    def test_duplicate_options_rejected(self):
        class FakeMessage:
            options = (
                dns.edns.ECSOption("192.0.2.0", 24, 24),
                dns.edns.ECSOption("198.51.100.0", 24, 24),
            )

        with self.assertRaises(ECSMalformed):
            extract_ecs(FakeMessage())


class MakeOptionTestCase(unittest.TestCase):
    def test_option_uses_network_address(self):
        option = make_ecs_option(client_subnet("192.0.2.137", 24))
        self.assertEqual(option.address, "192.0.2.0")
        self.assertEqual(option.srclen, 24)
        self.assertEqual(option.scopelen, 0)

    def test_host_bits_do_not_leak(self):
        option = make_ecs_option(client_subnet("10.0.0.255", 25))
        self.assertEqual(option.address, "10.0.0.128")


class ECSCacheTestCase(unittest.TestCase):
    def setUp(self):
        self.cache = ECSCache()
        self.subnet_a = client_subnet("192.0.2.10", 24)
        self.subnet_b = client_subnet("198.51.100.20", 24)
        self.client_a = dns.ecscache.ECSData(1, 24, self.subnet_a)
        self.client_b = dns.ecscache.ECSData(1, 24, self.subnet_b)

    def _put(self, client, answer_ip, scope_len, scope_addr=None):
        scope_addr = scope_addr or str(client.network.network_address)
        option = dns.edns.ECSOption(scope_addr, client.prefixlen, scope_len)
        answer = _answer(answer_ip, option)
        stored = self.cache.put(QKEY, client, answer, answer.response)
        return answer, stored

    def test_subnet_isolation(self):
        answer_a, _ = self._put(self.client_a, "203.0.113.1", 24)
        answer_b, _ = self._put(self.client_b, "203.0.113.2", 24)
        self.assertIs(self.cache.get(QKEY, self.client_a), answer_a)
        self.assertIs(self.cache.get(QKEY, self.client_b), answer_b)

    def test_hit_and_miss_statistics(self):
        self._put(self.client_a, "203.0.113.1", 24)
        self.cache.get(QKEY, self.client_a)
        self.cache.get(QKEY, self.client_b)
        snapshot = self.cache.get_statistics_snapshot()
        self.assertEqual(snapshot.hits, 1)
        self.assertEqual(snapshot.misses, 1)

    def test_scope_zero_is_global(self):
        events = []
        option = dns.edns.ECSOption("192.0.2.0", 24, 0)
        answer = _answer("203.0.113.9", option)
        self.assertTrue(
            self.cache.put(QKEY, self.client_a, answer, answer.response, events.append)
        )
        self.assertIn(ECSEvent.SCOPE_ZERO_GLOBAL, events)
        # A global entry serves a client from an unrelated subnet.
        self.assertIs(self.cache.get(QKEY, self.client_b), answer)

    def test_no_ecs_global_policy(self):
        events = []
        answer = _answer("203.0.113.9")
        self.assertTrue(
            self.cache.put(QKEY, self.client_a, answer, answer.response, events.append)
        )
        self.assertIn(ECSEvent.NO_ECS_GLOBAL, events)
        self.assertIs(self.cache.get(QKEY, self.client_b), answer)

    def test_no_ecs_never_cache_policy(self):
        cache = ECSCache(no_ecs_policy=NoECSPolicy.NEVER_CACHE)
        answer = _answer("203.0.113.9")
        self.assertFalse(cache.put(QKEY, self.client_a, answer, answer.response))
        self.assertIsNone(cache.get(QKEY, self.client_a))

    def test_wider_scope_clamped_by_default(self):
        events = []
        # Only a /24 was queried, but the upstream asserts reuse for a wider
        # /20 block (a shorter prefix reaches beyond the queried network).
        option = _raw_ecs(dns.ecscache.FAMILY_IPV4, 24, 20, "192.0.2.0")
        answer = _answer("203.0.113.4", option)
        self.assertTrue(
            self.cache.put(QKEY, self.client_a, answer, answer.response, events.append)
        )
        self.assertIn(ECSEvent.SCOPE_CLAMPED, events)
        # A different /24 inside the claimed /20 must not receive the answer.
        other = dns.ecscache.ECSData(1, 24, client_subnet("192.0.3.5", 24))
        self.assertIsNone(self.cache.get(QKEY, other))
        # The queried subnet itself still gets a hit.
        self.assertIs(self.cache.get(QKEY, self.client_a), answer)

    def test_wider_scope_trusted_policy(self):
        cache = ECSCache(wider_scope_policy=WiderScopePolicy.TRUST)
        option = _raw_ecs(dns.ecscache.FAMILY_IPV4, 24, 20, "192.0.2.0")
        answer = _answer("203.0.113.4", option)
        cache.put(QKEY, self.client_a, answer, answer.response)
        # Another /24 inside the asserted /20 reuses the trusted answer.
        other = dns.ecscache.ECSData(1, 24, client_subnet("192.0.3.5", 24))
        self.assertIs(cache.get(QKEY, other), answer)

    def test_narrower_scope_reuses_within(self):
        # Query /24, upstream returns a more specific /28 scope (larger
        # prefix length), so only part of the queried network is covered.
        option = _raw_ecs(dns.ecscache.FAMILY_IPV4, 24, 28, "192.0.2.0")
        answer = _answer("203.0.113.7", option)
        self.cache.put(QKEY, self.client_a, answer, answer.response)
        inside = dns.ecscache.ECSData(1, 28, client_subnet("192.0.2.5", 28))
        outside = dns.ecscache.ECSData(1, 28, client_subnet("192.0.2.200", 28))
        self.assertIs(self.cache.get(QKEY, inside), answer)
        self.assertIsNone(self.cache.get(QKEY, outside))

    def test_malformed_response_not_cached(self):
        events = []
        response = _response(
            "203.0.113.8",
            dns.edns.GenericOption(dns.edns.ECS, b"\x00\x01\x18\x00\x0a"),
        )
        answer = dns.resolver.Answer(
            QNAME, dns.rdatatype.A, dns.rdataclass.IN, response
        )
        self.assertFalse(
            self.cache.put(QKEY, self.client_a, answer, response, events.append)
        )
        self.assertIn(ECSEvent.MALFORMED_NOT_CACHED, events)
        self.assertIsNone(self.cache.get(QKEY, self.client_a))

    def test_family_mismatch_not_cached(self):
        events = []
        # Response claims IPv6 ECS on an IPv4 query.
        option = dns.edns.ECSOption("2001:db8::", 56, 56)
        response = _response("203.0.113.8", option)
        answer = dns.resolver.Answer(
            QNAME, dns.rdatatype.A, dns.rdataclass.IN, response
        )
        self.assertFalse(
            self.cache.put(QKEY, self.client_a, answer, response, events.append)
        )
        self.assertIn(ECSEvent.MALFORMED_NOT_CACHED, events)

    def test_longest_prefix_match(self):
        global_option = dns.edns.ECSOption("192.0.2.0", 24, 0)
        global_answer = _answer("203.0.113.100", global_option)
        self.cache.put(QKEY, self.client_a, global_answer, global_answer.response)
        specific_answer, _ = self._put(self.client_a, "203.0.113.1", 24)
        # The /24 entry is more specific than the /0 global entry.
        self.assertIs(self.cache.get(QKEY, self.client_a), specific_answer)

    def test_expired_entry_misses(self):
        answer, _ = self._put(self.client_a, "203.0.113.1", 24)
        answer.expiration = 0
        self.assertIsNone(self.cache.get(QKEY, self.client_a))

    def test_flush(self):
        self._put(self.client_a, "203.0.113.1", 24)
        self.cache.flush(QKEY)
        self.assertIsNone(self.cache.get(QKEY, self.client_a))
        self._put(self.client_a, "203.0.113.1", 24)
        self.cache.flush()
        self.assertIsNone(self.cache.get(QKEY, self.client_a))

    def test_only_masked_network_stored(self):
        answer, _ = self._put(self.client_a, "203.0.113.1", 24)
        entries = self.cache.data[QKEY]
        for family, prefixlen, packed in entries:
            network = ipaddress.ip_network((ipaddress.ip_address(packed), prefixlen))
            self.assertEqual(network.network_address, network.network_address)
            self.assertEqual(int(network.hostmask) & int(network.network_address), 0)


class ECSResolverTestCase(unittest.TestCase):
    def _fake_upstream(self):
        """Return (upstream, seen_options, responses_by_subnet)."""
        seen = []

        def upstream(qname, rdtype, rdclass, ecs_option):
            seen.append(ecs_option)
            network = client_subnet(ecs_option.address, ecs_option.srclen)
            answer_ip = self.responses[str(network)]
            option = dns.edns.ECSOption(
                str(network.network_address), network.prefixlen, network.prefixlen
            )
            return _answer(answer_ip, option)

        return upstream, seen

    def setUp(self):
        self.responses = {
            "192.0.2.0/24": "203.0.113.1",
            "198.51.100.0/24": "203.0.113.2",
        }

    def test_sends_masked_ecs_and_caches(self):
        upstream, seen = self._fake_upstream()
        resolver = ECSResolver(upstream=upstream)
        first = resolver.resolve(QNAME, "A", "IN", client_address="192.0.2.137")
        second = resolver.resolve(QNAME, "A", "IN", client_address="192.0.2.7")
        self.assertEqual(second, first)
        # Second client in the same /24 is a cache hit, so only one upstream call.
        self.assertEqual(len(seen), 1)
        sent = seen[0]
        self.assertEqual(sent.address, "192.0.2.0")
        self.assertEqual(sent.srclen, 24)
        self.assertEqual(sent.scopelen, 0)

    def test_two_subnets_get_different_answers(self):
        upstream, seen = self._fake_upstream()
        resolver = ECSResolver(upstream=upstream)
        answer_a = resolver.resolve(QNAME, client_address="192.0.2.10")
        answer_b = resolver.resolve(QNAME, client_address="198.51.100.30")
        self.assertEqual(answer_a[0].address, "203.0.113.1")
        self.assertEqual(answer_b[0].address, "203.0.113.2")
        self.assertEqual(len(seen), 2)
        # Repeating either subnet hits the cache instead of the upstream.
        resolver.resolve(QNAME, client_address="192.0.2.99")
        resolver.resolve(QNAME, client_address="198.51.100.99")
        self.assertEqual(len(seen), 2)
        self.assertEqual(resolver.cache.hits(), 2)

    def test_full_client_address_not_used_as_key(self):
        upstream, _ = self._fake_upstream()
        resolver = ECSResolver(upstream=upstream)
        resolver.resolve(QNAME, client_address="192.0.2.137")
        entries = resolver.cache.data[QKEY]
        for family, prefixlen, packed in entries:
            self.assertEqual(packed, ipaddress.ip_address("192.0.2.0").packed)

    def test_requires_client_address(self):
        upstream, _ = self._fake_upstream()
        resolver = ECSResolver(upstream=upstream)
        with self.assertRaises(ECSError):
            resolver.resolve(QNAME)

    def test_family_mismatch_rejected(self):
        upstream, _ = self._fake_upstream()
        resolver = ECSResolver(upstream=upstream)
        with self.assertRaises(ECSError):
            resolver.resolve(QNAME, "A", client_address="2001:db8::1")

    def test_malformed_upstream_response_never_cached(self):
        calls = 0

        def upstream(qname, rdtype, rdclass, ecs_option):
            nonlocal calls
            calls += 1
            response = _response(
                "203.0.113.1",
                dns.edns.GenericOption(dns.edns.ECS, b"\x00\x01\x18\x00\x0a"),
            )
            return dns.resolver.Answer(
                QNAME, dns.rdatatype.A, dns.rdataclass.IN, response
            )

        resolver = ECSResolver(upstream=upstream)
        resolver.resolve(QNAME, client_address="192.0.2.1")
        resolver.resolve(QNAME, client_address="192.0.2.2")
        self.assertEqual(calls, 2)
        self.assertEqual(resolver.cache.misses(), 2)

    def test_response_scope_controls_reuse(self):
        def upstream(qname, rdtype, rdclass, ecs_option):
            # Scope zero means the answer is reusable by every client.
            option = dns.edns.ECSOption(ecs_option.address, ecs_option.srclen, 0)
            return _answer("203.0.113.9", option)

        calls = 0

        def counting_upstream(qname, rdtype, rdclass, ecs_option):
            nonlocal calls
            calls += 1
            return upstream(qname, rdtype, rdclass, ecs_option)

        resolver = ECSResolver(upstream=counting_upstream)
        resolver.resolve(QNAME, client_address="192.0.2.1")
        resolver.resolve(QNAME, client_address="198.51.100.1")
        self.assertEqual(calls, 1)

    def test_ipv6_subnet_isolation(self):
        def upstream(qname, rdtype, rdclass, ecs_option):
            network = client_subnet(ecs_option.address, ecs_option.srclen)
            answer_ip = (
                "2001:db8::1" if str(network) == "2001:db8::/56" else "2001:db8:1::1"
            )
            option = dns.edns.ECSOption(
                str(network.network_address), network.prefixlen, network.prefixlen
            )
            q = dns.message.make_query(qname, dns.rdatatype.AAAA)
            response = dns.message.make_response(q)
            rrset = response.find_rrset(
                response.answer,
                qname,
                dns.rdataclass.IN,
                dns.rdatatype.AAAA,
                create=True,
            )
            rrset.ttl = 300
            rrset.add(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, answer_ip)
            )
            response.use_edns(options=[option])
            return dns.resolver.Answer(
                qname, dns.rdatatype.AAAA, dns.rdataclass.IN, response
            )

        resolver = ECSResolver(upstream=upstream)
        first = resolver.resolve(QNAME, "AAAA", client_address="2001:db8::dead:beef")
        second = resolver.resolve(QNAME, "AAAA", client_address="2001:db8:1::1234")
        self.assertEqual(first[0].address, "2001:db8::1")
        self.assertEqual(second[0].address, "2001:db8:1::1")
        # A repeat in the first /56 must hit, proving subnet-scoped reuse.
        repeat = resolver.resolve(QNAME, "AAAA", client_address="2001:db8::5")
        self.assertIs(repeat, first)

    def test_never_cache_policy_counts_misses(self):
        cache = ECSCache(no_ecs_policy=NoECSPolicy.NEVER_CACHE)

        def upstream_without_ecs(qname, rdtype, rdclass, ecs_option):
            return _answer("203.0.113.1")

        resolver = ECSResolver(upstream=upstream_without_ecs, cache=cache)
        resolver.resolve(QNAME, client_address="192.0.2.1")
        resolver.resolve(QNAME, client_address="192.0.2.2")
        self.assertEqual(cache.misses(), 2)
        self.assertEqual(cache.hits(), 0)
        self.assertEqual(cache.data, {})


if __name__ == "__main__":
    unittest.main()
