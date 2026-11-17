# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.cookie
import dns.edns
import dns.message
import dns.rcode


class CookiePolicyTestCase(unittest.TestCase):
    def setUp(self):
        self.policy = dns.cookie.CookiePolicy(secret=b"s" * 32)
        self.a = dns.cookie.Endpoint("192.0.2.1", 53)
        self.b = dns.cookie.Endpoint("192.0.2.2", 53)
        self.q = dns.message.make_query("example.", "A")
        self.q.set_id(1234)

    def response(self, cookie=None, rcode=dns.rcode.NOERROR):
        r = dns.message.make_response(self.q)
        r.set_rcode(rcode)
        if cookie is not None:
            r.use_edns(0, 0, 1232, options=[cookie])
        return r

    def test_endpoint_canonicalization(self):
        self.assertEqual(dns.cookie.Endpoint("2001:0db8::1", 53).address, "2001:db8::1")
        e = dns.cookie.Endpoint("192.0.2.1", "53", "UDP", "2001:0db8::2")
        self.assertEqual(e.port, 53)
        self.assertEqual(e.transport, "udp")
        self.assertEqual(e.source_address, "2001:db8::2")

    def test_client_cookie_is_endpoint_bound_and_stable(self):
        first = self.policy.client_cookie(self.a)
        self.assertEqual(len(first), 8)
        self.assertEqual(first, self.policy.client_cookie(self.a))
        self.assertNotEqual(first, self.policy.client_cookie(self.b))
        # A different source address is a different binding.
        a2 = dns.cookie.Endpoint("192.0.2.1", 53, source_address="192.0.2.100")
        self.assertNotEqual(first, self.policy.client_cookie(a2))
        # A different port is a different binding.
        self.assertNotEqual(
            first, self.policy.client_cookie(dns.cookie.Endpoint("192.0.2.1", 5353))
        )
        # Different policies do not share client cookies.
        other = dns.cookie.CookiePolicy(secret=b"t" * 32)
        self.assertNotEqual(first, other.client_cookie(self.a))

    def test_server_cookie_is_endpoint_bound(self):
        self.policy.set_server_cookie(self.a, b"AAAAAAAA")
        self.policy.set_server_cookie(self.b, b"BBBBBBBB")
        self.assertEqual(self.policy.server_cookie(self.a), b"AAAAAAAA")
        self.assertEqual(self.policy.server_cookie(self.b), b"BBBBBBBB")
        # An equal IPv6 address in a different textual form maps to one slot.
        e1 = dns.cookie.Endpoint("2001:0db8::1", 53)
        e2 = dns.cookie.Endpoint("2001:db8::1", 53)
        self.policy.set_server_cookie(e1, b"CCCCCCCC")
        self.assertEqual(self.policy.server_cookie(e2), b"CCCCCCCC")

    def test_server_cookie_length_validation(self):
        with self.assertRaises(ValueError):
            self.policy.set_server_cookie(self.a, b"short")
        with self.assertRaises(ValueError):
            self.policy.set_server_cookie(self.a, b"x" * 33)
        self.policy.set_server_cookie(self.a, b"x" * 32)
        self.policy.set_server_cookie(self.a, b"")
        self.assertEqual(self.policy.server_cookie(self.a), b"")

    def test_request_cookie_includes_stored_server_cookie(self):
        client = self.policy.client_cookie(self.a)
        option = self.policy.request_cookie(self.a)
        self.assertEqual(option.client, client)
        self.assertEqual(option.server, b"")
        self.policy.set_server_cookie(self.a, b"S" * 16)
        option = self.policy.request_cookie(self.a)
        self.assertEqual(option.server, b"S" * 16)

    def test_bound_response_stores_server_cookie(self):
        client = self.policy.client_cookie(self.a)
        server = b"S" * 16
        response = self.response(dns.edns.CookieOption(client, server))
        validation = self.policy.validate_response(response, self.a, client)
        self.assertTrue(validation.bound)
        self.assertFalse(validation.data_authenticated)
        self.assertEqual(validation.server_cookie, server)
        self.assertEqual(self.policy.server_cookie(self.a), server)
        # It went only to endpoint A.
        self.assertEqual(self.policy.server_cookie(self.b), b"")

    def test_server_rotation_replaces_cookie(self):
        client = self.policy.client_cookie(self.a)
        old = b"O" * 16
        new = b"N" * 24
        self.policy.set_server_cookie(self.a, old)
        validation = self.policy.validate_response(
            self.response(dns.edns.CookieOption(client, new)), self.a, client
        )
        self.assertTrue(validation.bound)
        self.assertEqual(self.policy.server_cookie(self.a), new)

    def test_wrong_client_cookie_rejected_in_all_modes(self):
        for mode in dns.cookie.CookieMode:
            if mode is dns.cookie.CookieMode.OFF:
                continue
            policy = dns.cookie.CookiePolicy(mode, secret=b"s" * 32)
            client = policy.client_cookie(self.a)
            response = self.response(dns.edns.CookieOption(b"WRONGcok", b"12345678"))
            with self.assertRaises(dns.cookie.CookieError):
                policy.validate_response(response, self.a, client)

    def test_missing_server_cookie_opportunistic_unbound(self):
        client = self.policy.client_cookie(self.a)
        response = self.response(dns.edns.CookieOption(client, b""))
        validation = self.policy.validate_response(response, self.a, client)
        self.assertFalse(validation.bound)
        self.assertEqual(self.policy.server_cookie(self.a), b"")

    def test_missing_cookie_opportunistic_unbound(self):
        client = self.policy.client_cookie(self.a)
        validation = self.policy.validate_response(self.response(), self.a, client)
        self.assertFalse(validation.bound)
        self.assertIsNone(validation.response_cookie)

    def test_missing_server_cookie_required_rejected(self):
        policy = dns.cookie.CookiePolicy(
            dns.cookie.CookieMode.REQUIRED, secret=b"s" * 32
        )
        client = policy.client_cookie(self.a)
        with self.assertRaises(dns.cookie.CookieError):
            policy.validate_response(
                self.response(dns.edns.CookieOption(client, b"")), self.a, client
            )

    def test_get_cookie_option_rejects_duplicates_and_malformed(self):
        response = self.response()
        response.use_edns(
            0,
            0,
            1232,
            options=[
                dns.edns.CookieOption(b"12345678", b""),
                dns.edns.CookieOption(b"12345678", b""),
            ],
        )
        with self.assertRaises(dns.cookie.CookieError):
            dns.cookie.get_cookie_option(response)
        response.use_edns(0, 0, 1232, options=[dns.edns.GenericOption(10, b"short")])
        with self.assertRaises(dns.cookie.CookieError):
            dns.cookie.get_cookie_option(response)

    def test_validate_udp_response_helper(self):
        self.q.use_edns(0)
        client = self.policy.client_cookie(self.a)
        dns.cookie.set_cookie_option(self.q, self.policy.request_cookie(self.a))
        response = self.response(dns.edns.CookieOption(client, b"S" * 8))
        validation = dns.cookie.validate_udp_response(
            self.q, response, self.policy, "192.0.2.1", 53
        )
        self.assertTrue(validation.bound)
        self.assertIs(response.cookie_validation, validation)
        self.assertEqual(self.policy.server_cookie(self.a), b"S" * 8)
        # A query without a Cookie cannot be validated.
        bare = dns.message.make_query("example.", "A")
        with self.assertRaises(dns.cookie.CookieError):
            dns.cookie.validate_udp_response(
                bare, response, self.policy, "192.0.2.1", 53
            )

    def test_set_cookie_option_enables_edns(self):
        cookie = dns.edns.CookieOption(b"12345678", b"")
        dns.cookie.set_cookie_option(self.q, cookie)
        self.assertEqual(self.q.edns, 0)
        self.assertEqual(self.q.options, (cookie,))

    def test_set_cookie_option_preserves_edns(self):
        self.q.use_edns(0, 0x8000, 1400, options=[dns.edns.ECSOption("1.2.3.0", 24)])
        state = dns.cookie.save_edns_state(self.q)
        cookie = dns.edns.CookieOption(b"12345678", b"")
        dns.cookie.set_cookie_option(self.q, cookie)
        self.assertEqual(self.q.edns, 0)
        self.assertEqual(self.q.ednsflags, 0x8000)
        self.assertEqual(self.q.payload, 1400)
        cookies = [o for o in self.q.options if o.otype == dns.edns.OptionType.COOKIE]
        self.assertEqual(cookies, [cookie])
        self.assertTrue(any(o.otype == dns.edns.OptionType.ECS for o in self.q.options))
        dns.cookie.restore_edns_state(self.q, state)
        self.assertFalse(
            any(o.otype == dns.edns.OptionType.COOKIE for o in self.q.options)
        )


if __name__ == "__main__":
    unittest.main()
