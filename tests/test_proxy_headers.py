import copy
import unittest


class TestProxyHeadersMiddleware(unittest.TestCase):
    def _makeOne(self, app, **kw):
        from waitress.proxy_headers import proxy_headers_middleware

        return proxy_headers_middleware(app, **kw)

    def _callFUT(self, app, **kw):
        response = DummyResponse()
        environ = DummyEnviron(**kw)

        def start_response(status, response_headers):
            response.status = status
            response.headers = response_headers

        response.steps = list(app(environ, start_response))
        response.body = b"".join(s for s in response.steps)
        return response

    def test_get_environment_values_w_scheme_override_untrusted(self):
        inner = DummyApp()
        app = self._makeOne(inner)
        response = self._callFUT(
            app,
            headers={
                "X_FOO": "BAR",
                "X_FORWARDED_PROTO": "https",
            },
        )
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(inner.environ["wsgi.url_scheme"], "http")

    def test_get_environment_values_w_scheme_override_trusted(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="192.168.1.1",
            trusted_proxy_headers={"x-forwarded-proto"},
        )
        response = self._callFUT(
            app,
            addr=["192.168.1.1", 8080],
            headers={
                "X_FOO": "BAR",
                "X_FORWARDED_PROTO": "https",
            },
        )

        environ = inner.environ
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(environ["SERVER_PORT"], "443")
        self.assertEqual(environ["SERVER_NAME"], "localhost")
        self.assertEqual(environ["REMOTE_ADDR"], "192.168.1.1")
        self.assertEqual(environ["HTTP_X_FOO"], "BAR")

    def test_get_environment_values_w_bogus_scheme_override(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="192.168.1.1",
            trusted_proxy_headers={"x-forwarded-proto"},
        )
        response = self._callFUT(
            app,
            addr=["192.168.1.1", 80],
            headers={
                "X_FOO": "BAR",
                "X_FORWARDED_PROTO": "http://p02n3e.com?url=http",
            },
        )
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Proto" malformed', response.body)

    def test_get_environment_warning_other_proxy_headers(self):
        inner = DummyApp()
        logger = DummyLogger()
        app = self._makeOne(
            inner,
            trusted_proxy="192.168.1.1",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
            log_untrusted=True,
            logger=logger,
        )
        response = self._callFUT(
            app,
            addr=["192.168.1.1", 80],
            headers={
                "X_FORWARDED_FOR": "[2001:db8::1]",
                "FORWARDED": "For=198.51.100.2;host=example.com:8080;proto=https",
            },
        )
        self.assertEqual(response.status, "200 OK")

        self.assertEqual(len(logger.logged), 1)

        environ = inner.environ
        self.assertNotIn("HTTP_X_FORWARDED_FOR", environ)
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["wsgi.url_scheme"], "https")

    def test_get_environment_contains_all_headers_including_untrusted(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="192.168.1.1",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-by"},
            clear_untrusted=False,
        )
        headers_orig = {
            "X_FORWARDED_FOR": "198.51.100.2",
            "X_FORWARDED_BY": "Waitress",
            "X_FORWARDED_PROTO": "https",
            "X_FORWARDED_HOST": "example.org",
        }
        response = self._callFUT(
            app,
            addr=["192.168.1.1", 80],
            headers=headers_orig.copy(),
        )
        self.assertEqual(response.status, "200 OK")
        environ = inner.environ
        for k, expected in headers_orig.items():
            result = environ["HTTP_%s" % k]
            self.assertEqual(result, expected)

    def test_get_environment_contains_only_trusted_headers(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="192.168.1.1",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-by"},
            clear_untrusted=True,
        )
        response = self._callFUT(
            app,
            addr=["192.168.1.1", 80],
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "X_FORWARDED_BY": "Waitress",
                "X_FORWARDED_PROTO": "https",
                "X_FORWARDED_HOST": "example.org",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["HTTP_X_FORWARDED_BY"], "Waitress")
        self.assertNotIn("HTTP_X_FORWARDED_FOR", environ)
        self.assertNotIn("HTTP_X_FORWARDED_PROTO", environ)
        self.assertNotIn("HTTP_X_FORWARDED_HOST", environ)

    def test_get_environment_clears_headers_if_untrusted_proxy(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="192.168.1.1",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-by"},
            clear_untrusted=True,
        )
        response = self._callFUT(
            app,
            addr=["192.168.1.255", 80],
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "X_FORWARDED_BY": "Waitress",
                "X_FORWARDED_PROTO": "https",
                "X_FORWARDED_HOST": "example.org",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertNotIn("HTTP_X_FORWARDED_BY", environ)
        self.assertNotIn("HTTP_X_FORWARDED_FOR", environ)
        self.assertNotIn("HTTP_X_FORWARDED_PROTO", environ)
        self.assertNotIn("HTTP_X_FORWARDED_HOST", environ)

    def test_parse_proxy_headers_forwarded_for(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_headers={"x-forwarded-for"},
        )
        response = self._callFUT(app, headers={"X_FORWARDED_FOR": "192.0.2.1"})
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "192.0.2.1")

    def test_parse_proxy_headers_forwarded_for_v6_missing_brackets(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_headers={"x-forwarded-for"},
        )
        response = self._callFUT(app, headers={"X_FORWARDED_FOR": "2001:db8::0"})
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "2001:db8::0")

    def test_parse_proxy_headers_forwared_for_multiple(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={"x-forwarded-for"},
        )
        response = self._callFUT(
            app, headers={"X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1"}
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["HTTP_X_FORWARDED_FOR"], "198.51.100.2, 203.0.113.1")

    def test_parse_forwarded_multiple_proxies_trust_only_two(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": (
                    "For=192.0.2.1;host=fake.com, "
                    "For=198.51.100.2;host=example.com:8080, "
                    "For=203.0.113.1"
                ),
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(
            environ["HTTP_FORWARDED"],
            "For=198.51.100.2;host=example.com:8080, For=203.0.113.1",
        )

    def test_parse_forwarded_multiple_proxies(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": (
                    'for="[2001:db8::1]:3821";host="example.com:8443";proto="https", '
                    'for=192.0.2.1;host="example.internal:8080"'
                ),
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "2001:db8::1")
        self.assertEqual(environ["REMOTE_PORT"], "3821")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8443")
        self.assertEqual(environ["SERVER_PORT"], "8443")
        self.assertEqual(environ["wsgi.url_scheme"], "https")
        self.assertEqual(
            environ["HTTP_FORWARDED"],
            'for="[2001:db8::1]:3821";host="example.com:8443";proto="https", '
            'for=192.0.2.1;host="example.internal:8080"',
        )

    def test_parse_forwarded_multiple_proxies_minimal(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": (
                    'for="[2001:db8::1]";proto="https", '
                    'for=192.0.2.1;host="example.org"'
                ),
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "2001:db8::1")
        self.assertEqual(environ["SERVER_NAME"], "example.org")
        self.assertEqual(environ["HTTP_HOST"], "example.org")
        self.assertEqual(environ["SERVER_PORT"], "443")
        self.assertEqual(environ["wsgi.url_scheme"], "https")
        self.assertEqual(
            environ["HTTP_FORWARDED"],
            'for="[2001:db8::1]";proto="https", for=192.0.2.1;host="example.org"',
        )

    def test_parse_proxy_headers_forwarded_host_with_port(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-host",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "X_FORWARDED_PROTO": "http",
                "X_FORWARDED_HOST": "example.com:8080",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["HTTP_X_FORWARDED_FOR"], "198.51.100.2, 203.0.113.1")

    def test_parse_proxy_headers_forwarded_host_without_port(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-host",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "X_FORWARDED_PROTO": "http",
                "X_FORWARDED_HOST": "example.com",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com")
        self.assertEqual(environ["SERVER_PORT"], "80")
        self.assertEqual(environ["HTTP_X_FORWARDED_FOR"], "198.51.100.2, 203.0.113.1")

    def test_parse_proxy_headers_forwarded_host_with_forwarded_port(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-host",
                "x-forwarded-port",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "X_FORWARDED_PROTO": "http",
                "X_FORWARDED_HOST": "example.com",
                "X_FORWARDED_PORT": "8080",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["HTTP_X_FORWARDED_FOR"], "198.51.100.2, 203.0.113.1")

    def test_parse_proxy_headers_forwarded_host_multiple_with_forwarded_port(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=2,
            trusted_proxy_headers={
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-host",
                "x-forwarded-port",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "X_FORWARDED_PROTO": "http",
                "X_FORWARDED_HOST": "example.com, example.org",
                "X_FORWARDED_PORT": "8080",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["HTTP_X_FORWARDED_FOR"], "198.51.100.2, 203.0.113.1")
        self.assertEqual(environ["HTTP_X_FORWARDED_HOST"], "example.com, example.org")

    def test_parse_proxy_headers_forwarded_host_multiple_with_forwarded_port_limit_one_trusted(
        self,
    ):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-host",
                "x-forwarded-port",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "X_FORWARDED_PROTO": "http",
                "X_FORWARDED_HOST": "example.com, example.org",
                "X_FORWARDED_PORT": "8080",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "203.0.113.1")
        self.assertEqual(environ["SERVER_NAME"], "example.org")
        self.assertEqual(environ["HTTP_HOST"], "example.org:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["HTTP_X_FORWARDED_FOR"], "203.0.113.1")
        self.assertEqual(environ["HTTP_X_FORWARDED_HOST"], "example.org")

    def test_parse_forwarded(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": "For=198.51.100.2:5858;host=example.com:8080;proto=https",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["REMOTE_PORT"], "5858")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["wsgi.url_scheme"], "https")

    def test_parse_forwarded_empty_pair(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": "For=198.51.100.2;;proto=https;by=_unused",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")

    def test_parse_forwarded_pair_token_whitespace(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": "For=198.51.100.2; proto =https",
            },
        )
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "Forwarded" malformed', response.body)

    def test_parse_forwarded_pair_value_whitespace(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": 'For= "198.51.100.2"; proto =https',
            },
        )
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "Forwarded" malformed', response.body)

    def test_parse_forwarded_pair_no_equals(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
        )
        response = self._callFUT(app, headers={"FORWARDED": "For"})
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "Forwarded" malformed', response.body)

    def test_parse_forwarded_warning_unknown_token(self):
        inner = DummyApp()
        logger = DummyLogger()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"forwarded"},
            logger=logger,
        )
        response = self._callFUT(
            app,
            headers={
                "FORWARDED": (
                    "For=198.51.100.2;host=example.com:8080;proto=https;"
                    'unknown="yolo"'
                ),
            },
        )
        self.assertEqual(response.status, "200 OK")

        self.assertEqual(len(logger.logged), 1)
        self.assertIn("Unknown Forwarded token", logger.logged[0])

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8080")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["wsgi.url_scheme"], "https")

    def test_parse_no_valid_proxy_headers(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "FORWARDED": "For=198.51.100.2;host=example.com:8080;proto=https",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "127.0.0.1")
        self.assertEqual(environ["SERVER_NAME"], "localhost")
        self.assertEqual(environ["HTTP_HOST"], "192.168.1.1:80")
        self.assertEqual(environ["SERVER_PORT"], "8080")
        self.assertEqual(environ["wsgi.url_scheme"], "http")

    def test_parse_multiple_x_forwarded_proto(self):
        inner = DummyApp()
        logger = DummyLogger()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-proto"},
            logger=logger,
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_PROTO": "http, https",
            },
        )
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Proto" malformed', response.body)

    def test_parse_multiple_x_forwarded_port(self):
        inner = DummyApp()
        logger = DummyLogger()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-port"},
            logger=logger,
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_PORT": "443, 80",
            },
        )
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Port" malformed', response.body)

    def test_parse_forwarded_port_wrong_proto_port_80(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={
                "x-forwarded-port",
                "x-forwarded-host",
                "x-forwarded-proto",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_PORT": "80",
                "X_FORWARDED_PROTO": "https",
                "X_FORWARDED_HOST": "example.com",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:80")
        self.assertEqual(environ["SERVER_PORT"], "80")
        self.assertEqual(environ["wsgi.url_scheme"], "https")

    def test_parse_forwarded_port_wrong_proto_port_443(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={
                "x-forwarded-port",
                "x-forwarded-host",
                "x-forwarded-proto",
            },
        )
        response = self._callFUT(
            app,
            headers={
                "X_FORWARDED_PORT": "443",
                "X_FORWARDED_PROTO": "http",
                "X_FORWARDED_HOST": "example.com",
            },
        )
        self.assertEqual(response.status, "200 OK")

        environ = inner.environ
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:443")
        self.assertEqual(environ["SERVER_PORT"], "443")
        self.assertEqual(environ["wsgi.url_scheme"], "http")

    def test_parse_forwarded_for_bad_quote(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-for"},
        )
        response = self._callFUT(app, headers={"X_FORWARDED_FOR": '"foo'})
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-For" malformed', response.body)

    def test_parse_forwarded_host_bad_quote(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_count=1,
            trusted_proxy_headers={"x-forwarded-host"},
        )
        response = self._callFUT(app, headers={"X_FORWARDED_HOST": '"foo'})
        self.assertEqual(response.status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Host" malformed', response.body)


class TestProxyHeadersFailureAtomicity(unittest.TestCase):
    """A malformed proxy header must short-circuit with a 400.

    The application is never called, so it can never observe an environ that
    was only partially rewritten by the headers parsed before the failure.
    """

    TRUSTED_PEER = "203.0.113.9"

    def _makeOne(self, inner, **kw):
        from waitress.proxy_headers import proxy_headers_middleware

        kw.setdefault("trusted_proxy", self.TRUSTED_PEER)
        return proxy_headers_middleware(inner, **kw)

    def _invoke(self, inner, headers, trusted_headers, count=1,
                addr=None, clear_untrusted=True):
        addr = addr or (self.TRUSTED_PEER, 5100)
        app = self._makeOne(
            inner,
            trusted_proxy_count=count,
            trusted_proxy_headers=set(trusted_headers),
            clear_untrusted=clear_untrusted,
        )
        environ = DummyEnviron(addr=addr, headers=headers)
        before = copy.deepcopy(environ)
        captured = {}

        def start_response(status, response_headers):
            captured["status"] = status
            captured["headers"] = response_headers

        body = b"".join(app(environ, start_response))
        return before, environ, captured.get("status"), body

    def test_valid_multi_hop_control_x_forwarded(self):
        inner = DummyApp()
        before, _, status, _ = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "X_FORWARDED_HOST": "example.com, example.org:9000",
                "X_FORWARDED_PROTO": "https",
                "X_FORWARDED_PORT": "8443",
            },
            trusted_headers=[
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto",
                "x-forwarded-port",
            ],
            count=2,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(inner.calls, 1)
        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "198.51.100.2")
        self.assertEqual(environ["SERVER_NAME"], "example.com")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8443")
        self.assertEqual(environ["SERVER_PORT"], "8443")
        self.assertEqual(environ["wsgi.url_scheme"], "https")
        self.assertEqual(
            environ["HTTP_X_FORWARDED_FOR"], "198.51.100.2, 203.0.113.1"
        )
        # identity fields really were rewritten relative to the input environ
        self.assertNotEqual(before["REMOTE_ADDR"], environ["REMOTE_ADDR"])
        self.assertNotEqual(before["HTTP_HOST"], environ["HTTP_HOST"])

    def test_valid_multi_hop_control_forwarded_ipv6(self):
        inner = DummyApp()
        _, _, status, _ = self._invoke(
            inner,
            headers={
                "FORWARDED": (
                    'for="[2001:db8::1]:3821";host="example.com:8443";'
                    'proto="https", for=192.0.2.1;host="example.internal:8080"'
                ),
            },
            trusted_headers=["forwarded"],
            count=2,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(inner.calls, 1)
        environ = inner.environ
        self.assertEqual(environ["REMOTE_ADDR"], "2001:db8::1")
        self.assertEqual(environ["REMOTE_PORT"], "3821")
        self.assertEqual(environ["HTTP_HOST"], "example.com:8443")
        self.assertEqual(environ["SERVER_PORT"], "8443")
        self.assertEqual(environ["wsgi.url_scheme"], "https")

    def test_xff_already_rewritten_then_forwarded_malformed(self):
        # The multi-hop XFF header rewrites HTTP_X_FORWARDED_FOR before the
        # malformed Forwarded header is reached; the failure still has to
        # reject the whole request instead of handing that half-set environ
        # (or the XFF-derived identity) to the application.
        inner = DummyApp()
        before, environ, status, body = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": "192.0.2.1, 198.51.100.2, 203.0.113.1",
                "FORWARDED": "for=1.2.3.4; proto =https",
            },
            trusted_headers=["x-forwarded-for", "forwarded"],
            count=2,
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(b'Header "Forwarded" malformed', body)
        self.assertEqual(inner.calls, 0)
        self.assertIsNone(inner.environ)
        # the environ object itself was mutated before the short-circuit, but
        # the application never saw it and the identity keys were untouched
        self.assertEqual(environ["REMOTE_ADDR"], before["REMOTE_ADDR"])
        self.assertEqual(environ["HTTP_HOST"], before["HTTP_HOST"])
        self.assertEqual(environ["wsgi.url_scheme"], before["wsgi.url_scheme"])
        self.assertNotEqual(
            environ["HTTP_X_FORWARDED_FOR"], before["HTTP_X_FORWARDED_FOR"]
        )

    def test_malformed_xff_does_not_fallback_to_forwarded(self):
        inner = DummyApp()
        before, environ, status, body = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": '"unterminated',
                "FORWARDED": "for=198.51.100.2;host=example.com:8080;proto=https",
            },
            trusted_headers=["x-forwarded-for", "forwarded"],
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-For" malformed', body)
        self.assertEqual(inner.calls, 0)
        # no fallback to the wider Forwarded identity happened
        self.assertEqual(environ["REMOTE_ADDR"], before["REMOTE_ADDR"])
        self.assertEqual(environ["SERVER_NAME"], before["SERVER_NAME"])
        self.assertEqual(environ["HTTP_HOST"], before["HTTP_HOST"])

    def test_valid_xff_then_malformed_xproto(self):
        inner = DummyApp()
        before, environ, status, body = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "X_FORWARDED_PROTO": "http, https",
            },
            trusted_headers=["x-forwarded-for", "x-forwarded-proto"],
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Proto" malformed', body)
        self.assertEqual(inner.calls, 0)
        self.assertEqual(environ["REMOTE_ADDR"], before["REMOTE_ADDR"])
        self.assertEqual(environ["wsgi.url_scheme"], before["wsgi.url_scheme"])

    def test_valid_xff_then_malformed_xhost_quote(self):
        inner = DummyApp()
        _, _, status, body = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "X_FORWARDED_HOST": '"bad',
            },
            trusted_headers=["x-forwarded-for", "x-forwarded-host"],
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Host" malformed', body)
        self.assertEqual(inner.calls, 0)

    def test_forwarded_valid_for_illegal_host_port_counterexample(self):
        # Address parses fine but a later host element carries an illegal
        # port: the whole request has to be rejected, not accepted with the
        # valid for= identity and a poisoned HTTP_HOST/SERVER_PORT.
        inner = DummyApp()
        before, environ, status, body = self._invoke(
            inner,
            headers={
                "FORWARDED": 'for=198.51.100.2;host="example.com:notaport";'
                "proto=https"
            },
            trusted_headers=["forwarded"],
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(b'Header "Forwarded host=" malformed', body)
        self.assertEqual(inner.calls, 0)
        self.assertEqual(environ["REMOTE_ADDR"], before["REMOTE_ADDR"])
        self.assertEqual(environ["HTTP_HOST"], before["HTTP_HOST"])
        self.assertEqual(environ["SERVER_PORT"], before["SERVER_PORT"])

    def test_forwarded_host_out_of_range_port_counterexample(self):
        inner = DummyApp()
        _, _, status, body = self._invoke(
            inner,
            headers={
                "FORWARDED": 'for=198.51.100.2;host="example.com:70000";'
                "proto=https"
            },
            trusted_headers=["forwarded"],
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertEqual(inner.calls, 0)
        self.assertIn(b"malformed", body)

    def test_illegal_x_forwarded_port_values_rejected(self):
        for bad_port in ("abc", "-1", "70000", "8.0", " 80 "):
            with self.subTest(bad_port=bad_port):
                inner = DummyApp()
                _, environ, status, body = self._invoke(
                    inner,
                    headers={
                        "X_FORWARDED_HOST": "example.com",
                        "X_FORWARDED_PORT": bad_port,
                    },
                    trusted_headers=[
                        "x-forwarded-host",
                        "x-forwarded-port",
                    ],
                )
                self.assertEqual(status, "400 Bad Request")
                self.assertIn(
                    b'Header "X-Forwarded-Port" malformed', body
                )
                self.assertEqual(inner.calls, 0)
                self.assertNotIn("abc", str(environ.get("SERVER_PORT", "")))

    def test_x_forwarded_host_embedded_illegal_port_rejected(self):
        inner = DummyApp()
        _, environ, status, body = self._invoke(
            inner,
            headers={"X_FORWARDED_HOST": "example.com:99999"},
            trusted_headers=["x-forwarded-host"],
        )
        self.assertEqual(status, "400 Bad Request")
        self.assertIn(b'Header "X-Forwarded-Host" malformed', body)
        self.assertEqual(inner.calls, 0)
        self.assertEqual(environ["HTTP_HOST"], "192.168.1.1:80")

    def test_ipv6_xff_without_brackets_accepted(self):
        inner = DummyApp()
        _, _, status, _ = self._invoke(
            inner,
            headers={"X_FORWARDED_FOR": "2001:db8::1, 198.51.100.2"},
            trusted_headers=["x-forwarded-for"],
            count=2,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(inner.calls, 1)
        self.assertEqual(inner.environ["REMOTE_ADDR"], "2001:db8::1")

    def test_untrusted_direct_peer_headers_cleared_identity_kept(self):
        inner = DummyApp()
        before, _, status, _ = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "X_FORWARDED_HOST": "evil.example",
                "X_FORWARDED_PROTO": "https",
                "FORWARDED": "for=6.6.6.6",
            },
            trusted_headers=[
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto",
                "forwarded",
            ],
            addr=("198.18.0.77", 4000),
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(inner.calls, 1)
        environ = inner.environ
        # direct untrusted peer identity is preserved
        self.assertEqual(environ["REMOTE_ADDR"], "198.18.0.77")
        self.assertEqual(environ["REMOTE_HOST"], "198.18.0.77")
        self.assertEqual(environ["wsgi.url_scheme"], before["wsgi.url_scheme"])
        self.assertEqual(environ["HTTP_HOST"], before["HTTP_HOST"])
        # clear_untrusted policy still strips every proxy header
        for name in (
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED_HOST",
            "HTTP_X_FORWARDED_PROTO",
            "HTTP_FORWARDED",
        ):
            self.assertNotIn(name, environ)

    def test_trusted_wildcard_direct_peer(self):
        inner = DummyApp()
        app = self._makeOne(
            inner,
            trusted_proxy="*",
            trusted_proxy_headers={"x-forwarded-for"},
        )
        environ = DummyEnviron(
            addr=(self.TRUSTED_PEER, 5100),
            headers={"X_FORWARDED_FOR": "198.51.100.2"},
        )
        status = {}

        def start_response(s, h):
            status["s"] = s

        body = b"".join(app(environ, start_response))
        self.assertEqual(status["s"], "200 OK")
        self.assertEqual(body, b"hello")
        self.assertEqual(inner.calls, 1)
        self.assertEqual(inner.environ["REMOTE_ADDR"], "198.51.100.2")

    def test_clear_untrusted_false_preserves_headers_on_success(self):
        inner = DummyApp()
        _, _, status, _ = self._invoke(
            inner,
            headers={
                "X_FORWARDED_FOR": "198.51.100.2",
                "X_FORWARDED_HOST": "example.org",
            },
            trusted_headers=["x-forwarded-for"],
            clear_untrusted=False,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(inner.calls, 1)
        # untrusted X-Forwarded-Host is retained because the policy opted out
        self.assertEqual(
            inner.environ["HTTP_X_FORWARDED_HOST"], "example.org"
        )


class DummyLogger:
    def __init__(self):
        self.logged = []

    def warning(self, msg, *args):
        self.logged.append(msg % args)


class DummyApp:
    def __init__(self):
        self.calls = 0
        self.environ = None

    def __call__(self, environ, start_response):
        self.calls += 1
        self.environ = environ
        start_response("200 OK", [("Content-Type", "text/plain")])
        yield b"hello"


class DummyResponse:
    status = None
    headers = None
    body = None


def DummyEnviron(
    addr=("127.0.0.1", 8080),
    scheme="http",
    server="localhost",
    headers=None,
):
    environ = {
        "REMOTE_ADDR": addr[0],
        "REMOTE_HOST": addr[0],
        "REMOTE_PORT": addr[1],
        "SERVER_PORT": str(addr[1]),
        "SERVER_NAME": server,
        "wsgi.url_scheme": scheme,
        "HTTP_HOST": "192.168.1.1:80",
    }
    if headers:
        environ.update(
            {
                "HTTP_" + key.upper().replace("-", "_"): value
                for key, value in headers.items()
            }
        )
    return environ
