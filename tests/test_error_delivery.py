"""Regression tests for what an application error sends to the client.

These tests run a real WSGI application through ``WSGITask`` and
``HTTPChannel`` over a socket pair, so the assertions are made against the
bytes that actually cross the kernel boundary.  The log records are captured
separately: a credential appearing in the server log is expected and is not
evidence that the client received it.
"""

import logging
import socket
import unittest

from waitress.adjustments import Adjustments
from waitress.channel import HTTPChannel

GENERIC_BODY = b"The server encountered an unexpected internal server error"

AUTH_CANARY = "AUTH-CANARY-6f4d1c2b9a"
COOKIE_CANARY = "COOKIE-CANARY-8e7a5d3c1f"
API_KEY_CANARY = "APIKEY-CANARY-2b9c4e6a8d"
QUERY_CANARY = "QUERY-CANARY-5a1f3c7e9b"
CREDENTIALS = (AUTH_CANARY, COOKIE_CANARY, API_KEY_CANARY, QUERY_CANARY)


def _credentials(environ):
    """Return every request credential the application can see in environ."""
    return " ".join(
        [
            environ.get("HTTP_AUTHORIZATION", ""),
            environ.get("HTTP_COOKIE", ""),
            environ.get("HTTP_X_API_KEY", ""),
            environ.get("QUERY_STRING", ""),
        ]
    )


class SecretErrorApp:
    """A WSGI application that deliberately puts request credentials in errors."""

    HEADER = ("X-Application-Secret", AUTH_CANARY)

    def __call__(self, environ, start_response):
        path = environ["PATH_INFO"]
        message = "application failure: " + _credentials(environ)

        if path == "/raise-in-call":
            raise RuntimeError(message)

        if path == "/raise-in-call-after-start":
            # Calling start_response alone does not put headers on the wire.
            start_response(
                "200 OK",
                [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "999"),
                    self.HEADER,
                ],
            )
            raise RuntimeError(message)

        if path == "/raise-after-write-in-call":
            # The write callable returned by start_response sends headers and
            # body immediately, so this is an application-call failure after
            # the response is already on the wire.
            write = start_response(
                "200 OK",
                [("Content-Type", "text/plain"), ("Content-Length", "999")],
            )
            write(b"partial-body")
            raise RuntimeError(message)

        if path == "/raise-in-close-after-empty-write":
            write = start_response("200 OK", [("Content-Type", "text/plain")])
            write(b"")  # generate headers without a body

            class CloseAfterEmptyWrite:
                def __iter__(self):
                    return iter(())

                def close(self):
                    raise RuntimeError(message)

            return CloseAfterEmptyWrite()

        if path == "/raise-before-first-chunk":
            start_response("200 OK", [("Content-Type", "text/plain")])

            def before_first_chunk():
                raise RuntimeError(message)
                yield b""  # pragma: no cover

            return before_first_chunk()

        if path == "/raise-after-first-chunk":
            start_response("200 OK", [("Content-Type", "text/plain")])

            def after_first_chunk():
                yield b"partial-body"
                raise RuntimeError(message)

            return after_first_chunk()

        if path == "/raise-in-close-before-body":
            start_response("200 OK", [("Content-Type", "text/plain")])

            class CloseBeforeBody:
                def __iter__(self):
                    return iter(())

                def close(self):
                    raise RuntimeError(message)

            return CloseBeforeBody()

        if path == "/raise-in-close-after-chunk":
            start_response("200 OK", [("Content-Type", "text/plain")])

            class CloseAfterChunk:
                def __iter__(self):
                    return iter([b"partial-body"])

                def close(self):
                    raise RuntimeError(message)

            return CloseAfterChunk()

        if path == "/raise-in-close-after-complete-body":
            start_response(
                "200 OK",
                [("Content-Type", "text/plain"), ("Content-Length", "5")],
            )

            class CloseAfterCompleteBody:
                def __iter__(self):
                    return iter([b"hello"])

                def close(self):
                    raise RuntimeError(message)

            return CloseAfterCompleteBody()

        raise AssertionError("unknown path: %s" % path)  # pragma: no cover


class _Server:
    def __init__(self, application, adj):
        self.application = application
        self.adj = adj
        self.effective_port = 80
        self.server_name = "localhost"
        self.active_channels = {}

    def add_task(self, task):
        pass

    def pull_trigger(self):
        pass


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []
        self.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))

    def emit(self, record):
        self.lines.append(self.format(record))


class Result:
    def __init__(self, wire, logs, closed, eof):
        self.wire = wire
        self.logs = logs
        self.closed = closed
        self.eof = eof

    @property
    def status_lines(self):
        return [
            line for line in self.wire.split(b"\r\n") if line.startswith(b"HTTP/1.")
        ]


def _request(path):
    return (
        "GET %s?token=%s HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Authorization: Bearer %s\r\n"
        "Cookie: session=%s\r\n"
        "X-Api-Key: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n" % (path, QUERY_CANARY, AUTH_CANARY, COOKIE_CANARY, API_KEY_CANARY)
    ).encode("ascii")


def _drain(sock):
    data = bytearray()
    eof = False

    while True:
        try:
            chunk = sock.recv(65536)
        except BlockingIOError:
            break
        except OSError:
            break

        if not chunk:
            eof = True
            break
        data.extend(chunk)

    return bytes(data), eof


def _run(raw_request, expose_tracebacks):
    adj = Adjustments(expose_tracebacks=expose_tracebacks, threads=1)
    server = _Server(SecretErrorApp(), adj)
    client, server_socket = socket.socketpair()
    client.setblocking(False)
    server_socket.setblocking(False)
    channel = HTTPChannel(server, server_socket, ("127.0.0.1", 12345), adj, map={})

    capture = _Capture()
    logger = logging.getLogger("waitress")
    old_level = logger.level
    old_propagate = logger.propagate
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(capture)

    try:
        channel.received(raw_request)
        channel.service()

        wire = bytearray()
        eof = False

        # Emulate the main loop: push outbuf data to the socket, then finish.
        for _ in range(100):
            channel._flush_some()
            chunk, eof = _drain(client)
            wire.extend(chunk)

            if channel.total_outbufs_len == 0:
                break

        closed = channel.close_when_flushed or channel.will_close
        closed = closed or not channel.connected

        if channel.close_when_flushed or channel.will_close:
            channel.handle_close()

        chunk, eof = _drain(client)
        wire.extend(chunk)
        eof = eof or not channel.connected
    finally:
        logger.removeHandler(capture)
        logger.setLevel(old_level)
        logger.propagate = old_propagate
        client.close()

        try:
            server_socket.close()
        except OSError:  # pragma: no cover - handle_close normally closes it
            pass

    return Result(bytes(wire), "\n".join(capture.lines), closed, eof)


def run_request(path, expose_tracebacks):
    return _run(_request(path), expose_tracebacks)


# path, headers already on the wire before the exception, connection closed
CASES = (
    ("application-call", "/raise-in-call", False, True),
    (
        "application-call-after-start-response",
        "/raise-in-call-after-start",
        False,
        True,
    ),
    ("application-call-after-write", "/raise-after-write-in-call", True, True),
    ("iteration-before-first-chunk", "/raise-before-first-chunk", False, True),
    ("iteration-after-first-chunk", "/raise-after-first-chunk", True, True),
    ("iterator-close-before-body", "/raise-in-close-before-body", False, True),
    (
        "iterator-close-after-empty-write",
        "/raise-in-close-after-empty-write",
        True,
        True,
    ),
    ("iterator-close-after-chunk", "/raise-in-close-after-chunk", True, True),
    (
        "iterator-close-after-complete-body",
        "/raise-in-close-after-complete-body",
        True,
        True,
    ),
)


class ApplicationErrorDeliveryTests(unittest.TestCase):
    def assert_canaries_absent(self, blob, where):
        for canary in CREDENTIALS:
            self.assertNotIn(
                canary.encode("ascii"), blob, "%s leaked to %s" % (canary, where)
            )

    def assert_canaries_present(self, text, where):
        for canary in CREDENTIALS:
            self.assertIn(canary, text, "%s missing from %s" % (canary, where))

    def test_default_config_does_not_put_tracebacks_or_credentials_on_wire(self):
        for case, path, headers_sent, _ in CASES:
            with self.subTest(case=case):
                result = run_request(path, expose_tracebacks=False)

                # The server must not append a second response in order to hide
                # the body: a partial application response gets one status line
                # and a closed connection instead.
                self.assertEqual(len(result.status_lines), 1)
                self.assertTrue(result.closed)
                self.assertTrue(result.eof)

                self.assert_canaries_absent(result.wire, "wire")
                self.assertNotIn(b"Traceback (most recent call last)", result.wire)
                self.assertNotIn(b"RuntimeError", result.wire)

                if headers_sent:
                    self.assertIn(b"200 OK", result.status_lines[0])
                    self.assertNotIn(b"500", result.wire)
                    self.assertNotIn(GENERIC_BODY, result.wire)
                else:
                    self.assertIn(b"500 Internal Server Error", result.status_lines[0])
                    self.assertIn(GENERIC_BODY, result.wire)
                    # Application headers prepared before the failure must not
                    # be reused for the generated error response.
                    self.assertNotIn(b"X-Application-Secret", result.wire)
                    self.assertNotIn(b"Content-Length: 999", result.wire)

                # The server-side record still has the full diagnostic detail.
                self.assertIn("Traceback (most recent call last)", result.logs)
                self.assert_canaries_present(result.logs, "server log")
                # The log is not the client's copy of the response.
                self.assertNotEqual(result.logs.encode("utf-8"), result.wire)

    def test_headers_already_sent_still_do_not_receive_a_second_response(self):
        for case, path, headers_sent, _ in CASES:
            if not headers_sent:
                continue

            with self.subTest(case=case):
                result = run_request(path, expose_tracebacks=True)

                # Even when tracebacks are enabled, it is too late to change
                # the response once headers have been sent.
                self.assertEqual(len(result.status_lines), 1)
                self.assertIn(b"200 OK", result.status_lines[0])
                self.assertNotIn(b"500", result.wire)
                self.assertNotIn(b"Traceback (most recent call last)", result.wire)
                self.assert_canaries_absent(result.wire, "wire")

                self.assertIn("Traceback (most recent call last)", result.logs)
                self.assert_canaries_present(result.logs, "server log")

    def test_expose_tracebacks_is_an_explicit_client_visible_boundary(self):
        for case, path, headers_sent, _ in CASES:
            if headers_sent:
                continue

            with self.subTest(case=case):
                result = run_request(path, expose_tracebacks=True)

                self.assertEqual(len(result.status_lines), 1)
                self.assertIn(b"500 Internal Server Error", result.status_lines[0])
                self.assertIn(b"Traceback (most recent call last)", result.wire)
                self.assert_canaries_present(
                    result.wire.decode("utf-8"), "wire with expose_tracebacks"
                )

    def test_generic_error_body_does_not_reveal_the_failure_stage(self):
        bodies = set()

        for case, path, headers_sent, _ in CASES:
            if headers_sent:
                continue

            with self.subTest(case=case):
                result = run_request(path, expose_tracebacks=False)
                body = result.wire.split(b"\r\n\r\n", 1)[1]
                self.assertIn(GENERIC_BODY, body)
                bodies.add(body)

        # Application call, iteration and iterator close failures before any
        # headers are sent are indistinguishable to the client.
        self.assertEqual(len(bodies), 1, bodies)

    def test_chunked_partial_response_is_terminated_by_connection_close(self):
        result = run_request("/raise-after-first-chunk", expose_tracebacks=False)

        self.assertIn(b"Transfer-Encoding: chunked", result.wire)
        self.assertIn(b"partial-body", result.wire)
        # finish() is skipped, so the chunked terminator must not be sent and
        # the client has to notice the truncated response from the close.
        self.assertFalse(result.wire.endswith(b"0\r\n\r\n"))
        self.assertTrue(result.eof)

    def test_complete_content_length_response_gets_no_error_appended(self):
        result = run_request(
            "/raise-in-close-after-complete-body", expose_tracebacks=False
        )

        self.assertIn(b"Content-Length: 5", result.wire)
        self.assertTrue(result.wire.endswith(b"hello"))
        self.assertEqual(len(result.status_lines), 1)
        self.assertNotIn(b"500", result.wire)
        self.assertNotIn(GENERIC_BODY, result.wire)
        self.assertTrue(result.eof)
        self.assert_canaries_present(result.logs, "server log")


class RequestDataReflectionTests(unittest.TestCase):
    """Malformed requests must not have their bytes echoed in a 400 body.

    Parser diagnostics are used as the response body, so anything interpolated
    from the request would come back to the client.  Credentials can appear in
    a malformed request method and in a header line or continuation.
    """

    def assert_canaries_absent(self, blob, where):
        for canary in CREDENTIALS:
            self.assertNotIn(
                canary.encode("ascii"), blob, "%s leaked to %s" % (canary, where)
            )

    def test_malformed_method_is_not_reflected(self):
        result = _run(
            b"ge" + AUTH_CANARY.encode("ascii") + b"T / HTTP/1.1\r\n"
            b"Host: localhost\r\n\r\n",
            expose_tracebacks=False,
        )
        self.assertIn(b"400 Bad Request", result.wire)
        self.assertIn(b"Malformed HTTP method", result.wire)
        self.assert_canaries_absent(result.wire, "wire")

    def test_header_line_with_bare_cr_is_not_reflected(self):
        result = _run(
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"X-Credential: " + AUTH_CANARY.encode("ascii") + b"\r\n"
            b"Bad: value\rwith-cr\r\n\r\n",
            expose_tracebacks=False,
        )
        self.assertIn(b"400 Bad Request", result.wire)
        self.assertIn(b"Bare CR or LF found in header line", result.wire)
        self.assert_canaries_absent(result.wire, "wire")

    def test_malformed_header_continuation_is_not_reflected(self):
        result = _run(
            b"GET / HTTP/1.1\r\n"
            b" " + AUTH_CANARY.encode("ascii") + b" continuation\r\n"
            b"Host: localhost\r\n\r\n",
            expose_tracebacks=False,
        )
        self.assertIn(b"400 Bad Request", result.wire)
        self.assertIn(b"Malformed header line", result.wire)
        self.assert_canaries_absent(result.wire, "wire")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
