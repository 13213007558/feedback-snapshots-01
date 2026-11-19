#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""One redaction policy for the access log, WSGI and ASGI alike.

The access log format is chosen by the application, so the fields it can
write are not known in advance. These tests drive one fake request through
the WSGI and ASGI access log paths and check that:

- the request the application sees is not changed;
- a field the operator selected is redacted under every name a format can
  use for it, while the request identifier used for troubleshooting stays;
- the standard format and a custom format both come out redacted.
"""

import asyncio
import datetime
import logging
from types import SimpleNamespace

import pytest

from gunicorn.accesslog import REDACTED
from gunicorn.config import Config, validate_access_log_redaction
from gunicorn.glogging import Logger
from gunicorn.http.parser import RequestParser
from gunicorn.http.wsgi import create as wsgi_create

RAW_REQUEST = (
    b"GET /orders/42?status=open&token=SECRET-TOKEN HTTP/1.1\r\n"
    b"Host: shop.example\r\n"
    b"Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"
    b"Cookie: sessionid=abc123\r\n"
    b"X-Request-Id: 7d3f9a2c\r\n"
    b"X-Api-Key: k-live-9f8e7d\r\n"
    b"\r\n"
)

STANDARD_FORMAT = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
)
CUSTOM_FORMAT = (
    'id=%( {x-request-id}i )s user=%(u)s '
    'auth=%( {authorization}i )s '
    'key=%( {x-api-key}i )s '
    'uri=%( {raw_uri}e )s q=%( {query_string}e )s '
    'method=%(m)s path=%(U)s'
).replace(" ", "")

# What the operator asks to hide, by name and by atom, exercising both
# spellings a format may use.
REDACT_FIELDS = [
    "authorization",   # header name
    "u",               # standard atom decoded from it
    "x-api-key",       # a custom header
    "q",               # standard atom for the query string
]


def _parse(raw):
    """Parse ``raw`` with the WSGI parser, as a sync worker does."""
    cfg = Config()
    cfg.set("keepalive", 2)
    return next(iter(RequestParser(cfg, iter([raw]), ("198.51.100.7", 40000))))


class _Socket:
    def send(self, data):
        pass

    def sendall(self, data):
        pass


def _wsgi_access_line(fmt):
    """Build the request and environ the WSGI worker logs from."""
    cfg = Config()
    cfg.set("accesslog", "-")
    cfg.set("access_log_format", fmt)
    cfg.set("access_log_redact", REDACT_FIELDS)
    req = _parse(RAW_REQUEST)
    resp, environ = wsgi_create(
        req, _Socket(), ("198.51.100.7", 40000),
        ("127.0.0.1", 8000), cfg)
    resp.status = "200 OK"
    resp.sent = 3
    return cfg, req, resp, environ


class _ASGIResponse:
    """The response info the ASGI worker hands to the logger."""

    status = "200 OK"
    sent = 3

    def __init__(self):
        self.headers = [("Content-Type", "application/json"),
                        ("Set-Cookie", "sessionid=abc123"),
                        ("X-Request-Id", "7d3f9a2c")]


@pytest.mark.asyncio
async def _asgi_access_line(fmt):
    """Serve ``RAW_REQUEST`` through the ASGI protocol and return its line."""
    from gunicorn.asgi.protocol import ASGIProtocol
    from test_asgi_keepalive_smuggling import _FakeTransport, _build_worker

    seen = []

    async def app(scope, receive, send):
        seen.append(scope)
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json"),
                                (b"set-cookie", b"sessionid=abc123"),
                                (b"x-request-id", b"7d3f9a2c")]})
        await send({"type": "http.response.body", "body": b"ok"})

    loop = asyncio.get_event_loop()
    worker = _build_worker(loop, app, "python")
    worker.log = Logger(worker.cfg)
    worker.cfg.set("accesslog", "-")
    worker.cfg.set("access_log_format", fmt)
    worker.cfg.set("access_log_redact", REDACT_FIELDS)
    worker.log.setup(worker.cfg)

    lines = []

    class _Capture(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Capture()
    worker.log.access_log.addHandler(handler)
    try:
        protocol = ASGIProtocol(worker)
        transport = _FakeTransport()
        protocol.connection_made(transport)
        protocol.data_received(RAW_REQUEST)
        for _ in range(50):
            await asyncio.sleep(0)
        if protocol._task and not protocol._task.done():
            protocol._task.cancel()
            try:
                await protocol._task
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        worker.log.access_log.removeHandler(handler)
    return lines, seen


def _wsgi_line(cfg, req, resp, environ):
    logger = Logger(cfg)
    lines = []

    class _Capture(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Capture()
    logger.access_log.addHandler(handler)
    try:
        logger.access(resp, req, environ,
                      datetime.timedelta(seconds=0, microseconds=1200))
    finally:
        logger.access_log.removeHandler(handler)
    return lines


class TestWSGIAccessLog:
    def test_standard_format_hides_selected_fields(self):
        cfg, req, resp, environ = _wsgi_access_line(STANDARD_FORMAT)
        line, = _wsgi_line(cfg, req, resp, environ)

        assert line.startswith('198.51.100.7 - [REDACTED] [')
        assert line.endswith(' "[REDACTED]" 200 3 "-" "-"')
        assert "dXNlcjpwYXNzd29yZA==" not in line

    def test_custom_format_hides_selected_fields(self):
        cfg, req, resp, environ = _wsgi_access_line(CUSTOM_FORMAT)
        line, = _wsgi_line(cfg, req, resp, environ)

        assert "id=7d3f9a2c" in line          # still useful for debugging
        assert "user=[REDACTED]" in line
        assert "auth=[REDACTED]" in line
        assert "key=[REDACTED]" in line
        assert "uri=[REDACTED]" in line
        assert "q=[REDACTED]" in line
        assert "SECRET-TOKEN" not in line
        assert "dXNlcjpwYXNzd29yZA==" not in line
        assert "k-live-9f8e7d" not in line

    def test_application_environ_is_unchanged(self):
        _, _, _, environ = _wsgi_access_line(CUSTOM_FORMAT)

        assert environ["HTTP_AUTHORIZATION"] == "Basic dXNlcjpwYXNzd29yZA=="
        assert environ["HTTP_X_API_KEY"] == "k-live-9f8e7d"
        assert environ["QUERY_STRING"] == "status=open&token=SECRET-TOKEN"
        assert environ["RAW_URI"].endswith("token=SECRET-TOKEN")

    def test_credential_headers_are_redacted_without_configuration(self):
        """A format naming a credential is redacted by default."""
        fmt = ('%( {cookie}i )s %( {authorization}i )s '
               '%( {x-api-key}i )s %( {set-cookie}o )s').replace(" ", "")
        cfg = Config()
        cfg.set("accesslog", "-")
        cfg.set("access_log_format", fmt)
        cfg.set("access_log_redact", [])
        req = _parse(RAW_REQUEST)
        resp, environ = wsgi_create(
            req, _Socket(), ("198.51.100.7", 40000),
            ("127.0.0.1", 8000), cfg)
        resp.status = "200 OK"
        resp.sent = 3
        resp.headers = [("Set-Cookie", "sessionid=abc123")]

        line, = _wsgi_line(cfg, req, resp, environ)
        assert "abc123" not in line
        assert "dXNlcjpwYXNzd29yZA==" not in line
        assert "k-live-9f8e7d" not in line
        assert line == REDACTED * 4

    def test_unselected_fields_are_untouched(self):
        fmt = ('%( {user-agent}i )s %( {referer}i )s '
               '%( {x-request-id}i )s').replace(" ", "")
        cfg, req, resp, environ = _wsgi_access_line(fmt)
        line, = _wsgi_line(cfg, req, resp, environ)
        assert "7d3f9a2c" in line

    def test_query_atom_redacts_the_whole_value_when_selected(self):
        cfg, req, resp, environ = _wsgi_access_line("%(q)s")
        line, = _wsgi_line(cfg, req, resp, environ)
        assert line == REDACTED

    def test_unselected_query_hides_only_credential_values(self):
        """A credential inside the query is hidden, the rest still helps."""
        cfg, _, _, _ = _wsgi_access_line("%(q)s")
        cfg.set("access_log_redact", [])
        req = _parse(RAW_REQUEST)
        resp, environ = wsgi_create(
            req, _Socket(), ("198.51.100.7", 40000),
            ("127.0.0.1", 8000), cfg)
        resp.status = "200 OK"
        resp.sent = 3
        line, = _wsgi_line(cfg, req, resp, environ)
        assert line == "status=open&token=" + REDACTED


class TestASGIAccessLog:
    @pytest.mark.asyncio
    async def test_standard_format_matches_the_wsgi_result(self):
        lines, _ = await _asgi_access_line(STANDARD_FORMAT)
        line, = lines
        assert line.startswith("127.0.0.1 - [REDACTED] [")
        assert '"[REDACTED]" 200 2' in line
        assert "SECRET-TOKEN" not in line

    @pytest.mark.asyncio
    async def test_custom_format_hides_selected_fields(self):
        lines, _ = await _asgi_access_line(CUSTOM_FORMAT)
        line, = lines
        assert "id=7d3f9a2c" in line
        assert "user=[REDACTED]" in line
        assert "auth=[REDACTED]" in line
        assert "key=[REDACTED]" in line
        assert "uri=[REDACTED]" in line
        assert "q=[REDACTED]" in line
        assert "SECRET-TOKEN" not in line

    @pytest.mark.asyncio
    async def test_application_scope_is_unchanged(self):
        _, scopes = await _asgi_access_line(CUSTOM_FORMAT)
        headers = dict(scopes[0]["headers"])
        assert headers[b"authorization"] == b"Basic dXNlcjpwYXNzd29yZA=="
        assert headers[b"x-api-key"] == b"k-live-9f8e7d"
        assert scopes[0]["query_string"] == b"status=open&token=SECRET-TOKEN"

    @pytest.mark.asyncio
    async def test_same_line_from_wsgi_and_asgi(self):
        """Both workers log the same request the same way."""
        wsgi_line, = _wsgi_line(*_wsgi_access_line(STANDARD_FORMAT))
        asgi_line, = (await _asgi_access_line(STANDARD_FORMAT))[0]
        # Only the client address and body length differ: the fake request
        # reaches the ASGI transport from 127.0.0.1 and the app answers two
        # bytes. Everything the policy controls is identical.
        wsgi_fields = wsgi_line.split(" ")
        asgi_fields = asgi_line.split(" ")
        assert wsgi_fields[2:5] == asgi_fields[2:5]
        assert wsgi_fields[5] == asgi_fields[5] == '"[REDACTED]"'
        assert wsgi_fields[6] == asgi_fields[6] == "200"
        assert wsgi_fields[8:] == asgi_fields[8:]


class TestHTTP2AccessLog:
    def test_http2_request_is_redacted_too(self):
        """HTTP/2 builds its own header list; the policy applies to it."""
        from gunicorn.http2.request import HTTP2Request
        from gunicorn.http2.stream import HTTP2Stream

        class _Connection:
            initial_window_size = 65535

        stream = HTTP2Stream(stream_id=1, connection=_Connection())
        stream.receive_headers([
            (":method", "GET"),
            (":path", "/orders/42?status=open&token=SECRET-TOKEN"),
            (":scheme", "https"),
            (":authority", "shop.example"),
            ("authorization", "Basic dXNlcjpwYXNzd29yZA=="),
            ("x-request-id", "7d3f9a2c"),
        ], end_stream=True)
        request = HTTP2Request(stream, Config(), ("198.51.100.7", 40000))

        cfg = Config()
        cfg.set("accesslog", "-")
        cfg.set("access_log_format", CUSTOM_FORMAT)
        cfg.set("access_log_redact", REDACT_FIELDS)
        environ = {
            "REQUEST_METHOD": request.method,
            "RAW_URI": request.uri,
            "PATH_INFO": request.path,
            "QUERY_STRING": request.query,
            "SERVER_PROTOCOL": "HTTP/2",
            "REMOTE_ADDR": "198.51.100.7",
        }
        for name, value in request.headers:
            environ["HTTP_" + name.replace("-", "_")] = value
        resp = _ASGIResponse()
        resp.headers = list(request.headers) + [("Set-Cookie", "a=b")]
        line, = _wsgi_line(cfg, request, resp, environ)

        assert "id=7d3f9a2c" in line
        assert "auth=[REDACTED]" in line
        assert "uri=[REDACTED]" in line
        assert "dXNlcjpwYXNzd29yZA==" not in line


class TestSetting:
    def test_atoms_and_names(self):
        assert validate_access_log_redaction("u,q") == ["u", "q"]
        assert validate_access_log_redaction(
            ["authorization", "x-api-key"]) == ["authorization", "x-api-key"]
        assert validate_access_log_redaction("{set-cookie}o") == [
            "{set-cookie}o"]

    def test_unknown_atom_is_refused(self):
        with pytest.raises(ValueError):
            validate_access_log_redaction("z")

    def test_empty(self):
        assert validate_access_log_redaction(None) == []
        assert validate_access_log_redaction("") == []

    def test_reload_rebuilds_the_policy(self):
        cfg = Config()
        cfg.set("accesslog", "-")
        logger = Logger(cfg)
        cfg.set("access_log_redact", ["q"])
        logger.setup(cfg)
        assert "q" in logger._access_log_redactor.atoms
