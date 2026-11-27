"""Regression coverage for sensitive data disclosure via error responses.

Customer tickets may arrive with a Falcon error response attached, so the
body and headers rendered to the client must never echo internal data that
was embedded in an exception message. The same fictional contact detail is
deliberately placed in each distinct place a request can fail:

1. the request body parsed by a custom media handler, and the
   :class:`~falcon.MediaMalformedError` raised while parsing JSON;
2. the response media serializer invoked while rendering the body; and
3. the custom error serializer invoked after a public error was generated.

The public response keeps a valid media type and a stable, locatable error
classification, while the full details remain observable through the
internal error reporter. Both the WSGI and ASGI request paths are covered.
"""

import io
import json

import pytest

import falcon
from falcon import media
from falcon import testing


SECRET_CONTACT = 's3cr3t-contact-555-0199'
CUSTOM_MEDIA_TYPE = 'application/x-falcon-disclosure-test'


class ReportCollector:
    """Record every exception observed through the internal error reporter."""

    def __init__(self):
        self.log = []

    def report(self, req, ex, params, handled):
        self.log.append((ex, handled))

    def types(self):
        return [type(entry[0]) for entry in self.log]

    def messages(self):
        return [str(entry[0]) for entry in self.log]


class DisclosureMediaError(Exception):
    """Generic parse error that is not an :class:`~falcon.HTTPError`."""


class LeakyRequestHandler(media.BaseHandler):
    """Media handler whose parse failure quotes the raw request body."""

    exhaust_stream = False

    def _fail(self, raw):
        raise DisclosureMediaError(
            f'malformed {CUSTOM_MEDIA_TYPE} payload {raw!r}; '
            f'contact {SECRET_CONTACT}'
        )

    def deserialize(self, stream, content_type, content_length):
        self._fail(stream.read())

    async def deserialize_async(self, stream, content_type, content_length):
        self._fail(await stream.read())

    def serialize(self, value, content_type=None):
        return json.dumps(value).encode()


class LeakyResponseHandler(media.BaseHandler):
    """Media handler whose response serializer raises while rendering."""

    exhaust_stream = False

    def deserialize(self, stream, content_type, content_length):
        return {}

    async def deserialize_async(self, stream, content_type, content_length):
        return {}

    def serialize(self, value, content_type=None):
        raise RuntimeError(
            f'cannot render response for {value!r}; contact {SECRET_CONTACT}'
        )

    async def serialize_async(self, value, content_type=None):
        self.serialize(value, content_type)


class ErrorSerializerFailure(Exception):
    """Raised by the custom error serializer while rendering a public error."""


def make_leaky_error_serializer():
    def serialize_error(req, resp, ex):
        raise ErrorSerializerFailure(
            f'error serializer failed for {ex!r}; contact {SECRET_CONTACT}'
        )

    return serialize_error


class ParseResource:
    def on_post(self, req, resp):
        req.media


class ParseResourceAsync:
    async def on_post(self, req, resp):
        await req.media


class RenderResource:
    def on_get(self, req, resp):
        resp.content_type = CUSTOM_MEDIA_TYPE
        resp.media = {'answer': 42}


class RenderResourceAsync:
    async def on_get(self, req, resp):
        resp.content_type = CUSTOM_MEDIA_TYPE
        resp.media = {'answer': 42}


def build_app(asgi, util):
    app = util.create_app(asgi)
    app.req_options.media_handlers[CUSTOM_MEDIA_TYPE] = LeakyRequestHandler()
    app.resp_options.media_handlers[CUSTOM_MEDIA_TYPE] = LeakyResponseHandler()
    app.add_route('/parse', ParseResourceAsync() if asgi else ParseResource())
    app.add_route('/render', RenderResourceAsync() if asgi else RenderResource())

    collector = ReportCollector()
    app.set_error_reporter(collector.report)
    return app, collector


@pytest.fixture()
def client(asgi, util):
    app, collector = build_app(asgi, util)
    test_client = testing.TestClient(app)
    test_client.collector = collector
    return test_client


def assert_no_secret_in_public_response(result):
    assert SECRET_CONTACT.encode() not in result.content
    for value in result.headers.values():
        assert SECRET_CONTACT not in value


def assert_json_content_type(result):
    assert (
        falcon.parse_header(result.headers['content-type'])[0] == falcon.MEDIA_JSON
    )


def adapt_handler(asgi, app, exception_type, handler):
    """Register a sync handler, or an async wrapper for the ASGI app."""
    if not asgi:
        app.add_error_handler(exception_type, handler)
        return

    async def handler_async(req, resp, ex, params):
        handler(req, resp, ex, params)

    app.add_error_handler(exception_type, handler_async)


class TestRequestBodyParseDisclosure:
    """Point 1: failures while parsing the request body."""

    def test_custom_media_handler_parse_error_is_not_disclosed(self, client):
        result = client.simulate_post(
            '/parse',
            headers={'Content-Type': CUSTOM_MEDIA_TYPE},
            body=b'not-a-valid-payload',
        )

        assert result.status_code == 500
        assert_json_content_type(result)
        assert_no_secret_in_public_response(result)

        # The generic 500 keeps a stable classification instead of echoing
        # the raw parser message.
        assert result.json == {'title': '500 Internal Server Error'}

        log = client.collector
        assert log.types() == [DisclosureMediaError]
        assert log.log[0][1] is True
        assert SECRET_CONTACT in log.messages()[0]

    def test_malformed_json_error_is_classified_without_body_echo(self, client):
        body = '{' + f'"contact": "{SECRET_CONTACT}"'
        result = client.simulate_post(
            '/parse',
            headers={'Content-Type': falcon.MEDIA_JSON},
            body=body,
        )

        assert result.status_code == 400
        assert_json_content_type(result)
        assert_no_secret_in_public_response(result)

        payload = result.json
        assert payload['title'] == 'Invalid JSON'
        assert payload['description'].startswith('Could not parse JSON body')
        # Parser diagnostics reference positions, never the raw document.
        assert SECRET_CONTACT not in payload['description']
        assert body not in payload['description']

        log = client.collector
        assert log.types() == [falcon.MediaMalformedError]
        assert log.log[0][1] is True

    def test_malformed_json_reporter_keeps_full_cause(self, client):
        result = client.simulate_post(
            '/parse',
            headers={'Content-Type': falcon.MEDIA_JSON},
            body='{broken-json',
        )
        assert result.status_code == 400

        reported = client.collector.log[0][0]
        assert isinstance(reported, falcon.MediaMalformedError)
        assert isinstance(reported.__cause__, json.JSONDecodeError)


class TestResponseBodyRenderDisclosure:
    """Point 2: failures while rendering the response body.

    Rendering happens after the responder returns and re-enters the exception
    handling, so a double that only sanitizes the first-level exception is not
    sufficient. The safe handler keeps the re-entrant pass equally clean.
    """

    def test_default_render_failure_uses_clean_fallback(self, client):
        result = client.simulate_get('/render')

        assert result.status_code == 500
        assert_json_content_type(result)
        assert_no_secret_in_public_response(result)

        log = client.collector
        assert log.types() == [RuntimeError]
        # The re-entrant handler rendered a response, so it is handled.
        assert log.log[0][1] is True
        assert SECRET_CONTACT in log.messages()[0]

    def test_safe_reentrant_handler_keeps_render_failure_internal(
        self, asgi, util
    ):
        app, collector = build_app(asgi, util)

        def handle_runtime_error(req, resp, ex, params):
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_JSON

        adapt_handler(asgi, app, RuntimeError, handle_runtime_error)

        result = testing.TestClient(app).simulate_get('/render')

        assert result.status_code == 500
        assert_no_secret_in_public_response(result)
        assert collector.types() == [RuntimeError]
        assert collector.log[0][1] is True
        assert SECRET_CONTACT in collector.messages()[0]

    def test_shallow_first_level_double_is_caught(self, asgi, util):
        # The double sanitizes the responder's exception but forgets the
        # re-entrant render-failure pass, copying the message into a header.
        # The disclosure regression assertion must catch that.
        app, collector = build_app(asgi, util)

        def shallow_handle_runtime_error(req, resp, ex, params):
            resp.set_header('X-Debug-Detail', str(ex))
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_JSON

        adapt_handler(asgi, app, RuntimeError, shallow_handle_runtime_error)

        result = testing.TestClient(app).simulate_get('/render')

        assert result.status_code == 500
        assert SECRET_CONTACT in result.headers['x-debug-detail']
        with pytest.raises(AssertionError):
            assert_no_secret_in_public_response(result)
        assert collector.types() == [RuntimeError]
        assert SECRET_CONTACT in collector.messages()[0]


class TestErrorSerializerDisclosure:
    """Point 3: the error serializer fails after a public error is generated.

    The body parse failure first produces an :class:`~falcon.HTTPError`. When
    the configured error serializer itself raises, no response can be rendered,
    so the new exception is reported as unhandled and bubbles up to the
    application server rather than reaching a public header or body. The
    internal reporter still observes the complete exception chain.
    """

    def _install_classified_http_error_handler(self, asgi, app):
        def handle_http_error(req, resp, ex, params):
            # First level: convert the parse error into a clean, locatable
            # public error that never quotes the request body.
            raise falcon.HTTPInternalServerError(
                title='Internal Server Error',
                description='The request could not be processed.',
            )

        adapt_handler(asgi, app, falcon.HTTPError, handle_http_error)

    def test_failing_error_serializer_bubbles_up_and_stays_internal(
        self, asgi, util
    ):
        app, collector = build_app(asgi, util)
        app.set_error_serializer(make_leaky_error_serializer())
        self._install_classified_http_error_handler(asgi, app)

        wsgierrors = io.StringIO()
        with pytest.raises(ErrorSerializerFailure) as exc_info:
            falcon.testing.simulate_post(
                app,
                '/parse',
                headers={'Content-Type': falcon.MEDIA_JSON},
                body='{malformed-json',
                wsgierrors=wsgierrors,
            )

        # The serializer exception reaches the app server, not a public body,
        # and the detail it carries is confined to the internal record.
        assert SECRET_CONTACT in str(exc_info.value)
        assert wsgierrors.getvalue() == ''
        assert collector.types() == [
            falcon.MediaMalformedError,
            falcon.HTTPInternalServerError,
            ErrorSerializerFailure,
        ]
        assert all(handled is False for _, handled in collector.log)
        assert any(SECRET_CONTACT in m for m in collector.messages())

    def test_shallow_first_level_sanitizer_still_gets_caught(self, asgi, util):
        # The double scrubs the HTTPError it is registered for, but the
        # serializer exception still escapes. Nothing public may carry it.
        app, collector = build_app(asgi, util)
        app.set_error_serializer(make_leaky_error_serializer())
        self._install_classified_http_error_handler(asgi, app)

        with pytest.raises(ErrorSerializerFailure):
            falcon.testing.simulate_post(
                app,
                '/parse',
                headers={'Content-Type': falcon.MEDIA_JSON},
                body='{malformed-json',
            )

        assert collector.types()[-1] is ErrorSerializerFailure
        assert collector.log[-1][1] is False
        assert SECRET_CONTACT in collector.messages()[-1]
