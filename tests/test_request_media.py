import io
import json

import pytest

import falcon
from falcon import errors
from falcon import media
from falcon import testing
from falcon import util
import falcon.asgi


@pytest.fixture(scope='session')
def msgpack():
    return pytest.importorskip('msgpack')


def create_client(asgi, handlers=None, resource=None):
    if not resource:
        resource = (
            testing.SimpleTestResourceAsync() if asgi else testing.SimpleTestResource()
        )

    app_cls = falcon.asgi.App if asgi else falcon.App
    app = app_cls()
    app.add_route('/', resource)

    if handlers:
        app.req_options.media_handlers.update(handlers)

    client = testing.TestClient(app, headers={'capture-req-media': 'yes'})
    client.resource = resource

    return client


@pytest.fixture()
def client(asgi):
    return create_client(asgi)


class ResourceCachedMedia:
    def on_post(self, req, resp, **kwargs):
        self.captured_req_media = req.media

        # NOTE(kgriffs): Ensure that the media object is cached
        assert self.captured_req_media is req.get_media()


class ResourceCachedMediaAsync:
    async def on_post(self, req, resp, **kwargs):
        self.captured_req_media = await req.get_media()

        # NOTE(kgriffs): Ensure that the media object is cached
        assert self.captured_req_media is await req.get_media()


class ResourceInvalidMedia:
    def __init__(self, expected_error):
        self._expected_error = expected_error

    def on_post(self, req, resp, **kwargs):
        with pytest.raises(self._expected_error) as error:
            req.media

        self.captured_error = error


class ResourceInvalidMediaAsync:
    def __init__(self, expected_error):
        self._expected_error = expected_error

    async def on_post(self, req, resp, **kwargs):
        with pytest.raises(self._expected_error) as error:
            await req.get_media()

        self.captured_error = error


@pytest.mark.parametrize(
    'media_type',
    [
        (None),
        ('*/*'),
        ('application/json'),
        ('application/json; charset=utf-8'),
    ],
)
def test_json(client, media_type):
    expected_body = b'{"something": true}'
    headers = {'Content-Type': media_type}
    client.simulate_post('/', body=expected_body, headers=headers)

    media = client.resource.captured_req_media
    assert media is not None
    assert media.get('something') is True


@pytest.mark.parametrize(
    'media_type',
    [
        ('application/msgpack'),
        ('application/msgpack; charset=utf-8'),
        ('application/x-msgpack'),
    ],
)
def test_msgpack(asgi, media_type, msgpack):
    client = create_client(
        asgi,
        {
            'application/msgpack': media.MessagePackHandler(),
            'application/x-msgpack': media.MessagePackHandler(),
        },
    )
    headers = {'Content-Type': media_type}

    # Bytes
    expected_body = b'\x81\xc4\tsomething\xc3'
    assert (
        client.simulate_post('/', body=expected_body, headers=headers).status_code
        == 200
    )

    req_media = client.resource.captured_req_media
    assert req_media.get(b'something') is True

    # Unicode
    expected_body = b'\x81\xa9something\xc3'
    assert (
        client.simulate_post('/', body=expected_body, headers=headers).status_code
        == 200
    )

    req_media = client.resource.captured_req_media
    assert req_media.get('something') is True


@pytest.mark.parametrize(
    'media_type',
    [
        ('nope/json'),
    ],
)
def test_unknown_media_type(asgi, media_type):
    client = _create_client_invalid_media(asgi, errors.HTTPUnsupportedMediaType)

    headers = {'Content-Type': media_type}
    assert (
        client.simulate_post('/', body=b'something', headers=headers).status_code == 200
    )

    title_msg = '415 Unsupported Media Type'
    description_msg = f'{media_type} is an unsupported media type.'
    assert client.resource.captured_error.value.title == title_msg
    assert client.resource.captured_error.value.description == description_msg


@pytest.mark.parametrize('media_type', ['application/json', 'application/msgpack'])
def test_empty_body(asgi, media_type, msgpack):
    client = _create_client_invalid_media(
        asgi,
        errors.HTTPBadRequest,
        {
            'application/msgpack': media.MessagePackHandler(),
            'application/json': media.JSONHandler(),
        },
    )
    headers = {'Content-Type': media_type}
    assert client.simulate_post('/', headers=headers).status_code == 200

    assert (
        'Could not parse an empty' in client.resource.captured_error.value.description
    )
    assert isinstance(client.resource.captured_error.value, errors.MediaNotFoundError)


def test_invalid_json(asgi):
    client = _create_client_invalid_media(asgi, errors.HTTPBadRequest)

    expected_body = '{'
    headers = {'Content-Type': 'application/json'}
    assert (
        client.simulate_post('/', body=expected_body, headers=headers).status_code
        == 200
    )

    assert (
        'Could not parse JSON body' in client.resource.captured_error.value.description
    )
    assert isinstance(client.resource.captured_error.value, errors.MediaMalformedError)

    try:
        json.loads(expected_body)
    except Exception as e:
        assert type(client.resource.captured_error.value.__cause__) is type(e)
        assert str(client.resource.captured_error.value.__cause__) == str(e)


def test_invalid_msgpack(asgi, msgpack):
    handlers = {'application/msgpack': media.MessagePackHandler()}
    client = _create_client_invalid_media(
        asgi, errors.HTTPBadRequest, handlers=handlers
    )

    expected_body = '/////////////////////'
    headers = {'Content-Type': 'application/msgpack'}
    assert (
        client.simulate_post('/', body=expected_body, headers=headers).status_code
        == 200
    )

    desc = 'Could not parse MessagePack body - unpack(b) received extra data.'
    assert client.resource.captured_error.value.description == desc
    assert isinstance(client.resource.captured_error.value, errors.MediaMalformedError)

    try:
        msgpack.unpackb(expected_body.encode('utf-8'))
    except Exception as e:
        assert type(client.resource.captured_error.value.__cause__) is type(e)
        assert str(client.resource.captured_error.value.__cause__) == str(e)


class NopeHandler(media.BaseHandler):
    def serialize(self, *args, **kwargs):
        pass

    def deserialize(self, *args, **kwargs):
        pass

    exhaust_stream = True


def test_complete_consumption(asgi):
    client = create_client(asgi, {'nope/nope': NopeHandler()})
    body = b'{"something": "abracadabra"}'
    headers = {'Content-Type': 'nope/nope'}

    assert client.simulate_post('/', body=body, headers=headers).status_code == 200

    req_media = client.resource.captured_req_media
    assert req_media is None
    req_bounded_stream = client.resource.captured_req.bounded_stream
    assert req_bounded_stream.eof


@pytest.mark.parametrize('payload', [False, 0, 0.0, '', [], {}])
def test_empty_json_media(asgi, payload):
    resource = ResourceCachedMediaAsync() if asgi else ResourceCachedMedia()
    client = create_client(asgi, resource=resource)
    assert client.simulate_post('/', json=payload).status_code == 200
    assert resource.captured_req_media == payload


def test_null_json_media(client):
    assert (
        client.simulate_post(
            '/', body='null', headers={'Content-Type': 'application/json'}
        ).status_code
        == 200
    )
    assert client.resource.captured_req_media is None


def _create_client_invalid_media(asgi, error_type, handlers=None):
    resource_type = ResourceInvalidMediaAsync if asgi else ResourceInvalidMedia
    resource = resource_type(error_type)
    return create_client(asgi, handlers=handlers, resource=resource)


class FallBack:
    def on_get(self, req, res):
        res.media = req.get_media('fallback')


class FallBackAsync:
    async def on_get(self, req, res):
        res.media = await req.get_media('fallback')


def test_fallback(asgi):
    client = create_client(asgi, resource=FallBackAsync() if asgi else FallBack())

    res = client.simulate_get('/')
    assert res.status_code == 200
    assert res.json == 'fallback'


@pytest.mark.parametrize('exhaust_stream', (True, False))
@pytest.mark.parametrize('body', (True, False))
def test_fallback_not_for_error_body(asgi, exhaust_stream, body):
    js = media.JSONHandler()
    js.exhaust_stream = exhaust_stream
    client = create_client(
        asgi,
        resource=FallBackAsync() if asgi else FallBack(),
        handlers={
            'application/json': js,
        },
    )

    res = client.simulate_get('/', body=b'{' if body else '')
    if body:
        assert res.status_code == 400
        assert 'Could not parse JSON body' in res.json['description']
    else:
        assert res.status_code == 200


def test_fallback_does_not_override_media_default(asgi):
    client = create_client(asgi, resource=FallBackAsync() if asgi else FallBack())

    res = client.simulate_get(
        '/', headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert res.status_code == 200
    assert res.text == '{}'


async def _check_error(req, isasync):
    err, err2 = None, None
    try:
        (await req.media) if isasync else req.media
    except Exception as e:
        err = e
    try:
        (await req.get_media()) if isasync else req.get_media()
    except Exception as e:
        err2 = e
    assert err is not None
    assert err2 is not None
    assert err2 is err
    if isinstance(err, errors.MediaMalformedError):
        assert err2.__cause__ is err.__cause__
    obj = {}
    if req.get_param_as_bool('empty'):
        # default_when_empty is not cached
        res = (await req.get_media(obj)) if isasync else req.get_media(obj)
        assert res is obj
        err3 = None
        try:
            ((await req.media) if isasync else req.media) is obj
        except Exception as e:
            err3 = e
        assert err3 is err
    else:
        err3 = None
        try:
            (await req.get_media(obj)) if isasync else req.get_media(obj)
        except Exception as e:
            err3 = e
        assert err3 is err
    raise errors.HTTPError(falcon.HTTP_IM_A_TEAPOT)


class RepeatedError:
    def on_get(self, req, resp):
        util.async_to_sync(_check_error, req, False)


class RepeatedErrorAsync:
    async def on_get(self, req, resp):
        await _check_error(req, True)


@pytest.mark.parametrize('body', ('{', ''))
def test_repeated_error(asgi, body):
    client = create_client(
        asgi, resource=RepeatedErrorAsync() if asgi else RepeatedError()
    )

    res = client.simulate_get('/', body=body, params={'empty': not bool(body)})
    assert res.status == falcon.HTTP_IM_A_TEAPOT


def test_error_after_first_default(asgi):
    async def _check_error(req, isasync):
        assert (await req.get_media(42)) if isasync else req.get_media(42) == 42
        try:
            (await req.get_media()) if isasync else req.get_media()
        except falcon.MediaNotFoundError:
            raise falcon.HTTPStatus(falcon.HTTP_749)
        raise falcon.HTTPStatus(falcon.HTTP_703)

    class Res:
        def on_get(self, req, resp):
            util.async_to_sync(_check_error, req, False)

    class ResAsync:
        async def on_get(self, req, resp):
            await _check_error(req, True)

    client = create_client(asgi, resource=ResAsync() if asgi else Res())

    res = client.simulate_get('/', body='')
    assert res.status == falcon.HTTP_749


# ---------------------------------------------------------------------------
# Raw body verification boundary (get_raw_body + replay to media handlers)
# ---------------------------------------------------------------------------

_CALLBACK_BODY = b'{"event": "payment.succeeded", "amount": 100}'
_CALLBACK_MEDIA = {'event': 'payment.succeeded', 'amount': 100}


class _RecordingJSONHandler(media.JSONHandler):
    """JSON handler that records the exact bytes it receives."""

    def __init__(self):
        super().__init__()
        self.deserialize_calls = 0
        self.received = []

    def deserialize(self, stream, content_type, content_length):
        self.deserialize_calls += 1
        data = stream.read()
        self.received.append(data)
        return super().deserialize(io.BytesIO(data), content_type, content_length)

    async def deserialize_async(self, stream, content_type, content_length):
        self.deserialize_calls += 1
        data = await stream.read()
        self.received.append(data)
        return self._deserialize(data)


class _CallbackResource:
    def __init__(self):
        self.invocations = 0
        self.media_calls = 0
        self.raw_body = None
        self.media = None
        self.error = None

    def on_post(self, req, resp):
        self.invocations += 1
        self.raw_body = req.get_raw_body()
        self.media_calls += 1
        self.media = req.get_media()
        resp.media = {'ok': True}


class _CallbackResourceAsync:
    def __init__(self):
        self.invocations = 0
        self.media_calls = 0
        self.raw_body = None
        self.media = None
        self.error = None

    async def on_post(self, req, resp):
        self.invocations += 1
        self.raw_body = await req.get_raw_body()
        self.media_calls += 1
        self.media = await req.get_media()
        resp.media = {'ok': True}


class _BodyInspectingMiddleware:
    """Verify the raw body before the responder and media handler run."""

    def __init__(self, seen):
        self._seen = seen

    def process_request(self, req, resp):
        self._seen['body'] = req.get_raw_body()

    async def process_request_async(self, req, resp):
        self._seen['body'] = await req.get_raw_body()


class _FailingBodyInspectingMiddleware:
    """A verification step that records and propagates the failure."""

    def __init__(self, seen):
        self._seen = seen

    def process_request(self, req, resp):
        try:
            self._seen['body'] = req.get_raw_body()
        except Exception as ex:
            self._seen['error'] = ex
            raise

    async def process_request_async(self, req, resp):
        try:
            self._seen['body'] = await req.get_raw_body()
        except Exception as ex:
            self._seen['error'] = ex
            raise


def _create_callback_client(asgi, handler, middleware=None, resource=None):
    if resource is None:
        resource = _CallbackResourceAsync() if asgi else _CallbackResource()

    app = (
        falcon.asgi.App(middleware=middleware or [])
        if asgi
        else falcon.App(middleware=middleware or [])
    )
    app.add_route('/callback', resource)
    app.req_options.media_handlers[falcon.MEDIA_JSON] = handler

    client = testing.TestClient(app)
    client.resource = resource

    return client, handler


def _post_callback(client, body=_CALLBACK_BODY, **kwargs):
    headers = kwargs.pop('headers', {})
    headers.setdefault('Content-Type', falcon.MEDIA_JSON)
    return client.simulate_post('/callback', body=body, headers=headers, **kwargs)


@pytest.mark.parametrize('use_middleware', [False, True])
def test_raw_body_is_replayed_to_media_handler(asgi, use_middleware):
    handler = _RecordingJSONHandler()
    seen = {}
    middleware = [_BodyInspectingMiddleware(seen)] if use_middleware else None

    client, handler = _create_callback_client(asgi, handler, middleware=middleware)
    res = _post_callback(client)

    assert res.status_code == 200
    assert res.json == {'ok': True}

    resource = client.resource
    assert resource.invocations == 1
    assert resource.media_calls == 1
    assert resource.raw_body == _CALLBACK_BODY
    assert resource.media == _CALLBACK_MEDIA

    if use_middleware:
        assert seen['body'] == _CALLBACK_BODY

    # The exact bytes that were verified are the bytes that reached the media
    # handler, and the handler only ran once.
    assert handler.deserialize_calls == 1
    assert handler.received == [_CALLBACK_BODY]


def test_bounded_stream_replays_raw_body():
    class Resource:
        def on_post(self, req, resp):
            assert req.bounded_stream.read() == _CALLBACK_BODY
            resp.media = {'ok': True}

    handler = _RecordingJSONHandler()
    seen = {}
    client, handler = _create_callback_client(
        False,
        handler,
        middleware=[_BodyInspectingMiddleware(seen)],
        resource=Resource(),
    )

    res = _post_callback(client)

    assert res.status_code == 200
    assert seen['body'] == _CALLBACK_BODY
    assert handler.deserialize_calls == 0


def test_raw_body_too_large(asgi):
    handler = _RecordingJSONHandler()
    seen = {}
    client, handler = _create_callback_client(
        asgi,
        handler,
        middleware=[_FailingBodyInspectingMiddleware(seen)],
    )
    client.app.req_options.max_body_size = 4

    res = _post_callback(client)

    assert res.status_code == 413
    assert isinstance(seen['error'], falcon.RequestBodyTooLarge)
    # The size check fails before the responder or media handler is invoked.
    assert handler.deserialize_calls == 0
    assert client.resource.invocations == 0


def test_raw_body_interrupted_wsgi():
    env = testing.create_environ(
        method='POST',
        body=b'{"event"',
        headers={'Content-Length': str(len(_CALLBACK_BODY))},
    )
    req = falcon.Request(env)

    with pytest.raises(falcon.RequestBodyIncomplete) as error:
        req.get_raw_body()

    assert error.value.bytes_received == len(b'{"event"')
    # A partial body is never cached.
    assert req._raw_body is None


def test_raw_body_interrupted_asgi():
    scope = testing.create_scope(method='POST', content_length=len(_CALLBACK_BODY))
    emitter = testing.ASGIRequestEventEmitter(b'{"event"', disconnect_at=0)
    req = falcon.asgi.Request(scope, emitter)

    with pytest.raises(falcon.RequestBodyIncomplete):
        falcon.async_to_sync(req.get_raw_body)

    assert req._raw_body is None


def test_raw_body_interrupted_never_reaches_handler(asgi):
    handler = _RecordingJSONHandler()
    seen = {}

    # Build the same synthetic, truncated source request for both entries: the
    # body delivers only a prefix of what Content-Length promises.
    if asgi:
        scope = testing.create_scope(method='POST', content_length=len(_CALLBACK_BODY))
        emitter = testing.ASGIRequestEventEmitter(_CALLBACK_BODY[:8], disconnect_at=0)
        req = falcon.asgi.Request(scope, emitter)
    else:
        env = testing.create_environ(
            method='POST',
            body=_CALLBACK_BODY[:8],
            headers={'Content-Length': str(len(_CALLBACK_BODY))},
        )
        req = falcon.Request(env)
    req.options.media_handlers[falcon.MEDIA_JSON] = handler

    try:
        if asgi:
            seen['body'] = falcon.async_to_sync(req.get_raw_body)
        else:
            seen['body'] = req.get_raw_body()
    except Exception as ex:
        seen['error'] = ex

    assert isinstance(seen['error'], falcon.RequestBodyIncomplete)
    # Verification never completed, so the media handler must not have run.
    assert handler.deserialize_calls == 0
    # And the request must not expose any cached (partial) body or media.
    assert req._raw_body is None


def test_raw_body_after_media_is_refused(asgi):
    """get_raw_body() must not pretend an already-consumed body is available."""

    req = _create_request_from_body(asgi, _CALLBACK_BODY, falcon.MEDIA_JSON)
    req.options.media_handlers[falcon.MEDIA_JSON] = media.JSONHandler()

    if asgi:
        assert falcon.async_to_sync(req.get_media) == _CALLBACK_MEDIA
    else:
        assert req.get_media() == _CALLBACK_MEDIA

    with pytest.raises(falcon.OperationNotAllowed):
        if asgi:
            falcon.async_to_sync(req.get_raw_body)
        else:
            req.get_raw_body()

    assert req._raw_body is None


def _create_request_from_body(asgi, body, content_type):
    length = len(body)
    if asgi:
        scope = testing.create_scope(method='POST', content_length=length)
        emitter = testing.ASGIRequestEventEmitter(body)
        return falcon.asgi.Request(scope, emitter)

    return falcon.Request(
        testing.create_environ(
            method='POST', body=body, headers={'Content-Length': str(length)}
        )
    )


def test_raw_body_empty(asgi):
    handler = _RecordingJSONHandler()
    client, handler = _create_callback_client(asgi, handler)

    res = client.simulate_post('/callback', body=b'')
    # Empty body -> the JSON handler reports a 400 as usual.
    assert res.status_code == 400
    assert client.resource.raw_body == b''
    assert handler.received == [b'']


def test_raw_body_unlimited_size(asgi):
    handler = _RecordingJSONHandler()
    client, handler = _create_callback_client(asgi, handler)
    client.app.req_options.max_body_size = 0

    res = _post_callback(client)

    assert res.status_code == 200
    assert handler.received == [_CALLBACK_BODY]


def test_raw_body_too_large_end_to_end(asgi):
    """Exercise the 413 emitted by the default error handler."""

    class Resource:
        def on_post(self, req, resp):
            resp.media = {'len': len(req.get_raw_body())}

    class ResourceAsync:
        async def on_post(self, req, resp):
            resp.media = {'len': len(await req.get_raw_body())}

    app = falcon.asgi.App() if asgi else falcon.App()
    app.req_options.max_body_size = 4
    app.add_route('/callback', ResourceAsync() if asgi else Resource())

    res = _post_callback(testing.TestClient(app))

    assert res.status_code == 413
    assert 'exceeds the configured maximum size' in res.json['description']


def test_raw_body_interrupted_end_to_end():
    """A truncated body must fail closed with a 400, not reach the handler.

    This source-level interruption can only be simulated for WSGI via a
    handcrafted environ (the ASGI test client derives Content-Length from
    the body, so see test_raw_body_interrupted_asgi for the async entry).
    """

    class Resource:
        def on_post(self, req, resp):
            resp.media = {'len': len(req.get_raw_body())}

    app = falcon.App()
    app.add_route('/callback', Resource())

    res = _post_callback(
        testing.TestClient(app),
        body=_CALLBACK_BODY[:8],
        headers={'Content-Length': str(len(_CALLBACK_BODY))},
    )

    assert res.status_code == 400
    assert 'interrupted' in res.json['description']


def test_raw_body_larger_than_content_length(asgi):
    """A stream that yields more bytes than Content-Length is not trusted."""

    body = b'{"a": 1}'
    req = _create_request_from_body(asgi, body, falcon.MEDIA_JSON)
    req.options.max_body_size = 4

    with pytest.raises(falcon.RequestBodyTooLarge):
        if asgi:
            falcon.async_to_sync(req.get_raw_body)
        else:
            req.get_raw_body()

    assert req._raw_body is None


def test_get_raw_body_cached(asgi):
    req = _create_request_from_body(asgi, _CALLBACK_BODY, falcon.MEDIA_JSON)
    req.options.media_handlers[falcon.MEDIA_JSON] = media.JSONHandler()

    if asgi:
        assert falcon.async_to_sync(req.get_raw_body) == _CALLBACK_BODY
        assert falcon.async_to_sync(req.get_raw_body) == _CALLBACK_BODY
    else:
        assert req.get_raw_body() == _CALLBACK_BODY
        assert req.get_raw_body() == _CALLBACK_BODY

    assert req._raw_body == _CALLBACK_BODY


def test_raw_body_too_large_unknown_length():
    """A chunked ASGI upload without Content-Length is also capped."""

    scope = testing.create_scope(method='POST')
    emitter = testing.ASGIRequestEventEmitter(_CALLBACK_BODY)
    req = falcon.asgi.Request(scope, emitter)
    req.options.max_body_size = 4

    with pytest.raises(falcon.RequestBodyTooLarge):
        falcon.async_to_sync(req.get_raw_body)

    assert req._raw_body is None


def test_replay_stream_interface():
    """Exercise the ASGI replay stream used after get_raw_body()."""

    def make(body):
        return falcon.asgi.Request(
            testing.create_scope(method='POST', content_length=len(body)),
            testing.ASGIRequestEventEmitter(body),
        )

    async def replay_stream(body):
        req = make(body)
        await req.get_raw_body()
        return req.stream

    stream = falcon.async_to_sync(replay_stream, b'abcdef')
    assert stream.readable()
    assert not stream.writable()
    assert not stream.seekable()
    assert not stream.isatty()
    assert not stream.closed
    assert falcon.async_to_sync(stream.read, 0) == b''
    assert falcon.async_to_sync(stream.read, 2) == b'ab'
    assert falcon.async_to_sync(stream.read, 2) == b'cd'
    assert falcon.async_to_sync(stream.readall) == b'ef'
    assert falcon.async_to_sync(stream.read) == b''
    assert stream.eof

    stream = falcon.async_to_sync(replay_stream, b'123')
    assert falcon.async_to_sync(_collect_async, stream) == b'123'

    stream = falcon.async_to_sync(replay_stream, b'xyz')
    falcon.async_to_sync(stream.exhaust)
    assert stream.eof
    assert falcon.async_to_sync(stream.read) == b''

    stream.close()
    assert stream.closed
    with pytest.raises(ValueError):
        falcon.async_to_sync(stream.read)


async def _collect_async(stream):
    chunks = [chunk async for chunk in stream]
    return b''.join(chunks)


def test_replay_stream_single_iteration():
    async def setup():
        req = falcon.asgi.Request(
            testing.create_scope(method='POST', content_length=3),
            testing.ASGIRequestEventEmitter(b'abc'),
        )
        await req.get_raw_body()
        return req.stream

    stream = falcon.async_to_sync(setup)
    assert falcon.async_to_sync(_collect_async, stream) == b'abc'


def test_replay_stream_empty():
    async def setup():
        req = falcon.asgi.Request(
            testing.create_scope(method='POST', content_length=0),
            testing.ASGIRequestEventEmitter(b''),
        )
        await req.get_raw_body()
        return req.stream

    # An empty stream yields no chunk at all.
    stream = falcon.async_to_sync(setup)
    assert falcon.async_to_sync(_collect_async, stream) == b''


def test_raw_body_unsupported_for_websocket():
    scope = testing.create_scope_ws()
    emitter = testing.ASGIRequestEventEmitter(b'')
    req = falcon.asgi.Request(scope, emitter)

    with pytest.raises(falcon.UnsupportedError):
        falcon.async_to_sync(req.get_raw_body)


class _ShortReadStream:
    """A WSGI input stream that returns at most `chunk` bytes per read()."""

    def __init__(self, data, chunk):
        self._data = data
        self._chunk = chunk
        self._pos = 0

    def read(self, size=-1):
        end = min(self._pos + self._chunk, len(self._data))
        data = self._data[self._pos : end]
        self._pos = end
        return data


def test_raw_body_short_reads_are_assembled():
    """Short reads (common with buffered WSGI inputs) must not look truncated."""

    env = testing.create_environ(method='POST', body=_CALLBACK_BODY)
    env['wsgi.input'] = _ShortReadStream(_CALLBACK_BODY, 3)
    env['CONTENT_LENGTH'] = str(len(_CALLBACK_BODY))

    req = falcon.Request(env)
    assert req.get_raw_body() == _CALLBACK_BODY

    # And the assembled bytes are what the media handler subsequently sees.
    assert req.get_media() == _CALLBACK_MEDIA


def test_raw_body_after_partial_stream_read_fails_closed(asgi):
    """A partial prior read must not yield a silently truncated raw body."""

    req = _create_request_from_body(asgi, _CALLBACK_BODY, falcon.MEDIA_JSON)

    if asgi:

        async def consume_then_read_raw():
            await req.stream.read(2)
            with pytest.raises(falcon.RequestBodyIncomplete):
                await req.get_raw_body()

        falcon.async_to_sync(consume_then_read_raw)
    else:
        req.bounded_stream.read(2)
        with pytest.raises(falcon.RequestBodyIncomplete):
            req.get_raw_body()

    assert req._raw_body is None


def test_raw_body_with_preloaded_first_event():
    """Real ASGI apps preload the first event; that must not break buffering."""

    body = b'{"a": 1}'
    scope = testing.create_scope(method='POST', content_length=len(body))
    emitter = testing.ASGIRequestEventEmitter(b'')
    req = falcon.asgi.Request(
        scope,
        emitter,
        first_event={'type': 'http.request', 'body': body, 'more_body': False},
    )

    assert falcon.async_to_sync(req.get_raw_body) == body


def test_callback_signature_boundary_same_request_both_entries(asgi):
    """Verify the raw body, then deserialize the exact same bytes.

    The same synthetic request is exercised against the WSGI and ASGI entries;
    a valid signature lets the verified bytes through to the media handler,
    while a bad signature never invokes the handler.
    """

    import hashlib
    import hmac

    secret = b'super-secret'

    def verify(raw, signature):
        expected = hmac.new(secret, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature or ''):
            raise falcon.HTTPUnauthorized(description='invalid signature')

    received = []

    class RecordingJSON(media.JSONHandler):
        def deserialize(self, stream, content_type, content_length):
            data = stream.read()
            received.append(data)
            return super().deserialize(io.BytesIO(data), content_type, content_length)

        async def deserialize_async(self, stream, content_type, content_length):
            data = await stream.read()
            received.append(data)
            return self._deserialize(data)

    class Middleware:
        def process_request(self, req, resp):
            verify(req.get_raw_body(), req.get_header('X-Signature'))

        async def process_request_async(self, req, resp):
            verify(await req.get_raw_body(), req.get_header('X-Signature'))

    class Resource:
        def on_post(self, req, resp):
            resp.media = {'media': req.get_media()}

    class ResourceAsync:
        async def on_post(self, req, resp):
            resp.media = {'media': await req.get_media()}

    app = (
        falcon.asgi.App(middleware=[Middleware()])
        if asgi
        else falcon.App(middleware=[Middleware()])
    )
    app.add_route('/callback', ResourceAsync() if asgi else Resource())
    app.req_options.media_handlers[falcon.MEDIA_JSON] = RecordingJSON()
    client = testing.TestClient(app)

    signature = hmac.new(secret, _CALLBACK_BODY, hashlib.sha256).hexdigest()
    res = client.simulate_post(
        '/callback',
        body=_CALLBACK_BODY,
        headers={
            'Content-Type': falcon.MEDIA_JSON,
            'X-Signature': signature,
        },
    )

    assert res.status_code == 200
    assert res.json == {'media': _CALLBACK_MEDIA}
    # Exactly the verified bytes reached the handler, exactly once.
    assert received == [_CALLBACK_BODY]

    # A bad signature fails closed before the handler is invoked.
    res = client.simulate_post(
        '/callback',
        body=_CALLBACK_BODY,
        headers={
            'Content-Type': falcon.MEDIA_JSON,
            'X-Signature': 'deadbeef',
        },
    )

    assert res.status_code == 401
    assert received == [_CALLBACK_BODY]
