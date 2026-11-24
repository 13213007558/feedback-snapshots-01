"""Failure-path body budget: bounded reads, shared retries, streamed success.

The local fake below is the interleaved response stand-in.  A scripted list of
responses is fed through the real client/endpoint/parser stack; each response
records the bytes the client actually pulled and whether its connection was
closed (truncated) or released (complete).  One test wires an oversized error
followed by a long successful stream for the same call; another proves the
retry cannot mint a fresh allowance; the rest cover the safe edges.
"""

from __future__ import annotations

import aiohttp
import pytest
from botocore.exceptions import ClientError, ParamValidationError

from aiobotocore._errorbody import ErrorBodyBudget
from aiobotocore.awsrequest import AioAWSResponse, HttpxAWSResponse
from aiobotocore.config import AioConfig
from aiobotocore.httpsession import AIOHTTPSession
from aiobotocore.session import AioSession

S3_XML_ERROR = (
    b'<?xml version="1.0" encoding="UTF-8"?><Error>'
    b'<Code>SlowDown</Code><Message>'
    + b'x' * 64_000
    + b'</Message><RequestId>req-1</RequestId></Error>'
)
SHORT_XML_ERROR = (
    b'<?xml version="1.0" encoding="UTF-8"?><Error>'
    b'<Code>AccessDenied</Code><Message>denied</Message>'
    b'<RequestId>req-2</RequestId></Error>'
)
# A streamed download: any error-body bound must not apply here.
LONG_SUCCESS_BODY = b'\x00\x01\x02\x03' * 64_000
ERROR_HEADERS = {'content-type': 'application/xml'}
SUCCESS_HEADERS = {'content-type': 'application/octet-stream'}


class _FakeAiohttpRaw:
    """Mimics aiohttp's ClientResponse: body exposed as ``.content.read``."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self.bytes_read = 0
        self.closed = False
        self.released = False

    @property
    def content(self):
        return self

    async def read(self, amt: int = -1) -> bytes:
        if amt is None or amt < 0:
            amt = len(self._data) - self._pos
        chunk = self._data[self._pos : self._pos + amt]
        self._pos += len(chunk)
        self.bytes_read += len(chunk)
        return chunk

    def at_eof(self) -> bool:
        return self._pos >= len(self._data)

    def close(self) -> None:
        self.closed = True

    def release(self) -> None:
        self.released = True


class _BrokenAiohttpRaw(_FakeAiohttpRaw):
    """Stops mid-body with the same error a dropped connection raises."""

    def __init__(self, data: bytes, fail_after: int) -> None:
        super().__init__(data)
        self._fail_after = fail_after

    async def read(self, amt: int = -1) -> bytes:
        if self._pos >= self._fail_after:
            raise aiohttp.ClientPayloadError('connection reset mid-body')
        if amt is None or amt < 0:
            amt = len(self._data) - self._pos
        amt = min(amt, self._fail_after - self._pos)
        return await super().read(amt)

    def at_eof(self) -> bool:
        return False


class _FakeHttpxRaw:
    """Mimics httpx's Response streaming: body exposed via ``aiter_raw``."""

    def __init__(self, data: bytes, chunk_size: int = 4096) -> None:
        self._data = data
        self._chunk_size = chunk_size
        self.bytes_read = 0
        self.closed = False

    def aiter_raw(self, chunk_size: int | None = None):
        step = chunk_size or self._chunk_size

        async def _gen():
            pos = 0
            while pos < len(self._data):
                chunk = self._data[pos : pos + step]
                pos += len(chunk)
                self.bytes_read += len(chunk)
                yield chunk

        return _gen()

    async def aread(self) -> bytes:
        self.bytes_read = len(self._data)
        return self._data

    # Real httpx.Response exposes both; the streaming body closes via
    # ``aclose`` and the error reader closes via ``close``.
    async def aclose(self) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True


class _ScriptedSession(AIOHTTPSession):
    """Feeds pre-scripted (status, body, headers, backend) responses."""

    script: list[tuple[int, bytes, dict, str]] = []
    raws: list[object] = []

    # When set, the next aiohttp response breaks mid-body after this many
    # bytes.  Only the aiohttp raw models a mid-stream failure.
    break_after: int | None = None

    async def send(self, request):
        status, body, headers, backend = type(self).script.pop(0)
        if backend == 'httpx':
            raw = _FakeHttpxRaw(body)
            response_cls = HttpxAWSResponse
        else:
            break_after = type(self).break_after
            type(self).break_after = None
            if break_after is not None:
                raw = _BrokenAiohttpRaw(body, break_after)
            else:
                raw = _FakeAiohttpRaw(body)
            response_cls = AioAWSResponse
        type(self).raws.append(raw)
        headers = dict(headers)
        if body:
            headers['content-length'] = str(len(body))
        return response_cls(request.url, status, headers, raw)


@pytest.fixture(params=['aiohttp', 'httpx'])
def backend(request):
    if request.param == 'httpx':
        pytest.importorskip('httpx')
    return request.param


async def _client(session, error_body_limit):
    config = AioConfig(
        http_session_cls=_ScriptedSession,
        region_name='us-east-1',
        retries={'max_attempts': 1, 'mode': 'standard'},
        error_body_limit=error_body_limit,
    )
    return session.create_client(
        's3',
        region_name='us-east-1',
        endpoint_url='http://fake-s3',
        aws_secret_access_key='x',
        aws_access_key_id='x',
        config=config,
    )


def test_error_body_limit_validation():
    AioConfig(error_body_limit=None)
    AioConfig(error_body_limit=0)
    AioConfig(error_body_limit=1024)

    for bad in (-1, 1.5, '1', True):
        with pytest.raises(
            ParamValidationError, match='error_body_limit must be a'
        ):
            AioConfig(error_body_limit=bad)


def test_error_body_limit_survives_config_merge():
    config = AioConfig(error_body_limit=64)
    merged = config.merge(AioConfig(region_name='us-east-1'))
    assert merged.error_body_limit == 64

    # An explicit override wins, and ``None`` (unlimited) survives the merge.
    overridden = merged.merge(AioConfig(error_body_limit=None))
    assert overridden.error_body_limit is None


async def test_error_body_limit_reaches_the_client(backend):
    session = AioSession()
    async with await _client(session, error_body_limit=64) as client:
        assert client.meta.config.error_body_limit == 64


async def test_error_body_stops_then_retry_streams_full_success(backend):
    limit = 128
    _ScriptedSession.script = [
        # Attempt 1: an error body far larger than the budget.
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
        # Retry: the same call then returns a long successful stream, which
        # the error budget must not cap.
        (200, LONG_SUCCESS_BODY, SUCCESS_HEADERS, backend),
    ]
    _ScriptedSession.raws = []

    session = AioSession()
    async with await _client(session, error_body_limit=limit) as client:
        response = await client.get_object(Bucket='bucket', Key='key')
        async with response['Body'] as body:
            downloaded = await body.read()

    first, success = _ScriptedSession.raws

    # The failed attempt stopped at the budget instead of draining the body.
    assert first.bytes_read == limit
    assert first.bytes_read < len(S3_XML_ERROR)
    # A truncated body cannot be reused: the connection was closed, not pooled.
    if isinstance(first, _FakeAiohttpRaw):
        assert first.closed and not first.released
    else:
        assert first.closed

    # The retry delivered the whole successful stream.
    assert success.bytes_read == len(LONG_SUCCESS_BODY)
    assert downloaded == LONG_SUCCESS_BODY
    assert len(downloaded) > limit
    assert response['ResponseMetadata']['RetryAttempts'] == 1


async def test_budget_is_per_api_call(backend):
    # One call truncating its error body must not shrink the allowance of a
    # later, unrelated call.
    limit = 128
    _ScriptedSession.raws = []
    _ScriptedSession.script = [
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
        (200, LONG_SUCCESS_BODY, SUCCESS_HEADERS, backend),
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
        (200, LONG_SUCCESS_BODY, SUCCESS_HEADERS, backend),
    ]

    session = AioSession()
    async with await _client(session, error_body_limit=limit) as client:
        for _ in range(2):
            response = await client.get_object(Bucket='bucket', Key='key')
            async with response['Body'] as body:
                assert await body.read() == LONG_SUCCESS_BODY

    error_attempts = _ScriptedSession.raws[::2]
    assert [raw.bytes_read for raw in error_attempts] == [limit, limit]


async def test_truncated_error_keeps_status_and_bounded_diagnostics(backend):
    limit = 64
    _ScriptedSession.script = [
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
    ]
    _ScriptedSession.raws = []

    session = AioSession()
    async with await _client(session, error_body_limit=limit) as client:
        with pytest.raises(ClientError) as excinfo:
            await client.list_objects(Bucket='bucket')

    error = excinfo.value.response
    # The status code survives even though the error body could not be parsed;
    # a parser failure must not replace the service error.
    assert error['ResponseMetadata']['HTTPStatusCode'] == 503
    assert error['Error']['Code'] == '503'
    # Diagnostics stay bounded and mark the truncation.
    assert error['ResponseMetadata']['ErrorBodyBytesRead'] <= limit
    assert error['ResponseMetadata']['ErrorBodyTruncated'] is True
    assert error['ResponseMetadata']['RetryAttempts'] == 1

    # The budget was spent on the first attempt; the retry got none of it.
    # It still closed its unread connection immediately rather than parking
    # it in the pool.
    first, retry = _ScriptedSession.raws
    assert first.bytes_read == limit
    assert retry.bytes_read == 0
    if isinstance(retry, _FakeAiohttpRaw):
        assert retry.closed and not retry.released
    else:
        assert retry.closed


async def test_error_body_budget_is_shared_across_retries(backend):
    # A budget smaller than either error plus a second attempt proves the
    # retry cannot mint a fresh allowance.
    limit = 32
    _ScriptedSession.script = [
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
        (503, S3_XML_ERROR, ERROR_HEADERS, backend),
    ]
    _ScriptedSession.raws = []

    session = AioSession()
    config = AioConfig(
        http_session_cls=_ScriptedSession,
        region_name='us-east-1',
        retries={'max_attempts': 2, 'mode': 'standard'},
        error_body_limit=limit,
    )
    async with session.create_client(
        's3',
        region_name='us-east-1',
        endpoint_url='http://fake-s3',
        aws_secret_access_key='x',
        aws_access_key_id='x',
        config=config,
    ) as client:
        with pytest.raises(ClientError):
            await client.list_objects(Bucket='bucket')

    total_read = sum(raw.bytes_read for raw in _ScriptedSession.raws)
    assert len(_ScriptedSession.raws) == 3
    assert total_read <= limit
    # Every attempt that started reading a truncated body closed it.
    for raw in _ScriptedSession.raws:
        if raw.bytes_read:
            assert getattr(raw, 'closed', False) or getattr(
                raw, 'released', False
            )


async def test_broken_stream_keeps_status_and_bounded_prefix():
    # A network failure part way through the error body must not replace the
    # service's status code, and must not leak the connection back to the pool.
    limit = 4096
    fail_after = 24
    _ScriptedSession.raws = []
    _ScriptedSession.break_after = fail_after
    _ScriptedSession.script = [
        (503, S3_XML_ERROR, ERROR_HEADERS, 'aiohttp'),
        (503, S3_XML_ERROR, ERROR_HEADERS, 'aiohttp'),
    ]

    session = AioSession()
    async with await _client(session, error_body_limit=limit) as client:
        with pytest.raises(ClientError) as excinfo:
            await client.list_objects(Bucket='bucket')

    error = excinfo.value.response
    assert error['ResponseMetadata']['HTTPStatusCode'] == 503
    assert error['Error']['Code'] == '503'
    assert error['ResponseMetadata']['ErrorBodyTruncated'] is True
    assert error['ResponseMetadata']['ErrorBodyBytesRead'] <= limit

    first, retry = _ScriptedSession.raws
    assert first.bytes_read == fail_after
    assert first.closed and not first.released
    # The retry draws from what the failed attempt left, not a fresh limit.
    assert retry.bytes_read == limit - fail_after
    assert retry.closed and not retry.released


async def test_stub_response_without_raw_body_is_empty():
    # Stubbed responses inject a parsed response with no wire raw; the reader
    # must not try to touch it, with or without a budget.
    for limit in (None, 16):
        response = AioAWSResponse(None, 400, {}, None)
        assert await response.read_error_body(ErrorBodyBudget(limit)) == b''


async def test_declared_length_short_body_is_truncated():
    # If the body ends before its content-length, the connection is closed and
    # the response is marked truncated even though it ended cleanly.
    raw = _FakeAiohttpRaw(SHORT_XML_ERROR)
    response = AioAWSResponse(
        'http://fake', 400, {'content-length': '9999'}, raw
    )

    body = await response.read_error_body(ErrorBodyBudget(9999))

    assert body == SHORT_XML_ERROR
    assert response.error_body_truncated is True
    assert raw.closed and not raw.released


async def test_unlimited_budget_reads_whole_error_body(backend):
    _ScriptedSession.script = [(400, SHORT_XML_ERROR, ERROR_HEADERS, backend)]
    _ScriptedSession.raws = []

    session = AioSession()
    async with await _client(session, error_body_limit=None) as client:
        with pytest.raises(ClientError) as excinfo:
            await client.list_objects(Bucket='bucket')

    assert excinfo.value.response['Error']['Code'] == 'AccessDenied'
    assert excinfo.value.response['ResponseMetadata'][
        'ErrorBodyBytesRead'
    ] == len(SHORT_XML_ERROR)
    (only,) = _ScriptedSession.raws
    assert only.bytes_read == len(SHORT_XML_ERROR)


async def test_successful_error_sized_response_is_not_budgeted(backend):
    # A large *successful* body must still be delivered in full even with a
    # tiny error budget.
    _ScriptedSession.script = [
        (200, LONG_SUCCESS_BODY, SUCCESS_HEADERS, backend)
    ]
    _ScriptedSession.raws = []
    session = AioSession()
    async with await _client(session, error_body_limit=8) as client:
        response = await client.get_object(Bucket='bucket', Key='key')
        async with response['Body'] as body:
            assert await body.read() == LONG_SUCCESS_BODY
