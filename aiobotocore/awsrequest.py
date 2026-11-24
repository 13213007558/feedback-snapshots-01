import asyncio
import logging

import aiohttp
import botocore.utils
from botocore.awsrequest import AWSResponse

from aiobotocore._httpx import httpx

logger = logging.getLogger(__name__)

# Errors a backend raises when an error response body is cut short.  That body
# is diagnostic input only, so a broken stream must not mask the status code
# that drives the retry decision; the prefix read so far is kept instead.
_AIOHTTP_STREAM_ERRORS: tuple[type[BaseException], ...] = (
    aiohttp.ClientPayloadError,
    aiohttp.ClientConnectionError,
)
_HTTPX_STREAM_ERRORS: tuple[type[BaseException], ...] = (
    (
        httpx.NetworkError,
        httpx.RemoteProtocolError,
        httpx.StreamError,
        httpx.TimeoutException,
    )
    if httpx is not None
    else ()
)


class AioAWSResponse(AWSResponse):
    # Unlike AWSResponse, these return awaitables

    # True for the aiohttp backend, whose raw response exposes the body as
    # ``raw.content``.  The httpx backend sets this to False.
    _aiohttp_backend = True

    _error_body_truncated = False
    _error_body_bytes_read = 0

    @property
    def error_body_truncated(self) -> bool:
        """Whether the error body was cut short.

        True when the body exceeded the error-body budget, the stream failed
        part way through, or the service sent fewer bytes than its
        content-length promised.  The status code and the bytes read before
        the cut remain available to the retry decision and the caller.
        """
        return self._error_body_truncated

    @property
    def error_body_bytes_read(self) -> int:
        """How many error-body bytes this response actually consumed."""
        return self._error_body_bytes_read

    async def _content_prop(self):
        """Content of the response as bytes."""

        if self._content is None:
            # NOTE: this will cache the data in self.raw
            self._content = await self.raw.read() or b''

        return self._content

    async def read_error_body(self, budget):
        """Read an error body under ``budget`` and cache the result.

        Only a bounded prefix is retained, and retries share ``budget`` so a
        failed call cannot read a fresh allowance per attempt.  When the body
        is not fully consumed (over budget, broken stream, or shorter than its
        content-length) the connection is closed instead of returned to the
        pool, because unread bytes make the connection unusable.  A fully and
        exactly consumed body is released promptly for reuse.
        """
        if self._content is not None:
            return self._content

        if self.raw is None:
            # Injected response (e.g. a stub): there is no wire body to read.
            self._content = b''
            return self._content

        if budget.unlimited:
            self._content = await self.content
            self._error_body_bytes_read = len(self._content)
            if self.raw is not None:
                await _release_error_stream(self.raw)
            return self._content

        declared_length = _declared_content_length(self.headers)
        chunks: list[bytes] = []
        total = 0
        eof = False
        truncated = False

        try:
            async for chunk, eof in _iter_error_body(
                self.raw, budget, aiohttp_raw=self._aiohttp_backend
            ):
                chunks.append(chunk)
                total += len(chunk)
        except (*_AIOHTTP_STREAM_ERRORS, *_HTTPX_STREAM_ERRORS) as exc:
            truncated = True
            _log_stream_failure(exc, total)
        except asyncio.TimeoutError as exc:
            truncated = True
            _log_stream_failure(exc, total)

        if not truncated and not eof:
            # The budget stopped us before an explicit EOF.  When the declared
            # length is exactly what we read, the body is complete.
            truncated = declared_length is None or declared_length > total
        if declared_length is not None and declared_length > total:
            truncated = True

        self._content = b''.join(chunks)
        self._error_body_bytes_read = total
        self._error_body_truncated = truncated

        if truncated:
            await _close_error_stream(self.raw)
        else:
            # The body was consumed exactly; hand the connection back for
            # reuse.  Both backends also release on EOF, so this is a no-op
            # there, but it keeps a body that stops right at its declared
            # length from lingering.
            await _release_error_stream(self.raw)

        return self._content

    @property
    def content(self):
        return self._content_prop()

    async def _text_prop(self):
        encoding = botocore.utils.get_encoding_from_headers(self.headers)
        if encoding:
            return (await self.content).decode(encoding)
        else:
            return (await self.content).decode('utf-8')

    @property
    def text(self):
        return self._text_prop()


class HttpxAWSResponse(AioAWSResponse):
    _aiohttp_backend = False

    async def _content_prop(self):
        """Content of the response as bytes."""

        if self._content is None:
            # NOTE: this will cache the data in self.raw
            self._content = await self.raw.aread() or b''

        return self._content


def _declared_content_length(headers) -> int | None:
    value = headers.get('content-length')
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


async def _iter_error_body(raw, budget, aiohttp_raw=None):
    """Yield ``(chunk, eof)`` for at most ``budget.remaining`` body bytes."""
    content = getattr(raw, 'content', None)
    # ``_aiohttp_backend`` is True for aiohttp, False for httpx, and None for
    # plain responses whose raw shape must be detected.
    use_aiohttp = aiohttp_raw is True or (
        aiohttp_raw is None
        and content is not None
        and hasattr(content, 'read')
    )
    if use_aiohttp:
        if content is None or not hasattr(content, 'read'):
            # No readable body (e.g. an injected stub) to diagnose.
            yield b'', True
            return
        # aiohttp: read(n) honours the requested size exactly.
        while budget.remaining is None or budget.remaining > 0:
            size = -1 if budget.remaining is None else budget.remaining
            chunk = await content.read(size)
            if not chunk:
                yield b'', True
                return
            if budget.remaining is not None:
                chunk = chunk[: budget.remaining]
            budget.consume(len(chunk))
            at_eof = getattr(content, 'at_eof', None)
            eof = bool(at_eof()) if at_eof is not None else False
            if eof:
                yield chunk, True
                return
            yield chunk, False
        return

    aiter_raw = getattr(raw, 'aiter_raw', None)
    if aiter_raw is not None:
        # httpx: ask the iterator for the remaining allowance so a transport
        # chunk cannot overshoot the budget.
        remaining = budget.remaining
        iterator = aiter_raw(chunk_size=None if not remaining else remaining)
        iterator = iterator.__aiter__()
        exhausted = False
        try:
            while budget.remaining is None or budget.remaining > 0:
                try:
                    chunk = await iterator.__anext__()
                except StopAsyncIteration:
                    exhausted = True
                    yield b'', True
                    return
                if budget.remaining is not None:
                    chunk = chunk[: budget.remaining]
                budget.consume(len(chunk))
                if chunk:
                    yield chunk, False
        finally:
            if not exhausted:
                # The budget stopped us early; close the async iterator now
                # rather than leaving it to the event loop's finalizer.
                aclose = getattr(iterator, 'aclose', None)
                if aclose is not None:
                    await aclose()
        return

    # No readable stream; nothing to contribute to the error diagnosis.
    yield b'', True


async def _close_error_stream(raw) -> None:
    # Close, not release: unread bytes mean this connection cannot be reused.
    for name in ('aclose', 'close'):
        method = getattr(raw, name, None)
        if method is not None:
            result = method()
            if asyncio.iscoroutine(result):
                await result
            return


async def _release_error_stream(raw) -> None:
    # The body was consumed exactly; hand the connection back for reuse.
    for name in ('release', 'aclose'):
        method = getattr(raw, name, None)
        if method is not None:
            result = method()
            if asyncio.iscoroutine(result):
                await result
            return


def _log_stream_failure(exc, total):
    # Never log the body itself: it is service controlled, and the point of
    # the budget is to keep failure-path memory bounded.
    logger.debug(
        'Error response body ended after %s bytes: %s',
        total,
        type(exc).__name__,
    )
