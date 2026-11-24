"""Regression tests for the streaming checksum contract.

The customer reads a small magic prefix, fills one buffer with
``readinto()`` and then consumes the remainder asynchronously.  Both HTTP
backends have a concrete checksum body shell, so the same mixed access pattern
is exercised against both.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import pytest
from botocore.exceptions import FlexibleChecksumError
from botocore.httpchecksum import Crc32Checksum

from aiobotocore._httpx import httpx
from aiobotocore.httpchecksum import (
    AioHttpxStreamingChecksumBody,
    AioStreamingChecksumBody,
)

PAYLOAD = b"AIOR" + b"0123456789abcdef" * 65
CONTENT_LENGTH = len(PAYLOAD)
EXPECTED_CRC32 = "H8IYjg=="
BAD_CRC32 = "AAAAAA=="
READINTO_SIZE = 8
FIRST_ASYNC_READ = 1024


@dataclass
class RecyclingProbe:
    """Records whether a raw response was closed or released for reuse."""

    close_calls: int = 0
    clean_release_calls: int = 0
    state: str = "open"

    def mark_closed(self) -> None:
        self.close_calls += 1
        self.state = "discarded"

    def mark_clean_release(self) -> None:
        self.clean_release_calls += 1
        self.state = "reusable"

    def assert_closed_once(self) -> None:
        assert self.close_calls == 1

    def assert_discarded_once(self) -> None:
        self.assert_closed_once()
        assert self.state == "discarded"
        assert self.clean_release_calls == 0


class TrackingAiohttpRaw(io.BytesIO):
    """aiohttp-shaped raw response: ``content.read`` and sync ``close``."""

    url = "http://example.test/bucket/key"

    def __init__(self, payload: bytes):
        super().__init__(payload)
        self.content = self
        self.probe = RecyclingProbe()
        self._tracking_closed = False

    def at_eof(self) -> bool:
        return self.tell() >= CONTENT_LENGTH

    async def read(self, amt: int = -1) -> bytes:
        if amt == -1:
            amt = None
        return super().read(amt)

    def close(self) -> None:
        if not self._tracking_closed:
            self._tracking_closed = True
            self.probe.mark_closed()
        super().close()

    def release(self) -> None:
        self.probe.mark_clean_release()


class TrackingHttpxRaw:
    """httpx-shaped raw response: ``aiter_raw`` and async ``aclose``."""

    url = "http://example.test/bucket/key"

    def __init__(self, payload: bytes, chunk_size: int = 64):
        self._payload = payload
        self._chunk_size = chunk_size
        self.closed = False
        self.probe = RecyclingProbe()

    async def aiter_raw(self):
        for offset in range(0, len(self._payload), self._chunk_size):
            yield self._payload[offset : offset + self._chunk_size]

    async def aclose(self) -> None:
        if not self.closed:
            self.closed = True
            self.probe.mark_closed()

    def release(self) -> None:
        self.probe.mark_clean_release()


@pytest.fixture(params=["aiohttp", "httpx"])
def backend(request):
    if request.param == "httpx" and httpx is None:
        pytest.skip("httpx backend is not installed")
    return request.param


def make_body(backend_name: str, expected_checksum: str = EXPECTED_CRC32):
    checksum = Crc32Checksum()
    if backend_name == "aiohttp":
        raw = TrackingAiohttpRaw(PAYLOAD)
        body = AioStreamingChecksumBody(
            raw, CONTENT_LENGTH, checksum, expected_checksum
        )
    else:
        raw = TrackingHttpxRaw(PAYLOAD)
        body = AioHttpxStreamingChecksumBody(
            raw, CONTENT_LENGTH, checksum, expected_checksum
        )
    return body, raw


async def read_like_customer(body, sink: bytearray, *, early_exit: bool):
    magic = await body.read(4)
    assert magic == PAYLOAD[:4]
    sink.extend(magic)

    buffer = bytearray(READINTO_SIZE)
    amount_read = await body.readinto(buffer)
    assert amount_read == READINTO_SIZE
    sink.extend(buffer)

    async for chunk in body:
        sink.extend(chunk)
        if early_exit:
            break


async def test_complete_mixed_reads_produce_same_checksum(backend):
    body, raw = make_body(backend)
    delivered = bytearray()

    async with body:
        await read_like_customer(body, delivered, early_exit=False)

    assert bytes(delivered) == PAYLOAD
    assert body.tell() == CONTENT_LENGTH
    assert body.checksum.b64digest() == EXPECTED_CRC32
    assert raw.closed is True
    raw.probe.assert_closed_once()


async def test_early_exit_recycles_partial_response(backend):
    body, raw = make_body(backend)
    delivered = bytearray()

    async with body:
        await read_like_customer(body, delivered, early_exit=True)

        delivered_before_context_exit = len(delivered)
        assert delivered_before_context_exit == (
            4 + READINTO_SIZE + FIRST_ASYNC_READ
        )
        assert bytes(delivered) == PAYLOAD[:delivered_before_context_exit]
        assert body.tell() == delivered_before_context_exit

    assert bytes(delivered) == PAYLOAD[:delivered_before_context_exit]
    assert raw.closed is True
    raw.probe.assert_discarded_once()


async def test_final_checksum_failure_delivers_bytes_and_discards_response(
    backend,
):
    body, raw = make_body(backend, expected_checksum=BAD_CRC32)
    delivered = bytearray()

    async with body:
        with pytest.raises(FlexibleChecksumError):
            await read_like_customer(body, delivered, early_exit=False)

    # The mismatch is only known at the terminating read, after every payload
    # byte has been handed to the consumer.
    assert bytes(delivered) == PAYLOAD
    assert body.tell() == CONTENT_LENGTH
    assert body.checksum.b64digest() == EXPECTED_CRC32

    # Leaving the body context must close/discard the failed raw response
    # rather than leaving it available as a cleanly completed stream.
    assert raw.closed is True
    raw.probe.assert_discarded_once()
