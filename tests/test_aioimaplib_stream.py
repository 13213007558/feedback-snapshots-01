# -*- coding: utf-8 -*-
#    Tests for the backpressured, streaming literal reception entry point.
#    These tests drive the protocol straight through data_received with a mock transport so
#    they do not need a real socket (the sandbox used in CI forbids local port binding).
import asyncio
import hashlib

import pytest

from aioimaplib import aioimaplib
from aioimaplib.aioimaplib import (
    IMAP4ClientProtocol, FetchCommand, StreamingFetchCommand, LiteralChunk, LiteralEnd,
    LiteralStreamEnd, LiteralStreamAborted, CommandTimeout, Abort,
)

aioimaplib.get_running_loop = asyncio.get_running_loop  # protocol built outside a running coroutine


class MockTransport:
    def __init__(self):
        self.paused = False
        self.pause_events = []
        self.resume_events = []
        self.closed = False
        self.written = []

    def pause_reading(self):
        self.paused = True
        self.pause_events.append(len(self.pause_events) + 1)

    def resume_reading(self):
        self.paused = False
        self.resume_events.append(len(self.resume_events) + 1)

    def close(self):
        self.closed = True

    def write(self, data):
        self.written.append(data)


def build_streaming_protocol(event_loop, max_queue=2, timeout=None, total_timeout=None):
    protocol = IMAP4ClientProtocol(event_loop)
    transport = MockTransport()
    protocol.connection_made(transport)
    protocol.state = aioimaplib.SELECTED
    command = StreamingFetchCommand(
        protocol.new_tag(), '1', '(RFC822)', loop=event_loop,
        timeout=timeout, total_timeout=total_timeout,
        max_queue=max_queue, transport=transport)
    stream = protocol.stream(command)
    return protocol, transport, command, stream


def fetch_frame(payload: bytes, tag: str) -> bytes:
    return (b'* 1 FETCH (RFC822 {%d}\r\n' % len(payload)) + payload + \
           b')\r\n' + tag.encode() + b' OK FETCH completed\r\n'


def feed_byte_by_byte(protocol, data: bytes) -> None:
    for byte in data:
        protocol.data_received(bytes([byte]))


@pytest.mark.asyncio()
async def test_streaming_fetch_delivers_every_raw_byte_in_attributed_chunks(event_loop):
    protocol, transport, command, stream = build_streaming_protocol(event_loop)
    payload = b'0123456789abcdef' * 4  # 64 bytes, fed one byte at a time

    feed_byte_by_byte(protocol, fetch_frame(payload, command.tag))

    assert transport.closed is False
    received = bytearray()
    literal_ends = []
    chunk_offsets = []
    while True:
        event = await stream.read_event()
        if isinstance(event, LiteralStreamEnd):
            break
        if isinstance(event, LiteralEnd):
            literal_ends.append(event)
            continue
        assert isinstance(event, LiteralChunk)
        assert event.command == 'FETCH'
        assert event.tag == command.tag
        assert event.literal_index == 0
        assert event.offset == len(received)
        chunk_offsets.append(event.offset)
        received.extend(event.data)

    assert bytes(received) == payload
    assert hashlib.sha256(bytes(received)).digest() == hashlib.sha256(payload).digest()
    assert literal_ends == [LiteralEnd('FETCH', command.tag, 0, len(payload))]
    assert chunk_offsets[0] == 0
    # the full literal was never reassembled in the command response
    assert payload not in command.response.lines
    assert b'<literal 0: %d bytes streamed>' % len(payload) in command.response.lines

    await command.wait()
    assert command.response.result == 'OK'
    assert stream.failed is False


@pytest.mark.asyncio()
async def test_streaming_fetch_pauses_transport_and_bounds_retained_buffer(event_loop):
    # queue of 2, payload delivered in 4-byte frames while the consumer is not reading
    protocol, transport, command, stream = build_streaming_protocol(event_loop, max_queue=2)
    payload = b'abcdefghijklmnop'  # 16 bytes
    frame = fetch_frame(payload, command.tag)

    # deliver the whole 16-byte payload in 4-byte frames without consuming anything:
    # two chunks fill the queue, the other two pause reading and get retained
    head, _, _ = frame.partition(b'\r\n')
    protocol.data_received(head + b'\r\n')
    for start in range(0, len(payload), 4):
        protocol.data_received(payload[start:start + 4])

    assert transport.paused is True
    assert len(transport.pause_events) >= 1
    # backpressure: the bounded queue holds at most max_queue chunks; the rest is retained as
    # discrete frames rather than being reassembled into one big buffer
    assert stream.queued_bytes == 8
    assert stream.retained_bytes == 8

    # consume everything and check the transport is resumed
    received = bytearray()
    async for chunk in stream:
        received.extend(chunk.data)
        if len(received) == len(payload):
            break

    assert transport.paused is False
    assert len(transport.resume_events) >= 1
    assert stream.retained_bytes == 0

    # feed the rest of the frame (closing parenthesis + tagged OK)
    protocol.data_received(b')\r\n' + command.tag.encode() + b' OK FETCH completed\r\n')
    await command.wait()
    assert bytes(received) == payload
    assert command.response.result == 'OK'


@pytest.mark.asyncio()
async def test_streaming_fetch_remaining_bytes_are_not_another_response_after_consumer_failure(event_loop):
    protocol, transport, command, stream = build_streaming_protocol(event_loop, max_queue=2)
    payload = b'ABCDEFGHIJKLMNOP'
    frame = fetch_frame(payload, command.tag)

    head, _, _ = frame.partition(b'\r\n')
    protocol.data_received(head + b'\r\n' + payload[:6])

    class ConsumerBoom(Exception):
        pass

    with pytest.raises(ConsumerBoom):
        async with stream:
            await stream.read_event()  # first chunk is fine
            raise ConsumerBoom('scanner rejected this content')

    assert stream.failed is True
    assert transport.closed is True
    # the command can never look like a complete, scannable input
    with pytest.raises((LiteralStreamAborted, ConsumerBoom)):
        await command.wait()
    assert command.response.result != 'OK'

    # any bytes still on the wire must be ignored, not parsed as a fresh response
    lines_before = list(command.response.lines)
    protocol.data_received(b')\r\n' + command.tag.encode() + b' OK FETCH completed\r\n')
    protocol.data_received(b'* 99 EXISTS\r\n')
    assert command.response.lines == lines_before


@pytest.mark.asyncio()
async def test_streaming_fetch_cancellation_aborts_and_does_not_complete(event_loop):
    protocol, transport, command, stream = build_streaming_protocol(event_loop, max_queue=2)
    payload = b'0123456789'
    head, _, _ = fetch_frame(payload, command.tag).partition(b'\r\n')
    protocol.data_received(head + b'\r\n' + payload[:4])

    async def cancelling_consumer():
        async with stream:
            await stream.read_event()
            raise asyncio.CancelledError()

    consumer = asyncio.ensure_future(cancelling_consumer())
    with pytest.raises(asyncio.CancelledError):
        await consumer

    assert stream.failed is True
    assert transport.closed is True
    with pytest.raises((LiteralStreamAborted, asyncio.CancelledError)):
        await command.wait()
    assert command.response.result != 'OK'


@pytest.mark.asyncio()
async def test_paused_reading_suspends_inactivity_timer_but_total_deadline_still_fires(event_loop):
    from tests.server_fixture import EventLoopClockAdvancer
    advance = EventLoopClockAdvancer(event_loop)

    protocol, transport, command, stream = build_streaming_protocol(
        event_loop, max_queue=1, timeout=2, total_timeout=5)
    payload = b'zzzzzzzz'
    head, _, _ = fetch_frame(payload, command.tag).partition(b'\r\n')

    # one chunk fills the size-1 queue, the next frame pauses reading; the inactivity timer is
    # now suspended
    protocol.data_received(head + b'\r\n' + payload[:2])
    protocol.data_received(payload[2:4])
    assert transport.paused is True

    # well past the inactivity timeout: nothing fires while reading is paused
    await advance(3)
    assert command._exception is None
    assert transport.paused is True

    # the total deadline is independent of pausing and still aborts the stream
    await advance(2.5)
    assert isinstance(command._exception, CommandTimeout)
    assert stream.failed is True
    with pytest.raises(CommandTimeout):
        await command.wait()
    # the failed command does not linger in the protocol's pending commands
    assert command.untagged_resp_name not in protocol.pending_async_commands


@pytest.mark.asyncio()
async def test_resuming_reading_rearms_inactivity_timer_and_completes(event_loop):
    from tests.server_fixture import EventLoopClockAdvancer
    advance = EventLoopClockAdvancer(event_loop)

    protocol, transport, command, stream = build_streaming_protocol(
        event_loop, max_queue=1, timeout=2, total_timeout=10)
    payload = b'qwertyui'
    head, _, _ = fetch_frame(payload, command.tag).partition(b'\r\n')

    protocol.data_received(head + b'\r\n' + payload[:2])
    protocol.data_received(payload[2:4])
    assert transport.paused is True

    # consume: reading resumes and the inactivity timer is rearmed
    first = await stream.read_event()
    assert isinstance(first, LiteralChunk)
    assert transport.paused is False
    assert command._timer_suspended is False

    await advance(1.5)  # within the rearmed inactivity window
    # the first two frames delivered payload[:4]; resume with the remaining bytes
    protocol.data_received(payload[4:])
    protocol.data_received(b')\r\n' + command.tag.encode() + b' OK FETCH completed\r\n')

    received = bytearray(first.data)
    async for chunk in stream:
        received.extend(chunk.data)
    await command.wait()
    assert bytes(received) == payload
    assert command.response.result == 'OK'


@pytest.mark.asyncio()
async def test_multiple_literals_are_attributed_per_literal_and_only_full_completion_reports_ok(event_loop):
    protocol, transport, command, stream = build_streaming_protocol(event_loop, max_queue=4)
    first, second = b'first-literal!', b'second'

    protocol.data_received(b'* 1 FETCH (BODY[1] {%d}\r\n' % len(first) + first +
                           b' BODY[2] {%d}\r\n' % len(second) + second + b')\r\n' +
                           command.tag.encode() + b' OK FETCH completed\r\n')

    seen = {0: bytearray(), 1: bytearray()}
    ends = []
    while True:
        event = await stream.read_event()
        if isinstance(event, LiteralStreamEnd):
            assert event.literals == 2
            break
        if isinstance(event, LiteralEnd):
            ends.append((event.literal_index, event.size))
        else:
            seen[event.literal_index].extend(event.data)

    assert bytes(seen[0]) == first
    assert bytes(seen[1]) == second
    assert ends == [(0, len(first)), (1, len(second))]
    assert command.literal_complete == [True, True]
    await command.wait()
    assert command.response.result == 'OK'


@pytest.mark.asyncio()
async def test_buffered_fetch_api_still_assembles_the_full_literal(event_loop):
    # the legacy buffered behavior must keep working alongside the streaming entry point
    protocol = IMAP4ClientProtocol(event_loop)
    transport = MockTransport()
    protocol.connection_made(transport)
    protocol.state = aioimaplib.SELECTED
    command = FetchCommand(protocol.new_tag(), '1', '(RFC822)', loop=event_loop)
    protocol.pending_async_commands[command.untagged_resp_name] = command
    payload = b'buffered whole literal'
    protocol.data_received(fetch_frame(payload, command.tag))

    response = command.response
    assert payload in response.lines
    assert response.result == 'OK'


@pytest.mark.asyncio()
async def test_connection_lost_before_full_literal_fails_the_stream(event_loop):
    protocol, transport, command, stream = build_streaming_protocol(event_loop)
    payload = b'partial'
    head, _, _ = fetch_frame(payload, command.tag).partition(b'\r\n')
    protocol.data_received(head + b'\r\n' + payload[:3])

    protocol.connection_lost(ConnectionResetError('boom'))

    assert stream.failed is True
    with pytest.raises(Abort):
        await stream.read_event()
    with pytest.raises(Abort):
        await command.wait()
    assert command.response.result != 'OK'
