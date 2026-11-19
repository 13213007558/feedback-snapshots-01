#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Per-stream ``first_request_timeout`` on the async HTTP/2 connection.

Each stream is timed on its own from its HEADERS frame. An unanswered stream
is reset with RST_STREAM while the others keep running, a stream that answers
disarms its timer, and the connection stays reusable. Time is driven by a
manual clock.
"""

from io import BytesIO

import h2.connection
import h2.config
import pytest

from gunicorn.config import Config
from gunicorn.http2.async_connection import AsyncHTTP2Connection
from gunicorn.http2.stream import StreamState
from gunicorn.http2.errors import HTTP2ErrorCode

BUDGET = 5


class _Reader:
    def __init__(self):
        self._buf = BytesIO()

    async def read(self, n=-1):
        return self._buf.read(n)

    def set_data(self, data):
        self._buf = BytesIO(data)


class _Writer:
    def __init__(self):
        self.buffer = bytearray()

    def write(self, data):
        self.buffer.extend(data)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class _ManualClock:
    def __init__(self):
        self.now = 0.0
        self._due = []
        self._seq = 0

    def time(self):
        return self.now

    def call_later(self, delay, callback, *args):
        # Record rather than run: the tests call the expiry path explicitly
        # after asserting state, which is what makes the boundary observable.
        self._seq += 1
        due = self.now + delay
        seq = self._seq

        class _Handle:
            cancelled = False

            def cancel(self):
                self.cancelled = True

        handle = _Handle()

        def _fire():
            if not handle.cancelled:
                callback(*args)

        self._due.append((due, seq, handle, _fire))
        return handle

    def advance(self, seconds):
        target = self.now + seconds
        due = [item for item in self._due if item[0] <= target]
        self._due = [item for item in self._due if item[0] > target]
        # A real loop drains timers in scheduling order at the same instant.
        for _, _, _, fire in sorted(due, key=lambda item: (item[0], item[1])):
            fire()
        self.now = target


def _make_conn():
    cfg = Config()
    cfg.set("http2_max_concurrent_streams", 100)
    cfg.set("http2_initial_window_size", 65535)
    cfg.set("http2_max_frame_size", 16384)
    cfg.set("http2_max_header_list_size", 65536)
    cfg.set("first_request_timeout", BUDGET)

    reader = _Reader()
    writer = _Writer()
    conn = AsyncHTTP2Connection(cfg, reader, writer, ("127.0.0.1", 12345))
    clock = _ManualClock()
    conn.clock = clock
    return conn, reader, writer, clock


def _client():
    h2cfg = h2.config.H2Configuration(client_side=True)
    client = h2.connection.H2Connection(config=h2cfg)
    client.initiate_connection()
    return client


def _headers(stream_id, path="/"):
    return [
        (":method", "GET"),
        (":path", path),
        (":scheme", "https"),
        (":authority", "localhost"),
    ]


@pytest.mark.asyncio
async def test_unanswered_stream_is_reset_but_connection_lives():
    conn, reader, writer, clock = _make_conn()
    await conn.initiate_connection()
    client = _client()
    reader.set_data(client.data_to_send())
    await conn.receive_data()
    client.receive_data(bytes(writer.buffer))
    writer.buffer.clear()

    # Two streams open at the same instant, neither answered. Both budgets
    # therefore elapse together; each is reset individually (no GOAWAY).
    for stream_id in (1, 3):
        client.send_headers(stream_id=stream_id,
                            headers=_headers(stream_id, f"/s{stream_id}"),
                            end_stream=True)
    reader.set_data(client.data_to_send())
    requests = await conn.receive_data()
    assert len(requests) == 2
    assert set(conn._ingress_timers) == {1, 3}

    # Both expire: the individual RST_STREAMs leave the connection itself open.
    clock.advance(BUDGET)
    assert conn.streams == {}
    assert conn._ingress_timers == {}
    assert not conn.is_closed

    # The wire carries one RST_STREAM(CANCEL) per stream, and no GOAWAY.
    events = client.receive_data(bytes(writer.buffer))
    resets = [e for e in events if isinstance(e, h2.events.StreamReset)]
    assert sorted(e.stream_id for e in resets) == [1, 3]
    assert all(e.error_code == HTTP2ErrorCode.CANCEL for e in resets)
    assert not any(isinstance(e, h2.events.ConnectionTerminated) for e in events)


@pytest.mark.asyncio
async def test_one_stream_reset_while_a_later_stream_keeps_running():
    conn, reader, writer, clock = _make_conn()
    await conn.initiate_connection()
    client = _client()
    reader.set_data(client.data_to_send())
    await conn.receive_data()
    client.receive_data(bytes(writer.buffer))
    writer.buffer.clear()

    client.send_headers(stream_id=1, headers=_headers(1, "/early"),
                        end_stream=True)
    reader.set_data(client.data_to_send())
    await conn.receive_data()

    # The second stream starts two seconds into the first one's budget.
    clock.advance(2)
    client.send_headers(stream_id=3, headers=_headers(3, "/late"),
                        end_stream=True)
    reader.set_data(client.data_to_send())
    await conn.receive_data()
    assert set(conn._ingress_timers) == {1, 3}

    # At t=BUDGET only the early stream expires; the late one still runs.
    clock.advance(BUDGET - 2)
    assert 1 not in conn.streams
    assert 3 in conn.streams
    assert not conn.is_closed

    # And the late stream is reset only once its own budget elapses.
    clock.advance(2)
    assert 3 not in conn.streams
    assert not conn.is_closed


@pytest.mark.asyncio
async def test_answered_stream_disarms_its_timer():
    conn, reader, writer, clock = _make_conn()
    await conn.initiate_connection()
    client = _client()
    reader.set_data(client.data_to_send())
    await conn.receive_data()
    client.receive_data(bytes(writer.buffer))
    writer.buffer.clear()

    client.send_headers(stream_id=1, headers=_headers(1, "/ok"),
                        end_stream=True)
    reader.set_data(client.data_to_send())
    requests = await conn.receive_data()
    assert 1 in conn._ingress_timers

    # The response HEADERS frame ends this stream's preparation phase and
    # disarms the timer; the (still open) stream is left with no budget.
    req = requests[0]
    ok = await conn.send_response_headers(
        req.stream.stream_id,
        [(":status", "200"), ("content-length", "2")],
        end_stream=False)
    assert ok
    assert 1 not in conn._ingress_timers
    assert req.stream.response_headers_sent

    # Advancing past the budget does nothing to the answered stream.
    clock.advance(BUDGET * 10)
    assert not conn.is_closed
    assert req.stream.state is not StreamState.CLOSED


@pytest.mark.asyncio
async def test_disabled_setting_arms_no_timers():
    cfg = Config()
    cfg.set("http2_max_concurrent_streams", 100)
    cfg.set("http2_initial_window_size", 65535)
    cfg.set("http2_max_frame_size", 16384)
    cfg.set("http2_max_header_list_size", 65536)
    cfg.set("first_request_timeout", 0)
    reader = _Reader()
    writer = _Writer()
    conn = AsyncHTTP2Connection(cfg, reader, writer, ("127.0.0.1", 12345))
    await conn.initiate_connection()
    client = _client()
    reader.set_data(client.data_to_send())
    await conn.receive_data()
    client.receive_data(bytes(writer.buffer))
    writer.buffer.clear()

    client.send_headers(stream_id=1, headers=_headers(1), end_stream=True)
    reader.set_data(client.data_to_send())
    await conn.receive_data()
    assert conn._ingress_timers == {}
