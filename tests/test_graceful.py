import threading
import unittest

from waitress import graceful
from waitress import wasyncore


class FakeClock:
    """Deterministic clock: time only moves when sleep() is called."""

    def __init__(self, start=1000.0):
        self.now = start
        self.slept = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class FakeOutbuf:
    def __init__(self, data=b""):
        self.data = bytearray(data)
        self.closed = False

    def close(self):
        self.closed = True

    def __len__(self):
        return len(self.data)


class FakeChannel:
    """Minimal channel standing in for HTTPChannel in controller tests."""

    def __init__(self, outbuf_len=0):
        self.shutting_down = False
        self.total_outbufs_len = outbuf_len
        self.aborted = False
        self.closed = False
        self.outbufs = [FakeOutbuf(b"x" * outbuf_len)]

    def abort(self):
        # Mirror HTTPChannel.abort: discard buffered bytes then close.
        for outbuf in self.outbufs:
            outbuf.close()
        self.outbufs = []
        self.total_outbufs_len = 0
        self.aborted = True
        self.closed = True


class FakeListener:
    def __init__(self):
        self.accepting = True
        self.closed = False

    def close(self):
        self.closed = True


class FakeDispatcher:
    def __init__(self, queue=0, active=0):
        self.lock = threading.Lock()
        self.queue = deque_stub(queue)
        self.active_count = active
        self.shutdown_calls = []

    def shutdown(self, cancel_pending=True, timeout=5):
        self.shutdown_calls.append((cancel_pending, timeout))
        self.queue.clear()
        self.active_count = 0
        return True


def deque_stub(n):
    from collections import deque

    return deque(object() for _ in range(n))


class FakeServer:
    """Single-socket server shape (has accept_connections/_map/active_channels)."""

    def __init__(self, channels=(), dispatcher=None):
        self._map = {}
        self.listener = FakeListener()
        # A real BaseWSGIServer carries its own accepting flag.
        self.accepting = True
        self.active_channels = {}
        for index, channel in enumerate(channels):
            self.active_channels[index] = channel
        self.task_dispatcher = dispatcher or FakeDispatcher()

    def accept_connections(self):  # pragma: no cover - marker only
        pass

    def close(self):
        self.accepting = False
        self.listener.closed = True


def make_one(server=None, timeout=30.0, clock=None):
    clock = clock or FakeClock()
    server = server or FakeServer()
    return graceful.GracefulShutdown(server, timeout=timeout, time=clock), clock


class TestGracefulShutdown(unittest.TestCase):
    def test_begin_stops_accepting_and_marks_channels(self):
        channel = FakeChannel()
        server = FakeServer(channels=[channel])
        controller, _ = make_one(server)

        controller.begin()

        self.assertFalse(server.accepting)
        self.assertTrue(channel.shutting_down)
        self.assertEqual(controller.state, graceful.STOP_ACCEPTING)
        self.assertIn("accepting", controller.status()._fields)

    def test_begin_is_idempotent_and_rerunnable(self):
        server = FakeServer()
        controller, clock = make_one(server)

        controller.begin()
        first_deadline = controller.deadline
        clock.now += 1
        controller.begin()  # must not reset the deadline mid-shutdown

        self.assertEqual(controller.deadline, first_deadline)

        # After completion a fresh controller over the same server runs again.
        controller.poll()  # nothing outstanding -> completes immediately
        self.assertEqual(controller.state, graceful.COMPLETE)
        second, _ = make_one(server, clock=clock)
        second.begin()
        self.assertEqual(second.state, graceful.STOP_ACCEPTING)

    def test_clean_drain_passes_through_output_stage(self):
        # A channel with buffered output but no queued/running work should be
        # reported in the output-drain stage, then complete once it is empty.
        channel = FakeChannel(outbuf_len=10)
        dispatcher = FakeDispatcher(queue=0, active=0)
        server = FakeServer(channels=[channel], dispatcher=dispatcher)
        controller, clock = make_one(server, timeout=30)

        controller.begin()
        status = controller.poll()
        self.assertEqual(controller.state, graceful.DRAIN_OUTPUT)
        self.assertEqual(status.buffered_bytes, 10)
        self.assertEqual(status.open_channels, 1)
        self.assertFalse(status.accepting)

        # Simulate the mainloop flushing the remaining output.
        channel.total_outbufs_len = 0
        server.active_channels.clear()
        status = controller.poll()

        self.assertEqual(controller.state, graceful.COMPLETE)
        self.assertEqual(status.open_channels, 0)
        self.assertTrue(server.listener.closed)
        self.assertEqual(dispatcher.shutdown_calls, [(True, 30.0)])

    def test_queue_then_running_then_complete_stages(self):
        dispatcher = FakeDispatcher(queue=2, active=0)
        server = FakeServer(dispatcher=dispatcher)
        controller, clock = make_one(server, timeout=30)

        controller.begin()
        self.assertEqual(controller.poll().queued, 2)
        self.assertEqual(controller.state, graceful.DRAIN_QUEUE)

        dispatcher.queue.clear()
        dispatcher.active_count = 1
        controller.poll()
        self.assertEqual(controller.state, graceful.DRAIN_RUNNING)

        dispatcher.active_count = 0
        controller.poll()
        self.assertEqual(controller.state, graceful.COMPLETE)

    def test_timeout_aborts_and_presents_incomplete_transfer(self):
        slow_channel = FakeChannel(outbuf_len=50)
        queued_channel = FakeChannel()
        dispatcher = FakeDispatcher(queue=1, active=1)
        server = FakeServer(
            channels=[slow_channel, queued_channel], dispatcher=dispatcher
        )
        clock = FakeClock()
        controller = graceful.GracefulShutdown(server, timeout=5, time=clock)

        controller.begin()
        # First poll is within the deadline: still draining.
        controller.poll()
        self.assertNotIn(controller.state, (graceful.FORCED, graceful.COMPLETE))

        # Expire the deadline while work/output is still outstanding.
        clock.now = controller.deadline + 1
        status = controller.poll()

        self.assertEqual(controller.state, graceful.FORCED)
        self.assertTrue(slow_channel.aborted)
        self.assertTrue(queued_channel.aborted)
        # Buffered output was discarded, never flushed as a clean terminator.
        self.assertEqual(slow_channel.total_outbufs_len, 0)
        self.assertEqual(status.buffered_bytes, 0)
        self.assertEqual(controller.forced_channels, [slow_channel, queued_channel])

    def test_wait_uses_clock_sleep_and_terminates(self):
        dispatcher = FakeDispatcher(queue=1, active=1)
        server = FakeServer(dispatcher=dispatcher)
        clock = FakeClock()
        controller = graceful.GracefulShutdown(
            server, timeout=2, time=clock, poll_interval=0.5
        )

        def drain_on_second_tick():
            # Pretend the app finishes once time has advanced.
            if clock.now >= 1001.0:
                dispatcher.queue.clear()
                dispatcher.active_count = 0

        original_poll = controller.poll

        def wrapped_poll():
            drain_on_second_tick()
            return original_poll()

        controller.poll = wrapped_poll
        status = controller.wait()

        self.assertEqual(controller.state, graceful.COMPLETE)
        self.assertTrue(clock.slept)
        self.assertEqual(status.queued, 0)
        self.assertEqual(status.running, 0)


class TestHTTPChannelAbort(unittest.TestCase):
    def _make_channel(self):
        from waitress.channel import HTTPChannel

        class Sock:
            blocking = False

            def __init__(self):
                self.sent = b""
                self.closed = False
                # Simulate a full client receive window: writes stay buffered
                # in the channel instead of reaching the socket.
                self.send_returns = 0

            def setblocking(self, *a):
                self.blocking = True

            def fileno(self):
                return 77

            def getpeername(self):
                return ("127.0.0.1", 1)

            def getsockopt(self, *a):
                return 2048

            def send(self, data, do_close=True):
                if self.send_returns == 0:
                    return 0
                self.sent += data
                return len(data)

            def recv(self, size):
                return b""

            def close(self):
                self.closed = True

        class Adj:
            outbuf_overflow = 1048576
            outbuf_high_watermark = 1048576
            recv_bytes = 8192
            send_bytes = 1
            channel_request_lookahead = 0
            log_socket_errors = True

        class Server:
            def __init__(self):
                self.active_channels = {}

            def add_task(self, task):
                pass

            def pull_trigger(self):
                pass

        sock = Sock()
        map = {}
        channel = HTTPChannel(Server(), sock, ("127.0.0.1", 1), Adj(), map=map)
        return channel, sock, map

    def test_abort_discards_outbuf_without_terminator(self):
        channel, sock, map = self._make_channel()
        # Client window is full, so these body bytes stay in the outbuf.
        channel.write_soon(b"partial-body")
        self.assertGreater(channel.total_outbufs_len, 0)
        self.assertEqual(sock.sent, b"")

        channel.abort()

        # Socket was removed from the map and closed; no footer appended and
        # none of the buffered body reached the client.
        self.assertNotIn(77, map)
        self.assertEqual(channel.total_outbufs_len, 0)
        self.assertEqual(channel.outbufs, [])
        self.assertFalse(channel.connected)
        self.assertTrue(channel.will_close)
        self.assertEqual(sock.sent, b"")
        self.assertTrue(sock.closed)

    def test_shutting_down_blocks_new_request_readability(self):
        channel, _, _ = self._make_channel()
        self.assertTrue(channel.readable())
        channel.shutting_down = True
        self.assertFalse(channel.readable())
        # received() refuses data while shutting down.
        self.assertFalse(channel.received(b"GET / HTTP/1.1\r\n\r\n"))
