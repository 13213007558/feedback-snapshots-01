"""Backpressure and close contract tests for :class:`SerialTransport`.

No serial hardware is used.  A controllable serial double records every byte
that reaches "the wire", while a real asyncio event loop drives the writer
callbacks.  This lets the tests assert the exact transmitted bytes, the
pause/resume flow-control notifications and the bounded buffer behaviour when
the port is slow, does short/zero writes, raises or is closed mid-stream.
"""

from __future__ import annotations

import asyncio
import socket
from unittest import mock

import serial

from pymodbus.transport.serialtransport import SerialTransport


class FakeSerial:
    """Deterministic stand-in for a pyserial port.

    ``write_plan`` controls :meth:`write`: each entry is either the number of
    bytes accepted on that call, or an exception instance to raise.  Every
    accepted byte is appended to :attr:`wire` so tests can verify the exact
    on-wire ordering.  A real socketpair fd backs the selector callbacks.
    """

    def __init__(self, write_plan=None):
        """Initialize the fake port and its write-result plan."""
        self._read_fd, self._write_fd = socket.socketpair()
        self._write_plan = list(write_plan or [])
        self.wire = bytearray()
        self.closed = False
        self.in_waiting = 0
        self.timeout = 0
        self.write_timeout = 0

    def fileno(self):
        """Return the writable fd used by the event loop selector."""
        return self._write_fd.fileno()

    def write(self, data):
        """Accept (or refuse) bytes according to the configured plan."""
        if not self._write_plan:
            accepted = len(data)
        else:
            planned = self._write_plan.pop(0)
            if isinstance(planned, Exception):
                raise planned
            accepted = min(planned, len(data))
        self.wire.extend(data[:accepted])
        return accepted

    def read(self, size=1024):
        """No inbound data in these tests."""
        return b""

    def close(self):
        """Release the socketpair."""
        if self.closed:
            return
        self.closed = True
        self._read_fd.close()
        self._write_fd.close()


def make_transport(loop, fake, protocol=None, high=64, low=16):
    """Build a SerialTransport wired to a FakeSerial without real hardware."""
    protocol = protocol or mock.Mock()
    with mock.patch(
        "pymodbus.transport.serialtransport.serial.serial_for_url",
        return_value=fake,
    ):
        transport = SerialTransport(
            loop, protocol, "dummy", None, None, None, None, None
        )
    transport.set_write_buffer_limits(high=high, low=low)
    return transport, protocol


async def pump(loop, times=64):
    """Let queued selector/call_soon callbacks run."""
    for _ in range(times):
        await asyncio.sleep(0)


def first_divergence(expected: bytes, actual: bytes) -> int:
    """Return the first offset where actual deviates from expected."""
    for index, byte in enumerate(expected):
        if index >= len(actual) or actual[index] != byte:
            return index
    return len(expected) if len(actual) != len(expected) else -1


class TailDroppingTransport(SerialTransport):
    """Mimic the historical bug: drop the tail of the current short write.

    The joined payload is treated as a single blob: on a short write the
    unwritten remainder is discarded while later frames stay queued, so the
    next command gets spliced onto the truncated one.
    """

    def intern_write_ready(self):
        """Perform the buggy short-write handling that loses the frame tail."""
        if self._closed or not self.intern_write_buffer or self.sync_serial is None:
            return False
        data = b"".join(self.intern_write_buffer)
        count = self.sync_serial.write(data)
        written = count if isinstance(count, int) else 0
        if written >= len(data):
            self.flush()
        else:
            # BUG: drop the unwritten tail of the first frame, keeping only
            # the frames that were queued behind it.
            self.intern_write_buffer = [data[len(self.intern_write_buffer[0]) :]]
            self.intern_write_buffer_size = sum(
                len(chunk) for chunk in self.intern_write_buffer
            )
        return bool(written)


class TestSerialBackpressure:
    """Verify bounded output buffering and flow control."""

    async def test_buffer_is_bounded_and_protocol_paused_resumed(self):
        """A port that accepts nothing keeps the buffer at a bounded size."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(write_plan=[0, 0, 0, 0, 0])
        transport, protocol = make_transport(loop, fake, high=32, low=8)

        observed_max = 0
        # The producer honours pause_writing()/resume_writing() like an
        # asyncio StreamWriter.drain() based sender would.
        paused = False
        pause_count = 0
        resume_count = 0

        def on_pause():
            nonlocal paused, pause_count
            paused = True
            pause_count += 1

        def on_resume():
            nonlocal paused, resume_count
            paused = False
            resume_count += 1

        protocol.pause_writing = mock.Mock(side_effect=on_pause)
        protocol.resume_writing = mock.Mock(side_effect=on_resume)

        frame = b"\x01\x03\x00\x00\x00\x0a\xc5\xcd"  # 8 byte RTU frame
        for _ in range(20):
            if not paused:
                transport.write(frame)
                observed_max = max(observed_max, transport.get_write_buffer_size())
            await pump(loop, 1)

        # Hard upper bound: high-water mark plus at most one in-flight frame.
        assert observed_max <= 32 + len(frame)
        assert transport.get_write_buffer_size() <= 32 + len(frame)
        assert pause_count >= 1
        assert protocol.pause_writing.called

        # Let the port drain: full frames must now leave in order.
        fake._write_plan.clear()
        await pump(loop, 100)
        assert transport.get_write_buffer_size() == 0
        assert resume_count >= 1
        assert not transport._protocol_paused
        assert bytes(fake.wire)
        # Every transmitted frame is intact and correctly ordered.
        assert bytes(fake.wire) == bytes(frame) * (len(fake.wire) // len(frame))
        transport.abort()

    async def test_short_write_keeps_tail_ahead_of_next_frame(self):
        """Partial writes preserve the exact byte order across frames."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(write_plan=[3, 2, 4, 1, 5])
        transport, _protocol = make_transport(loop, fake, high=4096, low=1024)

        frame_a = bytes(range(1, 9))  # 8 bytes
        frame_b = bytes(range(10, 20))  # 10 bytes
        transport.write(frame_a)
        transport.write(frame_b)
        await pump(loop, 50)

        assert transport.get_write_buffer_size() == 0
        assert bytes(fake.wire) == frame_a + frame_b
        transport.abort()

    async def test_zero_progress_then_recovery_does_not_lose_bytes(self):
        """Zero-byte/exception retries still deliver the whole frame."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(
            write_plan=[
                0,
                BlockingIOError("temporarily unwritable"),
                serial.SerialTimeoutException("timeout"),
                4,
                0,
                4,
            ]
        )
        transport, _protocol = make_transport(loop, fake)
        transport.write(b"abcdefgh")
        await pump(loop, 80)

        assert transport.get_write_buffer_size() == 0
        assert bytes(fake.wire) == b"abcdefgh"
        transport.abort()

    async def test_wire_bytes_are_exact_under_mixed_schedule(self):
        """The complete on-wire stream matches every queued frame exactly."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(write_plan=[1, 2, 1, 3, 2, 8, 4, 2])
        transport, _protocol = make_transport(loop, fake, high=8192, low=2048)

        frames = [b"\xaa\xbb", b"\x00\x01\x02\x03", b"\xff" * 5, b"\x7e\x7f"]
        for frame in frames:
            transport.write(frame)
            await pump(loop, 4)
        await pump(loop, 100)

        assert bytes(fake.wire) == b"".join(frames)
        transport.abort()


class StuckSerial(FakeSerial):
    """A port that accepts a few single bytes and then never accepts more."""

    def __init__(self, accept_before_stall=0):
        """Configure how many single bytes are accepted before stalling."""
        super().__init__()
        self._accept_before_stall = accept_before_stall

    def write(self, data):
        """Accept single bytes up to a limit, afterwards report zero progress."""
        if self._accept_before_stall > 0:
            self._accept_before_stall -= 1
            self.wire.append(data[0])
            return 1
        return 0


class PartialSerial(FakeSerial):
    """A port that always accepts at most three bytes per write call."""

    def write(self, data):
        """Record and accept only the leading three bytes each time."""
        accepted = min(3, len(data))
        self.wire.extend(data[:accepted])
        return accepted


class TestSerialCloseContract:
    """Verify graceful close vs immediate abort semantics."""

    async def test_graceful_close_drains_queued_bytes(self):
        """close() transmits everything already accepted before closing."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(write_plan=[2, 2, 2])
        transport, protocol = make_transport(loop, fake)
        transport.write(b"abcdef")
        transport.close()

        assert transport.is_closing()
        # A write after close starts must not reach the released port.
        transport.write(b"late")
        await pump(loop, 80)

        assert fake.closed
        assert bytes(fake.wire) == b"abcdef"
        protocol.connection_lost.assert_called_once_with(None)

    async def test_abort_discards_pending_bytes(self):
        """abort() closes immediately and never sends the queued tail."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(write_plan=[2])
        transport, protocol = make_transport(loop, fake)
        transport.write(b"abcdefgh")
        await pump(loop, 20)
        wire_before_abort = bytes(fake.wire)

        transport.abort()
        assert transport.is_closing()
        assert fake.closed
        await pump(loop, 20)

        # Nothing more is written after the abort, even with callbacks pending.
        assert bytes(fake.wire) == wire_before_abort
        assert transport.get_write_buffer_size() == 0
        protocol.connection_lost.assert_called_once_with(None)

    async def test_no_write_after_port_released(self):
        """Drain callbacks scheduled before abort must not touch a dead port."""
        loop = asyncio.get_running_loop()
        fake = StuckSerial(accept_before_stall=3)
        transport, _protocol = make_transport(loop, fake)
        transport.write(b"abcdefgh")
        # Simulate three single-byte serial writes before the stall.
        transport.intern_write_ready()
        transport.intern_write_ready()
        transport.intern_write_ready()
        assert bytes(fake.wire) == b"abc"
        assert transport.get_write_buffer_size() == 5
        transport.abort()
        # Manually invoke a stale callback the way a selector could.
        transport.intern_write_ready()
        # abort stopped further writes: the still-pending bytes never move.
        assert transport.get_write_buffer_size() == 0
        assert bytes(fake.wire) == b"abc"

    async def test_write_exception_aborts_with_exception(self):
        """A serial write error tears the connection down and reports it."""
        loop = asyncio.get_running_loop()
        failure = serial.SerialException("port vanished")
        fake = FakeSerial(write_plan=[failure])
        transport, protocol = make_transport(loop, fake)
        transport.write(b"abcd")
        await pump(loop, 20)

        assert fake.closed
        assert transport.is_closing()
        protocol.connection_lost.assert_called_once()
        assert protocol.connection_lost.call_args.args[0] is failure
        assert bytes(fake.wire) == b""

    async def test_close_interleaved_with_short_writes(self):
        """close() during a slow drain still delivers the full frame."""
        loop = asyncio.get_running_loop()
        fake = FakeSerial(write_plan=[1, 0, 2, 1, 2])
        transport, protocol = make_transport(loop, fake)
        transport.write(b"abcdef")
        await pump(loop, 3)
        transport.close()
        await pump(loop, 100)

        assert fake.closed
        assert bytes(fake.wire) == b"abcdef"
        protocol.connection_lost.assert_called_once_with(None)


class TestSerialIsolationAndOrdering:
    """Cross-connection liveness and byte-ordering regression checks."""

    async def test_stalled_port_never_blocks_event_loop(self):
        """A blocked serial drain must not freeze unrelated loop tasks."""
        loop = asyncio.get_running_loop()
        stuck = StuckSerial()
        transport, _protocol = make_transport(loop, stuck, high=8, low=2)
        transport.write(b"z" * 32)

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(25):
                await asyncio.sleep(0)
                ticks += 1

        await heartbeat()
        # The unrelated coroutine ran to completion even though the serial
        # port accepted nothing and the writer kept retrying.
        assert ticks == 25
        assert transport.get_write_buffer_size() > 0
        transport.abort()

    async def test_blocked_connection_does_not_stall_other_connections(self):
        """A full queue on one port leaves a second transport productive."""
        loop = asyncio.get_running_loop()
        blocked = StuckSerial()
        healthy = FakeSerial()
        blocked_transport, blocked_proto = make_transport(loop, blocked, high=16, low=4)
        healthy_transport, _ = make_transport(loop, healthy, high=64, low=16)

        blocked_transport.write(b"x" * 40)
        for _ in range(10):
            healthy_transport.write(b"ping")
            await pump(loop, 5)
        await pump(loop, 100)

        # The healthy connection drains completely on the same event loop.
        assert healthy_transport.get_write_buffer_size() == 0
        assert bytes(healthy.wire) == b"ping" * 10
        # While the stuck one never drains, stays paused and is hard bounded.
        assert blocked_transport._protocol_paused
        assert blocked_transport.get_write_buffer_size() == 40
        blocked_transport.abort()
        healthy_transport.abort()
        assert blocked_proto.pause_writing.called

    async def test_dropped_tail_corrupts_next_command_is_detected(self):
        """Regression guard: losing a frame tail splices the next command.

        A buggy variant that truncates the unwritten tail is driven through the
        same short-write schedule as the fixed transport.  The assertion names
        the exact offset where the following command gets misspelled.
        """
        loop = asyncio.get_running_loop()
        frame_a = b"\x01\x03\x00\x00\x00\x02"  # 6 byte command
        frame_b = b"\x02\x06\x00\x01\x00\x03"  # next command
        expected = frame_a + frame_b

        buggy_fake = PartialSerial()
        with mock.patch(
            "pymodbus.transport.serialtransport.serial.serial_for_url",
            return_value=buggy_fake,
        ):
            buggy = TailDroppingTransport(
                loop, mock.Mock(), "dummy", None, None, None, None, None
            )
        buggy.write(frame_a)
        buggy.write(frame_b)
        buggy.intern_write_ready()  # short write -> tail of frame A dropped
        buggy.intern_write_ready()  # frame B spliced onto the truncated A

        actual = bytes(buggy_fake.wire)
        offset = first_divergence(expected, actual)
        # The first three bytes of frame A survive; frame B then starts where
        # the dropped tail should have been, i.e. the next command is misspelled
        # starting at offset 3 (inside frame A).
        assert offset == len(frame_a[:3])
        assert actual.startswith(frame_a[:3])
        assert actual != expected
        buggy.abort()

        # The fixed transport on the identical schedule keeps the tail and
        # therefore delivers both commands byte-for-byte.
        good_fake = PartialSerial()
        good_transport, _ = make_transport(loop, good_fake)
        good_transport.write(frame_a)
        good_transport.write(frame_b)
        for _ in range(10):
            good_transport.intern_write_ready()
        assert bytes(good_fake.wire) == expected
        good_transport.abort()


class TestSerialPolling:
    """Exercise the force-poll path used on Windows."""

    async def test_poll_mode_backpressure_and_ordering(self):
        """The polling task drains bounded buffers without busy spinning."""
        loop = asyncio.get_running_loop()
        original_force_poll = SerialTransport.force_poll
        SerialTransport.force_poll = True
        try:
            fake = FakeSerial(write_plan=[2, 0, 3, 1, 4, 2])
            transport, protocol = make_transport(loop, fake, high=32, low=8)
            transport.setup()
            await pump(loop, 5)

            transport.write(b"abcdef")
            transport.write(b"ghijkl")
            transport.write(b"mnopqr")
            await asyncio.sleep(0.05)

            assert transport.get_write_buffer_size() == 0
            assert bytes(fake.wire) == b"abcdefghijklmnopqr"
            transport.close()
            await pump(loop, 10)
            assert fake.closed
            protocol.connection_lost.assert_called_once_with(None)
        finally:
            SerialTransport.force_poll = original_force_poll
