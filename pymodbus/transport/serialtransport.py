"""asyncio serial support for modbus (based on pyserial).

The serial port is a slow, blocking device compared with the upstream
requests.  To stop a slow port from growing an unbounded output backlog, the
transport keeps the pending bytes bounded and drives the standard asyncio
write flow control:

* :meth:`write` never silently truncates a frame.  Accepted bytes are kept in
  order and the remainder of a partially written frame is re-queued ahead of
  any later frame, so command bytes cannot be reordered on the wire.
* when the buffered byte count crosses the high-water limit the protocol is
  paused (``pause_writing``) and resumed (``resume_writing``) once it drains
  below the low-water limit.
* :meth:`close` drains the already accepted bytes before closing while
  :meth:`abort` discards pending bytes and closes immediately.  After the
  transport is closing or closed no further bytes are accepted or written.

The event loop is never blocked waiting for the port to drain: writes stay
non-blocking and a writer callback (or the polling task on Windows) is
rescheduled until the buffer has been transmitted.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys


with contextlib.suppress(ImportError):
    import serial


class SerialTransport(asyncio.Transport):
    """An asyncio serial transport."""

    force_poll: bool = os.name == "nt"
    # async_loop: asyncio.AbstractEventLoop

    def __init__(
        self, loop, protocol, url, baudrate, bytesize, parity, stopbits, timeout
    ) -> None:
        """Initialize."""
        super().__init__()
        if "serial" not in sys.modules:
            raise RuntimeError(
                "Serial client requires pyserial "
                'Please install with "pip install pyserial" and try again.'
            )
        self.async_loop = loop
        self.intern_protocol: asyncio.BaseProtocol = protocol
        self.sync_serial = serial.serial_for_url(
            url,
            exclusive=True,
            baudrate=baudrate,
            bytesize=bytesize,
            parity=parity,
            stopbits=stopbits,
            timeout=timeout,
        )
        self.intern_write_buffer: list[bytes] = []
        self.intern_write_buffer_size: int = 0
        self._high_water: int = 2**16
        self._low_water: int = 2**14
        self._protocol_paused: bool = False
        self._writer_active: bool = False
        self._closing: bool = False
        self._closed: bool = False
        self.poll_task: asyncio.Task | None = None
        self._poll_wait_time = 0.0005
        self.sync_serial.timeout = 0
        self.sync_serial.write_timeout = 0

    def setup(self) -> None:
        """Prepare to read/write."""
        if self.force_poll:
            self.poll_task = asyncio.create_task(self.polling_task())
            self.poll_task.set_name("SerialTransport poll")
        else:
            self.async_loop.add_reader(
                self.sync_serial.fileno(), self.intern_read_ready
            )
        self.async_loop.call_soon(self.intern_protocol.connection_made, self)

    def close(self, exc: Exception | None = None) -> None:
        """Close the transport.

        Without an exception the transport is closed gracefully: bytes already
        accepted by :meth:`write` are transmitted as the port accepts them and
        the port is only closed once the output buffer is drained.  New writes
        are rejected while the drain is in progress.

        With an exception the transport is torn down immediately (as with
        :meth:`abort`): pending bytes are discarded and the protocol is
        notified with the exception.
        """
        if self._closed or self.sync_serial is None:
            self._closed = True
            return
        if exc:
            self._hard_close(exc)
            return
        if self._closing:
            return
        self._closing = True
        if self.intern_write_buffer:
            # Keep draining the accepted bytes; the last successful write
            # completes the close through _hard_close().
            self._ensure_writer()
            return
        self._hard_close(None)

    def abort(self) -> None:
        """Close immediately and discard any buffered output.

        Unlike :meth:`close` the pending write buffer is not transmitted and
        the port is closed without waiting for the serial line to drain.
        """
        if self._closed:
            return
        self._hard_close(None)

    def write(self, data) -> None:
        """Queue data for the serial port.

        The whole frame is queued in order; partial serial writes keep the
        unwritten tail ahead of any frame written later.  Writes arriving
        after a close/abort has started are ignored instead of touching the
        released serial port.
        """
        if self._closing or self._closed or self.sync_serial is None:
            return
        if not data:
            return
        self.intern_write_buffer.append(bytes(data))
        self.intern_write_buffer_size += len(data)
        self._ensure_writer()
        self._maybe_pause_protocol()

    def flush(self) -> None:
        """Discard the output buffer and stop the writer callback."""
        self.intern_write_buffer.clear()
        self.intern_write_buffer_size = 0
        self._writer_active = False
        if not self.poll_task and self.sync_serial is not None:
            self.async_loop.remove_writer(self.sync_serial.fileno())
        self._maybe_resume_protocol()

    # ------------------------------------------------
    # Dummy methods needed to please asyncio.Transport.
    # ------------------------------------------------
    @property
    def loop(self):
        """Return asyncio event loop."""
        return self.async_loop

    def get_protocol(self) -> asyncio.BaseProtocol:
        """Return protocol."""
        return self.intern_protocol

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        """Set protocol."""
        self.intern_protocol = protocol

    def get_write_buffer_limits(self) -> tuple[int, int]:
        """Return (low-water, high-water) write buffer limits in bytes."""
        return (self._low_water, self._high_water)

    def can_write_eof(self):
        """Return Serial do not support end-of-file."""
        return False

    def write_eof(self):
        """Write end of file marker."""

    def set_write_buffer_limits(self, high=None, low=None):
        """Set the high- and low-water limits for write flow control.

        Mirrors asyncio's semantics: a ``None`` high limit restores the
        default and a ``None`` low limit defaults to high // 4.
        """
        if high is None:
            high = 2**16
        if high <= 0:
            raise ValueError("high water mark must be positive")
        if low is None:
            low = high // 4
        if not 0 <= low <= high:
            raise ValueError("low water mark must satisfy 0 <= low <= high")
        self._high_water = high
        self._low_water = low
        self._maybe_pause_protocol()
        self._maybe_resume_protocol()

    def get_write_buffer_size(self):
        """Return the number of bytes queued in the write buffer."""
        return self.intern_write_buffer_size

    def is_reading(self) -> bool:
        """Return true if read is active."""
        return not self._closed

    def pause_reading(self):
        """Pause receiver."""

    def resume_reading(self):
        """Resume receiver."""

    def is_closing(self):
        """Return True if the transport is closing or closed."""
        return self._closing or self._closed

    # ------------------------------------------------
    # Write flow control
    # ------------------------------------------------
    def _maybe_pause_protocol(self) -> None:
        """Pause the protocol once the high-water mark is exceeded."""
        if (
            not self._protocol_paused
            and self.intern_write_buffer_size > self._high_water
        ):
            self._protocol_paused = True
            with contextlib.suppress(AttributeError):
                self.intern_protocol.pause_writing()

    def _maybe_resume_protocol(self) -> None:
        """Resume the protocol after draining below the low-water mark."""
        if self._protocol_paused and self.intern_write_buffer_size <= self._low_water:
            self._protocol_paused = False
            with contextlib.suppress(AttributeError):
                self.intern_protocol.resume_writing()

    def _ensure_writer(self) -> None:
        """Schedule the writer callback once until the buffer is drained."""
        if self.poll_task or self._writer_active or self.sync_serial is None:
            return
        self._writer_active = True
        self.async_loop.add_writer(self.sync_serial.fileno(), self.intern_write_ready)

    def _hard_close(self, exc: Exception | None) -> None:
        """Release the serial port and notify the protocol exactly once."""
        if self._closed:
            return
        self._closing = True
        self.flush()
        if self.poll_task:
            self.poll_task.cancel()
            self.poll_task = None
        elif self.sync_serial is not None:
            self.async_loop.remove_reader(self.sync_serial.fileno())
            self.async_loop.remove_writer(self.sync_serial.fileno())
        if self.sync_serial is not None:
            self.sync_serial.close()
            self.sync_serial = None  # type: ignore[assignment]
        self._closed = True
        with contextlib.suppress(Exception):
            self.intern_protocol.connection_lost(exc)

    def intern_read_ready(self) -> None:
        """Test if there are data waiting."""
        if self.sync_serial is None:
            return
        try:
            if data := self.sync_serial.read(1024):
                self.intern_protocol.data_received(data)  # type: ignore[attr-defined]
        except serial.SerialException as exc:
            self.close(exc=exc)

    def intern_write_ready(self) -> None:
        """Asynchronously write buffered data.

        Returns ``True`` when at least one byte was transmitted.  A short or
        zero-length write keeps the unwritten tail at the front of the buffer
        (so the next frame cannot overtake it) and keeps the writer scheduled.
        The event loop is never blocked while waiting for room in the port.
        """
        if self._closed or not self.intern_write_buffer or self.sync_serial is None:
            return False
        data = b"".join(self.intern_write_buffer)
        try:
            count = self.sync_serial.write(data)
        except (BlockingIOError, InterruptedError, serial.SerialTimeoutException):
            # Temporarily unwritable: keep the whole frame and retry.
            return False
        except serial.SerialException as exc:
            self.close(exc=exc)
            return False
        written = count if isinstance(count, int) else 0
        if written < 0:
            written = 0
        if written > len(data):
            written = len(data)
        if not written:
            # Zero progress: the buffer is untouched and the writer (or the
            # polling task) retries when the port can accept bytes again.
            return False
        self.intern_write_buffer_size -= written
        if written < len(data):
            self.intern_write_buffer = [data[written:]]
            # The writer stays registered; short writes do not complete the
            # buffer and must never let a later frame jump ahead.
            return True
        self.flush()
        if self._closing:
            # Graceful close: every accepted byte has reached the port now.
            self._hard_close(None)
        return True

    async def polling_task(self):
        """Poll and try to read/write without blocking the loop."""
        while not self._closed and self.sync_serial is not None:
            await asyncio.sleep(self._poll_wait_time)
            if self.intern_write_buffer:
                # A single attempt per cycle; a blocked port must not busy
                # spin the loop while waiting for room to write.
                self.intern_write_ready()
            if self.sync_serial is not None and self.sync_serial.in_waiting:
                self.intern_read_ready()


async def create_serial_connection(
    loop,
    protocol_factory,
    url,
    baudrate=None,
    bytesize=None,
    parity=None,
    stopbits=None,
    timeout=None,
) -> tuple[asyncio.Transport, asyncio.BaseProtocol]:
    """Create a connection to a new serial port instance."""
    protocol = protocol_factory()
    transport = SerialTransport(
        loop, protocol, url, baudrate, bytesize, parity, stopbits, timeout
    )
    loop.call_soon(transport.setup)
    return transport, protocol
