##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Controlled, re-runnable graceful shutdown.

The shutdown is split into four independently observable stages so that a
rolling deployment can tell exactly where a server stopped:

1. ``STOP_ACCEPTING`` - the listening socket(s) stop taking new connections.
   No new (sensitive) request can enter after this point.
2. ``DRAIN_QUEUE``    - requests already parsed and queued are allowed to run.
3. ``DRAIN_RUNNING``  - the WSGI applications that are executing are given a
   bounded deadline to finish.
4. ``DRAIN_OUTPUT``   - the bytes the finished applications produced are
   flushed to clients.

If the deadline expires while work or output is still outstanding, the
remaining channels are *aborted*.  An abort drops the connection without
writing the normal response terminator (the chunked ``0\\r\\n\\r`` footer or a
Content-Length satisfying final chunk), so the client observes an incomplete
transfer rather than a response that looks normally completed.
"""

from collections import namedtuple

from . import wasyncore

# Shutdown states, ordered.  A higher number means further along.
IDLE = "idle"
STOP_ACCEPTING = "stop-accepting"
DRAIN_QUEUE = "drain-queue"
DRAIN_RUNNING = "drain-running"
DRAIN_OUTPUT = "drain-output"
FORCED = "forced"
COMPLETE = "complete"

# A snapshot of the four things the task asks us to watch separately.
DrainStatus = namedtuple(
    "DrainStatus",
    (
        "accepting",
        "queued",
        "running",
        "buffered_bytes",
        "open_channels",
    ),
)


class GracefulShutdown:
    """Drive a single server through a bounded, re-runnable shutdown.

    The controller never blocks on real time by itself.  ``poll`` performs one
    non-blocking maintenance step and returns the current :class:`DrainStatus`.
    A runner (the blocking :meth:`wait` helper, a test, or an external
    supervisor) decides how long to keep polling.  Re-calling :meth:`begin`
    after a completed or forced shutdown is supported.
    """

    def __init__(self, server, timeout=30.0, time=None, poll_interval=0.1):
        self.server = server
        self.timeout = float(timeout)
        self.poll_interval = poll_interval
        # ``time`` is a shim so tests can supply a fake clock.  It only needs
        # ``time()`` and ``sleep()``.
        if time is None:
            import time as _time

            time = _time
        self._time = time
        self.state = IDLE
        self.deadline = None
        self.forced_channels = []

    # -- lifecycle ---------------------------------------------------------

    def begin(self):
        """Stage 1: stop accepting new connections.

        Idempotent: calling this on an already-started controller is a no-op.
        Returns ``self`` so callers can chain ``GracefulShutdown(s).begin()``.
        """
        if self.state != IDLE:
            return self
        for listener in self._listeners():
            listener.accepting = False
        # Requests already in flight must not be allowed to pull freshly
        # pipelined requests into the queue.  Mark every open channel so its
        # readable()/received() paths refuse new work.
        for channel in self._channels():
            channel.shutting_down = True
        self.state = STOP_ACCEPTING
        self.deadline = self._time.time() + self.timeout
        return self

    def wait(self):
        """Block (using real/fake sleep) until complete or forced.

        Returns the final :class:`DrainStatus`.  This is the convenience
        wrapper used by ``server.graceful_shutdown``; tests normally call
        :meth:`poll` directly against a fake clock instead.
        """
        self.begin()
        while self.state not in (COMPLETE, FORCED):
            status = self.poll()
            if self.state not in (COMPLETE, FORCED):
                self._time.sleep(self.poll_interval)
        return status

    # -- observation -------------------------------------------------------

    def status(self):
        queued, running = self._dispatcher_load()
        buffered = 0
        channels = self._channels()
        for channel in channels:
            buffered += getattr(channel, "total_outbufs_len", 0)
        accepting = any(getattr(s, "accepting", False) for s in self._listeners())
        return DrainStatus(
            accepting=accepting,
            queued=queued,
            running=running,
            buffered_bytes=buffered,
            open_channels=len(channels),
        )

    def poll(self):
        """Run one maintenance step.

        Advances through the drain stages while the deadline has not passed.
        On expiry the remaining channels are aborted and the state becomes
        :data:`FORCED`.  Otherwise, once nothing is outstanding, the listening
        socket and all channels are closed cleanly and the state becomes
        :data:`COMPLETE`.
        """
        if self.state == IDLE:
            self.begin()

        if self.state in (COMPLETE, FORCED):
            return self.status()

        expired = self._time.time() >= self.deadline

        # Drive the I/O loop once so buffered output can actually be sent and
        # completed channels can remove themselves.  A zero timeout keeps this
        # non-blocking and deterministic for the fake clock.
        wasyncore.poll(0.0, self._map())

        status = self.status()

        if expired:
            return self._force(status)

        # Advance the stage marker purely for observability.  The actual drain
        # condition is "nothing left anywhere"; stages only describe what is
        # currently the bottleneck.
        if status.queued:
            self.state = DRAIN_QUEUE
        elif status.running:
            self.state = DRAIN_RUNNING
        elif status.buffered_bytes or status.open_channels:
            self.state = DRAIN_OUTPUT
        else:
            return self._finish()

        return status

    # -- internals ---------------------------------------------------------

    def _force(self, status):
        # Abort everything that remains.  ``abort`` closes the socket
        # immediately and discards the outbuf, so no normal terminator can be
        # appended: the client only ever sees the bytes already transmitted.
        remaining = self._channels()
        for channel in remaining:
            channel.abort()
        self.forced_channels = remaining
        wasyncore.poll(0.0, self._map())
        self.state = FORCED
        return self.status()

    def _finish(self):
        # Clean shutdown: every queued/running request completed and every
        # outbuf reached the client.  Close the listening socket and let the
        # dispatcher wind its threads down.
        dispatcher = getattr(self.server, "task_dispatcher", None)
        if dispatcher is not None and hasattr(dispatcher, "shutdown"):
            dispatcher.shutdown(cancel_pending=True, timeout=self.timeout)
        for listener in self._listeners():
            try:
                listener.close()
            except OSError:
                pass
        wasyncore.close_all(self._map())
        self.state = COMPLETE
        return self.status()

    def _map(self):
        # BaseWSGIServer exposes its wasyncore map as ``_map``; the
        # MultiSocketServer wrapper holds the shared map as ``map``.
        map = getattr(self.server, "_map", None)
        if map is not None:
            return map
        return self.server.map

    def _channels(self):
        # Prefer the server's live channel registry when present (single
        # socket server); otherwise derive HTTP channels from the socket map.
        active = getattr(self.server, "active_channels", None)
        if active is not None:
            return list(active.values())
        from .channel import HTTPChannel

        return [
            obj
            for obj in self._map().values()
            if isinstance(obj, HTTPChannel)
        ]

    def _listeners(self):
        # A single-socket server is its own listener.  MultiSocketServer keeps
        # the individual TcpWSGIServer objects in its map.
        if hasattr(self.server, "accept_connections"):
            return [self.server]
        return [
            obj
            for obj in self.server.map.values()
            if hasattr(obj, "accept_connections")
        ]

    def _dispatcher_load(self):
        dispatcher = getattr(self.server, "task_dispatcher", None)
        if dispatcher is None:
            return 0, 0
        with dispatcher.lock:
            queued = len(dispatcher.queue)
            # active_count counts threads currently executing a task; idle
            # threads are parked in queue_cv.wait().  It can transiently read
            # below zero around thread teardown, so clamp it.
            running = max(dispatcher.active_count, 0)
            # A task parked in the queue with no idle worker is still "in
            # flight" from a drain perspective; treat it as running work once
            # the queue itself is no longer the headline bottleneck.
            if not running and queued:
                running = queued
        return queued, running
