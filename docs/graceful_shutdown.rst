Controlled (Graceful) Shutdown
==============================

.. contents::
   :local:

Why a dedicated shutdown path
-----------------------------

A rolling restart of a security/update service must never leave a client
holding a response that *looks* complete but was actually truncated.  The
shutdown machinery in :mod:`waitress.graceful` separates the four things that
were previously conflated, gives them a single deadline, and guarantees that
any deadline breach is visible to the client as an **incomplete transfer**.

The four independently observed quantities are reported together in a
:class:`~waitress.graceful.DrainStatus` named tuple:

``accepting``
    Whether any listening socket still admits new connections.

``queued``
    Requests already parsed and sitting in the
    :class:`~waitress.task.ThreadedTaskDispatcher` queue waiting for a worker.

``running``
    WSGI applications currently executing on a worker thread.

``buffered_bytes`` / ``open_channels``
    Response bytes already produced but not yet flushed, and the channels that
    still own them.  Output buffering is deliberately watched separately from
    running applications: a finished app can still have megabytes queued in a
    slow client's outbuf.

Shutdown stages
---------------

A :class:`~waitress.graceful.GracefulShutdown` controller moves through the
states in :mod:`waitress.graceful`:

1. ``stop-accepting`` — every listener flips ``accepting = False`` and every
   open channel is flagged ``shutting_down``.  New connections stop at the
   kernel backlog, and pipelined requests on existing connections are refused
   by :meth:`waitress.channel.HTTPChannel.readable` /
   :meth:`~waitress.channel.HTTPChannel.received`.  No new sensitive request
   can enter the WSGI application after this point.
2. ``drain-queue`` — already-queued requests are handed to workers.
3. ``drain-running`` — executing WSGI applications run to completion while the
   deadline has not passed.
4. ``drain-output`` — finished responses are flushed through the outbufs.
5. Terminal state, exactly one of:

   ``complete``
       Nothing was outstanding.  Listeners and channels close cleanly; every
       response kept its normal terminator (the chunked ``0\r\n\r\n`` footer
       or a Content-Length-satisfying body).

   ``forced``
       The deadline expired with work or output outstanding.  Every remaining
       channel is :meth:`aborted <waitress.channel.HTTPChannel.abort>`: its
       outbuf is discarded and the socket is closed immediately, bypassing the
       normal write path.  No terminator is ever appended, so the client's
       next read returns EOF (or a reset) partway through the body.

What the pre-existing close interface guarantees
-------------------------------------------------

The historical entry points are:

* :meth:`waitress.server.BaseWSGIServer.run` only calls
  ``task_dispatcher.shutdown()`` when it catches ``SystemExit`` /
  ``KeyboardInterrupt``;
* :meth:`waitress.server.BaseWSGIServer.close` closes the trigger and the
  listening dispatcher;
* :meth:`waitress.task.ThreadedTaskDispatcher.shutdown` asks the worker
  threads to stop, waits up to a fixed ``timeout`` (default 5 s), logs
  "*N thread(s) still running*" on timeout, then ``cancel()``s queued tasks;
* :meth:`waitress.channel.HTTPChannel.cancel` sets ``will_close`` /
  ``connected = False`` and empties the request list, but still lets the
  normal :meth:`~waitress.channel.HTTPChannel.handle_write` path flush whatever
  is in the outbuf.

Consequently the old interface guarantees only that **threads are eventually
asked to stop and queued tasks are cancelled**.  It does **not** provide:

* a single observable deadline spanning accept, queue, running app and output
  buffer;
* a guarantee that listeners stop accepting *before* workers wind down;
* any protection against a partial download being indistinguishable from a
  normal completion — ``cancel`` relies on the ordinary flush path and does
  not suppress a chunked terminator;
* a re-runnable, externally observable state machine.

The new :meth:`waitress.server.BaseWSGIServer.graceful_shutdown` (and the
identically named method on :class:`~waitress.server.MultiSocketServer`) wrap a
:class:`~waitress.graceful.GracefulShutdown` to close those gaps.

Usage
-----

Blocking convenience wrapper::

    controller = server.graceful_shutdown(timeout=30)
    if controller.state == "forced":
        # at least one response was truncated on purpose
        ...

Driving the controller step by step (for a supervisor or tests with a fake
clock)::

    from waitress.graceful import GracefulShutdown

    controller = GracefulShutdown(server, timeout=30, time=clock).begin()
    while controller.state not in ("complete", "forced"):
        status = controller.poll()   # one non-blocking maintenance step
        # status.accepting / .queued / .running / .buffered_bytes ...

``begin()`` is idempotent and a fresh controller can be built over the same
server once a prior shutdown has reached a terminal state, so the routine is
safe to re-run.

In-process demonstration
------------------------

``demo/graceful_shutdown_demo.py`` runs entirely in one process.  It uses a
``socketpair`` for the transport (no TCP port and no process supervisor) and a
fake clock for deterministic deadlines.  It shows a short application draining
to a clean, terminator-complete response and a slow application being aborted
into a terminator-free, truncated transfer::

    .venv/bin/python demo/graceful_shutdown_demo.py
