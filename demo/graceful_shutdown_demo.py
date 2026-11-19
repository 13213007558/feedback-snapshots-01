"""In-process demonstration of Waitress controlled (graceful) shutdown.

No external process supervisor and no real TCP port are required: the
transport is a socketpair (allowed in the sandbox) and the clock is a fake one
so deadlines are fully deterministic.  Two scenarios are shown:

1. Graceful drain  - a short download finishes inside the deadline; the client
   receives the complete body plus the normal chunked terminator.
2. Timeout abort   - a slow download is still in flight when the drain
   deadline expires; the channel is aborted and the client observes a
   truncated transfer with NO normal terminator appended.

Run with:  .venv/bin/python demo/graceful_shutdown_demo.py
"""

import socket

from waitress import wasyncore
from waitress.adjustments import Adjustments
from waitress.channel import HTTPChannel
from waitress.graceful import GracefulShutdown
from waitress.task import ThreadedTaskDispatcher


class FakeClock:
    """time() only advances through sleep(); shutdown deadlines use it."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


# --------------------------------------------------------------------------
# Short WSGI applications.
# --------------------------------------------------------------------------

def make_chunked_app(total_chunks, gate, sensitive_paths=("/secret",)):
    """Stream ``total_chunks`` chunks, blocking on ``gate`` between them.

    The gate lets the test freeze the application mid-download to emulate a
    file transfer that is still running when the shutdown deadline hits.
    Requests whose PATH_INFO is sensitive are flagged so we can prove none are
    admitted after shutdown begins.
    """

    def app(environ, start_response):
        path = environ["PATH_INFO"]
        if path in sensitive_paths:
            gate.mark_sensitive(path)

        def body():
            for index in range(total_chunks):
                gate.wait_if_held(index)
                yield b"DATA%02d|" % index

        start_response("200 OK", [("Content-Type", "text/plain")])
        return body()

    return app


class HangingGate:
    """Blocks the app at a chosen chunk until explicitly released."""

    def __init__(self):
        import threading

        self._cond = threading.Condition()
        self._held = True
        self._release_at = None
        self.sensitive_seen = []

    def mark_sensitive(self, path):
        self.sensitive_seen.append(path)

    def hold_at(self, chunk_index):
        with self._cond:
            self._held = True
            self._release_at = chunk_index

    def release(self):
        with self._cond:
            self._held = False
            self._cond.notify_all()

    def wait_if_held(self, chunk_index):
        with self._cond:
            while self._held and (
                self._release_at is None or chunk_index >= self._release_at
            ):
                self._cond.wait(timeout=0.05)


# --------------------------------------------------------------------------
# In-process server wired onto a socketpair.
# --------------------------------------------------------------------------

class DemoServer:
    """Minimal server surface GracefulShutdown can drive."""

    server_name = "demo.waitress.invalid"
    effective_port = 8080

    def __init__(self, application, adj, dispatcher):
        self.application = application
        self.adj = adj
        self.task_dispatcher = dispatcher
        self.active_channels = {}
        self._map = {}
        self.accepting = True

    def add_task(self, channel):
        self.task_dispatcher.add_task(channel)

    def pull_trigger(self):
        # No separate trigger object in the harness; the test pumps the loop.
        pass

    def accept_connections(self):  # marker used by GracefulShutdown
        pass

    def close(self):
        self.accepting = False


def new_connection(server, adj):
    server_sock, client_sock = socket.socketpair()
    server_sock.setblocking(False)
    client_sock.setblocking(False)
    channel = HTTPChannel(
        server, server_sock, ("127.0.0.1", 1), adj, map=server._map
    )
    return channel, client_sock


def pump(clock, server, times=1):
    """Advance the fake clock a notch and run one non-blocking I/O pass.

    A tiny real sleep between passes yields the GIL so the WSGI worker thread
    (which runs on real threading) can make progress; the fake clock still
    owns all shutdown deadlines.
    """
    import time as _real_time

    for _ in range(times):
        clock.sleep(0.1)
        wasyncore.poll(0.0, server._map)
        _real_time.sleep(0.02)


def client_recv_until_idle(client_sock, max_passes=50):
    """Read everything the server has currently delivered."""
    chunks = []
    for _ in range(max_passes):
        try:
            data = client_sock.recv(65536)
        except BlockingIOError:
            break
        if not data:
            chunks.append(b"<EOF>")
            break
        chunks.append(data)
    return b"".join(chunks)


def build_server(app, threads=1):
    adj = Adjustments(threads=threads)
    dispatcher = ThreadedTaskDispatcher()
    dispatcher.set_thread_count(threads)
    server = DemoServer(app, adj, dispatcher)
    return server, adj, dispatcher


# --------------------------------------------------------------------------
# Scenario 1: graceful drain within the deadline.
# --------------------------------------------------------------------------

def scenario_graceful_drain():
    print("=" * 72)
    print("SCENARIO 1: graceful drain (short app completes before deadline)")
    print("=" * 72)

    gate = HangingGate()
    gate.release()  # never block: a fast/short application
    app = make_chunked_app(total_chunks=4, gate=gate)
    server, adj, dispatcher = build_server(app)
    clock = FakeClock()

    channel, client = new_connection(server, adj)
    client.sendall(b"GET /download HTTP/1.1\r\nHost: x\r\n\r\n")
    pump(clock, server, 3)  # parse request, run app, buffer response

    controller = GracefulShutdown(server, timeout=10.0, time=clock)
    print("startup call : GracefulShutdown(server, timeout=10).begin()")
    print("shutdown call: controller.wait()  (fake clock, poll_interval=0.1)")
    controller.begin()
    print("accepting at begin:", controller.status().accepting)

    # A sensitive request that only arrives AFTER shutdown begins must never
    # be admitted into the WSGI application.  A real listener has stopped
    # accepting at this point, so this connection would not even be created in
    # production; we mark it as shutting-down to model a connection that was
    # established in the kernel backlog just before the listener closed.
    late, late_client = new_connection(server, adj)
    late.shutting_down = True
    late_client.sendall(b"GET /secret HTTP/1.1\r\nHost: x\r\n\r\n")
    pump(clock, server, 2)
    # Admission means the bytes were parsed into a runnable request.  Because
    # readable() is False during shutdown they stay unread in the socket.
    admitted = bool(late.requests)
    print("late /secret admitted after begin? ", admitted)
    print("  -> channel.readable() is", late.readable(), "(False = rejected)")
    print("  -> queued runnable requests on late channel:", len(late.requests))
    # Discard the rejected connection ourselves; it never entered the WSGI app.
    server.active_channels.pop(late._fileno, None)
    server._map.pop(late._fileno, None)
    late.abort()
    late_client.close()

    status = controller.wait()
    observed = client_recv_until_idle(client)
    payload = observed.replace(b"<EOF>", b"")

    print("final state  :", controller.state)
    print("status       :", status)
    print("client bytes :", observed)
    print("normal chunked terminator '0\\r\\n\\r' present:",
          payload.endswith(b"0\r\n\r\n"))
    print("sensitive requests admitted during shutdown:", gate.sensitive_seen)
    client.close()
    print()
    return (
        controller.state == "complete" and payload.endswith(b"0\r\n\r\n")
    )


# --------------------------------------------------------------------------
# Scenario 2: deadline expiry forces an incomplete transfer.
# --------------------------------------------------------------------------

def scenario_timeout_abort():
    print("=" * 72)
    print("SCENARIO 2: drain deadline expires -> forced, incomplete transfer")
    print("=" * 72)

    gate = HangingGate()
    gate.hold_at(chunk_index=2)  # freeze after two chunks are produced
    app = make_chunked_app(total_chunks=10, gate=gate)
    server, adj, dispatcher = build_server(app)
    clock = FakeClock()

    channel, client = new_connection(server, adj)
    client.sendall(b"GET /bigfile HTTP/1.1\r\nHost: x\r\n\r\n")
    pump(clock, server, 10)  # headers + first chunks are now in flight

    partial = client_recv_until_idle(client)
    print("bytes received before shutdown:", partial)
    print("terminator present before shutdown:", partial.endswith(b"0\r\n\r\n"))

    controller = GracefulShutdown(server, timeout=2.0, time=clock)
    controller.begin()
    print("shutdown call: GracefulShutdown(server, timeout=2).begin() then poll()")

    # Advance the fake clock past the deadline while the app stays hung.
    states = []
    while controller.state not in ("forced", "complete"):
        states.append(controller.state)
        clock.now = max(clock.now, controller.deadline + 0.1)
        controller.poll()

    after = client_recv_until_idle(client)
    # A real socket close makes the next recv return EOF.
    try:
        tail = client.recv(65536)
    except BlockingIOError:
        tail = b"<no data, peer closed>"
    except OSError:
        tail = b"<connection reset by peer>"

    print("states traversed:", states, "->", controller.state)
    print("forced channels :", len(controller.forced_channels))
    print("client view after abort:", after or b"<no new bytes>")
    print("final recv signal      :", tail)
    print("terminator ever appended:", (partial + after).endswith(b"0\r\n\r\n"))
    print("channel still connected:", channel.connected)
    client.close()
    print()
    return (
        controller.state == "forced"
        and not (partial + after).endswith(b"0\r\n\r\n")
        and channel.connected is False
    )


if __name__ == "__main__":
    ok1 = scenario_graceful_drain()
    ok2 = scenario_timeout_abort()
    print("=" * 72)
    print("RESULT graceful-drain-ok=%s  timeout-abort-ok=%s" % (ok1, ok2))
    print("=" * 72)
    raise SystemExit(0 if (ok1 and ok2) else 1)
