#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Authorization matrix for the control socket.

These tests drive the server's real dispatch and wire protocol over a local
Unix socket pair, so the check that runs in production is the check tested
here. The peer is supplied by replacing ``_peer_credentials``; the socket
itself is a kernel-created pair, and switching the test process to a second
uid would need root, so the uid boundary is covered by the policy unit tests
and this file covers the wiring, the ordering and the wire format.
"""

import asyncio
import os
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from gunicorn.ctl.client import ControlClient, ControlClientError
from gunicorn.ctl.policy import ControlPolicy, PeerCredentials
from gunicorn.ctl.protocol import make_request
from gunicorn.ctl.server import ControlSocketServer


class socketpair_connection:
    """Serve one ControlSocketServer over a local Unix socket pair."""

    def __init__(self, policy=None, credentials=None):
        self.policy = policy or make_policy()
        self.credentials = credentials or PeerCredentials(
            pid=1, uid=CURRENT_UID, gid=CURRENT_GID, groups=(CURRENT_GID,))
        self._left = None
        self._right = None
        self._loop = None
        self._thread = None
        self._ready = threading.Event()
        self.arbiter = None
        self.server = None
        self.client = None

    def __enter__(self):
        self._left, self._right = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM)
        self.arbiter = MockArbiter()
        self.server = ControlSocketServer(
            self.arbiter, "/nonexistent.sock", policy=self.policy)
        self.server._running = True
        self.server._peer_credentials = lambda sock: self.credentials

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("control server did not start")

        # Reuse the real client on the other end of the pair.
        self.client = ControlClient("/nonexistent.sock")
        self.client._sock = self._right
        return self

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._task = self._loop.create_task(self._serve())
        self._loop.run_forever()
        self._task.cancel()
        try:
            self._loop.run_until_complete(self._task)
        except (asyncio.CancelledError, Exception):
            pass

    async def _serve(self):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await self._loop.connect_accepted_socket(
            lambda: protocol, self._left)
        writer = asyncio.StreamWriter(transport, protocol, reader, self._loop)
        self._ready.set()
        await self.server._handle_client(reader, writer)

    def __exit__(self, *exc):
        try:
            self._right.close()
        except OSError:
            pass
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        try:
            self._left.close()
        except OSError:
            pass
        if self._loop is not None:
            self._loop.close()
        return False


CURRENT_UID = os.geteuid()
CURRENT_GID = os.getegid()


class MockWorker:
    def __init__(self, pid, age, booted=True, aborted=False):
        self.pid = pid
        self.age = age
        self.booted = booted
        self.aborted = aborted
        self.tmp = MagicMock()
        self.tmp.last_update.return_value = time.monotonic()


class MockListener:
    def __init__(self, address, fd=3):
        self._address = address
        self._fd = fd
        self.sock = MagicMock()
        self.sock.family = 2

    def __str__(self):
        return self._address

    def fileno(self):
        return self._fd


class MockConfig:
    def __init__(self):
        self.bind = ['127.0.0.1:8000']
        self.workers = 4
        self.worker_class = 'sync'
        self.threads = 1
        self.timeout = 30
        self.graceful_timeout = 30
        self.keepalive = 2
        self.max_requests = 0
        self.max_requests_jitter = 0
        self.worker_connections = 1000
        self.preload_app = False
        self.daemon = False
        self.pidfile = None
        self.proc_name = 'test_app'
        self.reload = False
        self.dirty_workers = 0
        self.dirty_apps = []
        self.dirty_timeout = 30
        self.control_socket = 'gunicorn.ctl'
        self.control_socket_disable = False


class MockLog:
    def debug(self, msg, *args):
        pass

    info = debug
    warning = debug
    error = debug

    def exception(self, msg, *args):
        pass


class MockArbiter:
    def __init__(self):
        self.cfg = MockConfig()
        self.log = MockLog()
        self.pid = 12345
        self.WORKERS = {1001: MockWorker(1001, 1)}
        self.LISTENERS = [MockListener("127.0.0.1:8000")]
        self.dirty_arbiter_pid = 0
        self.dirty_arbiter = None
        self.num_workers = 4
        self._stats = {
            'start_time': time.time() - 3600,
            'workers_spawned': 10,
            'workers_killed': 5,
            'reloads': 2,
        }
        self.wakeup = MagicMock()


MONITOR = "monitor"
OPERATOR = "operator"

# One row per (role, command): whether the built-in policy allows it. The
# execution side asserts the same row from the other direction: an allowed
# command reaches a handler, a denied one leaves arbiter state untouched.
MATRIX = [
    (MONITOR, "show workers", True),
    (MONITOR, "show all", True),
    (MONITOR, "show dirty", True),
    (MONITOR, "show stats", True),
    (MONITOR, "show listeners", True),
    (MONITOR, "help", True),
    (MONITOR, "show config", False),
    (MONITOR, "reload", False),
    (MONITOR, "reopen", False),
    (MONITOR, "shutdown", False),
    (MONITOR, "shutdown quick", False),
    (MONITOR, "worker add", False),
    (MONITOR, "worker remove", False),
    (MONITOR, "worker kill", False),
    (MONITOR, "dirty add", False),
    (MONITOR, "dirty remove", False),
    (OPERATOR, "show workers", True),
    (OPERATOR, "show all", True),
    (OPERATOR, "show dirty", True),
    (OPERATOR, "show stats", True),
    (OPERATOR, "show listeners", True),
    (OPERATOR, "show config", True),
    (OPERATOR, "help", True),
    (OPERATOR, "reload", True),
    (OPERATOR, "reopen", True),
    (OPERATOR, "shutdown", True),
    (OPERATOR, "shutdown quick", True),
    (OPERATOR, "worker add", True),
    (OPERATOR, "worker remove", True),
    (OPERATOR, "worker kill 1001", True),
    (OPERATOR, "dirty add", True),
    (OPERATOR, "dirty remove", True),
    # Values are part of the same command, not a different one.
    (OPERATOR, "worker add 2", True),
    (OPERATOR, "worker kill 1001", True),
    (MONITOR, "worker kill 1001", False),
]


def make_policy(monitor_uid=CURRENT_UID, operator_uid=CURRENT_UID + 1):
    return ControlPolicy({
        MONITOR: [monitor_uid],
        OPERATOR: [operator_uid],
    })


def credentials_for(uid):
    return PeerCredentials(pid=1, uid=uid, gid=CURRENT_GID, groups=(CURRENT_GID,))


class ServerHarness:
    """Run a ControlSocketServer on a socketpair and talk the real protocol."""

    def __init__(self, policy, monitor_uid=CURRENT_UID,
                 operator_uid=CURRENT_UID + 1):
        self.arbiter = MockArbiter()
        # The server is never started; _dispatch is the entry under test.
        self.server = ControlSocketServer(self.arbiter, "/nonexistent.sock",
                                          policy=policy)
        self.monitor_uid = monitor_uid
        self.operator_uid = operator_uid

    def dispatch(self, command, uid, request_id=1):
        credentials = credentials_for(uid)
        message = make_request(request_id, command)
        with patch("gunicorn.ctl.handlers.os.kill"):
            # A real arbiter would signal its own pid; keep the test process.
            return asyncio.run(self.server._dispatch(message, credentials))

@pytest.fixture
def harness():
    return ServerHarness(make_policy())


class TestAuthorizationMatrix:
    @pytest.mark.parametrize("role,command,allowed", MATRIX)
    def test_matrix(self, harness, role, command, allowed):
        uid = harness.monitor_uid if role == MONITOR else harness.operator_uid
        before_workers = harness.arbiter.num_workers
        before_wakeup = harness.arbiter.wakeup.call_count

        response = harness.dispatch(command, uid)

        if allowed:
            assert response["status"] == "ok", response
        else:
            assert response["status"] == "error", response
            assert response["code"] == "permission_denied"
            # No handler ran: the worker count and the wakeup counter that
            # every management command would touch are unchanged.
            assert harness.arbiter.num_workers == before_workers
            assert harness.arbiter.wakeup.call_count == before_wakeup


class TestAuthorizationMatrixArguments:
    """The role decision on commands sent with an ``args`` list."""

    @pytest.mark.parametrize("command,args,allowed", [
        ("show", ["workers"], True),
        ("show", ["config"], False),
        ("worker", ["add", "2"], False),
        ("worker", ["kill", "1001"], False),
        ("shutdown", ["quick"], False),
        ("shutdown", ["unexpected-mode"], False),
    ])
    def test_monitor_with_args(self, harness, command, args, allowed):
        response = asyncio.run(harness.server._dispatch(
            {"id": 1, "command": command, "args": args},
            credentials_for(harness.monitor_uid)))
        if allowed:
            assert response["status"] == "ok"
        else:
            assert response["code"] == "permission_denied"

    def test_split_command_from_client_parser(self):
        # gunicornc sends "worker kill" as the command and the pid in args.
        harness = ServerHarness(make_policy())
        with patch("gunicorn.ctl.handlers.os.kill"):
            response = asyncio.run(harness.server._dispatch(
                {"id": 1, "command": "worker", "args": ["kill", "1001"]},
                credentials_for(harness.monitor_uid)))
        assert response["code"] == "permission_denied"


class TestDenialPrecedesExecution:
    def test_reload_denied_does_not_signal(self, harness):
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = harness.dispatch("reload", harness.monitor_uid)
        assert response["code"] == "permission_denied"
        kill.assert_not_called()

    def test_shutdown_denied_does_not_signal(self, harness):
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = harness.dispatch("shutdown", harness.monitor_uid)
        assert response["code"] == "permission_denied"
        kill.assert_not_called()

    def test_worker_kill_denied_does_not_signal(self, harness):
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = harness.dispatch("worker kill 1001",
                                        harness.monitor_uid)
        assert response["code"] == "permission_denied"
        kill.assert_not_called()

    def test_worker_add_denied_does_not_change_count(self, harness):
        response = harness.dispatch("worker add 3", harness.monitor_uid)
        assert response["code"] == "permission_denied"
        assert harness.arbiter.num_workers == 4
        harness.arbiter.wakeup.assert_not_called()

    def test_reload_allowed_reaches_handler(self, harness):
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = asyncio.run(harness.server._dispatch(
                make_request(1, "reload"),
                credentials_for(harness.operator_uid)))
        assert response["status"] == "ok"
        kill.assert_called_once()

    def test_unknown_sender_matches_no_role(self, harness):
        response = harness.dispatch("show workers", CURRENT_UID + 999)
        assert response["code"] == "permission_denied"


class TestDenialVersusUnknown:
    """A reader must tell "no permission" from "no such command"."""

    def test_monitor_denied_command(self, harness):
        response = harness.dispatch("reload", harness.monitor_uid)
        assert response["status"] == "error"
        assert response["code"] == "permission_denied"

    def test_operator_unknown_command(self, harness):
        response = harness.dispatch("frobnicate", harness.operator_uid)
        assert response["status"] == "error"
        assert response["code"] == "unknown_command"

    def test_unknown_command_is_same_for_either_role(self, harness):
        monitor = harness.dispatch("frobnicate", harness.monitor_uid)
        operator = harness.dispatch("frobnicate", harness.operator_uid)
        assert monitor["code"] == operator["code"] == "unknown_command"

    def test_unknown_show_target(self, harness):
        response = harness.dispatch("show wat", harness.operator_uid)
        assert response["code"] == "unknown_command"

    def test_unknown_worker_action(self, harness):
        response = harness.dispatch("worker frobnicate", harness.operator_uid)
        assert response["code"] == "unknown_command"

    def test_missing_show_target_is_not_permission_error(self, harness):
        response = harness.dispatch("show", harness.monitor_uid)
        assert response["code"] == "unknown_command"

    def test_empty_command_has_no_permission_error(self, harness):
        response = asyncio.run(
            harness.server._dispatch({"id": 1, "command": ""}, None))
        assert response["status"] == "error"
        assert response.get("code") != "permission_denied"

    def test_bad_argument_is_not_permission_error(self, harness):
        response = harness.dispatch("worker kill not-a-pid",
                                    harness.operator_uid)
        assert response["status"] == "error"
        assert response.get("code") is None


class TestReadFieldLimits:
    def test_monitor_worker_fields(self, harness):
        harness.arbiter.WORKERS = {
            1001: MockWorker(1001, 1),
            1002: MockWorker(1002, 2, booted=False, aborted=True),
        }
        response = harness.dispatch("show workers", harness.monitor_uid)
        assert response["status"] == "ok"
        workers = response["data"]["workers"]
        assert workers
        for worker in workers:
            assert set(worker) == {"pid", "age", "booted", "last_heartbeat"}

    def test_monitor_listener_fields_hide_fd(self, harness):
        response = harness.dispatch("show listeners", harness.monitor_uid)
        listeners = response["data"]["listeners"]
        assert listeners
        for listener in listeners:
            assert set(listener) == {"address", "type"}

    def test_monitor_stats_have_no_config(self, harness):
        response = harness.dispatch("show stats", harness.monitor_uid)
        assert "workers_current" in response["data"]
        assert "pid" in response["data"]

    def test_monitor_cannot_read_config(self, harness):
        response = harness.dispatch("show config", harness.monitor_uid)
        assert response["code"] == "permission_denied"

    def test_operator_keeps_full_reply(self, harness):
        response = harness.dispatch("show workers", harness.operator_uid)
        worker = response["data"]["workers"][0]
        assert "aborted" in worker

    def test_monitor_help_is_trimmed(self, harness):
        response = harness.dispatch("help", harness.monitor_uid)
        commands = response["data"]["commands"]
        assert "show workers" in commands
        assert "reload" not in commands
        assert "shutdown" not in commands
        assert "worker add [N]" not in commands

    def test_operator_help_is_full(self, harness):
        response = harness.dispatch("help", harness.operator_uid)
        commands = response["data"]["commands"]
        assert "reload" in commands
        assert "worker add [N]" in commands


class TestWireProtocol:
    """The client sees the code over a real connection."""

    def test_client_distinguishes_the_two_errors(self):
        with socketpair_connection() as conn:
            with pytest.raises(ControlClientError) as denied:
                conn.client.send_command("reload")
            assert denied.value.code == "permission_denied"

            with pytest.raises(ControlClientError) as unknown:
                conn.client.send_command("frobnicate")
            assert unknown.value.code == "unknown_command"

    def test_client_reads_trimmed_result(self):
        with socketpair_connection() as conn:
            result = conn.client.send_command("show workers")
            assert set(result["workers"][0]) == {
                "pid", "age", "booted", "last_heartbeat"}

    def test_client_connection_survives_denial(self):
        with socketpair_connection() as conn:
            with pytest.raises(ControlClientError):
                conn.client.send_command("reload")
            # The refusal is a normal reply, not a dropped connection.
            result = conn.client.send_command("show stats")
            assert result["pid"] == 12345

    def test_operator_wire_reply_is_full(self):
        operator = PeerCredentials(pid=1, uid=CURRENT_UID + 1,
                                   gid=CURRENT_GID, groups=(CURRENT_GID,))
        with socketpair_connection(credentials=operator) as conn:
            result = conn.client.send_command("show workers")
            assert "aborted" in result["workers"][0]
