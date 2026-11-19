#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Tests for control socket server."""

import asyncio
import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from gunicorn.ctl.server import ControlSocketServer
from gunicorn.ctl.client import ControlClient
from gunicorn.ctl.policy import ControlPolicy, PeerCredentials


class MockWorker:
    """Mock worker for testing."""

    def __init__(self, pid, age, booted=True, aborted=False):
        self.pid = pid
        self.age = age
        self.booted = booted
        self.aborted = aborted
        self.tmp = MagicMock()
        self.tmp.last_update.return_value = time.monotonic()


class MockConfig:
    """Mock config for testing."""

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
    """Mock logger for testing."""

    def debug(self, msg, *args):
        pass

    def info(self, msg, *args):
        pass

    def warning(self, msg, *args):
        pass

    def error(self, msg, *args):
        pass

    def exception(self, msg, *args):
        pass


class MockArbiter:
    """Mock arbiter for testing."""

    def __init__(self):
        self.cfg = MockConfig()
        self.log = MockLog()
        self.pid = 12345
        self.WORKERS = {}
        self.LISTENERS = []
        self.dirty_arbiter_pid = 0
        self.dirty_arbiter = None
        self.num_workers = 4
        self._stats = {
            'start_time': time.time() - 3600,
            'workers_spawned': 10,
            'workers_killed': 5,
            'reloads': 2,
        }

    def wakeup(self):
        pass


class TestControlSocketServerInit:
    """Tests for server initialization."""

    def test_init(self):
        """Test server initialization."""
        arbiter = MockArbiter()
        server = ControlSocketServer(arbiter, "/tmp/test.sock", 0o600)

        assert server.arbiter is arbiter
        assert server.socket_path == "/tmp/test.sock"
        assert server.socket_mode == 0o600
        assert server._running is False


class TestControlSocketServerLifecycle:
    """Tests for server start/stop."""

    def test_start_stop(self):
        """Test starting and stopping the server."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            # Wait for server to start
            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            assert os.path.exists(socket_path)

            server.stop()

            # Wait for cleanup
            time.sleep(0.2)

            # Socket should be cleaned up
            assert not os.path.exists(socket_path)

    def test_start_already_running(self):
        """Test that start is idempotent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()
            first_thread = server._thread
            server.start()

            assert server._thread is first_thread

            server.stop()

    def test_stop_not_running(self):
        """Test stopping a non-running server."""
        arbiter = MockArbiter()
        server = ControlSocketServer(arbiter, "/tmp/test.sock")

        # Should not raise
        server.stop()


class TestControlSocketServerForkLeak:
    """Regression tests for the SIGHUP fd/thread leak (#3648)."""

    def test_stop_for_fork_joins_thread_started_immediately(self):
        """_stop_for_fork must stop the thread even with no startup delay.

        Calling _stop_for_fork right after start() lands in the window before
        the loop thread has set _loop/_server. Before the fix this skipped the
        shutdown, join() timed out, and the thread was orphaned while still
        holding its selector fd and the unix socket.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            server = ControlSocketServer(MockArbiter(), socket_path)

            server.start()
            thread = server._thread  # capture before stop drops the reference
            try:
                server._stop_for_fork()

                assert not thread.is_alive(), "control thread leaked after fork"
                assert server._thread is None
                assert server._loop is None
                assert server._server is None
            finally:
                server.stop()

    def test_repeated_fork_cycles_do_not_leak_threads(self):
        """A reload spawns workers back to back; no cycle may orphan a thread."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")
            server = ControlSocketServer(MockArbiter(), socket_path)

            threads = []
            server.start()
            threads.append(server._thread)
            try:
                # Mimic the tight spawn_worker() loop in Arbiter.reload().
                for _ in range(8):
                    server._stop_for_fork()
                    server._restart_after_fork()
                    threads.append(server._thread)
            finally:
                server.stop()

            time.sleep(0.2)
            alive = [t for t in threads if t is not None and t.is_alive()]
            assert not alive, f"{len(alive)} control thread(s) leaked"


class TestControlSocketServerPolicyWiring:
    """The server checks the peer's role and trims replies."""

    def _server(self, policy=None):
        arbiter = MockArbiter()
        arbiter.WORKERS = {1001: MockWorker(1001, 1)}
        return arbiter, ControlSocketServer(
            arbiter, "/nonexistent.sock", policy=policy)

    def test_no_policy_leaves_dispatch_open(self):
        _arbiter, server = self._server()
        response = asyncio.run(server._dispatch(
            {"id": 1, "command": "show workers"}, None))
        assert response["status"] == "ok"
        assert "aborted" in response["data"]["workers"][0]

    def test_policy_denies_before_dispatch(self):
        policy = ControlPolicy({"monitor": ["*"]})
        _arbiter, server = self._server(policy)
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = asyncio.run(server._dispatch(
                {"id": 1, "command": "reload"},
                PeerCredentials(pid=1, uid=0, gid=0)))
        assert response["status"] == "error"
        assert response["code"] == "permission_denied"
        kill.assert_not_called()

    def test_policy_allows_operator(self):
        policy = ControlPolicy({"operator": ["*"]})
        _arbiter, server = self._server(policy)
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = asyncio.run(server._dispatch(
                {"id": 1, "command": "reload"},
                PeerCredentials(pid=1, uid=0, gid=0)))
        assert response["status"] == "ok"
        kill.assert_called_once()

    def test_policy_trims_reads(self):
        policy = ControlPolicy({"monitor": ["*"]})
        _arbiter, server = self._server(policy)
        response = asyncio.run(server._dispatch(
            {"id": 1, "command": "show workers"},
            PeerCredentials(pid=1, uid=0, gid=0)))
        assert set(response["data"]["workers"][0]) == {
            "pid", "age", "booted", "last_heartbeat"}

    def test_policy_missing_credentials_denied(self):
        policy = ControlPolicy({"monitor": ["*"]})
        _arbiter, server = self._server(policy)
        response = asyncio.run(server._dispatch(
            {"id": 1, "command": "show workers"}, None))
        assert response["code"] == "permission_denied"

    def test_policy_does_not_leak_unknown_commands(self):
        policy = ControlPolicy({"operator": ["*"]})
        _arbiter, server = self._server(policy)
        monitor = PeerCredentials(pid=1, uid=0, gid=0)
        response = asyncio.run(server._dispatch(
            {"id": 1, "command": "frobnicate"}, monitor))
        assert response["code"] == "unknown_command"

    def test_policy_denies_before_parsing_arguments(self):
        policy = ControlPolicy({"monitor": ["*"]})
        arbiter, server = self._server(policy)
        worker = MockWorker(1001, 1)
        arbiter.WORKERS = {1001: worker}
        with patch("gunicorn.ctl.handlers.os.kill") as kill:
            response = asyncio.run(server._dispatch(
                {"id": 1, "command": "worker", "args": ["kill", "1001"]},
                PeerCredentials(pid=1, uid=0, gid=0)))
        assert response["code"] == "permission_denied"
        kill.assert_not_called()
        assert 1001 in arbiter.WORKERS


class TestControlSocketServerIntegration:
    """Integration tests for server with client."""

    def test_show_workers(self):
        """Test show workers command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            arbiter.WORKERS = {
                1001: MockWorker(1001, 1),
                1002: MockWorker(1002, 2),
            }
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            # Wait for server to start
            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            try:
                with ControlClient(socket_path, timeout=5.0) as client:
                    result = client.send_command("show workers")

                assert result["count"] == 2
                assert len(result["workers"]) == 2
            finally:
                server.stop()

    def test_show_stats(self):
        """Test show stats command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            try:
                with ControlClient(socket_path, timeout=5.0) as client:
                    result = client.send_command("show stats")

                assert result["pid"] == 12345
                assert result["workers_spawned"] == 10
            finally:
                server.stop()

    def test_help_command(self):
        """Test help command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            try:
                with ControlClient(socket_path, timeout=5.0) as client:
                    result = client.send_command("help")

                assert "commands" in result
                assert "show workers" in result["commands"]
            finally:
                server.stop()

    def test_worker_add(self):
        """Test worker add command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            arbiter.wakeup = MagicMock()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            try:
                with ControlClient(socket_path, timeout=5.0) as client:
                    result = client.send_command("worker add 2")

                assert result["added"] == 2
                assert result["total"] == 6
                assert arbiter.num_workers == 6
                arbiter.wakeup.assert_called()
            finally:
                server.stop()

    def test_invalid_command(self):
        """Test handling invalid command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            try:
                with ControlClient(socket_path, timeout=5.0) as client:
                    with pytest.raises(Exception) as exc_info:
                        client.send_command("invalid_command")

                    assert "Unknown command" in str(exc_info.value)
            finally:
                server.stop()

    def test_multiple_commands(self):
        """Test sending multiple commands on same connection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            arbiter.WORKERS = {1001: MockWorker(1001, 1)}
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)
            time.sleep(0.2)  # Extra wait for server to be fully ready

            try:
                with ControlClient(socket_path, timeout=5.0) as client:
                    result1 = client.send_command("show workers")
                    result2 = client.send_command("show stats")
                    result3 = client.send_command("help")

                assert result1["count"] == 1
                assert result2["pid"] == 12345
                assert "commands" in result3
            finally:
                server.stop()


class TestControlSocketServerPermissions:
    """Tests for socket permissions."""

    @pytest.mark.skipif(
        os.uname().sysname == "FreeBSD",
        reason="FreeBSD socket permissions behavior differs"
    )
    def test_socket_permissions(self):
        """Test that socket is created with correct permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, "test.sock")

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path, 0o660)

            server.start()

            # Wait for socket to exist
            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)

            # Extra wait for chmod to complete
            time.sleep(0.2)

            try:
                mode = os.stat(socket_path).st_mode & 0o777
                assert mode == 0o660
            finally:
                server.stop()


class TestControlSocketServerDirectoryCreation:
    """Tests for automatic directory creation."""

    def test_creates_parent_directory(self):
        """Test that server creates parent directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a path with a non-existent subdirectory
            subdir = os.path.join(tmpdir, '.gunicorn')
            socket_path = os.path.join(subdir, 'gunicorn.ctl')

            assert not os.path.exists(subdir)

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            # Wait for socket to exist
            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)

            try:
                # Directory should have been created
                assert os.path.isdir(subdir)
                # Directory should have restricted permissions (0o700)
                mode = os.stat(subdir).st_mode & 0o777
                assert mode == 0o700
                # Socket should exist
                assert os.path.exists(socket_path)
            finally:
                server.stop()

    def test_works_with_existing_directory(self):
        """Test that server works when parent directory already exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            socket_path = os.path.join(tmpdir, 'gunicorn.ctl')

            arbiter = MockArbiter()
            server = ControlSocketServer(arbiter, socket_path)

            server.start()

            # Wait for socket to exist
            for _ in range(50):
                if os.path.exists(socket_path):
                    break
                time.sleep(0.1)

            try:
                assert os.path.exists(socket_path)
            finally:
                server.stop()
