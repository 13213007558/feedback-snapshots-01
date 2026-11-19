#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Tests for dirty app capabilities and the pre-dispatch check.

The scenarios here cover what a reload means for a permission: a request
that was already being processed finishes, and every request that starts
after the new snapshot is installed is checked against it.
"""

import asyncio
from unittest import mock

import pytest

from gunicorn.config import Config
from gunicorn.dirty.arbiter import DirtyArbiter
from gunicorn.dirty.capabilities import (
    CapabilityPolicy,
    build_capability_policy,
    normalize_capabilities,
)
from gunicorn.dirty.errors import DirtyCapabilityError
from gunicorn.dirty.protocol import (    BinaryProtocol,
    DirtyProtocol,
    HEADER_SIZE,
    make_request,
    make_response,
)


RESTRICTED_APP = "tests.support_dirty_app:RestrictedDirtyApp"
UNRESTRICTED_APP = "tests.support_dirty_app:TestDirtyApp"


class MockLog:
    """Mock logger for testing."""

    def __init__(self):
        self.messages = []

    def debug(self, msg, *args):
        self.messages.append(("debug", msg % args if args else msg))

    def info(self, msg, *args):
        self.messages.append(("info", msg % args if args else msg))

    def warning(self, msg, *args):
        self.messages.append(("warning", msg % args if args else msg))

    def error(self, msg, *args):
        self.messages.append(("error", msg % args if args else msg))

    def critical(self, msg, *args):
        self.messages.append(("critical", msg % args if args else msg))

    def exception(self, msg, *args):
        self.messages.append(("exception", msg % args if args else msg))

    def close_on_exec(self):
        pass

    def reopen_files(self):
        pass


class MockStreamWriter:
    """Mock StreamWriter that captures written messages."""

    def __init__(self):
        self.messages = []
        self._buffer = b""
        self.closed = False

    def write(self, data):
        self._buffer += data

    async def drain(self):
        while len(self._buffer) >= HEADER_SIZE:
            _, _, length = BinaryProtocol.decode_header(
                self._buffer[:HEADER_SIZE]
            )
            total_size = HEADER_SIZE + length
            if len(self._buffer) < total_size:
                break
            msg_data = self._buffer[:total_size]
            self._buffer = self._buffer[total_size:]
            msg_type, request_id, payload = BinaryProtocol.decode_message(
                msg_data
            )
            result = {"type": msg_type, "id": request_id}
            result.update(payload)
            self.messages.append(result)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        return None


def make_arbiter(apps, capabilities=None, workers=None):
    cfg = Config()
    cfg.set("dirty_workers", 1)
    cfg.set("dirty_apps", apps)
    if capabilities is not None:
        cfg.set("dirty_capabilities", capabilities)
    log = MockLog()
    arbiter = DirtyArbiter(cfg=cfg, log=log)
    arbiter.alive = True
    arbiter.pid = 1
    arbiter.workers = dict(workers or {1234: "worker"})
    arbiter.worker_sockets = {pid: f"/tmp/worker-{pid}.sock" for pid in arbiter.workers}
    for pid in arbiter.workers:
        arbiter._register_worker_apps(pid, list(arbiter.app_specs))
    return arbiter


async def cleanup_arbiter(arbiter):
    arbiter.alive = False
    for task in list(arbiter.worker_consumers.values()):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    arbiter._cleanup_sync()


class TestCapabilityDeclaration:
    """Tests for reading and normalizing capability declarations."""

    def test_class_attribute_is_the_default_scope(self):
        policy = build_capability_policy(
            config_with_apps([RESTRICTED_APP]), MockLog()
        )

        assert policy.allows(RESTRICTED_APP, "compute")
        assert policy.allows(RESTRICTED_APP, "fast_action")
        assert not policy.allows(RESTRICTED_APP, "secret_action")

    def test_app_without_declaration_is_unrestricted(self):
        policy = build_capability_policy(
            config_with_apps([UNRESTRICTED_APP]), MockLog()
        )

        assert policy.allows(UNRESTRICTED_APP, "store")
        assert policy.allows(UNRESTRICTED_APP, "anything")

    def test_config_override_wins_over_class_attribute(self):
        cfg = config_with_apps(
            [RESTRICTED_APP], {"": None, RESTRICTED_APP: ["compute"]}
        )

        policy = build_capability_policy(cfg, MockLog())

        assert policy.allows(RESTRICTED_APP, "compute")
        assert not policy.allows(RESTRICTED_APP, "fast_action")

    def test_normalize_star_means_unrestricted(self):
        assert normalize_capabilities("*") is None
        assert normalize_capabilities(["*"]) is None
        assert normalize_capabilities([]) == frozenset()

    def test_policy_snapshot_is_flat_and_immutable(self):
        policy = CapabilityPolicy({RESTRICTED_APP: {"compute"}})
        policy.to_dict()[RESTRICTED_APP].append("secret_action")

        assert not policy.allows(RESTRICTED_APP, "secret_action")


class TestPreDispatchAuthorization:
    """A denied request must not select a worker or enter a queue."""

    @pytest.mark.asyncio
    async def test_declared_action_reaches_the_worker(self):
        arbiter = make_arbiter([RESTRICTED_APP])
        calls = []

        async def fake_execute(pid, request, client_writer):
            calls.append((pid, request["action"]))
            await DirtyProtocol.write_message_async(
                client_writer, make_response(request["id"], "ok")
            )

        arbiter._execute_on_worker = fake_execute
        writer = MockStreamWriter()
        try:
            await arbiter.route_request(
                make_request("ok-1", RESTRICTED_APP, "compute"), writer
            )
            assert writer.messages[0]["type"] == DirtyProtocol.MSG_TYPE_RESPONSE
            assert calls == [(1234, "compute")]
        finally:
            await cleanup_arbiter(arbiter)

    @pytest.mark.asyncio
    async def test_undeclared_action_is_rejected_before_any_worker(self):
        arbiter = make_arbiter([RESTRICTED_APP])
        executed = []

        async def fake_execute(pid, request, client_writer):
            executed.append(pid)
            await DirtyProtocol.write_message_async(
                client_writer, make_response(request["id"], "should not run")
            )

        arbiter._execute_on_worker = fake_execute
        writer = MockStreamWriter()
        try:
            await arbiter.route_request(
                make_request("deny-1", RESTRICTED_APP, "secret_action"), writer
            )

            assert executed == []
            assert 1234 not in arbiter.worker_queues
            assert len(writer.messages) == 1
            error = writer.messages[0]
            assert error["type"] == DirtyProtocol.MSG_TYPE_ERROR
            assert error["error"]["error_type"] == "DirtyCapabilityError"
            assert error["error"]["details"]["app_path"] == RESTRICTED_APP
            assert error["error"]["details"]["action"] == "secret_action"
        finally:
            await cleanup_arbiter(arbiter)

    @pytest.mark.asyncio
    async def test_unknown_action_on_unrestricted_app_still_routes(self):
        """An app that declares nothing keeps the historical behaviour."""
        arbiter = make_arbiter([UNRESTRICTED_APP])
        executed = []

        async def fake_execute(pid, request, client_writer):
            executed.append(request["action"])
            await DirtyProtocol.write_message_async(
                client_writer, make_response(request["id"], "ok")
            )

        arbiter._execute_on_worker = fake_execute
        writer = MockStreamWriter()
        try:
            await arbiter.route_request(
                make_request("ok-2", UNRESTRICTED_APP, "never_declared"),
                writer,
            )
            assert executed == ["never_declared"]
            assert writer.messages[0]["type"] == DirtyProtocol.MSG_TYPE_RESPONSE
        finally:
            await cleanup_arbiter(arbiter)


class TestReloadWithdrawsCapability:
    """Simulate an old request in flight while a reload withdraws an action."""

    @pytest.mark.asyncio
    async def test_withdrawn_action_never_reaches_a_worker(self):
        arbiter = make_arbiter([RESTRICTED_APP])
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def fake_execute(pid, request, client_writer):
            calls.append(request["action"])
            if request["action"] == "compute":
                started.set()
                await release.wait()
            await DirtyProtocol.write_message_async(
                client_writer, make_response(request["id"], request["action"])
            )

        arbiter._execute_on_worker = fake_execute
        old_writer = MockStreamWriter()

        try:
            # 1. An old request passes the check and starts executing.
            old_task = asyncio.create_task(
                arbiter.route_request(
                    make_request("old-1", RESTRICTED_APP, "compute"), old_writer
                )
            )
            await asyncio.wait_for(started.wait(), timeout=2)

            # 2. A reload installs a snapshot that no longer exposes
            #    "compute". The swap is one assignment inside the handler.
            reload_writer = MockStreamWriter()
            await arbiter.handle_policy_request(
                {"id": 99, "apps": {RESTRICTED_APP: ["fast_action"]}},
                reload_writer,
            )
            assert reload_writer.messages[0]["type"] == (
                DirtyProtocol.MSG_TYPE_RESPONSE
            )

            # 3. A new request for the withdrawn action is refused before
            #    dispatch, while the old one still holds worker 1234.
            new_writer = MockStreamWriter()
            await arbiter.route_request(
                make_request("new-1", RESTRICTED_APP, "compute"), new_writer
            )
            assert calls == ["compute"]  # only the old request ran
            assert new_writer.messages[0]["error"]["error_type"] == (
                "DirtyCapabilityError"
            )

            # A different, still-exposed action keeps its normal routing.
            allowed_writer = MockStreamWriter()
            allowed_task = asyncio.create_task(
                arbiter.route_request(
                    make_request("new-2", RESTRICTED_APP, "fast_action"),
                    allowed_writer,
                )
            )
            await asyncio.sleep(0)
            assert not allowed_task.done()  # queued behind the old request

            # 4. Let the old request finish. It is answered normally.
            release.set()
            await asyncio.wait_for(old_task, timeout=2)
            await asyncio.wait_for(allowed_task, timeout=2)

            assert old_writer.messages[0]["result"] == "compute"
            assert allowed_writer.messages[0]["result"] == "fast_action"
            assert calls == ["compute", "fast_action"]
        finally:
            release.set()
            await cleanup_arbiter(arbiter)

    @pytest.mark.asyncio
    async def test_policy_replacement_is_atomic_for_readers(self):
        arbiter = make_arbiter([RESTRICTED_APP])
        old_policy = arbiter.capability_policy

        writer = MockStreamWriter()
        try:
            await arbiter.handle_policy_request(
                {"id": 1, "apps": {RESTRICTED_APP: []}}, writer
            )

            # The old snapshot is untouched, the new one denies everything.
            assert old_policy.allows(RESTRICTED_APP, "compute")
            assert not arbiter.capability_policy.allows(
                RESTRICTED_APP, "compute"
            )
            assert not arbiter.capability_policy.allows(
                RESTRICTED_APP, "fast_action"
            )
        finally:
            await cleanup_arbiter(arbiter)

    @pytest.mark.asyncio
    async def test_invalid_policy_keeps_the_previous_snapshot(self):
        arbiter = make_arbiter([RESTRICTED_APP])
        previous = arbiter.capability_policy
        writer = MockStreamWriter()

        try:
            await arbiter.handle_policy_request(
                {"id": 1, "apps": ["not-a-mapping"]}, writer
            )

            assert arbiter.capability_policy is previous
            assert writer.messages[0]["type"] == DirtyProtocol.MSG_TYPE_ERROR
        finally:
            await cleanup_arbiter(arbiter)


class TestMainArbiterSync:
    """The main arbiter builds the reloaded policy and pushes it."""

    def test_sync_sends_the_reloaded_configuration(self):
        from gunicorn.arbiter import Arbiter
        from tests.test_dirty_integration import SimpleDirtyTestApp

        app = SimpleDirtyTestApp(options={
            "dirty_workers": 1,
            "dirty_apps": [RESTRICTED_APP],
            "dirty_capabilities": {RESTRICTED_APP: ["fast_action"]},
            "bind": "127.0.0.1:0",
        })
        arbiter = Arbiter(app)
        arbiter.dirty_arbiter_pid = 4321
        arbiter.dirty_arbiter = mock.Mock(socket_path="/tmp/dirty.sock")

        sent = {}

        def fake_send(socket_path, policy, timeout=5.0):
            sent["socket_path"] = socket_path
            sent["policy"] = policy
            return {"apps": len(policy)}

        with mock.patch(
            "gunicorn.dirty.capabilities.send_capability_policy",
            side_effect=fake_send,
        ):
            assert arbiter.sync_dirty_capabilities() is True

        assert sent["socket_path"] == "/tmp/dirty.sock"
        assert sent["policy"].allows(RESTRICTED_APP, "fast_action")
        assert not sent["policy"].allows(RESTRICTED_APP, "compute")

    def test_sync_failure_leaves_the_old_policy_in_place(self):
        from gunicorn.arbiter import Arbiter
        from tests.test_dirty_integration import SimpleDirtyTestApp

        app = SimpleDirtyTestApp(options={
            "dirty_workers": 1,
            "dirty_apps": [RESTRICTED_APP],
            "bind": "127.0.0.1:0",
        })
        arbiter = Arbiter(app)
        arbiter.dirty_arbiter_pid = 4321
        arbiter.dirty_arbiter = mock.Mock(socket_path="/tmp/dirty.sock")

        with mock.patch(
            "gunicorn.dirty.capabilities.send_capability_policy",
            side_effect=OSError("connection refused"),
        ):
            assert arbiter.sync_dirty_capabilities() is False


def config_with_apps(apps, capabilities=None):
    cfg = Config()
    cfg.set("dirty_workers", 1)
    cfg.set("dirty_apps", apps)
    if capabilities is not None:
        cfg.set("dirty_capabilities", capabilities)
    return cfg


class TestPolicyWireProtocol:
    """The policy snapshot travels over the dirty protocol unchanged."""

    def test_capability_error_round_trips(self):
        error = DirtyCapabilityError(RESTRICTED_APP, "secret_action")
        restored = DirtyCapabilityError.from_dict(error.to_dict())

        assert isinstance(restored, DirtyCapabilityError)
        assert restored.app_path == RESTRICTED_APP
        assert restored.action == "secret_action"

    def test_policy_message_round_trips(self):
        from gunicorn.dirty.protocol import make_policy_message

        message = make_policy_message(
            7, {RESTRICTED_APP: ["compute"], UNRESTRICTED_APP: None}
        )
        data = BinaryProtocol._encode_from_dict(message)
        msg_type, request_id, payload = BinaryProtocol.decode_message(data)

        assert msg_type == DirtyProtocol.MSG_TYPE_POLICY
        assert request_id == 7
        assert payload["apps"] == {
            RESTRICTED_APP: ["compute"],
            UNRESTRICTED_APP: None,
        }

    def test_send_and_apply_over_a_connected_socket(self):
        """Send a snapshot through the sync client and let the arbiter's
        handler install it, as the main arbiter does on reload."""
        import socket as socket_module

        from gunicorn.dirty.capabilities import send_capability_policy

        client_sock, server_sock = socket_module.socketpair()
        arbiter = make_arbiter([RESTRICTED_APP])
        received = {}

        class ConnectedSocket:
            """Stands in for the AF_UNIX socket the helper would create."""

            def __init__(self, sock):
                self._sock = sock

            def settimeout(self, timeout):
                self._sock.settimeout(timeout)

            def connect(self, path):
                pass

            def sendall(self, data):
                self._sock.sendall(data)

            def recv(self, n):
                return self._sock.recv(n)

            def close(self):
                self._sock.close()

        async def serve():
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            loop = asyncio.get_running_loop()
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, server_sock
            )
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            try:
                message = await DirtyProtocol.read_message_async(reader)
                received["message"] = message
                await arbiter.handle_policy_request(message, writer)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        async def run():
            loop = asyncio.get_running_loop()
            server_task = asyncio.create_task(serve())
            with mock.patch(
                "gunicorn.dirty.capabilities.socket.socket",
                return_value=ConnectedSocket(client_sock),
            ):
                result = await loop.run_in_executor(
                    None,
                    lambda: send_capability_policy(
                        "/unused",
                        CapabilityPolicy({RESTRICTED_APP: ["compute"]}),
                    ),
                )
            await asyncio.wait_for(server_task, timeout=2)
            return result

        try:
            result = asyncio.run(run())
            assert result["success"] is True
            assert arbiter.capability_policy.allows(RESTRICTED_APP, "compute")
            assert not arbiter.capability_policy.allows(
                RESTRICTED_APP, "secret_action"
            )
            assert received["message"]["apps"] == {RESTRICTED_APP: ["compute"]}
        finally:
            arbiter.alive = False
            arbiter._cleanup_sync()

