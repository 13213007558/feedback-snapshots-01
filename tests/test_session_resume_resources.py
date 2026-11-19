"""Workspace-local checks for session-file resume without binding a TCP port.

These mirror the scenarios demonstrated in ``examples/client-session-resume.py``
and run the real OPC UA binary exchange over an in-process socketpair.
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from asyncua import Client, Server, ua
from asyncua.crypto.permission_rules import User, UserRole
from asyncua.server.binary_server_asyncio import BinaryServer

pytestmark = pytest.mark.asyncio


class DemoUserManager:
    _USERS = {("alice", "alice-pw"): "alice", ("bob", "bob-pw"): "bob"}

    def get_user(
        self,
        iserver: object,
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        name = self._USERS.get((username, password))
        return None if name is None else User(role=UserRole.User, name=name)


class LoopbackNetwork:
    def __init__(self) -> None:
        self._servers: dict[int, BinaryServer] = {}

    @asynccontextmanager
    async def active(self) -> AsyncIterator[None]:
        loop = asyncio.get_running_loop()
        original = loop.create_connection

        async def create_connection(
            protocol_factory: Callable[[], asyncio.Protocol],
            host: str | None = None,
            port: int | None = None,
            **kwargs: Any,
        ) -> tuple[asyncio.Transport, asyncio.Protocol]:
            if port not in self._servers:
                return await original(protocol_factory, host, port, **kwargs)
            client_sock, server_sock = socket.socketpair()
            client_sock.setblocking(False)
            server_sock.setblocking(False)
            server_protocol = self._servers[port]._make_protocol()
            await loop.connect_accepted_socket(lambda: server_protocol, server_sock)
            return await loop.connect_accepted_socket(protocol_factory, client_sock)

        loop.create_connection = create_connection  # type: ignore[method-assign]
        try:
            yield
        finally:
            loop.create_connection = original  # type: ignore[method-assign]


async def _start_server(network: LoopbackNetwork, port: int) -> Server:
    server = Server(user_manager=DemoUserManager())
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    server.set_identity_tokens([ua.UserNameIdentityToken, ua.AnonymousIdentityToken])
    server.disable_clock()
    await server._setup_server_nodes()
    await server.iserver.start()
    binary_server = BinaryServer(server.iserver, "127.0.0.1", port, server.limits)
    binary_server.set_policies(server._policies)
    server.bserver = binary_server
    network._servers[port] = binary_server
    return server


async def _stop_server(server: Server) -> None:
    if server.bserver is not None:
        await server.bserver.stop()
    await server.iserver.stop()


async def _crash(client: Client) -> None:
    protocol = client.uaclient.protocol
    assert protocol is not None
    assert protocol.transport is not None
    protocol.transport.close()
    await asyncio.sleep(0.1)
    for task in (client._supervisor_task, client._stale_watchdog_task, client._renew_channel_task):
        if task is not None:
            task.cancel()
    await asyncio.sleep(0.1)


async def test_resume_same_identity_and_identity_switch() -> None:
    network = LoopbackNetwork()
    server = await _start_server(network, 48451)
    variable = await server.nodes.objects.add_variable(2, "Secret", "classified")
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "session.json"
        owner = Client("opc.tcp://127.0.0.1:48451", timeout=1.0)
        owner.set_user("alice")
        owner.set_password("alice-pw")
        owner.session_state_path = state
        try:
            async with network.active():
                await owner.connect()
                subscription = await owner.create_subscription(50)
                await subscription.subscribe_data_change(owner.get_node(variable.nodeid))
                await subscription.next_event(timeout=3.0)
                await _crash(owner)
                victim_token = owner.uaclient.session.authentication_token
                assert state.exists()

                intruder = Client("opc.tcp://127.0.0.1:48451", timeout=1.0)
                intruder.set_user("bob")
                intruder.set_password("bob-pw")
                intruder.session_state_path = state
                await intruder.connect()
                assert intruder.uaclient.session.authentication_token == victim_token
                session = server.iserver.lookup_external_session(victim_token)
                assert session is not None and session.user is not None and session.user.name == "bob"
                await intruder.disconnect()
        finally:
            await _stop_server(server)


async def test_failed_activation_does_not_bind_reused_session() -> None:
    network = LoopbackNetwork()
    server = await _start_server(network, 48452)
    variable = await server.nodes.objects.add_variable(2, "Secret", "classified")
    with tempfile.TemporaryDirectory():
        owner = Client("opc.tcp://127.0.0.1:48452", timeout=1.0)
        owner.set_user("alice")
        owner.set_password("alice-pw")
        try:
            async with network.active():
                await owner.connect()
                victim_token = owner.uaclient.session.authentication_token
                intruder = Client("opc.tcp://127.0.0.1:48452", timeout=1.0)
                await intruder.connect_sessionless()
                intruder.uaclient.session.restore_authentication_token(victim_token)
                with pytest.raises(ua.uaerrors.BadUserAccessDenied):
                    await intruder.activate_session(username="mallory", password="bad")
                with pytest.raises(ua.uaerrors.BadUserAccessDenied):
                    await intruder.get_node(variable.nodeid).read_value()
                assert owner.uaclient.session.authentication_token == victim_token
                await intruder.disconnect()
        finally:
            await _stop_server(server)


async def test_file_kept_when_resume_credential_fails() -> None:
    network = LoopbackNetwork()
    server = await _start_server(network, 48453)
    variable = await server.nodes.objects.add_variable(2, "Secret", "classified")
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "session.json"
        owner = Client("opc.tcp://127.0.0.1:48453", timeout=1.0)
        owner.set_user("alice")
        owner.set_password("alice-pw")
        owner.session_state_path = state
        try:
            async with network.active():
                await owner.connect()
                subscription = await owner.create_subscription(50)
                await subscription.subscribe_data_change(owner.get_node(variable.nodeid))
                await subscription.next_event(timeout=3.0)
                await _crash(owner)
                token = owner.uaclient.session.authentication_token
                assert token in server.iserver._external_sessions

                wrong = Client("opc.tcp://127.0.0.1:48453", timeout=1.0)
                wrong.set_user("alice")
                wrong.set_password("wrong")
                wrong.session_state_path = state
                with pytest.raises(ua.uaerrors.BadUserAccessDenied):
                    await wrong.connect()
                await wrong.disconnect()

                assert state.exists()
                assert token in server.iserver._external_sessions
        finally:
            await _stop_server(server)


async def test_graceful_close_removes_only_owned_file() -> None:
    network = LoopbackNetwork()
    server = await _start_server(network, 48454)
    variable = await server.nodes.objects.add_variable(2, "Secret", "classified")
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "session.json"
        owner = Client("opc.tcp://127.0.0.1:48454", timeout=1.0)
        owner.set_user("alice")
        owner.set_password("alice-pw")
        owner.session_state_path = state
        try:
            async with network.active():
                await owner.connect()
                subscription = await owner.create_subscription(50)
                await subscription.subscribe_data_change(owner.get_node(variable.nodeid))
                await subscription.next_event(timeout=3.0)
                assert state.exists()
                await owner.disconnect()
                assert not state.exists()

                await owner.connect()
                subscription = await owner.create_subscription(50)
                await subscription.subscribe_data_change(owner.get_node(variable.nodeid))
                await subscription.next_event(timeout=3.0)
                await _crash(owner)
                token = owner.uaclient.session.authentication_token

                wrong = Client("opc.tcp://127.0.0.1:48454", timeout=1.0)
                wrong.set_user("alice")
                wrong.set_password("wrong")
                wrong.session_state_path = state
                with pytest.raises(ua.uaerrors.BadUserAccessDenied):
                    await wrong.connect()
                await wrong.disconnect()
                assert state.exists()
                assert token in server.iserver._external_sessions
        finally:
            await _stop_server(server)
