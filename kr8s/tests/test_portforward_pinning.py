# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncGenerator
from typing import Any
from unittest import mock

import httpx_ws
import pytest

from kr8s._exceptions import ConnectionClosedError
from kr8s._objects import Pod
from kr8s._portforward import PortForward


@pytest.fixture(scope="session", autouse=True)
def k8s_cluster() -> Any:
    """Override the integration cluster for these fully local fakes."""
    yield None


@pytest.fixture(autouse=True)
def ns() -> str:
    """Override the namespace fixture because this module never calls Kubernetes."""
    return "unit-ns"


class FakeWebSocket:
    def __init__(self, api: FakeApi) -> None:
        self.api = api
        self.sent: list[bytes] = []
        self.handshake_sent = False
        self.response = api.response

    async def __aenter__(self) -> FakeWebSocket:
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False

    async def send_bytes(self, data: bytes) -> None:
        self.sent.append(data)

    async def receive_bytes(self) -> bytes:
        if not self.handshake_sent:
            self.handshake_sent = True
            return b"\x00"
        if self.response is not None:
            response = self.response
            self.response = None
            return response
        await asyncio.Event().wait()
        raise ConnectionClosedError("fake websocket closed")


class FakeApi:
    namespace = "unit-ns"

    def __init__(self, name: str, *, response: bytes = b"\x00ok") -> None:
        self.name = name
        self.response = response
        self.calls: list[dict[str, Any]] = []
        self.websockets: list[FakeWebSocket] = []
        self.fail = False

    @contextlib.asynccontextmanager
    async def open_websocket(
        self, **kwargs: Any
    ) -> AsyncGenerator[FakeWebSocket, None]:
        self.calls.append(kwargs)
        if self.fail:
            raise httpx_ws.WebSocketDisconnect(1001, "Pod has been replaced")
        websocket = FakeWebSocket(self)
        self.websockets.append(websocket)
        yield websocket


class FakeService:
    def __init__(self, pods: list[Pod]) -> None:
        self.pods = pods
        self.ready_pod_calls = 0

    def ready_pods(self) -> list[Pod]:
        raise AssertionError("port-forward must use the async API")

    async def async_ready_pods(self) -> list[Pod]:
        self.ready_pod_calls += 1
        return list(self.pods)


class FakeServer:
    def __init__(self, handler: Any, kwargs: dict[str, Any]) -> None:
        self.handler = handler
        self.kwargs = kwargs
        self.start_serving_count = 0
        self.close_count = 0
        self.wait_closed_count = 0

    async def start_serving(self) -> None:
        self.start_serving_count += 1

    def close(self) -> None:
        self.close_count += 1

    async def wait_closed(self) -> None:
        self.wait_closed_count += 1


class FakeStartServer:
    def __init__(self) -> None:
        self.servers: list[FakeServer] = []

    async def __call__(self, handler: Any, *args: Any, **kwargs: Any) -> FakeServer:
        server = FakeServer(handler, kwargs)
        self.servers.append(server)
        return server


class FakeReader:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read_count = 0

    async def read(self, size: int = -1) -> bytes:
        self.read_count += 1
        if self.read_count == 1:
            await asyncio.sleep(0)
            return self.payload
        # Give the fake downstream response task a chance to write before EOF.
        await asyncio.sleep(0.02)
        return b""


class FakeBlockingReader:
    async def read(self, size: int = -1) -> bytes:
        await asyncio.Event().wait()
        return b""


class FakeWriter:
    def __init__(self) -> None:
        self.parts: list[bytes] = []
        self.close_count = 0

    def write(self, data: bytes) -> None:
        self.parts.append(bytes(data))

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.close_count += 1

    @property
    def data(self) -> bytes:
        return b"".join(self.parts)


def make_pod(name: str, uid: str) -> tuple[Pod, FakeApi]:
    api = FakeApi(name, response=b"\x00hello-from-" + name.encode())
    pod = Pod(
        {
            "metadata": {
                "name": name,
                "namespace": "unit-ns",
                "uid": uid,
            }
        }
    )
    pod.api = api
    return pod, api


async def invoke_connection(
    server: FakeServer, payload: bytes
) -> tuple[FakeReader, FakeWriter, asyncio.Task[None]]:
    reader = FakeReader(payload)
    writer = FakeWriter()
    task = asyncio.create_task(server.handler(reader, writer))
    return reader, writer, task


async def test_reconnect_pins_approved_instance_and_never_fails_over() -> None:
    pod_a, api_a = make_pod("pod-a", "uid-a")
    pod_b, api_b = make_pod("pod-b", "uid-b")
    service = FakeService([pod_a])
    port_forward = PortForward(service, 9000, local_port=43180)

    for _ in range(2):
        async with port_forward._connect_websocket() as websocket:
            assert isinstance(websocket, FakeWebSocket)

    assert service.ready_pod_calls == 1
    assert [call["params"]["name"] for call in api_a.calls] == ["pod-a", "pod-a"]

    # The Service list now contains only the replacement generation. The old
    # approved Pod's network endpoint also reports that it is gone.
    service.pods = [pod_b]
    api_a.fail = True

    with mock.patch("kr8s._portforward.anyio.sleep", new=mock.AsyncMock()):
        with pytest.raises(ConnectionClosedError, match="approved Pod"):
            async with port_forward._connect_websocket():
                pass

    assert port_forward.pod is pod_a
    assert port_forward._approved_pod_uid == "uid-a"
    assert service.ready_pod_calls == 1
    assert all(call["params"]["name"] == "pod-a" for call in api_a.calls)
    assert len(api_a.calls) == 8
    assert api_b.calls == []


async def test_same_name_pod_uid_replacement_is_terminal() -> None:
    pod, api = make_pod("stable-name", "uid-v1")
    port_forward = PortForward(pod, 9000, local_port=43184)

    async def replace_pod_generation() -> None:
        pod.metadata["uid"] = "uid-v2"

    pod.async_refresh = replace_pod_generation  # type: ignore[method-assign]

    with pytest.raises(ConnectionClosedError, match="was replaced"):
        async with port_forward._connect_websocket():
            pass

    assert port_forward.pod is pod
    assert port_forward._approved_pod_uid == "uid-v1"
    assert api.calls == []


async def test_replacement_stops_one_forward_but_not_other() -> None:
    pod_a, api_a = make_pod("pod-a", "uid-a")
    pod_b, api_b = make_pod("pod-b", "uid-b")
    pod_c, api_c = make_pod("pod-c", "uid-c")
    service_a = FakeService([pod_a])
    service_c = FakeService([pod_c])

    forward_a = PortForward(service_a, 9000, local_port=43181)
    forward_c = PortForward(service_c, 9000, local_port=43182)
    start_server = FakeStartServer()

    with mock.patch("kr8s._portforward.asyncio.start_server", new=start_server):
        with mock.patch("kr8s._portforward.anyio.sleep", new=mock.AsyncMock()):
            async with forward_a._run(), forward_c._run():
                server_a = start_server.servers[0]
                server_c = start_server.servers[1]

                for payload in (b"one", b"two"):
                    _, writer, task = await invoke_connection(server_a, payload)
                    await asyncio.wait_for(task, timeout=1)
                    assert b"hello-from-pod-a" in writer.data

                assert len(api_a.calls) == 2
                assert service_a.ready_pod_calls == 1

                _, writer_c, task_c = await invoke_connection(server_c, b"before")
                await asyncio.wait_for(task_c, timeout=1)
                assert b"hello-from-pod-c" in writer_c.data

                service_a.pods = [pod_b]
                api_a.fail = True
                _, failed_writer, failed_task = await invoke_connection(
                    server_a, b"three"
                )

                with pytest.raises(ConnectionClosedError, match="approved Pod"):
                    await asyncio.wait_for(failed_task, timeout=1)

                assert failed_writer.close_count == 1
                assert server_a.close_count == 1
                assert server_c.close_count == 0
                assert api_b.calls == []

                _, writer_c_after, task_c_after = await invoke_connection(
                    server_c, b"after"
                )
                await asyncio.wait_for(task_c_after, timeout=1)
                assert b"hello-from-pod-c" in writer_c_after.data
                assert len(api_c.calls) == 2
                assert server_c.close_count == 0

        assert server_a.wait_closed_count == 1
        assert server_c.wait_closed_count == 1
        assert forward_a.servers == []
        assert forward_c.servers == []


async def test_all_bind_address_listeners_are_closed() -> None:
    pod, _ = make_pod("pod-multi-bind", "uid-multi-bind")
    port_forward = PortForward(
        pod,
        9000,
        local_port=43185,
        address=["127.0.0.1", "127.0.0.2"],
    )
    start_server = FakeStartServer()

    with mock.patch("kr8s._portforward.asyncio.start_server", new=start_server):
        async with port_forward._run():
            assert len(start_server.servers) == 2
            assert all(
                server.start_serving_count == 1 for server in start_server.servers
            )

        assert port_forward.servers == []
        assert all(server.close_count == 1 for server in start_server.servers)
        assert all(server.wait_closed_count == 1 for server in start_server.servers)


async def test_temporary_no_ready_pods_does_not_take_down_listener() -> None:
    service = FakeService([])
    port_forward = PortForward(service, 9000, local_port=43186)
    start_server = FakeStartServer()

    with mock.patch("kr8s._portforward.asyncio.start_server", new=start_server):
        async with port_forward._run():
            server = start_server.servers[0]
            _, writer, task = await invoke_connection(server, b"waiting")

            with pytest.raises(RuntimeError, match="No ready pods found"):
                await asyncio.wait_for(task, timeout=1)

            assert writer.close_count == 1
            assert server.close_count == 0
            assert port_forward.pod is None


async def test_context_exit_cancels_and_cleans_active_connection() -> None:
    pod, _ = make_pod("pod-active-cleanup", "uid-active-cleanup")
    port_forward = PortForward(pod, 9000, local_port=43187)
    start_server = FakeStartServer()
    writer = FakeWriter()

    with mock.patch("kr8s._portforward.asyncio.start_server", new=start_server):
        async with port_forward._run():
            server = start_server.servers[0]
            task = asyncio.create_task(
                server.handler(FakeBlockingReader(), writer)
            )
            await asyncio.sleep(0)
            assert not task.done()
            assert len(port_forward._connection_tasks) == 1

        assert task.done()
        assert task.cancelled()
        assert writer.close_count == 1
        assert port_forward._connection_tasks == set()
        assert server.wait_closed_count == 1


async def test_background_stop_waits_for_fake_listener_cleanup() -> None:
    pod, _ = make_pod("pod-background", "uid-background")
    port_forward = PortForward(pod, 9000, local_port=43183)
    start_server = FakeStartServer()

    with mock.patch("kr8s._portforward.asyncio.start_server", new=start_server):
        port = await asyncio.wait_for(port_forward.start(), timeout=1)
        assert port == 43183
        for _ in range(50):
            if port_forward.servers:
                break
            await asyncio.sleep(0.01)
        server = port_forward.servers[0]

        await asyncio.wait_for(port_forward.stop(), timeout=1)

        assert port_forward._bg_task is None
        assert port_forward.servers == []
        assert server.close_count == 1
        assert server.wait_closed_count == 1
