"""
Session-ownership regression tests for requests on a shared transport.

One `UaClient` transport can serve several `UaSession` objects. These tests
drive requests through the real binary encoding path (`struct_to_binary` +
`SecureConnection.message_to_binary`), record the wire bytes on fake
transports, and decode them again to assert that every request is encoded with
the authentication token and the transport of one consistent binding, even
while the pre-request hook pauses, a reconnect swaps the protocol, or tasks
are cancelled.
"""

import asyncio

import pytest

from asyncua import ua
from asyncua.client.ua_client import UaClient, UASocketProtocol
from asyncua.client.ua_session import UaSession
from asyncua.common.connection import MessageChunk, SecureConnection, TransportLimits
from asyncua.common.utils import Buffer
from asyncua.crypto import security_policies
from asyncua.ua.ua_binary import nodeid_from_binary, struct_from_binary, struct_to_binary

TOKEN_A = ua.NodeId(101, 1)
TOKEN_A_RENEWED = ua.NodeId(111, 1)
TOKEN_B = ua.NodeId(202, 1)
TOKEN_B_RENEWED = ua.NodeId(222, 1)
TOKEN_C = ua.NodeId(303, 1)


class RecordingTransport:
    """Minimal asyncio.Transport stand-in that records written packets."""

    def __init__(self) -> None:
        self.packets: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.packets.append(bytes(data))

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    async def wait_for_packets(self, count: int) -> None:
        async def _wait() -> None:
            while len(self.packets) < count:
                await asyncio.sleep(0)

        await asyncio.wait_for(_wait(), timeout=1)


class FakeServerWire:
    """Decodes client packets and encodes server responses for one connection."""

    def __init__(self) -> None:
        self._policy = security_policies.SecurityPolicyNone()
        self._connection = SecureConnection(security_policies.SecurityPolicyNone(), TransportLimits())

    def decode_request(self, packet: bytes) -> tuple[int, ua.RequestHeader]:
        chunk = MessageChunk.from_binary(self._policy, Buffer(packet))
        body = Buffer(chunk.Body)
        nodeid_from_binary(body)
        return chunk.SequenceHeader.RequestId, struct_from_binary(ua.RequestHeader, body)

    def encode_read_response(self, request_id: int, request_header: ua.RequestHeader) -> bytes:
        response = ua.ReadResponse()
        response.ResponseHeader.RequestHandle = request_header.RequestHandle
        return self._connection.message_to_binary(
            struct_to_binary(response), message_type=ua.MessageType.SecureMessage, request_id=request_id
        )


class PausableHook:
    """Pre-request hook that can pause the next call between enter and release."""

    def __init__(self) -> None:
        self.calls = 0
        self.armed = False
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    def arm(self) -> None:
        self.armed = True
        self.entered.clear()
        self.release.clear()

    async def wait_until_entered(self) -> None:
        await asyncio.wait_for(self.entered.wait(), timeout=1)

    async def __call__(self) -> None:
        self.calls += 1
        if not self.armed:
            return
        self.armed = False
        self.entered.set()
        await self.release.wait()


class SessionBindingHarness:
    """A UaClient wired to recording transports with real message encoding."""

    def __init__(self) -> None:
        self.client = UaClient()
        self.hook = PausableHook()
        self.client.pre_request_hook = self.hook
        self.connections: dict[UASocketProtocol, tuple[RecordingTransport, FakeServerWire]] = {}
        self.open_connection()

    def open_connection(self) -> tuple[UASocketProtocol, RecordingTransport, FakeServerWire]:
        protocol = self.client._make_protocol()
        transport = RecordingTransport()
        protocol.connection_made(transport)
        wire = FakeServerWire()
        self.connections[protocol] = (transport, wire)
        return protocol, transport, wire

    def current(self) -> tuple[UASocketProtocol, RecordingTransport, FakeServerWire]:
        protocol = self.client.protocol
        assert protocol is not None
        transport, wire = self.connections[protocol]
        return protocol, transport, wire

    def respond(self, protocol: UASocketProtocol, packet_index: int) -> ua.RequestHeader:
        transport, wire = self.connections[protocol]
        request_id, header = wire.decode_request(transport.packets[packet_index])
        protocol.data_received(wire.encode_read_response(request_id, header))
        return header

    def decoded_headers(self, protocol: UASocketProtocol) -> list[ua.RequestHeader]:
        transport, wire = self.connections[protocol]
        return [wire.decode_request(packet)[1] for packet in transport.packets]


async def read_request_handle(session: UaSession) -> int:
    data = await session._send_request(ua.ReadRequest())
    response = struct_from_binary(ua.ReadResponse, data)
    return response.ResponseHeader.RequestHandle


@pytest.fixture
def harness() -> SessionBindingHarness:
    return SessionBindingHarness()


async def test_interleaved_sessions_keep_own_token_on_the_wire(harness: SessionBindingHarness) -> None:
    session_a = harness.client.session
    session_b = UaSession(harness.client)
    session_a.restore_authentication_token(TOKEN_A)
    session_b.restore_authentication_token(TOKEN_B)
    protocol, transport, _ = harness.current()

    harness.hook.arm()
    task_a = asyncio.create_task(read_request_handle(session_a))
    await harness.hook.wait_until_entered()
    task_b = asyncio.create_task(read_request_handle(session_b))
    await transport.wait_for_packets(1)
    harness.hook.release.set()
    await transport.wait_for_packets(2)

    header_b = harness.respond(protocol, 0)
    header_a = harness.respond(protocol, 1)

    assert await task_b == header_b.RequestHandle
    assert await task_a == header_a.RequestHandle
    headers = harness.decoded_headers(protocol)
    assert [header.AuthenticationToken for header in headers] == [TOKEN_B, TOKEN_A]
    assert [header.RequestHandle for header in headers] == [1, 2]


async def test_default_session_uses_token_bound_at_header_write_time(harness: SessionBindingHarness) -> None:
    session_a = harness.client.session
    session_a.restore_authentication_token(TOKEN_A)
    protocol, transport, _ = harness.current()

    harness.hook.arm()
    task = asyncio.create_task(read_request_handle(session_a))
    await harness.hook.wait_until_entered()
    session_a.restore_authentication_token(TOKEN_A_RENEWED)
    harness.hook.release.set()
    await transport.wait_for_packets(1)

    header = harness.respond(protocol, 0)
    assert await task == header.RequestHandle
    assert header.AuthenticationToken == TOKEN_A_RENEWED


async def test_explicit_session_rebinds_to_new_transport_and_token_after_reconnect(
    harness: SessionBindingHarness,
) -> None:
    session_b = UaSession(harness.client)
    session_b.restore_authentication_token(TOKEN_B)
    protocol1, transport1, _ = harness.current()

    harness.hook.arm()
    task = asyncio.create_task(read_request_handle(session_b))
    await harness.hook.wait_until_entered()
    protocol1.connection_lost(ConnectionError("connection reset"))
    protocol2, transport2, _ = harness.open_connection()
    session_b.restore_authentication_token(TOKEN_B_RENEWED)
    harness.hook.release.set()
    await transport2.wait_for_packets(1)

    header = harness.respond(protocol2, 0)
    assert await task == header.RequestHandle
    assert transport1.packets == []
    assert header.AuthenticationToken == TOKEN_B_RENEWED


async def test_late_response_on_old_connection_is_not_routed_to_new_connection(
    harness: SessionBindingHarness,
) -> None:
    session_b = UaSession(harness.client)
    session_b.restore_authentication_token(TOKEN_B)
    protocol1, transport1, wire1 = harness.current()

    first = asyncio.create_task(read_request_handle(session_b))
    await transport1.wait_for_packets(1)

    protocol2, transport2, wire2 = harness.open_connection()
    second = asyncio.create_task(read_request_handle(session_b))
    await transport2.wait_for_packets(1)

    request_id1, header1 = wire1.decode_request(transport1.packets[0])
    request_id2, header2 = wire2.decode_request(transport2.packets[0])
    assert request_id1 == request_id2
    assert header1.AuthenticationToken == TOKEN_B
    assert header2.AuthenticationToken == TOKEN_B

    protocol1.data_received(wire1.encode_read_response(request_id1, header1))
    assert await first == header1.RequestHandle
    await asyncio.sleep(0)
    assert not second.done()

    protocol2.data_received(wire2.encode_read_response(request_id2, header2))
    assert await second == header2.RequestHandle


async def test_explicit_null_token_is_not_conflated_with_unspecified(harness: SessionBindingHarness) -> None:
    client = harness.client
    client.session.restore_authentication_token(TOKEN_A)
    protocol, transport, _ = harness.current()

    unspecified = asyncio.create_task(client._send_request(ua.ReadRequest()))
    explicit_null = asyncio.create_task(protocol.send_request(ua.ReadRequest(), authentication_token=ua.NodeId()))
    uncreated_session = asyncio.create_task(read_request_handle(UaSession(client)))
    await transport.wait_for_packets(3)
    for index in range(3):
        harness.respond(protocol, index)
    await asyncio.gather(unspecified, explicit_null, uncreated_session)

    headers = harness.decoded_headers(protocol)
    assert headers[0].AuthenticationToken == TOKEN_A
    assert headers[1].AuthenticationToken.is_null()
    assert headers[2].AuthenticationToken.is_null()


async def test_legacy_protocol_overrides_keep_working_on_the_wire(
    harness: SessionBindingHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = harness.client
    protocol, transport, _ = harness.current()
    original_send = protocol.send_request
    original_send_sync = protocol._send_request
    original_setup_header = protocol._setup_request_header

    async def send(
        request: object, timeout: float | None = None, message_type: ua.MessageType = ua.MessageType.SecureMessage
    ) -> Buffer:
        return await original_send(request, timeout, message_type)

    def send_sync(
        request: object, timeout: float = 1, message_type: ua.MessageType = ua.MessageType.SecureMessage
    ) -> asyncio.Future:
        return original_send_sync(request, timeout, message_type)

    def setup_header(header: ua.RequestHeader, timeout: float = 1) -> None:
        original_setup_header(header, timeout)

    monkeypatch.setattr(protocol, "send_request", send)
    monkeypatch.setattr(protocol, "_send_request", send_sync)
    monkeypatch.setattr(protocol, "_setup_request_header", setup_header)

    client.session.restore_authentication_token(TOKEN_A)
    first = asyncio.create_task(read_request_handle(client.session))
    await transport.wait_for_packets(1)
    header1 = harness.respond(protocol, 0)
    assert await first == header1.RequestHandle

    client.session.restore_authentication_token(TOKEN_A_RENEWED)
    second = asyncio.create_task(read_request_handle(client.session))
    await transport.wait_for_packets(2)
    header2 = harness.respond(protocol, 1)
    assert await second == header2.RequestHandle

    headers = harness.decoded_headers(protocol)
    assert [header.AuthenticationToken for header in headers] == [TOKEN_A, TOKEN_A_RENEWED]


async def test_cancelled_request_leaves_shared_transport_usable(harness: SessionBindingHarness) -> None:
    client = harness.client
    client.session.restore_authentication_token(TOKEN_A)
    session_b = UaSession(client)
    session_b.restore_authentication_token(TOKEN_B)
    protocol, transport, _ = harness.current()

    cancelled = asyncio.create_task(read_request_handle(session_b))
    await transport.wait_for_packets(1)
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled

    survivor = asyncio.create_task(read_request_handle(client.session))
    await transport.wait_for_packets(2)
    harness.respond(protocol, 0)
    header = harness.respond(protocol, 1)
    assert await survivor == header.RequestHandle

    headers = harness.decoded_headers(protocol)
    assert [h.AuthenticationToken for h in headers] == [TOKEN_B, TOKEN_A]


async def test_sessions_reconnect_and_cancellation_stay_on_their_own_binding(
    harness: SessionBindingHarness,
) -> None:
    client = harness.client
    session_a = client.session
    session_b = UaSession(client)
    session_a.restore_authentication_token(TOKEN_A)
    session_b.restore_authentication_token(TOKEN_B)
    protocol1, transport1, _ = harness.current()

    harness.hook.arm()
    paused_a = asyncio.create_task(read_request_handle(session_a))
    await harness.hook.wait_until_entered()

    done_b = asyncio.create_task(read_request_handle(session_b))
    await transport1.wait_for_packets(1)
    header_b = harness.respond(protocol1, 0)
    assert await done_b == header_b.RequestHandle

    protocol1.connection_lost(ConnectionError("connection reset"))
    protocol2, transport2, _ = harness.open_connection()
    session_a.restore_authentication_token(TOKEN_A_RENEWED)

    harness.hook.release.set()
    with pytest.raises(ConnectionError):
        await paused_a
    assert len(transport1.packets) == 1
    assert transport2.packets == []

    legacy_a = asyncio.create_task(read_request_handle(session_a))
    await transport2.wait_for_packets(1)
    header_a = harness.respond(protocol2, 0)
    assert await legacy_a == header_a.RequestHandle

    resumed_b = asyncio.create_task(read_request_handle(session_b))
    await transport2.wait_for_packets(2)
    header_b2 = harness.respond(protocol2, 1)
    assert await resumed_b == header_b2.RequestHandle

    session_c = UaSession(client)
    session_c.restore_authentication_token(TOKEN_C)
    harness.hook.arm()
    cancelled_c = asyncio.create_task(read_request_handle(session_c))
    await harness.hook.wait_until_entered()
    cancelled_c.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled_c
    harness.hook.release.set()
    await asyncio.sleep(0)
    assert len(transport2.packets) == 2

    retried_c = asyncio.create_task(read_request_handle(session_c))
    await transport2.wait_for_packets(3)
    header_c = harness.respond(protocol2, 2)
    assert await retried_c == header_c.RequestHandle

    headers1 = harness.decoded_headers(protocol1)
    headers2 = harness.decoded_headers(protocol2)
    assert [header.AuthenticationToken for header in headers1] == [TOKEN_B]
    assert [header.AuthenticationToken for header in headers2] == [TOKEN_A_RENEWED, TOKEN_B, TOKEN_C]
    assert [header.RequestHandle for header in headers2] == [1, 2, 3]
