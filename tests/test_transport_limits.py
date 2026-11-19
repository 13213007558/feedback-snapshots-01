"""Resource-exhaustion regressions for the OPC UA TCP framing and reassembly paths.

The tests drive the real chunk encoder/decoder with tiny, legal limits and
hand-written frame headers, so the boundaries are observed on the wire bytes
and on what the assembler keeps, not only on a single function return value.
"""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest

from asyncua import ua
from asyncua.common.connection import MessageChunk, SecureConnection, TransportLimits
from asyncua.common.utils import Buffer
from asyncua.crypto.security_policies import SecurityPolicyAes128Sha256RsaOaep, SecurityPolicyNone
from asyncua.server.binary_server_asyncio import OPCUAProtocol
from asyncua.ua.ua_binary import header_from_binary, struct_from_binary, struct_to_binary, uatcp_to_binary

EXAMPLES = Path(__file__).parent.parent / "examples"


def _frame(header: ua.Header) -> bytes:
    body_size = header.packet_size - header.header_size
    return struct.pack("<3scI", header.MessageType, header.ChunkType, header.packet_size) + bytes(body_size)


def _frames(wire: bytes) -> Iterator[bytes]:
    buf = Buffer(wire)
    while buf:
        start = buf.cur_pos
        header = header_from_binary(buf)
        end = start + header.header_size + header.body_size
        yield wire[start:end]
        buf.skip(header.body_size)


def _plain_connection(limits: TransportLimits) -> SecureConnection:
    connection = SecureConnection(SecurityPolicyNone(), limits)
    connection.security_token.ChannelId = 1
    connection.security_token.TokenId = 1
    return connection


def _raw_chunk(seq: int, request_id: int, body: bytes, chunk_type: ua.ChunkType) -> MessageChunk:
    chunk = MessageChunk(SecurityPolicyNone().symmetric_cryptography, body, ua.MessageType.SecureMessage, chunk_type)
    chunk.MessageHeader.ChannelId = 1
    chunk.MessageHeader.packet_size = len(body) + 24
    chunk.SequenceHeader.RequestId = request_id
    chunk.SequenceHeader.SequenceNumber = seq
    return chunk


def _new_request(connection: SecureConnection) -> None:
    connection._peer_sequence_number = None
    connection._drop_incoming_parts()


def _deliver(connection: SecureConnection, wire: bytes, *, new_request: bool = True) -> list[ua.Message]:
    messages = []
    for index, frame in enumerate(_frames(wire)):
        buf = Buffer(frame)
        header = header_from_binary(buf)
        if new_request and index == 0:
            _new_request(connection)
        result = connection.receive_from_header_and_body(header, buf)
        if result is not None:
            messages.append(result)
    return messages


@pytest.fixture(scope="module")
def crypto_pair() -> tuple[SecurityPolicyAes128Sha256RsaOaep, SecurityPolicyAes128Sha256RsaOaep]:
    from asyncua.crypto import uacrypto

    cert = asyncio.run(uacrypto.load_certificate(EXAMPLES / "certificate-example.der"))
    key = asyncio.run(uacrypto.load_private_key(EXAMPLES / "private-key-example.pem"))

    def policy() -> SecurityPolicyAes128Sha256RsaOaep:
        return SecurityPolicyAes128Sha256RsaOaep(
            peer_cert=cert, host_cert=cert, host_privkey=key, mode=ua.MessageSecurityMode.SignAndEncrypt
        )

    sender, receiver = policy(), policy()
    secret, seed = b"s" * 32, b"r" * 32
    sender.make_local_symmetric_key(secret, seed)
    receiver.make_remote_symmetric_key(secret, seed, 60_000)
    return sender, receiver


def test_zero_limits_mean_an_unbounded_receiver() -> None:
    limits = TransportLimits(max_recv_buffer=0, max_send_buffer=65535, max_chunk_count=0, max_message_size=0)
    connection = _plain_connection(limits)
    sender = _plain_connection(TransportLimits(max_send_buffer=0))

    body = bytes(20_000)
    messages = _deliver(connection, sender.message_to_binary(body, request_id=1))

    assert len(messages) == 1
    assert messages[0].body().read(len(body)) == body
    assert connection._incoming_parts == []


def test_receive_limit_counts_wire_bytes_not_body_bytes() -> None:
    plain_overhead = ua.Header.max_size() + ua.SymmetricAlgorithmHeader.max_size() + ua.SequenceHeader.max_size()
    body = bytes(plain_overhead + 10)
    limits = TransportLimits(max_recv_buffer=len(body) + plain_overhead, max_send_buffer=0, max_chunk_count=0)
    sender = _plain_connection(TransportLimits(max_send_buffer=0))
    wire = sender.message_to_binary(body, request_id=1)
    assert len(wire) == len(body) + plain_overhead

    _deliver(_plain_connection(limits), wire)

    too_small = TransportLimits(max_recv_buffer=len(wire) - 1, max_send_buffer=0, max_chunk_count=0)
    with pytest.raises(ua.UaStatusCodeError):
        _deliver(_plain_connection(too_small), wire)


def test_send_limit_is_the_wire_size_after_padding_and_signature(crypto_pair) -> None:
    sender_policy, receiver_policy = crypto_pair
    max_chunk = 128
    sender = SecureConnection(sender_policy, TransportLimits(max_send_buffer=max_chunk, max_chunk_count=0))
    sender.security_token.ChannelId = 1
    sender.security_token.TokenId = 1

    body = bytes(range(200))
    wire = sender.message_to_binary(body, request_id=9)
    chunks = list(_frames(wire))

    assert len(chunks) > 1
    assert max(len(chunk) for chunk in chunks) <= max_chunk
    assert all(len(chunk) % 16 == 0 for chunk in chunks)

    receiver = SecureConnection(receiver_policy, TransportLimits(max_recv_buffer=max_chunk, max_chunk_count=0))
    receiver.security_token.ChannelId = 1
    receiver.security_token.TokenId = 1
    messages = _deliver(receiver, wire)
    assert [message.body().read(200) for message in messages] == [body]


def test_abort_releases_fragments_so_the_next_request_starts_clean() -> None:
    limits = TransportLimits(max_recv_buffer=4096, max_send_buffer=0, max_chunk_count=0, max_message_size=0)
    connection = _plain_connection(limits)
    first = _raw_chunk(1, 1, b"fragment-1", ua.ChunkType.Intermediate)
    assert connection._receive(first) is None
    assert connection._incoming_size == len(b"fragment-1")

    abort = _raw_chunk(2, 1, struct_to_binary(ua.ErrorMessage()), ua.ChunkType.Abort)
    assert connection._receive(abort) is None
    assert connection._incoming_parts == []
    assert connection._incoming_size == 0

    sender = _plain_connection(TransportLimits(max_send_buffer=0))
    sender._sequence_number = 2
    second = sender.message_to_binary(b"next-request", request_id=2)
    messages = _deliver(connection, second)
    assert [message.body().read(12) for message in messages] == [b"next-request"]


def test_truncated_receive_does_not_brick_the_connection() -> None:
    limits = TransportLimits(max_recv_buffer=4096, max_send_buffer=0, max_chunk_count=0, max_message_size=0)
    connection = _plain_connection(limits)
    sender = _plain_connection(TransportLimits(max_send_buffer=0))
    wire = sender.message_to_binary(b"payload", request_id=1)

    truncated = wire[:-3]
    with pytest.raises((ua.uaerrors.UaError, ValueError)):
        _deliver(connection, truncated)
    assert connection._incoming_parts == []

    messages = _deliver(connection, sender.message_to_binary(b"payload", request_id=1))
    assert [message.body().read(7) for message in messages] == [b"payload"]


def test_a_rejected_oversized_fragment_leaves_nothing_for_the_next_request() -> None:
    limits = TransportLimits(max_recv_buffer=1024, max_send_buffer=0, max_chunk_count=0, max_message_size=2048)
    connection = _plain_connection(limits)
    sender = _plain_connection(TransportLimits(max_send_buffer=0))
    sender._sequence_number = 0

    for seq, chunk_type in ((1, ua.ChunkType.Intermediate), (2, ua.ChunkType.Intermediate), (3, ua.ChunkType.Single)):
        chunk = _raw_chunk(seq, 1, bytes(1000), chunk_type)
        if seq < 3:
            assert connection._receive(chunk) is None
        else:
            with pytest.raises(ua.UaStatusCodeError):
                connection._receive(chunk)
    assert connection._incoming_parts == []
    assert connection._incoming_size == 0

    messages = _deliver(connection, sender.message_to_binary(b"fresh", request_id=2))
    assert [message.body().read(5) for message in messages] == [b"fresh"]


def test_chunk_count_limit_includes_the_final_chunk() -> None:
    limits = TransportLimits(max_recv_buffer=1024, max_send_buffer=0, max_chunk_count=2, max_message_size=0)
    connection = _plain_connection(limits)
    for seq, chunk_type in ((1, ua.ChunkType.Intermediate), (2, ua.ChunkType.Single)):
        result = connection._receive(_raw_chunk(seq, 1, bytes(100), chunk_type))
    assert result is not None

    exact = TransportLimits(max_recv_buffer=1024, max_send_buffer=0, max_chunk_count=1, max_message_size=0)
    connection = _plain_connection(exact)
    for seq, chunk_type in ((1, ua.ChunkType.Intermediate), (2, ua.ChunkType.Single)):
        chunk = _raw_chunk(seq, 1, bytes(100), chunk_type)
        if seq == 1:
            assert connection._receive(chunk) is None
        else:
            with pytest.raises(ua.UaStatusCodeError):
                connection._receive(chunk)


def test_send_limit_smaller_than_the_headers_is_reported() -> None:
    sender = _plain_connection(TransportLimits(max_send_buffer=24))
    with pytest.raises(ua.UaError):
        sender.message_to_binary(b"payload", request_id=1)


def test_peer_message_limits_are_enforced_while_sending() -> None:
    limits = TransportLimits(max_send_buffer=64, max_send_message_size=10, max_send_chunk_count=1)
    sender = _plain_connection(limits)
    with pytest.raises(ua.UaError):
        sender.message_to_binary(bytes(11), request_id=1)

    limits = TransportLimits(max_send_buffer=64, max_send_message_size=0, max_send_chunk_count=1)
    sender = _plain_connection(limits)
    with pytest.raises(ua.UaError):
        sender.message_to_binary(bytes(200), request_id=1)

    limits = TransportLimits(max_send_buffer=64, max_send_message_size=0, max_send_chunk_count=0)
    sender = _plain_connection(limits)
    assert sender.message_to_binary(bytes(200), request_id=1)


def test_a_short_multichunk_message_still_completes() -> None:
    limits = TransportLimits(max_recv_buffer=40, max_send_buffer=40, max_chunk_count=0, max_message_size=0)
    receiver = _plain_connection(limits)
    sender = _plain_connection(TransportLimits(max_send_buffer=40))
    body = b"a" * 41

    wire = sender.message_to_binary(body, request_id=1)
    chunks = list(_frames(wire))
    assert len(chunks) > 1
    messages = _deliver(receiver, wire)
    assert [message.body().read(len(body)) for message in messages] == [body]


def test_hello_negotiation_keeps_directions_and_zero_means_unlimited() -> None:
    limits = TransportLimits(max_recv_buffer=16384, max_send_buffer=65535, max_chunk_count=5, max_message_size=4096)
    hello = ua.Hello(ReceiveBufferSize=8192, SendBufferSize=32768, MaxChunkCount=0, MaxMessageSize=0)

    ack = limits.create_acknowledge_and_set_limits(hello)

    assert ack.ReceiveBufferSize == 16384
    assert ack.SendBufferSize == 8192
    assert (limits.max_recv_buffer, limits.max_send_buffer) == (16384, 8192)
    assert (ack.MaxChunkCount, ack.MaxMessageSize) == (5, 4096)
    assert (limits.max_send_chunk_count, limits.max_send_message_size) == (0, 0)

    client = TransportLimits(max_recv_buffer=0, max_send_buffer=0, max_chunk_count=0, max_message_size=0)
    client.update_client_limits(ack)
    assert (client.max_recv_buffer, client.max_send_buffer) == (8192, 16384)
    assert (client.max_send_chunk_count, client.max_send_message_size) == (5, 4096)


def test_zero_hello_buffers_are_advertised_as_unlimited() -> None:
    limits = TransportLimits(max_recv_buffer=0, max_send_buffer=0, max_chunk_count=0, max_message_size=0)
    ack = limits.create_acknowledge_and_set_limits(ua.Hello(ReceiveBufferSize=0, SendBufferSize=0))
    assert ack.ReceiveBufferSize == 0x7FFFFFFF
    assert ack.SendBufferSize == 0x7FFFFFFF


class _RecordingTransport:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        self.closed = True


def _protocol(limits: TransportLimits) -> tuple[OPCUAProtocol, _RecordingTransport]:
    protocol = OPCUAProtocol.__new__(OPCUAProtocol)
    protocol.peer_name = "peer"
    protocol.transport = _RecordingTransport()
    protocol._buffer = b""
    protocol.limits = limits
    protocol.messages = asyncio.Queue(maxsize=10)
    return protocol, protocol.transport


def test_server_rejects_a_declared_oversized_frame_before_it_arrives() -> None:
    protocol, transport = _protocol(TransportLimits(max_recv_buffer=64))
    header = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    header.ChannelId = 1
    header.packet_size = 24 + 10_000

    protocol.data_received(_frame(header))

    assert transport.closed
    assert transport.written and transport.written[0].startswith(b"ERRF")
    assert protocol._buffer == b""
    assert protocol.messages.empty()


def test_server_accepts_a_frame_exactly_at_the_limit() -> None:
    protocol, transport = _protocol(TransportLimits(max_recv_buffer=64))
    header = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    header.ChannelId = 1
    header.packet_size = 64

    protocol.data_received(_frame(header))

    assert not transport.closed
    assert transport.written == []
    assert protocol.messages.qsize() == 1


def test_server_keeps_no_partial_frame_when_a_later_header_is_rejected() -> None:
    protocol, transport = _protocol(TransportLimits(max_recv_buffer=64))
    header = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    header.ChannelId = 1
    header.packet_size = 128

    protocol.data_received(_frame(header)[:32])
    assert protocol._buffer == b""
    assert transport.closed
    assert protocol.messages.empty()


def test_error_frame_is_sent_before_closing_on_an_oversized_frame() -> None:
    protocol, transport = _protocol(TransportLimits(max_recv_buffer=8192))
    header = ua.Header(ua.MessageType.Hello, ua.ChunkType.Single)
    header.packet_size = 8193

    protocol.data_received(_frame(header))

    assert transport.closed
    assert transport.written
    error = transport.written[0]
    assert error.startswith(b"ERRF")
    parsed = struct_from_binary(ua.ErrorMessage, Buffer(error[8:]))
    assert parsed.Error.value == ua.StatusCodes.BadTcpMessageTooLarge


def test_hello_frame_uses_the_same_limit_as_secure_frames() -> None:
    protocol, transport = _protocol(TransportLimits(max_recv_buffer=16))
    hello = ua.Hello(ReceiveBufferSize=8192, SendBufferSize=8192, EndpointUrl="opc.tcp://example")
    frame = uatcp_to_binary(ua.MessageType.Hello, hello)

    protocol.data_received(frame)

    assert transport.closed
    assert protocol.messages.empty()


def test_server_discards_the_previous_message_when_a_later_frame_exceeds_the_limit() -> None:
    protocol, transport = _protocol(TransportLimits(max_recv_buffer=64))
    ok = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    ok.ChannelId = 1
    ok.packet_size = 64
    protocol.data_received(_frame(ok))
    assert protocol.messages.qsize() == 1

    oversized = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    oversized.ChannelId = 1
    oversized.packet_size = 65
    protocol.data_received(_frame(oversized))

    assert transport.closed
    assert protocol.messages.qsize() == 1
    assert protocol._buffer == b""


def test_server_closes_bounded_when_a_response_cannot_fit_the_peer_limits() -> None:
    from asyncua.server.uaprocessor import UaProcessor

    transport = _RecordingTransport()
    transport.get_extra_info = lambda name: ("peer", 1234)  # type: ignore[method-assign]
    processor = UaProcessor.__new__(UaProcessor)
    processor._transport = transport
    processor._connection = _plain_connection(TransportLimits(max_send_buffer=24))
    processor._connection.security_token.ChannelId = 1

    processor.send_response(1, ua.SequenceHeader(SequenceNumber=1, RequestId=1), ua.ServiceFault())

    assert transport.closed
    assert transport.written and transport.written[0].startswith(b"ERRF")
    parsed = struct_from_binary(ua.ErrorMessage, Buffer(transport.written[0][8:]))
    assert parsed.Error.value == ua.StatusCodes.BadResponseTooLarge


def test_client_drops_a_declared_frame_larger_than_its_receive_limit() -> None:
    from asyncua.client.ua_client import UASocketProtocol

    class _ClientTransport:
        closed = False

        def write(self, data: bytes) -> None:
            pass

        def close(self) -> None:
            self.closed = True

        def get_extra_info(self, name: str) -> tuple[str, int]:
            return ("peer", 1234)

    protocol = UASocketProtocol(limits=TransportLimits(max_recv_buffer=64))
    transport = _ClientTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]

    header = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    header.ChannelId = 1
    header.packet_size = 4096
    protocol.data_received(_frame(header)[:16])

    assert transport.closed
    assert protocol.receive_buffer is None


def test_message_size_limit_is_inclusive_of_the_final_byte() -> None:
    sender = _plain_connection(TransportLimits(max_send_buffer=0))
    wire = sender.message_to_binary(b"x" * 100, request_id=1)

    exact = _plain_connection(TransportLimits(max_recv_buffer=4096, max_chunk_count=0, max_message_size=100))
    assert _deliver(exact, wire)

    tight = _plain_connection(TransportLimits(max_recv_buffer=4096, max_chunk_count=0, max_message_size=99))
    with pytest.raises(ua.UaStatusCodeError):
        _deliver(tight, wire)
    assert tight._incoming_size == 0
    assert tight._incoming_parts == []


def test_receive_limit_is_inclusive_of_the_header_bytes(crypto_pair) -> None:
    sender_policy, receiver_policy = crypto_pair
    sender = SecureConnection(sender_policy, TransportLimits(max_send_buffer=256, max_chunk_count=0))
    sender.security_token.ChannelId = 1
    sender.security_token.TokenId = 1
    wire = sender.message_to_binary(b"y" * 32, request_id=3)
    frame_size = max(len(frame) for frame in _frames(wire))

    exact = SecureConnection(receiver_policy, TransportLimits(max_recv_buffer=frame_size, max_chunk_count=0))
    exact.security_token.ChannelId = 1
    exact.security_token.TokenId = 1
    assert _deliver(exact, wire)

    tight = SecureConnection(receiver_policy, TransportLimits(max_recv_buffer=frame_size - 1, max_chunk_count=0))
    tight.security_token.ChannelId = 1
    tight.security_token.TokenId = 1
    with pytest.raises(ua.UaStatusCodeError):
        _deliver(tight, wire)
    assert tight._incoming_parts == []
