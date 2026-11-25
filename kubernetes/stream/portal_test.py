# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import websocket

from . import ws_client as ws_client_module
from .portal import (
    DisclosurePolicy,
    DiagnosticsAccessDenied,
    RestrictedPortal,
    SupportPortal,
)
from .ws_client import (
    ERROR_CHANNEL,
    STDOUT_CHANNEL,
    ProtocolReportedFailure,
    StreamDisconnected,
    V5_CHANNEL_PROTOCOL,
    WSClient,
)


PRIVATE_CHANNEL = 7
PUBLIC_OUTPUT = "public summary: ok\n"
PRIVATE_DIAGNOSTIC = "fictional diagnostic: internal-token-7558\n"
SUCCESS_STATUS = "apiVersion: v1\nkind: Status\nstatus: Success\n"
FAILURE_STATUS = """\
apiVersion: v1
kind: Status
status: Failure
message: command terminated with exit code 17
reason: NonZeroExitCode
details:
  causes:
  - reason: ExitCode
    message: '17'
"""


def data_frame(channel, payload):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return websocket.ABNF(
        1, 0, 0, 0, websocket.ABNF.OPCODE_BINARY, 0,
        bytes([channel]) + payload,
    ).format()


def close_frame():
    return websocket.ABNF(
        1, 0, 0, 0, websocket.ABNF.OPCODE_CLOSE, 0, b"\x03\xe8",
    ).format()


@pytest.fixture
def frame_client():
    config = MagicMock()
    config.assert_hostname = False
    config.proxy = None
    config.ssl_ca_cert = None
    config.cert_file = None
    config.key_file = None
    config.verify_ssl = True

    mock_ws = MagicMock()
    mock_ws.subprotocol = V5_CHANNEL_PROTOCOL
    mock_ws.connected = True
    with patch.object(ws_client_module, "create_websocket", return_value=mock_ws):
        client = WSClient(config, "wss://local/exec", None, capture_all=True)

    server_sock, client_sock = socket.socketpair()
    ws = websocket.WebSocket()
    ws.sock = client_sock
    ws.connected = True
    client.sock = ws
    client.subprotocol = V5_CHANNEL_PROTOCOL

    try:
        yield client, server_sock
    finally:
        server_sock.close()
        client_sock.close()


def send_frames(server_sock, *frames):
    server_sock.sendall(b"".join(frames))


def test_restricted_portal_applies_one_rule_to_channel_aggregate_and_exit(frame_client):
    client, server = frame_client
    portal = client.restricted_view(diagnostic_channels=[PRIVATE_CHANNEL])

    send_frames(
        server,
        data_frame(STDOUT_CHANNEL, PUBLIC_OUTPUT),
        data_frame(PRIVATE_CHANNEL, PRIVATE_DIAGNOSTIC),
    )
    client.update(timeout=5)

    assert client.read_channel(STDOUT_CHANNEL) == PUBLIC_OUTPUT
    assert client.read_channel(PRIVATE_CHANNEL) == PRIVATE_DIAGNOSTIC

    assert portal.read_channel(STDOUT_CHANNEL) == PUBLIC_OUTPUT
    assert portal.read_channel(PRIVATE_CHANNEL) == ""
    assert portal.read_all() == PUBLIC_OUTPUT
    assert client.read_all() == PUBLIC_OUTPUT
    assert PRIVATE_DIAGNOSTIC not in portal.read_all()

    send_frames(server, data_frame(ERROR_CHANNEL, SUCCESS_STATUS))
    client.update(timeout=5)
    send_frames(server, close_frame())
    client.update(timeout=5)

    internal_result = client.termination()
    public_result = portal.termination()
    assert internal_result.kind == "normal"
    assert internal_result.exit_code == 0
    assert public_result.kind == internal_result.kind
    assert public_result.exit_code == internal_result.exit_code == 0
    assert portal.returncode == client.returncode == 0
    assert public_result.status["status"] == "Success"


def test_buffered_portal_reads_drain_after_close_then_return_eof(frame_client):
    client, server = frame_client
    portal = RestrictedPortal(
        client,
        DisclosurePolicy(
            public_channels=[STDOUT_CHANNEL],
            diagnostic_channels=[PRIVATE_CHANNEL],
        ),
    )

    send_frames(
        server,
        data_frame(STDOUT_CHANNEL, PUBLIC_OUTPUT),
        data_frame(PRIVATE_CHANNEL, PRIVATE_DIAGNOSTIC),
        close_frame(),
    )
    client.update(timeout=5)

    assert not client.is_open()
    assert not portal.is_open()

    assert portal.peek_stdout() == PUBLIC_OUTPUT
    assert portal.read_stdout() == PUBLIC_OUTPUT
    assert portal.read_stdout() == ""
    assert portal.read_channel(PRIVATE_CHANNEL) == ""
    assert portal.read_all() == PUBLIC_OUTPUT
    assert portal.read_all() == ""

    assert client.read_channel(STDOUT_CHANNEL) == PUBLIC_OUTPUT
    assert client.read_channel(STDOUT_CHANNEL) == ""
    assert client.read_channel(PRIVATE_CHANNEL) == PRIVATE_DIAGNOSTIC
    assert client.read_channel(PRIVATE_CHANNEL) == ""

    result = portal.termination()
    assert result.kind == "disconnected"
    assert result.disconnected is True
    assert result.formal_status_received is False
    assert result.exit_code is None
    assert portal.returncode is None
    with pytest.raises(StreamDisconnected):
        portal.raise_for_termination()

    assert portal.read_stdout() == ""
    assert portal.read_all() == ""
    assert portal.termination() is result or portal.termination().kind == result.kind


def test_protocol_failure_is_distinguished_from_transport_disconnect(frame_client):
    client, server = frame_client
    portal = client.restricted_view()

    send_frames(server, data_frame(STDOUT_CHANNEL, "failed summary\n"))
    client.update(timeout=5)
    send_frames(server, data_frame(ERROR_CHANNEL, FAILURE_STATUS))
    client.update(timeout=5)
    send_frames(server, close_frame())
    client.update(timeout=5)

    result = portal.wait_termination(timeout=5)
    assert result.kind == "protocol_failure"
    assert result.protocol_failure is True
    assert result.exit_code == 17
    assert result.formal_status_received is True
    assert "exit code 17" in result.error
    with pytest.raises(ProtocolReportedFailure):
        client.raise_for_termination()


def test_approved_support_entry_reads_private_diagnostics(frame_client):
    client, server = frame_client

    with pytest.raises(DiagnosticsAccessDenied):
        SupportPortal(client, diagnostic_channels=[PRIVATE_CHANNEL])

    support = client.support_entry(
        approved=True,
        diagnostic_channels=[PRIVATE_CHANNEL],
    )
    send_frames(
        server,
        data_frame(STDOUT_CHANNEL, PUBLIC_OUTPUT),
        data_frame(PRIVATE_CHANNEL, PRIVATE_DIAGNOSTIC),
        data_frame(ERROR_CHANNEL, SUCCESS_STATUS),
        close_frame(),
    )
    client.wait_termination(timeout=5)

    assert support.read_channel(PRIVATE_CHANNEL) == PRIVATE_DIAGNOSTIC
    assert support.read_diagnostics() == ""
    assert support.termination().exit_code == 0

    second = client.support_entry(
        approval=SimpleNamespace(approved=True),
        channels=[PRIVATE_CHANNEL],
    )
    assert second.policy.allows_channel(PRIVATE_CHANNEL)


def test_support_entry_aggregate_contains_only_diagnostics(frame_client):
    client, server = frame_client
    support = SupportPortal(
        client,
        authorized=True,
        channels=[PRIVATE_CHANNEL],
    )

    send_frames(
        server,
        data_frame(STDOUT_CHANNEL, PUBLIC_OUTPUT),
        data_frame(PRIVATE_CHANNEL, PRIVATE_DIAGNOSTIC),
        close_frame(),
    )
    client.update(timeout=5)

    assert support.read_all() == PRIVATE_DIAGNOSTIC
    assert support.read() == ""
    assert support.entries()[PRIVATE_CHANNEL] == ""


def test_portal_applies_rule_to_manually_buffered_channel():
    class FakeStream:
        binary = False

        def __init__(self):
            self._channels = {}

        def update(self, timeout=0):
            pass

        def is_open(self):
            return False

    raw = FakeStream()
    portal = RestrictedPortal(
        raw,
        allowed_channels=[STDOUT_CHANNEL],
        secret_values=["secret-token"],
        replacement="[REDACTED]",
    )
    raw._channels[STDOUT_CHANNEL] = "summary secret-token"

    assert portal.read_channel(STDOUT_CHANNEL) == "summary [REDACTED]"
    assert portal.read_all() == "summary [REDACTED]"
    assert portal.read_channel(99) == ""


def test_same_redaction_rule_filters_terminal_error():
    policy = DisclosurePolicy(
        allowed_channels=[STDOUT_CHANNEL],
        secret_values=["internal-failure-token"],
        replacement="[REDACTED]",
    )
    termination = ws_client_module.Termination(
        "protocol_failure",
        exit_code=9,
        status={
            "status": "Failure",
            "message": "failed with internal-failure-token",
        },
        error="failed with internal-failure-token",
    )

    filtered = policy.filter_termination(termination)
    assert filtered.exit_code == 9
    assert "internal-failure-token" not in filtered.error
    assert "internal-failure-token" not in filtered.status["message"]
    assert "[REDACTED]" in filtered.error
