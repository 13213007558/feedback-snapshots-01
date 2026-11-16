# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import struct
from threading import Event
from unittest.mock import Mock, patch

import pytest

from fido2 import cbor
from fido2.ctap import STATUS, CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import (
    CAPABILITY,
    CTAPHID,
    TYPE_INIT,
    ConnectionFailure,
    CtapHidDevice,
    open_device,
)
from fido2.hid.base import parse_report_descriptor


def test_parse_report_descriptor_1():
    max_in_size, max_out_size = parse_report_descriptor(
        bytes.fromhex(
            "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
        )
    )

    assert max_in_size == 64
    assert max_out_size == 64


def test_parse_report_descriptor_2():
    with pytest.raises(ValueError):
        parse_report_descriptor(
            bytes.fromhex(
                "05010902a1010901a10005091901290515002501950575018102950175038101"
                "05010930093109381581257f750895038106c0c0"
            )
        )


@pytest.mark.parametrize("enumerate_devices", [False, True])
@pytest.mark.parametrize("close_fails", [False, True])
@pytest.mark.parametrize(
    "error", [OSError("disconnected during INIT"), KeyboardInterrupt()]
)
def test_failed_open_closes_connection(enumerate_devices, close_fails, error):
    descriptor = Mock(report_size_out=64)
    connection = Mock()
    if close_fails:
        connection.close.side_effect = OSError("close failed")
    with (
        patch("fido2.hid.list_descriptors", return_value=[descriptor]),
        patch("fido2.hid.get_descriptor", return_value=descriptor),
        patch("fido2.hid.open_connection", return_value=connection),
        patch.object(CtapHidDevice, "call", side_effect=error),
        pytest.raises(type(error)) as raised,
    ):
        if enumerate_devices:
            next(CtapHidDevice.list_devices())
        else:
            open_device("fake-hid")
    assert raised.value is error
    connection.close.assert_called_once_with()


@pytest.mark.parametrize("enumerate_devices", [False, True])
def test_successful_open_transfers_connection_to_device(enumerate_devices):
    descriptor = Mock(report_size_out=64)
    connection = Mock()
    nonce = b"12345678"
    response = nonce + struct.pack(">IBBBBB", 1, 2, 3, 4, 5, 4)
    with (
        patch("fido2.hid.list_descriptors", return_value=[descriptor]),
        patch("fido2.hid.get_descriptor", return_value=descriptor),
        patch("fido2.hid.open_connection", return_value=connection),
        patch("fido2.hid.os.urandom", return_value=nonce),
        patch.object(CtapHidDevice, "call", return_value=response),
    ):
        if enumerate_devices:
            device = next(CtapHidDevice.list_devices())
        else:
            device = open_device("fake-hid")
    connection.close.assert_not_called()
    assert device.device_version == (3, 4, 5)
    device.close()
    connection.close.assert_called_once_with()


class MemoryHidConnection:
    """A CTAPHID connection where both directions are scripted in memory."""

    def __init__(self):
        self.incoming = []
        self.written = []
        self.closed = False

    def write_packet(self, data):
        assert len(data) == PACKET_SIZE
        self.written.append(bytes(data))

    def read_packet(self):
        if not self.incoming:
            raise AssertionError("no scripted HID packet left")
        packet = self.incoming.pop(0)
        if isinstance(packet, BaseException):
            raise packet
        return packet

    def close(self):
        self.closed = True


PACKET_SIZE = 64
CHANNEL = 0x01020304


def _packet(channel, cmd_or_seq, payload=b"", length=None):
    if cmd_or_seq & TYPE_INIT:
        if length is None:
            length = len(payload)
        header = struct.pack(">IBH", channel, cmd_or_seq, length)
    else:
        header = struct.pack(">IB", channel, cmd_or_seq)
    return (header + payload).ljust(PACKET_SIZE, b"\0")


def _init_packet(channel, cmd, payload=b"", length=None):
    return _packet(channel, TYPE_INIT | cmd, payload, length)


def _fragments(cmd, payload, channel=CHANNEL):
    packets = [_init_packet(channel, cmd, payload[: PACKET_SIZE - 7], len(payload))]
    remaining = payload[PACKET_SIZE - 7 :]
    seq = 0
    while remaining:
        packets.append(_packet(channel, seq, remaining[: PACKET_SIZE - 5]))
        remaining = remaining[PACKET_SIZE - 5 :]
        seq += 1
    return packets


def _descriptor():
    return Mock(
        path="memory",
        report_size_in=PACKET_SIZE,
        report_size_out=PACKET_SIZE,
        product_name="Memory",
        serial_number=None,
    )


def _open_memory_device(nonce=b"12345678"):
    connection = MemoryHidConnection()
    response = nonce + struct.pack(">IBBBBB", CHANNEL, 2, 1, 2, 3, CAPABILITY.CBOR)
    connection.incoming.extend(_fragments(CTAPHID.INIT, response, 0xFFFFFFFF))
    with patch("fido2.hid.os.urandom", return_value=nonce):
        device = CtapHidDevice(_descriptor(), connection)
    connection.written.clear()
    return device, connection


_GET_INFO = cbor.encode(
    {
        1: ["U2F_V2", "FIDO_2_0"],
        3: b"\x11" * 16,
        4: {"rk": True, "up": True},
        5: 1200,
        10: [{"alg": -7, "type": "public-key"}] * 8,
    }
)


def test_memory_hid_real_ctap2_query():
    device, connection = _open_memory_device()
    connection.incoming.extend(_fragments(CTAPHID.CBOR, b"\0" + _GET_INFO))

    ctap2 = Ctap2(device)

    assert ctap2.info.versions == ["U2F_V2", "FIDO_2_0"]
    assert ctap2.info.max_msg_size == 1200
    channel, cmd, length = struct.unpack_from(">IBH", connection.written.pop(0))
    assert (channel, cmd, length) == (CHANNEL, TYPE_INIT | CTAPHID.CBOR, 1)
    assert not connection.incoming


def test_keepalive_dedup_allows_between_fragments():
    device, connection = _open_memory_device()
    payload = b"x" * 200
    fragments = _fragments(CTAPHID.PING, payload)
    assert len(fragments) == 4
    connection.incoming.extend(
        [
            _init_packet(CHANNEL, CTAPHID.KEEPALIVE, bytes([STATUS.PROCESSING])),
            _init_packet(CHANNEL, CTAPHID.KEEPALIVE, bytes([STATUS.PROCESSING])),
            _init_packet(CHANNEL, CTAPHID.KEEPALIVE, bytes([STATUS.UPNEEDED])),
            *fragments[:2],
            _init_packet(CHANNEL, CTAPHID.KEEPALIVE, bytes([STATUS.UPNEEDED])),
            _init_packet(CHANNEL, CTAPHID.KEEPALIVE, bytes([STATUS.PROCESSING])),
            *fragments[2:],
        ]
    )
    statuses = []

    assert device.call(CTAPHID.PING, payload, on_keepalive=statuses.append) == payload
    assert statuses == [STATUS.PROCESSING, STATUS.UPNEEDED, STATUS.PROCESSING]


def test_wrong_channel_rejected_before_payload_and_requires_relink():
    device, connection = _open_memory_device()
    stale = _init_packet(CHANNEL, CTAPHID.CBOR, b"\0\xa0")
    connection.incoming.extend(
        [_init_packet(CHANNEL + 1, CTAPHID.CBOR, b"\0\xa0"), stale]
    )
    writes = len(connection.written)

    with pytest.raises(ConnectionFailure, match="Wrong channel"):
        device.call(CTAPHID.CBOR, b"\x04")

    assert len(connection.written) == writes + 1
    assert connection.incoming == [stale]
    with pytest.raises(ConnectionFailure, match="out of sync"):
        device.call(CTAPHID.CBOR, b"\x04")
    assert connection.incoming == [stale]


def test_duplicate_continuation_rejected_at_sequence_check():
    device, connection = _open_memory_device()
    fragments = _fragments(CTAPHID.CBOR, b"\0" + b"z" * 250)
    assert len(fragments) > 3
    connection.incoming.extend([fragments[0], fragments[1], fragments[1]])

    with pytest.raises(ConnectionFailure, match="Wrong sequence number"):
        device.call(CTAPHID.CBOR, b"\x04")

    assert connection.incoming == []
    with pytest.raises(ConnectionFailure, match="out of sync"):
        device.call(CTAPHID.CBOR, b"\x04")


def test_sequence_127_cannot_wrap_to_a_new_fragment():
    device, connection = _open_memory_device()
    connection.incoming.append(_init_packet(CHANNEL, CTAPHID.CBOR, b"\0", 7609))
    # Short fragments keep the declared length unsatisfied while all 128
    # representable sequence numbers are consumed.
    for seq in range(128):
        connection.incoming.append(struct.pack(">IB", CHANNEL, seq))
    connection.incoming.append(struct.pack(">IB", CHANNEL, 0))

    with pytest.raises(ConnectionFailure, match="Too many continuation packets"):
        device.call(CTAPHID.CBOR, b"\x04")
    with pytest.raises(ConnectionFailure, match="out of sync"):
        device.call(CTAPHID.CBOR, b"\x04")


def test_declared_length_above_ctaphid_limit_rejected():
    device, connection = _open_memory_device()
    connection.incoming.append(_init_packet(CHANNEL, CTAPHID.CBOR, b"\0", 7610))

    with pytest.raises(ConnectionFailure, match="exceeds HID limit"):
        device.call(CTAPHID.CBOR, b"\x04")
    with pytest.raises(ConnectionFailure, match="out of sync"):
        device.call(CTAPHID.CBOR, b"\x04")


def test_cancel_is_terminal_so_late_response_is_not_reused():
    device, connection = _open_memory_device()
    late_success = _fragments(CTAPHID.CBOR, b"\0\xa0")
    connection.incoming.extend(
        [
            _init_packet(CHANNEL, CTAPHID.KEEPALIVE, bytes([STATUS.PROCESSING])),
            *late_success,
        ]
    )
    event = Event()

    def on_keepalive(_status):
        event.set()

    with pytest.raises(CtapError) as raised:
        device.call(CTAPHID.CBOR, b"\x04", event=event, on_keepalive=on_keepalive)
    assert raised.value.code == CtapError.ERR.KEEPALIVE_CANCEL

    channel, cmd = struct.unpack_from(">IB", connection.written[-1])
    assert (channel, cmd) == (CHANNEL, TYPE_INIT | CTAPHID.CANCEL)
    assert connection.incoming == late_success

    with pytest.raises(ConnectionFailure, match="out of sync"):
        device.call(CTAPHID.CBOR, b"\x04")
    assert connection.incoming == late_success


def test_transport_error_does_not_expose_stale_success():
    device, connection = _open_memory_device()
    success = _init_packet(CHANNEL, CTAPHID.CBOR, b"\0\xa0")
    connection.incoming.extend([OSError("disconnected"), success])

    with pytest.raises(OSError):
        device.call(CTAPHID.CBOR, b"\x04")

    assert connection.incoming == [success]
    with pytest.raises(ConnectionFailure, match="out of sync"):
        device.call(CTAPHID.CBOR, b"\x04")
    assert connection.incoming == [success]


def test_unknown_initial_command_cannot_be_taken_for_success():
    device, connection = _open_memory_device()
    connection.incoming.append(_init_packet(CHANNEL, CTAPHID.PING, b"\0\xa0"))

    with pytest.raises(ConnectionFailure, match="Unexpected initialization packet"):
        device.call(CTAPHID.CBOR, b"\x04")


def test_zero_length_response_is_a_complete_response():
    device, connection = _open_memory_device()
    connection.incoming.append(_init_packet(CHANNEL, CTAPHID.PING, b"", 0))

    assert device.call(CTAPHID.PING) == b""


def test_exact_ctaphid_limit_is_accepted():
    device, connection = _open_memory_device()
    payload = b"m" * 7609
    connection.incoming.extend(_fragments(CTAPHID.PING, payload))

    assert device.call(CTAPHID.PING) == payload


def test_error_reply_leaves_channel_reusable():
    device, connection = _open_memory_device()
    connection.incoming.extend(
        [
            _init_packet(
                CHANNEL, CTAPHID.ERROR, bytes([CtapError.ERR.INVALID_COMMAND])
            ),
            _init_packet(CHANNEL, CTAPHID.CBOR, b"\0\xa0"),
        ]
    )

    with pytest.raises(CtapError) as raised:
        device.call(CTAPHID.CBOR, b"\x04")
    assert raised.value.code == CtapError.ERR.INVALID_COMMAND

    assert device.call(CTAPHID.CBOR, b"\x04") == b"\0\xa0"


def test_oversized_request_is_rejected_before_writing():
    device, connection = _open_memory_device()
    writes = len(connection.written)

    with pytest.raises(CtapError) as raised:
        device.call(CTAPHID.PING, b"x" * 7610)

    assert raised.value.code == CtapError.ERR.REQUEST_TOO_LARGE
    assert len(connection.written) == writes
    # The channel state is untouched and the next command proceeds normally.
    connection.incoming.append(_init_packet(CHANNEL, CTAPHID.PING, b"ok"))
    assert device.call(CTAPHID.PING, b"ok") == b"ok"


def test_continuation_before_initialization_is_rejected():
    device, connection = _open_memory_device()
    connection.incoming.append(struct.pack(">IB", CHANNEL, 0))

    with pytest.raises(ConnectionFailure, match="Unexpected continuation packet"):
        device.call(CTAPHID.CBOR, b"\x04")


def test_declared_length_bounds_payload_in_initial_packet():
    device, connection = _open_memory_device()
    connection.incoming.append(
        _init_packet(CHANNEL, CTAPHID.PING, b"first-packet-tail", 5)
    )

    assert device.call(CTAPHID.PING) == b"first"
