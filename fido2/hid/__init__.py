# Copyright (c) 2020 Yubico AB
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

from __future__ import annotations

import logging
import os
import struct
import sys
from enum import IntEnum, IntFlag, unique
from threading import Event
from typing import Callable, Iterator

from ..ctap import STATUS, CtapDevice, CtapError
from ..utils import LOG_LEVEL_TRAFFIC
from .base import CtapHidConnection, HidDescriptor

logger = logging.getLogger(__name__)


if sys.platform == "linux":
    from . import linux as backend
elif sys.platform == "win32":
    from . import windows as backend
elif sys.platform == "darwin":
    from . import macos as backend
# The following have version numbers at the end
elif sys.platform.startswith("freebsd"):
    from . import freebsd as backend
elif sys.platform.startswith("netbsd"):
    from . import netbsd as backend
elif sys.platform.startswith("openbsd"):
    from . import openbsd as backend
else:
    raise Exception("Unsupported platform")


list_descriptors = backend.list_descriptors
get_descriptor = backend.get_descriptor
open_connection = backend.open_connection


class ConnectionFailure(Exception):
    """The CTAP connection failed or returned an invalid response."""


@unique
class CTAPHID(IntEnum):
    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11

    ERROR = 0x3F
    KEEPALIVE = 0x3B

    VENDOR_FIRST = 0x40


@unique
class CAPABILITY(IntFlag):
    WINK = 0x01
    LOCK = 0x02  # Not used
    CBOR = 0x04
    NMSG = 0x08

    def supported(self, flags: CAPABILITY) -> bool:
        return bool(flags & self)


TYPE_INIT = 0x80

# Continuation packets carry a 7-bit sequence number, so a message can span at
# most 128 of them.
MAX_SEQ = 0x7F

# Maximum size of a CTAPHID message, as defined by the CTAPHID protocol.
MAX_MSG_SIZE = 7609


class CtapHidDevice(CtapDevice):
    """
    CtapDevice implementation using the HID transport.

    :cvar descriptor: Device descriptor.
    """

    def __init__(self, descriptor: HidDescriptor, connection: CtapHidConnection):
        self.descriptor = descriptor
        self._packet_size = descriptor.report_size_out
        self._connection = connection
        self._out_of_sync = False

        nonce = os.urandom(8)
        self._channel_id = 0xFFFFFFFF
        response = self.call(CTAPHID.INIT, nonce)
        r_nonce, response = response[:8], response[8:]
        if r_nonce != nonce:
            raise ConnectionFailure("Wrong nonce")
        (
            self._channel_id,
            self._u2fhid_version,
            v1,
            v2,
            v3,
            self._capabilities,
        ) = struct.unpack_from(">IBBBBB", response)
        self._device_version = (v1, v2, v3)

    def __repr__(self):
        return f"CtapHidDevice({self.descriptor.path!r})"

    @property
    def version(self) -> int:
        """CTAP HID protocol version."""
        return self._u2fhid_version

    @property
    def device_version(self) -> tuple[int, int, int]:
        """Device version number."""
        return self._device_version

    @property
    def capabilities(self) -> int:
        """Capabilities supported by the device."""
        return self._capabilities

    @property
    def product_name(self) -> str | None:
        """Product name of device."""
        return self.descriptor.product_name

    @property
    def serial_number(self) -> str | None:
        """Serial number of device."""
        return self.descriptor.serial_number

    def _send_cancel(self):
        packet = struct.pack(">IB", self._channel_id, TYPE_INIT | CTAPHID.CANCEL).ljust(
            self._packet_size, b"\0"
        )
        logger.log(LOG_LEVEL_TRAFFIC, "SEND: %s", packet.hex())
        self._connection.write_packet(packet)

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        event = event or Event()
        if self._out_of_sync:
            raise ConnectionFailure("HID channel out of sync, re-open the device")

        while True:
            try:
                return self._do_call(cmd, data, event, on_keepalive)
            except CtapError as e:
                if e.code == CtapError.ERR.CHANNEL_BUSY:
                    if not event.wait(0.1):
                        logger.warning("CTAP channel busy, trying again...")
                        continue  # Keep retrying on BUSY while not cancelled
                raise

    def _do_call(self, cmd, data, event, on_keepalive):
        try:
            return self._transact(cmd, data, event, on_keepalive)
        except CtapError:
            # A complete ERROR packet ends the request, so the channel remains
            # usable for the next command.
            raise
        except KeyboardInterrupt:
            logger.debug("Keyboard interrupt, cancelling...")
            try:
                self._send_cancel()
            finally:
                self._out_of_sync = True
            raise
        except Exception:
            # Any other failure (including a transport error) means the stream
            # boundary is unknown. Do not let a later command read leftovers.
            self._out_of_sync = True
            raise

    def _transact(self, cmd, data, event, on_keepalive):
        max_len = min(
            MAX_MSG_SIZE,
            (self._packet_size - 7) + (MAX_SEQ + 1) * (self._packet_size - 5),
        )
        if len(data) > max_len:
            raise CtapError(CtapError.ERR.REQUEST_TOO_LARGE)

        remaining = data
        seq = 0

        # Send request
        header = struct.pack(">IBH", self._channel_id, TYPE_INIT | cmd, len(remaining))
        while remaining or seq == 0:
            size = min(len(remaining), self._packet_size - len(header))
            body, remaining = remaining[:size], remaining[size:]
            packet = header + body
            logger.log(LOG_LEVEL_TRAFFIC, "SEND: %s", packet.hex())
            self._connection.write_packet(packet.ljust(self._packet_size, b"\0"))
            header = struct.pack(">IB", self._channel_id, 0x7F & seq)
            seq += 1

        # Read response
        seq = 0
        r_len: int | None = None
        response = b""
        last_ka = None
        while True:
            if r_len is not None and len(response) >= r_len:
                break

            if event.is_set():
                # Cancellation ends this channel. A response may already be in
                # flight, and without a request identifier it could otherwise be
                # accepted as the response to the next command.
                logger.debug("Sending cancel...")
                self._out_of_sync = True
                self._send_cancel()
                raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)

            recv = self._connection.read_packet()
            logger.log(LOG_LEVEL_TRAFFIC, "RECV: %s", recv.hex())

            if len(recv) < 5:
                raise ConnectionFailure("Truncated HID packet")

            r_channel = struct.unpack_from(">I", recv)[0]
            recv = recv[4:]
            if r_channel != self._channel_id:
                raise ConnectionFailure("Wrong channel")

            if recv[0] & TYPE_INIT:  # Initialization packet
                if len(recv) < 3:
                    raise ConnectionFailure("Truncated HID packet")
                r_cmd, packet_len = struct.unpack_from(">BH", recv)
                payload = recv[3:]
                if r_cmd == TYPE_INIT | CTAPHID.KEEPALIVE:
                    # A keepalive may arrive between any two fragments.
                    if len(payload) < 1:
                        raise ConnectionFailure("Truncated keepalive packet")
                    try:
                        ka_status = STATUS(payload[0])
                    except ValueError:
                        raise ConnectionFailure("Invalid keepalive status")
                    logger.debug(f"Got keepalive status: {ka_status:02x}")
                    if on_keepalive and ka_status != last_ka:
                        last_ka = ka_status
                        on_keepalive(ka_status)
                    continue
                if r_len is not None:
                    raise ConnectionFailure("Unexpected initialization packet")
                if r_cmd == TYPE_INIT | cmd:
                    r_len = packet_len
                    if r_len > max_len:
                        raise ConnectionFailure("Response length exceeds HID limit")
                    body = payload[:r_len]
                elif r_cmd == TYPE_INIT | CTAPHID.ERROR:
                    if len(payload) < 1:
                        raise ConnectionFailure("Truncated error packet")
                    raise CtapError(payload[0])
                else:
                    raise ConnectionFailure("Unexpected initialization packet")
            else:  # Continuation packet
                if r_len is None:
                    raise ConnectionFailure("Unexpected continuation packet")
                r_seq = recv[0]
                recv = recv[1:]
                # The 7-bit sequence number must match exactly. In particular,
                # a wrapped value (0 after sequence 127) is not accepted.
                if seq > MAX_SEQ:
                    raise ConnectionFailure("Too many continuation packets")
                if r_seq != seq:
                    raise ConnectionFailure("Wrong sequence number")
                seq += 1
                body = recv

            response += body

        assert r_len is not None  # noqa: S101
        return response[:r_len]

    def wink(self) -> None:
        """Causes the authenticator to blink."""
        self.call(CTAPHID.WINK)

    def ping(self, msg: bytes = b"Hello FIDO") -> bytes:
        """Sends data to the authenticator, which echoes it back.

        :param msg: The data to send.
        :return: The response from the authenticator.
        """
        return self.call(CTAPHID.PING, msg)

    def lock(self, lock_time: int = 10) -> None:
        """Locks the channel."""
        self.call(CTAPHID.LOCK, struct.pack(">B", lock_time))

    def close(self) -> None:
        self._connection.close()

    @classmethod
    def _open(cls, descriptor: HidDescriptor) -> CtapHidDevice:
        connection = open_connection(descriptor)
        try:
            return cls(descriptor, connection)
        except BaseException:
            # No device was returned to the caller, so it cannot close the transport.
            try:
                connection.close()
            except Exception:
                logger.debug(
                    "Failed to close HID connection after INIT failure", exc_info=True
                )
            raise

    @classmethod
    def list_devices(cls) -> Iterator[CtapHidDevice]:
        for d in list_descriptors():
            yield cls._open(d)


def list_devices() -> Iterator[CtapHidDevice]:
    return CtapHidDevice.list_devices()


def open_device(path) -> CtapHidDevice:
    descriptor = get_descriptor(path)
    return CtapHidDevice._open(descriptor)
