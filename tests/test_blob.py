# Copyright (c) 2026 Yubico AB
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
#       disclaimer in the documentation and/or other materials provided.
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

"""Protocol-level regression tests for fragmented largeBlob writes.

These tests run LargeBlobs against a software authenticator which
independently implements the CTAP2.1 authenticatorLargeBlobs state machine:
it verifies the PIN/UV auth parameter of every fragment, enforces offset
sequencing, commits the array only when the full announced length has been
staged and the checksum validates, and logs every command it receives. It
can also inject failures mid-sequence, both as an explicit CTAP rejection
and as a "response lost" transport error after applying the fragment.
"""

import os
import struct
import unittest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Info, PinProtocolV1
from fido2.ctap2.blob import LargeBlobs, LargeBlobWriteError
from fido2.utils import sha256

MAX_MSG_SIZE = 1200
MAX_FRAGMENT_LENGTH = MAX_MSG_SIZE - 64
PIN_TOKEN = os.urandom(32)


def _pin_uv_auth_param(token, offset, fragment):
    msg = b"\xff" * 32 + b"\x0c\x00" + struct.pack("<I", offset) + sha256(fragment)
    return PinProtocolV1().authenticate(token, msg)


def _make_array(total_size):
    # A single-entry array whose CBOR encoding plus the 16 byte checksum
    # is exactly total_size bytes long.
    entry = {1: b"\x00" * (total_size - 16)}
    array = [entry]
    overhead = len(cbor.encode(array)) + 16 - total_size
    array = [{1: b"\x00" * (total_size - 16 - overhead)}]
    assert len(cbor.encode(array)) + 16 == total_size
    return array


class SoftLargeBlobDevice:
    """Software authenticator implementing CTAP2.1 largeBlobs semantics.

    Records every command in .commands. Set .fail_at to the 1-based index of
    the set-command to fail, and .failure_mode to "reject" (explicit CTAP
    error, fragment not applied) or "lost" (fragment applied, response lost
    in transit).
    """

    def __init__(self, max_msg_size=MAX_MSG_SIZE, pin_token=PIN_TOKEN):
        self.info = Info(
            versions=["FIDO_2_1"],
            options={"largeBlobs": True},
            max_msg_size=max_msg_size,
        )
        self.pin_token = pin_token
        self.commands = []
        self.fail_at = None
        self.failure_mode = "reject"
        self._committed = b""
        self._staged = b""
        self._expected_length = None

    def _reset_staging(self):
        self._staged = b""
        self._expected_length = None

    def large_blobs(
        self,
        offset,
        get=None,
        set=None,
        length=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
    ):
        if get is not None:
            return {1: self._committed[offset : offset + get]}

        command = {
            "offset": offset,
            "set": set,
            "length": length,
            "pin_uv_param": pin_uv_param,
            "pin_uv_protocol": pin_uv_protocol,
        }
        self.commands.append(command)
        set_count = len(self.commands)

        if self.fail_at == set_count and self.failure_mode == "lost":
            # The authenticator applies the command, but the response is
            # lost in transit: the platform sees a transport error and
            # cannot know whether the fragment was staged.
            self._apply(offset, set, length, pin_uv_param, pin_uv_protocol)
            raise OSError("response lost in transit")

        if self.fail_at == set_count and self.failure_mode == "reject":
            # Explicit rejection: the fragment is not applied and any
            # staged data is discarded.
            self._reset_staging()
            raise CtapError(CtapError.ERR.INTEGRITY_FAILURE)

        self._apply(offset, set, length, pin_uv_param, pin_uv_protocol)
        return {}

    def _apply(self, offset, set, length, pin_uv_param, pin_uv_protocol):
        if offset != len(self._staged):
            # Unexpected offset: discard staged fragments.
            self._reset_staging()
            raise CtapError(CtapError.ERR.INVALID_SEQ)
        if offset == 0:
            if length is None:
                raise CtapError(CtapError.ERR.MISSING_PARAMETER)
            self._expected_length = length

        if self.pin_token is not None:
            expected = _pin_uv_auth_param(self.pin_token, offset, set)
            if pin_uv_protocol != PinProtocolV1.VERSION or pin_uv_param != expected:
                self._reset_staging()
                raise CtapError(CtapError.ERR.PIN_AUTH_INVALID)

        self._staged += set
        if len(self._staged) == self._expected_length:
            data, check = self._staged[:-16], self._staged[-16:]
            if check != sha256(data)[:16]:
                self._reset_staging()
                raise CtapError(CtapError.ERR.INTEGRITY_FAILURE)
            self._committed = self._staged
            self._reset_staging()
        elif len(self._staged) > self._expected_length:
            self._reset_staging()
            raise CtapError(CtapError.ERR.INVALID_LENGTH)


class TestFragmentation(unittest.TestCase):
    def setUp(self):
        self.device = SoftLargeBlobDevice()
        self.lb = LargeBlobs(self.device, PinProtocolV1(), PIN_TOKEN)

    def test_max_fragment_length_derived_from_max_msg_size(self):
        self.assertEqual(self.lb.max_fragment_length, MAX_MSG_SIZE - 64)

    def test_single_fragment_write(self):
        array = _make_array(100)
        self.lb.write_blob_array(array)

        self.assertEqual(len(self.device.commands), 1)
        (cmd,) = self.device.commands
        self.assertEqual(cmd["offset"], 0)
        self.assertEqual(cmd["length"], 100)
        self.assertEqual(len(cmd["set"]), 100)
        self.assertEqual(self.lb.read_blob_array(), array)

    def test_exact_multiple_fragments(self):
        # The array (with checksum) is exactly two full fragments: no tail.
        total = 2 * MAX_FRAGMENT_LENGTH
        array = _make_array(total)
        self.lb.write_blob_array(array)

        self.assertEqual(len(self.device.commands), 2)
        first, second = self.device.commands

        # First fragment: offset 0, announces the total length, full size.
        self.assertEqual(first["offset"], 0)
        self.assertEqual(first["length"], total)
        self.assertEqual(len(first["set"]), MAX_FRAGMENT_LENGTH)

        # Second fragment: bound to its position, no repeated length.
        self.assertEqual(second["offset"], MAX_FRAGMENT_LENGTH)
        self.assertIsNone(second["length"])
        self.assertEqual(len(second["set"]), MAX_FRAGMENT_LENGTH)

        # Each fragment's PIN/UV auth input binds its offset and content.
        for cmd in (first, second):
            self.assertEqual(cmd["pin_uv_protocol"], PinProtocolV1.VERSION)
            self.assertEqual(
                cmd["pin_uv_param"],
                _pin_uv_auth_param(PIN_TOKEN, cmd["offset"], cmd["set"]),
            )

        self.assertEqual(self.lb.read_blob_array(), array)

    def test_short_tail_fragment(self):
        total = MAX_FRAGMENT_LENGTH + 17
        array = _make_array(total)
        self.lb.write_blob_array(array)

        self.assertEqual(len(self.device.commands), 2)
        first, second = self.device.commands
        self.assertEqual(first["offset"], 0)
        self.assertEqual(first["length"], total)
        self.assertEqual(len(first["set"]), MAX_FRAGMENT_LENGTH)
        self.assertEqual(second["offset"], MAX_FRAGMENT_LENGTH)
        self.assertIsNone(second["length"])
        self.assertEqual(len(second["set"]), 17)
        self.assertEqual(
            second["pin_uv_param"],
            _pin_uv_auth_param(PIN_TOKEN, MAX_FRAGMENT_LENGTH, second["set"]),
        )

        self.assertEqual(self.lb.read_blob_array(), array)

    def test_tampered_offset_rejected(self):
        array = _make_array(2 * MAX_FRAGMENT_LENGTH)
        data = cbor.encode(array)
        data += sha256(data)[:16]

        # First fragment is accepted and staged.
        self.device.large_blobs(
            0,
            set=data[:MAX_FRAGMENT_LENGTH],
            length=len(data),
            pin_uv_protocol=PinProtocolV1.VERSION,
            pin_uv_param=_pin_uv_auth_param(PIN_TOKEN, 0, data[:MAX_FRAGMENT_LENGTH]),
        )

        # A second fragment claiming the wrong offset is rejected and the
        # staged data is discarded.
        with self.assertRaises(CtapError) as ctx:
            self.device.large_blobs(
                1,
                set=data[MAX_FRAGMENT_LENGTH:],
                pin_uv_protocol=PinProtocolV1.VERSION,
                pin_uv_param=_pin_uv_auth_param(
                    PIN_TOKEN, 1, data[MAX_FRAGMENT_LENGTH:]
                ),
            )
        self.assertEqual(ctx.exception.code, CtapError.ERR.INVALID_SEQ)

        # The authenticator holds no committed array.
        self.assertEqual(self.lb.read_blob_array(), [])

    def test_tampered_fragment_content_rejected(self):
        # Replay a captured command sequence against a fresh device, with
        # one byte of the second fragment modified but the original
        # PIN/UV auth param kept: the device must reject it.
        array = _make_array(2 * MAX_FRAGMENT_LENGTH)
        self.lb.write_blob_array(array)
        first, second = self.device.commands

        victim = SoftLargeBlobDevice()
        victim.large_blobs(**first)
        tampered = dict(second)
        tampered["set"] = second["set"][:-1] + bytes([second["set"][-1] ^ 0xFF])
        with self.assertRaises(CtapError) as ctx:
            victim.large_blobs(**tampered)
        self.assertEqual(ctx.exception.code, CtapError.ERR.PIN_AUTH_INVALID)
        self.assertEqual(LargeBlobs(victim).read_blob_array(), [])


class TestWriteFailure(unittest.TestCase):
    def setUp(self):
        self.device = SoftLargeBlobDevice()
        self.lb = LargeBlobs(self.device, PinProtocolV1(), PIN_TOKEN)
        self.old_array = _make_array(100)
        self.lb.write_blob_array(self.old_array)
        self.device.commands.clear()

    def test_explicit_rejection_mid_write(self):
        self.device.fail_at = 2
        self.device.failure_mode = "reject"

        total = 2 * MAX_FRAGMENT_LENGTH
        with self.assertRaises(LargeBlobWriteError) as ctx:
            self.lb.write_blob_array(_make_array(total))

        err = ctx.exception
        self.assertTrue(err.explicit_rejection)
        self.assertEqual(err.offset, MAX_FRAGMENT_LENGTH)
        self.assertEqual(err.bytes_written, MAX_FRAGMENT_LENGTH)
        self.assertEqual(err.total_size, total)
        self.assertIsInstance(err.__cause__, CtapError)

        # The device explicitly rejected the write: staged data was
        # discarded and the previously committed array is still readable,
        # proven by actually reading it back.
        self.assertEqual(self.lb.read_blob_array(), self.old_array)

    def test_response_lost_mid_write(self):
        self.device.fail_at = 2
        self.device.failure_mode = "lost"

        total = 3 * MAX_FRAGMENT_LENGTH
        with self.assertRaises(LargeBlobWriteError) as ctx:
            self.lb.write_blob_array(_make_array(total))

        err = ctx.exception
        # The fragment may or may not have been applied: the caller gets
        # an uncertain result with actionable recheck information, not a
        # claim that the write was rolled back.
        self.assertFalse(err.explicit_rejection)
        self.assertEqual(err.offset, MAX_FRAGMENT_LENGTH)
        self.assertEqual(err.bytes_written, MAX_FRAGMENT_LENGTH)
        self.assertEqual(err.total_size, total)
        self.assertIn("read_blob_array()", str(err))

        # The only way to know the device state is to re-read it. Here the
        # final fragment never arrived, so the old array is still intact.
        self.assertEqual(self.lb.read_blob_array(), self.old_array)

    def test_response_lost_on_final_fragment(self):
        # The response to the last fragment is lost: the device actually
        # committed the new array, so a blind retry or an assumed rollback
        # would both be wrong. Only re-reading reveals the true state.
        self.device.fail_at = 2
        self.device.failure_mode = "lost"

        total = 2 * MAX_FRAGMENT_LENGTH
        new_array = _make_array(total)
        with self.assertRaises(LargeBlobWriteError) as ctx:
            self.lb.write_blob_array(new_array)

        self.assertFalse(ctx.exception.explicit_rejection)
        self.assertEqual(self.lb.read_blob_array(), new_array)


if __name__ == "__main__":
    unittest.main()
