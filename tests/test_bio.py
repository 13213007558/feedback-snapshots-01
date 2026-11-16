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

"""Tests for the FPEnrollmentContext enrollment state machine.

All tests run against a scripted software authenticator which allows
controlling the timing and result of begin, capture and cancel commands.
No real biometric data is involved.
"""

from __future__ import annotations

import threading
from collections import deque
from unittest import mock

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.bio import (
    BioEnrollment,
    CaptureError,
    FPBioEnrollment,
    FPEnrollmentContext,
)
from fido2.hid import CAPABILITY, CTAPHID

CMD = FPBioEnrollment.CMD
FEEDBACK = FPBioEnrollment.FEEDBACK
PARAM = FPBioEnrollment.PARAM
RESULT = BioEnrollment.RESULT
STATE = FPEnrollmentContext.STATE

_INFO = {
    0x01: ["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
    0x02: [],
    0x03: bytes(range(16)),
    0x04: {
        "rk": True,
        "up": True,
        "plat": False,
        "clientPin": True,
        "bioEnroll": True,
    },
    0x05: 1200,
    0x06: [1],
}


def begin_result(template_id, status=FEEDBACK.FP_GOOD, remaining=0):
    return {
        RESULT.TEMPLATE_ID: template_id,
        RESULT.LAST_SAMPLE_STATUS: status,
        RESULT.REMAINING_SAMPLES: remaining,
    }


def next_result(status=FEEDBACK.FP_GOOD, remaining=0):
    return {
        RESULT.LAST_SAMPLE_STATUS: status,
        RESULT.REMAINING_SAMPLES: remaining,
    }


def respond(result):
    def action(device, params):
        return b"\x00" + cbor.encode(result)

    return action


def fail(code):
    def action(device, params):
        return bytes([code])

    return action


class Gate:
    """Device action which blocks the response until released by the test."""

    def __init__(self, result):
        self.entered = threading.Event()
        self.release = threading.Event()
        self._result = result

    def __call__(self, device, params):
        self.entered.set()
        assert self.release.wait(5), "gate was not released"
        return b"\x00" + cbor.encode(self._result)


class SoftBioDevice:
    """Scripted software authenticator for bio enrollment.

    Every response is pre-programmed via `script`; the `bio_calls` log
    records each bio sub-command and its parameters, in order.
    """

    capabilities = CAPABILITY.CBOR

    def __init__(self):
        self.bio_calls = []
        self._actions = {}
        self._lock = threading.Lock()

    def script(self, sub_cmd, *actions):
        self._actions[sub_cmd] = deque(actions)

    @property
    def bio_commands(self):
        return [sub_cmd for sub_cmd, _ in self.bio_calls]

    def call(self, cmd, data, event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        if data[0] == Ctap2.CMD.GET_INFO:
            return b"\x00" + cbor.encode(_INFO)
        assert data[0] == Ctap2.CMD.BIO_ENROLLMENT
        request = cbor.decode(data[1:])
        if request.get(0x06):  # get_modality
            modality = {RESULT.MODALITY: BioEnrollment.MODALITY.FINGERPRINT}
            return b"\x00" + cbor.encode(modality)
        sub_cmd = CMD(request[0x02])
        params = request.get(0x03) or {}
        with self._lock:
            action = self._actions[sub_cmd].popleft()
            self.bio_calls.append((sub_cmd, params))
        return action(self, params)


def make_bio(device):
    ctap = Ctap2(device)
    pin_protocol = mock.Mock()
    pin_protocol.VERSION = 1
    pin_protocol.authenticate.return_value = b"pin-uv-auth-param"
    return FPBioEnrollment(ctap, pin_protocol, b"pin-uv-token")


def capture_async(context, results):
    threading.Thread(
        target=lambda: results.append(context.capture()), daemon=True
    ).start()


def test_normal_completion():
    """Begin followed by good samples completes; context then refuses reuse."""
    device = SoftBioDevice()
    template_id = b"template-normal"
    device.script(CMD.ENROLL_BEGIN, respond(begin_result(template_id, remaining=2)))
    device.script(
        CMD.ENROLL_CAPTURE_NEXT,
        respond(next_result(remaining=1)),
        respond(next_result(remaining=0)),
    )
    context = make_bio(device).enroll()
    assert context.state is STATE.IDLE

    assert context.capture() is None
    assert context.state is STATE.ENROLLING
    assert context.template_id == template_id
    assert context.remaining == 2

    assert context.capture() is None
    assert context.remaining == 1

    assert context.capture() == template_id
    assert context.state is STATE.COMPLETED
    assert context.remaining == 0

    # One begin, then continuations bound to the same template identity
    assert device.bio_commands == [
        CMD.ENROLL_BEGIN,
        CMD.ENROLL_CAPTURE_NEXT,
        CMD.ENROLL_CAPTURE_NEXT,
    ]
    for _, params in device.bio_calls[1:]:
        assert params[PARAM.TEMPLATE_ID] == template_id

    # A completed context cannot capture again, and cancel is a harmless
    # no-op which does not touch the committed template
    with pytest.raises(ValueError):
        context.capture()
    context.cancel()
    assert context.state is STATE.COMPLETED
    assert context.template_id == template_id
    assert len(device.bio_calls) == 3


def test_retry_after_poor_quality():
    """Quality feedback raises CaptureError; retry reuses the same template."""
    device = SoftBioDevice()
    template_id = b"template-retry"
    device.script(CMD.ENROLL_BEGIN, respond(begin_result(template_id, remaining=2)))
    device.script(
        CMD.ENROLL_CAPTURE_NEXT,
        respond(next_result(FEEDBACK.FP_TOO_HIGH, 2)),
        respond(next_result(FEEDBACK.FP_GOOD, 1)),
        respond(next_result(FEEDBACK.FP_GOOD, 0)),
    )
    context = make_bio(device).enroll()

    assert context.capture() is None
    with pytest.raises(CaptureError) as exc_info:
        context.capture()
    assert exc_info.value.code == FEEDBACK.FP_TOO_HIGH

    # Quality feedback is recoverable: still enrolling the same template
    assert context.state is STATE.ENROLLING
    assert context.template_id == template_id

    assert context.capture() is None
    assert context.capture() == template_id
    assert context.state is STATE.COMPLETED

    assert device.bio_commands == [CMD.ENROLL_BEGIN] + [CMD.ENROLL_CAPTURE_NEXT] * 3
    for _, params in device.bio_calls[1:]:
        assert params[PARAM.TEMPLATE_ID] == template_id


def test_late_success_after_cancel():
    """Cancel while a capture is in flight; a late completing sample wins."""
    device = SoftBioDevice()
    template_id = b"template-late"
    gate = Gate(next_result(FEEDBACK.FP_GOOD, 0))
    device.script(CMD.ENROLL_BEGIN, respond(begin_result(template_id, remaining=1)))
    device.script(CMD.ENROLL_CAPTURE_NEXT, gate)
    device.script(CMD.ENROLL_CANCEL, respond({}))
    context = make_bio(device).enroll()
    assert context.capture() is None  # begin done, one sample remains

    results = []
    capture_async(context, results)
    assert gate.entered.wait(5)  # capture is now blocked in the device

    context.cancel()
    assert context.state is STATE.CANCELLED
    assert context.template_id is None

    gate.release.set()
    for _ in range(50):
        if results:
            break
        threading.Event().wait(0.1)
    # The sample completed on the authenticator before the cancel took
    # effect: the template exists and is surfaced, not silently dropped
    assert results == [template_id]
    assert context.state is STATE.COMPLETED
    assert context.template_id == template_id

    assert device.bio_commands == [
        CMD.ENROLL_BEGIN,
        CMD.ENROLL_CAPTURE_NEXT,
        CMD.ENROLL_CANCEL,
    ]
    # The cancel cleanup did not delete the completed template
    assert CMD.REMOVE_ENROLLMENT not in device.bio_commands


def test_cancel_during_begin_in_flight():
    """Cancel is sent to the device even while the begin call is blocked."""
    device = SoftBioDevice()
    template_id = b"template-begin-late"
    gate = Gate(begin_result(template_id, remaining=0))
    device.script(CMD.ENROLL_BEGIN, gate)
    device.script(CMD.ENROLL_CANCEL, respond({}))
    context = make_bio(device).enroll()

    results = []
    capture_async(context, results)
    assert gate.entered.wait(5)  # begin is now blocked in the device

    context.cancel()
    assert context.state is STATE.CANCELLED

    gate.release.set()
    for _ in range(50):
        if results:
            break
        threading.Event().wait(0.1)
    assert results == [template_id]
    assert context.state is STATE.COMPLETED
    assert context.template_id == template_id
    assert device.bio_commands == [CMD.ENROLL_BEGIN, CMD.ENROLL_CANCEL]


def test_cancelled_context_does_not_restart_enrollment():
    """After cancel, capture refuses to silently begin a second enrollment."""
    device = SoftBioDevice()
    first_id = b"template-one"
    second_id = b"template-two"
    device.script(
        CMD.ENROLL_BEGIN,
        respond(begin_result(first_id, remaining=1)),
        respond(begin_result(second_id, remaining=0)),
    )
    device.script(CMD.ENROLL_CANCEL, respond({}))
    bio = make_bio(device)
    context = bio.enroll()
    assert context.capture() is None

    context.cancel()
    assert context.state is STATE.CANCELLED
    assert context.template_id is None

    # The cancelled context is dead: no capture, no silent second begin
    with pytest.raises(ValueError):
        context.capture()
    assert device.bio_commands == [CMD.ENROLL_BEGIN, CMD.ENROLL_CANCEL]

    # The caller explicitly starts a new enrollment with a fresh context,
    # resulting in a new template identity
    new_context = bio.enroll()
    assert new_context.state is STATE.IDLE
    assert new_context.capture() == second_id
    assert new_context.state is STATE.COMPLETED
    assert device.bio_commands == [
        CMD.ENROLL_BEGIN,
        CMD.ENROLL_CANCEL,
        CMD.ENROLL_BEGIN,
    ]


def test_failed_cancel_keeps_state():
    """A failed cancel must not reset the context to a fresh state."""
    device = SoftBioDevice()
    template_id = b"template-cancel-fail"
    device.script(CMD.ENROLL_BEGIN, respond(begin_result(template_id, remaining=1)))
    device.script(CMD.ENROLL_CANCEL, fail(CtapError.ERR.INVALID_COMMAND))
    device.script(CMD.ENROLL_CAPTURE_NEXT, respond(next_result(FEEDBACK.FP_GOOD, 0)))
    context = make_bio(device).enroll()
    assert context.capture() is None

    with pytest.raises(CtapError) as exc_info:
        context.cancel()
    assert exc_info.value.code == CtapError.ERR.INVALID_COMMAND

    # The enrollment may still be ongoing: state and template are kept
    assert context.state is STATE.ENROLLING
    assert context.template_id == template_id

    # The enrollment can still be driven to completion
    assert context.capture() == template_id
    assert context.state is STATE.COMPLETED
    assert device.bio_commands == [
        CMD.ENROLL_BEGIN,
        CMD.ENROLL_CANCEL,
        CMD.ENROLL_CAPTURE_NEXT,
    ]


def test_cancel_idle_context_sends_no_command():
    """Cancelling before the first capture needs no device interaction."""
    device = SoftBioDevice()
    context = make_bio(device).enroll()

    context.cancel()
    assert context.state is STATE.CANCELLED
    assert context.template_id is None
    assert device.bio_calls == []

    with pytest.raises(ValueError):
        context.capture()
    assert device.bio_calls == []


def test_device_error_during_capture_keeps_state():
    """A device error is distinct from quality feedback and keeps state."""
    device = SoftBioDevice()
    template_id = b"template-error"
    device.script(CMD.ENROLL_BEGIN, respond(begin_result(template_id, remaining=1)))
    device.script(
        CMD.ENROLL_CAPTURE_NEXT,
        fail(CtapError.ERR.KEEPALIVE_CANCEL),
        respond(next_result(FEEDBACK.FP_GOOD, 0)),
    )
    context = make_bio(device).enroll()
    assert context.capture() is None

    with pytest.raises(CtapError) as exc_info:
        context.capture()
    assert exc_info.value.code == CtapError.ERR.KEEPALIVE_CANCEL
    assert context.state is STATE.ENROLLING
    assert context.template_id == template_id

    assert context.capture() == template_id
    assert context.state is STATE.COMPLETED
