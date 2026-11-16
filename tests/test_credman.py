# Copyright (c) 2024 Yubico AB
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

import threading
from typing import Any, Callable

import pytest

from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import (
    CredentialManagement,
    EnumerationConflictError,
    EnumerationError,
    EnumerationSession,
)
from fido2.hid import CAPABILITY, CTAPHID
from fido2.utils import sha256

R = CredentialManagement.RESULT
P = CredentialManagement.PARAM
C = CredentialManagement.CMD


class VirtualCtapDevice:
    """In-memory authenticator implementing the credentialMgmt enumeration.

    Deliberately mirrors real hardware: each begin command overwrites the
    single server-side enumeration cursor, regardless of any enumeration still
    in progress. next calls continue whatever cursor is current. The client
    layer is therefore responsible for keeping sessions isolated.
    """

    capabilities = CAPABILITY.CBOR

    def __init__(self):
        # rp_id_hash -> list of credential dicts (insertion order preserved)
        self.rps: dict[bytes, list[dict[int, Any]]] = {}
        self._cursor_kind: EnumerationSession.Kind | None = None
        self._cursor_rp: bytes | None = None
        self._cursor_index = 0
        # Optional hook invoked with (sub_cmd, response) before returning.
        self.on_response: Callable[[int, dict[int, Any]], None] | None = None
        # sub_cmd -> number of next calls that should fail, and the error code.
        self.fail_next: dict[int, tuple[int, CtapError.ERR]] = {}
        self._fail_counts: dict[int, int] = {}

    def add_credential(self, rp_id: str, user_id: bytes) -> bytes:
        rp_id_hash = sha256(rp_id.encode())
        cred_id = b"cred-%s-%d" % (user_id, len(self.rps.get(rp_id_hash, [])))
        credential = {
            R.USER: {"id": user_id, "name": f"user-{user_id.hex()}"},
            R.CREDENTIAL_ID: {"id": cred_id, "type": "public-key"},
            R.PUBLIC_KEY: {1: 2, 3: -7, -1: 1, -2: b"x", -3: b"y"},
            R.RP_ID_HASH: rp_id_hash,
        }
        self.rps.setdefault(rp_id_hash, []).append(credential)
        return rp_id_hash

    # -- low level CTAP glue -------------------------------------------------
    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == CTAPHID.CBOR
        ctap_cmd = data[0]
        if ctap_cmd == Ctap2.CMD.GET_INFO:
            return b"\x00" + cbor.encode(
                {1: ["FIDO_2_1"], 4: {"credMgmt": True}}
            )
        request = cbor.decode(data[1:]) if len(data) > 1 else {}
        # Ctap2.credential_mgmt encodes {1: sub_cmd, 2: sub_cmd_params, ...}.
        sub_cmd = request.get(1)
        params = request.get(2) or {}
        try:
            response = self._credential_mgmt(sub_cmd, params)
        except CtapError as e:
            return bytes([int(e.code)])
        if self.on_response is not None:
            self.on_response(sub_cmd, response)
        return b"\x00" + cbor.encode(response)

    def _credential_mgmt(self, sub_cmd, params):
        if sub_cmd == C.ENUMERATE_RPS_BEGIN:
            return self._rps_begin()
        if sub_cmd == C.ENUMERATE_RPS_NEXT:
            return self._rps_next()
        if sub_cmd == C.ENUMERATE_CREDS_BEGIN:
            return self._creds_begin(params[P.RP_ID_HASH])
        if sub_cmd == C.ENUMERATE_CREDS_NEXT:
            return self._creds_next()
        if sub_cmd == C.GET_CREDS_METADATA:
            count = sum(len(v) for v in self.rps.values())
            return {R.EXISTING_CRED_COUNT: count, R.MAX_REMAINING_COUNT: 20}
        raise CtapError(CtapError.ERR.INVALID_COMMAND)

    def _maybe_fail(self, sub_cmd):
        remaining, code = self.fail_next.get(sub_cmd, (0, CtapError.ERR.OTHER))
        seen = self._fail_counts.get(sub_cmd, 0)
        if seen < remaining:
            self._fail_counts[sub_cmd] = seen + 1
            raise CtapError(code)

    def _rps_begin(self):
        hashes = list(self.rps)
        if not hashes:
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        # A new begin unconditionally replaces any existing cursor.
        self._cursor_kind = EnumerationSession.Kind.RP
        self._cursor_rp = None
        self._cursor_index = 0
        return self._rps_response(hashes[0], len(hashes), include_total=True)

    def _rps_next(self):
        self._maybe_fail(C.ENUMERATE_RPS_NEXT)
        hashes = list(self.rps)
        self._cursor_index += 1
        index = self._cursor_index
        if index >= len(hashes):
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        return self._rps_response(hashes[index], len(hashes), include_total=False)

    def _rps_response(self, rp_id_hash, total, include_total):
        response = {
            R.RP: {"id": f"rp-{rp_id_hash.hex()[:4]}"},
            R.RP_ID_HASH: rp_id_hash,
        }
        if include_total:
            response[R.TOTAL_RPS] = total
        return response

    def _creds_begin(self, rp_id_hash):
        creds = self.rps.get(rp_id_hash, [])
        if not creds:
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        # A new begin unconditionally replaces any existing cursor.
        self._cursor_kind = EnumerationSession.Kind.CREDENTIAL
        self._cursor_rp = rp_id_hash
        self._cursor_index = 0
        return self._cred_response(creds[0], len(creds), include_total=True)

    def _creds_next(self):
        self._maybe_fail(C.ENUMERATE_CREDS_NEXT)
        creds = self.rps[self._cursor_rp]
        self._cursor_index += 1
        index = self._cursor_index
        if index >= len(creds):
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        return self._cred_response(creds[index], len(creds), include_total=False)

    def _cred_response(self, credential, total, include_total):
        response = dict(credential)
        if include_total:
            response[R.TOTAL_CREDENTIALS] = total
        return response


class _PinProtocol:
    VERSION = 2

    def authenticate(self, token, message):
        return b"\x00" * 16


@pytest.fixture
def virtual():
    device = VirtualCtapDevice()
    ctap = Ctap2(device)
    credman = CredentialManagement(ctap, _PinProtocol(), b"token")
    return device, credman


def _rp_hashes(device):
    return list(device.rps)


def test_enumerate_rps_and_credentials(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    h2 = device.add_credential("b.example", b"u2")
    device.add_credential("b.example", b"u3")

    rps = credman.enumerate_rps()
    assert [rp[R.RP_ID_HASH] for rp in rps] == [h1, h2]

    creds = credman.enumerate_creds(h2)
    assert len(creds) == 2
    assert all(cred[R.RP_ID_HASH] == h2 for cred in creds)
    assert [cred[R.USER]["id"] for cred in creds] == [b"u2", b"u3"]
    assert credman.active_session is None


def test_no_credentials_is_empty_not_an_error(virtual):
    device, credman = virtual

    assert credman.enumerate_rps() == []
    with credman.enumerate_rps_session() as session:
        assert session.total == 0
        assert session.exhausted
        assert list(session) == []

    unknown_hash = sha256(b"missing.example")
    assert credman.enumerate_creds(unknown_hash) == []
    with credman.enumerate_creds_session(unknown_hash) as session:
        assert session.total == 0
        assert list(session) == []


def test_low_level_begin_next_round_trip(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    h2 = device.add_credential("b.example", b"u2")
    h3 = device.add_credential("c.example", b"u3")

    first = credman.enumerate_rps_begin()
    assert first[R.TOTAL_RPS] == 3
    second = credman.enumerate_rps_next()
    third = credman.enumerate_rps_next()
    assert [first[R.RP_ID_HASH], second[R.RP_ID_HASH], third[R.RP_ID_HASH]] == [
        h1,
        h2,
        h3,
    ]
    # The last next exhausts the session.
    assert credman.active_session is None
    with pytest.raises(EnumerationConflictError):
        credman.enumerate_rps_next()


def test_begin_while_session_active_is_rejected(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    device.add_credential("b.example", b"u2")

    with credman.enumerate_rps_session() as session:
        assert not session.exhausted
        # Any new begin conflicts with the active RP enumeration.
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_rps_begin()
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_creds_begin(h1)
        with pytest.raises(EnumerationConflictError):
            with credman.enumerate_creds_session(h1):
                pass
        # A next of the wrong kind is also a conflict, not mixed data.
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_creds_next()
        # The original session is untouched and still yields its own data.
        assert [rp[R.RP_ID_HASH] for rp in session] == _rp_hashes(device)


def test_credential_session_inside_rp_session_is_isolated(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    h2 = device.add_credential("b.example", b"u2")
    device.add_credential("b.example", b"u3")

    with credman.enumerate_rps_session() as rp_session:
        first_rp = next(rp_session)
        assert first_rp[R.RP_ID_HASH] == h1

        # Nested enumeration must not silently clobber the RP cursor.
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_creds(h2)

        # The RP session continues from where it was, not from a reset cursor.
        assert [rp[R.RP_ID_HASH] for rp in rp_session] == [h2]


def test_interleaved_begins_on_raw_device_are_blocked_by_sessions(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    h2 = device.add_credential("b.example", b"u2")
    device.add_credential("b.example", b"u3")

    # The raw device really does let a new begin overwrite an old cursor.
    device._rps_begin()
    device._creds_begin(h2)
    assert device._cursor_kind is EnumerationSession.Kind.CREDENTIAL
    assert device._cursor_rp == h2

    # But the managed session API prevents interleaving.
    with credman.enumerate_creds_session(h2) as session:
        first_cred = next(session)
        assert first_cred[R.USER]["id"] == b"u2"
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_rps_begin()
        # Same session resumes, returns the second credential of h2 only.
        assert next(session)[R.USER]["id"] == b"u3"


def test_mid_enumeration_error_keeps_incomplete_state(virtual):
    device, credman = virtual
    device.add_credential("a.example", b"u1")
    device.add_credential("b.example", b"u2")
    device.add_credential("c.example", b"u3")
    device.fail_next[C.ENUMERATE_RPS_NEXT] = (1, CtapError.ERR.OTHER)

    with credman.enumerate_rps_session() as session:
        first = next(session)
        assert first[R.RP_ID_HASH] == _rp_hashes(device)[0]
        with pytest.raises(CtapError) as exc_info:
            next(session)
        assert exc_info.value.code == CtapError.ERR.OTHER
        # The session is neither silently completed nor restarted: it stays open.
        assert not session.exhausted
        assert credman.active_session is session
        # A fresh enumeration cannot start while the broken session is open.
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_rps_begin()
        # After closing, a new session gets a consistent, fresh enumeration.
        session.close()
    assert credman.active_session is None
    assert [rp[R.RP_ID_HASH] for rp in credman.enumerate_rps()] == _rp_hashes(device)


def test_list_convenience_does_not_swallow_interruption(virtual):
    device, credman = virtual
    device.add_credential("a.example", b"u1")
    device.add_credential("b.example", b"u2")
    device.fail_next[C.ENUMERATE_RPS_NEXT] = (1, CtapError.ERR.OTHER)

    # A mid-enumeration failure must not be reported as an empty/partial list.
    with pytest.raises(CtapError):
        credman.enumerate_rps()
    assert credman.active_session is None


def test_abandoned_session_can_be_closed_and_reused(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    h2 = device.add_credential("b.example", b"u2")

    with credman.enumerate_rps_session() as session:
        first = next(session)
        assert first[R.RP_ID_HASH] == h1
        # Break out early: remaining entities are simply not fetched.
        session.close()
        assert session.exhausted

    # Ownership was released, so a brand new enumeration works normally.
    rps = credman.enumerate_rps()
    assert [rp[R.RP_ID_HASH] for rp in rps] == [h1, h2]


def test_total_is_fixed_when_store_grows_mid_enumeration(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    h2 = device.add_credential("b.example", b"u2")

    with credman.enumerate_rps_session() as session:
        assert session.total == 2
        seen = [next(session)[R.RP_ID_HASH]]
        # The store changes after the enumeration started.
        h3 = device.add_credential("c.example", b"u3")
        seen.extend(rp[R.RP_ID_HASH] for rp in session)

    # The session honors the count captured at begin time; it does not restart
    # and mix in the later third RP.
    assert seen == [h1, h2]
    assert h3 not in seen
    # The new RP is visible to a subsequent enumeration.
    assert [rp[R.RP_ID_HASH] for rp in credman.enumerate_rps()] == [h1, h2, h3]


def test_credential_with_wrong_rp_hash_is_rejected(virtual):
    device, credman = virtual
    h1 = device.add_credential("a.example", b"u1")
    other = sha256(b"other.example")

    def tamper(sub_cmd, response):
        if sub_cmd == C.ENUMERATE_CREDS_NEXT and R.RP_ID_HASH in response:
            response[R.RP_ID_HASH] = other

    device.on_response = tamper
    device.add_credential("a.example", b"u2")

    with credman.enumerate_creds_session(h1) as session:
        with pytest.raises(EnumerationError):
            list(session)


def test_next_without_begin_is_conflict(virtual):
    device, credman = virtual
    device.add_credential("a.example", b"u1")

    with pytest.raises(EnumerationConflictError):
        credman.enumerate_rps_next()
    h1 = _rp_hashes(device)[0]
    with pytest.raises(EnumerationConflictError):
        credman.enumerate_creds_next()

    # Opening an RP session does not enable credential next calls.
    with credman.enumerate_rps_session():
        with pytest.raises(EnumerationConflictError):
            credman.enumerate_creds_next()


def test_sessions_are_serialized_across_threads(virtual):
    device, credman = virtual
    for i in range(6):
        device.add_credential(f"rp{i}.example", f"u{i}".encode())

    errors = []
    results = []

    def worker():
        try:
            with credman.enumerate_rps_session() as session:
                results.append([rp[R.RP_ID_HASH] for rp in session])
        except EnumerationConflictError as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    expected = _rp_hashes(device)
    # Every thread that got a session saw a complete, consistent enumeration.
    assert all(result == expected for result in results)
    # Contended threads got an explicit conflict, never mixed data.
    assert len(results) + len(errors) == 4
    assert credman.active_session is None
