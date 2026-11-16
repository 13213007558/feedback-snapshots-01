#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
BBMD foreign device registration policy
---------------------------------------

These tests drive encoded BVLL frames through a virtual link (no sockets) and
use the deterministic ``clocked_test`` fixture as the lease clock.  They pin
down the admission policy of ``bacpypes3.ipv4.service.BIPBBMD``:

* a registration belongs to the transport source of the frame, not to
  anything the request claims;
* a lease is forwarding-eligible only until its TTL deadline — the grace
  period controls table retention, not forwarding;
* a renewal of the same source keeps its identity and restarts the lease;
* deletion is source-bound, so naming somebody else's address is rejected and
  leaves that entry in place;
* the table is bounded and refuses new sources instead of evicting live ones;
* every accept/reject decision is exposed with a reason and a deadline.
"""

import json
from typing import List, Tuple

import pytest

from bacpypes3.comm import Server, bind
from bacpypes3.pdu import IPv4Address, LocalBroadcast, PDU
from bacpypes3.ipv4.bvll import (
    BVLLCodec,
    DeleteForeignDeviceTableEntry,
    DistributeBroadcastToNetwork,
    LPCI,
    RegisterForeignDevice,
)
from bacpypes3.ipv4.service import (
    BIPBBMD,
    FDT_RESULT_DELETE_NAK,
    FDT_RESULT_OK,
    FDT_RESULT_REGISTRATION_NAK,
)


LOCAL = IPv4Address("192.0.2.1:47808")
A = IPv4Address("192.0.2.10:51001")
B = IPv4Address("192.0.2.11:51002")
C = IPv4Address("192.0.2.12:51003")


class Sink(Server[PDU]):
    """Records every encoded frame the BBMD hands downstream."""

    def __init__(self) -> None:
        super().__init__()
        self.frames: List[Tuple[object, bytes]] = []

    async def indication(self, pdu: PDU) -> None:  # type: ignore[override]
        self.frames.append((pdu.pduDestination, bytes(pdu.pduData)))


@pytest.fixture
async def bbmd_factory(clocked_test):
    """Build BIPBBMD -> BVLLCodec -> Sink stacks, cleaned up afterwards."""
    created: List[BIPBBMD] = []

    def factory(**kwargs):
        bbmd = BIPBBMD(LOCAL, **kwargs)
        codec = BVLLCodec()
        sink = Sink()
        bind(bbmd, codec, sink)
        created.append(bbmd)
        return bbmd, codec, sink

    yield factory

    for bbmd in created:
        bbmd._fdt_clock_handle.cancel()


def frame_function(data: bytes) -> int:
    return data[1]


def result_code(data: bytes) -> int:
    return int.from_bytes(data[-2:], "big")


async def send(codec: BVLLCodec, sink: Sink, lpdu) -> None:
    sink.frames.clear()
    pdu = lpdu.encode()
    pdu.pduSource = lpdu.pduSource
    await codec.confirmation(pdu)


async def register(codec: BVLLCodec, sink: Sink, source: IPv4Address, ttl: int):
    await send(codec, sink, RegisterForeignDevice(ttl, source=source))
    results = [data for _dest, data in sink.frames if frame_function(data) == 0x00]
    assert len(results) == 1
    return result_code(results[0]), sink.frames[0][0]


async def delete(codec: BVLLCodec, sink: Sink, source: IPv4Address, named):
    await send(
        codec,
        sink,
        DeleteForeignDeviceTableEntry(named, source=source),
    )
    results = [data for _dest, data in sink.frames if frame_function(data) == 0x00]
    assert len(results) == 1
    return result_code(results[0]), sink.frames[0][0]


async def distribute(codec: BVLLCodec, sink: Sink, source: IPv4Address):
    await send(
        codec,
        sink,
        DistributeBroadcastToNetwork(b"\x01\x04\x00\x00\x00", source=source),
    )
    return list(sink.frames)


def forwarded_targets(frames) -> set:
    """Return destinations of actual Forwarded-NPDU (function 0x04) frames."""
    return {
        str(dest) for dest, data in frames if frame_function(data) == LPCI.forwardedNPDU
    }


async def broadcast_targets(bbmd: BIPBBMD, sink: Sink) -> set:
    sink.frames.clear()
    await bbmd.indication(PDU(b"\x01\x04\x00\x00\x00", destination=LocalBroadcast()))
    return forwarded_targets(sink.frames)


# ---------------------------------------------------------------------------
# identity: transport source, not request contents
# ---------------------------------------------------------------------------


async def test_registration_keys_on_transport_source(bbmd_factory) -> None:
    bbmd, codec, sink = bbmd_factory()

    code, destination = await register(codec, sink, A, 60)
    assert code == FDT_RESULT_OK
    assert destination == A

    code, destination = await register(codec, sink, B, 60)
    assert code == FDT_RESULT_OK
    assert destination == B

    assert {str(entry.fdAddress) for entry in bbmd.bbmdFDT} == {str(A), str(B)}
    assert await broadcast_targets(bbmd, sink) == {str(A), str(B)}


async def test_forged_delete_is_rejected_and_leaves_victim(bbmd_factory) -> None:
    bbmd, codec, sink = bbmd_factory()
    assert (await register(codec, sink, A, 60))[0] == FDT_RESULT_OK
    assert (await register(codec, sink, B, 60))[0] == FDT_RESULT_OK

    # B names A in the request body; the transport source is still B
    code, destination = await delete(codec, sink, B, A)
    assert code == FDT_RESULT_DELETE_NAK
    assert destination == B
    assert A in [entry.fdAddress for entry in bbmd.bbmdFDT]
    assert await broadcast_targets(bbmd, sink) == {str(A), str(B)}

    record = bbmd.fdt_audit[-1]
    assert record.action == "delete"
    assert record.accepted is False
    assert record.reason == "source-mismatch"
    assert record.source == str(B)
    assert record.address == str(A)

    # B may still remove itself
    code, destination = await delete(codec, sink, B, B)
    assert code == FDT_RESULT_OK
    assert destination == B
    assert [entry.fdAddress for entry in bbmd.bbmdFDT] == [A]
    assert await broadcast_targets(bbmd, sink) == {str(A)}

    # deleting again is reported as not found
    assert (await delete(codec, sink, B, B))[0] == FDT_RESULT_DELETE_NAK


# ---------------------------------------------------------------------------
# lifetime: TTL is the forwarding deadline, grace only retains the row
# ---------------------------------------------------------------------------


async def test_expired_lease_stops_forwarding_before_grace_purge(
    bbmd_factory, clocked_test
) -> None:
    bbmd, codec, sink = bbmd_factory(fdt_grace_period=5)
    assert (await register(codec, sink, A, 3))[0] == FDT_RESULT_OK
    assert await broadcast_targets(bbmd, sink) == {str(A)}

    # still inside the lease
    await clocked_test.advance(2.5)
    assert await broadcast_targets(bbmd, sink) == {str(A)}
    assert bbmd.fdt_status()[0]["forwarding"] is True

    # past the TTL, inside the grace window: retained but not a target
    await clocked_test.advance(1)
    assert [entry.fdAddress for entry in bbmd.bbmdFDT] == [A]
    assert bbmd.fdt_status()[0]["forwarding"] is False
    assert bbmd.fdt_status()[0]["remaining"] == 0
    assert await broadcast_targets(bbmd, sink) == set()

    reasons = [(r.action, r.reason) for r in bbmd.fdt_audit]
    assert ("expire", "ttl-expired") in reasons

    # past the grace deadline: the row is purged entirely
    await clocked_test.advance(5)
    assert bbmd.bbmdFDT == []
    assert ("purge", "grace-period-elapsed") in [
        (r.action, r.reason) for r in bbmd.fdt_audit
    ]
    assert await broadcast_targets(bbmd, sink) == set()


async def test_renewal_keeps_identity_and_restarts_lease(
    bbmd_factory, clocked_test
) -> None:
    bbmd, codec, sink = bbmd_factory()
    assert (await register(codec, sink, A, 10))[0] == FDT_RESULT_OK
    first_deadline = bbmd.fdt_audit[-1].deadline

    await clocked_test.advance(8)
    assert (await register(codec, sink, A, 10))[0] == FDT_RESULT_OK
    renewed_deadline = bbmd.fdt_audit[-1].deadline
    assert renewed_deadline == first_deadline + 8

    # identity is the same source, not a second row
    assert [entry.fdAddress for entry in bbmd.bbmdFDT] == [A]
    assert bbmd.bbmdFDT[0].fdRenewals == 1
    assert bbmd.fdt_audit[-1].action == "renew"
    assert bbmd.fdt_audit[-1].reason == "renewal"

    # the old deadline has passed but the renewed one has not
    await clocked_test.advance(8)
    assert await broadcast_targets(bbmd, sink) == {str(A)}

    # and the renewed lease expires on its own deadline
    await clocked_test.advance(3)
    assert await broadcast_targets(bbmd, sink) == set()
    assert bbmd.fdt_status()[0]["forwarding"] is False


# ---------------------------------------------------------------------------
# capacity: bounded table, live entries are never evicted
# ---------------------------------------------------------------------------


async def test_capacity_rejects_new_source_without_evicting(
    bbmd_factory, clocked_test
) -> None:
    bbmd, codec, sink = bbmd_factory(fdt_capacity=2, fdt_grace_period=5)
    assert (await register(codec, sink, A, 2))[0] == FDT_RESULT_OK
    assert (await register(codec, sink, B, 2))[0] == FDT_RESULT_OK

    code, destination = await register(codec, sink, C, 60)
    assert code == FDT_RESULT_REGISTRATION_NAK
    assert destination == C
    assert [entry.fdAddress for entry in bbmd.bbmdFDT] == [A, B]
    assert await broadcast_targets(bbmd, sink) == {str(A), str(B)}

    record = bbmd.fdt_audit[-1]
    assert record.accepted is False
    assert record.reason == "table-full"
    assert record.entries == 2

    # once both leases lapse, the rows are only retained for renewal; a new
    # source may reclaim a lapsed row, never a live one
    await clocked_test.advance(3)
    assert bbmd.fdt_status()[0]["forwarding"] is False
    code, destination = await register(codec, sink, C, 60)
    assert code == FDT_RESULT_OK
    assert destination == C
    assert "expired-entry-reclaimed" in [r.reason for r in bbmd.fdt_audit]
    assert len(bbmd.bbmdFDT) == 2

    # the lapsed row is not a forwarding target; only the fresh lease is
    assert await broadcast_targets(bbmd, sink) == {str(C)}

    # and once the grace period passes only the live lease remains
    await clocked_test.advance(5)
    assert [entry.fdAddress for entry in bbmd.bbmdFDT] == [C]
    assert await broadcast_targets(bbmd, sink) == {str(C)}


async def test_registrations_can_be_disabled(bbmd_factory) -> None:
    bbmd, codec, sink = bbmd_factory(accept_fd_registrations=False)

    code, destination = await register(codec, sink, A, 60)
    assert code == FDT_RESULT_REGISTRATION_NAK
    assert destination == A
    assert bbmd.bbmdFDT == []
    assert bbmd.fdt_audit[-1].reason == "registrations-disabled"
    assert await broadcast_targets(bbmd, sink) == set()


# ---------------------------------------------------------------------------
# forwarding injection requires a live lease
# ---------------------------------------------------------------------------


async def test_distribute_requires_live_registration(
    bbmd_factory, clocked_test
) -> None:
    bbmd, codec, sink = bbmd_factory()
    assert (await register(codec, sink, B, 60))[0] == FDT_RESULT_OK

    # unregistered C cannot inject
    frames = await distribute(codec, sink, C)
    results = [data for _dest, data in frames if frame_function(data) == 0x00]
    assert [result_code(data) for data in results] == [0x0060]
    assert forwarded_targets(frames) == set()
    assert bbmd.fdt_audit[-1].reason == "entry-not-found"

    # registered A is forwarded to the other registered device B
    assert (await register(codec, sink, A, 2))[0] == FDT_RESULT_OK
    frames = await distribute(codec, sink, A)
    assert forwarded_targets(frames) == {str(B)}

    # once A's lease expires it may no longer inject
    await clocked_test.advance(3)
    frames = await distribute(codec, sink, A)
    results = [data for _dest, data in frames if frame_function(data) == 0x00]
    assert [result_code(data) for data in results] == [0x0060]
    assert forwarded_targets(frames) == set()
    assert bbmd.fdt_audit[-1].reason == "ttl-expired"


# ---------------------------------------------------------------------------
# audit output: reasons and deadlines are observable
# ---------------------------------------------------------------------------


async def test_audit_reports_reasons_and_deadlines(bbmd_factory) -> None:
    bbmd, codec, sink = bbmd_factory()

    assert (await register(codec, sink, A, 30))[0] == FDT_RESULT_OK
    record = bbmd.fdt_audit[-1]
    assert record.action == "register"
    assert record.accepted is True
    assert record.reason == "new-registration"
    assert record.source == str(A)
    assert record.address == str(A)
    assert record.ttl == 30
    assert record.deadline == 30
    assert record.remaining == 30

    status = bbmd.fdt_status()[0]
    assert status["address"] == str(A)
    assert status["ttl"] == 30
    assert status["deadline"] == 30
    assert status["remaining"] == 30
    assert status["grace_remaining"] == 35
    assert status["forwarding"] is True

    # the audit trail is plain JSON data, ready for an operator log
    json.dumps(bbmd.fdt_audit_records())

    # a rejected delete is recorded with its reason
    assert (await delete(codec, sink, B, A))[0] == FDT_RESULT_DELETE_NAK
    assert bbmd.fdt_audit[-1].as_dict()["reason"] == "source-mismatch"


# ---------------------------------------------------------------------------
# deterministic clock: explicit ticks and direct advance
# ---------------------------------------------------------------------------


async def test_manual_fdt_ticks_expire_lease(bbmd_factory) -> None:
    bbmd, codec, sink = bbmd_factory(fdt_grace_period=3)
    assert (await register(codec, sink, A, 2))[0] == FDT_RESULT_OK

    # drive the clock explicitly instead of waiting on real seconds
    bbmd.advance_fdt_clock(2)
    assert bbmd.fdt_status()[0]["forwarding"] is False
    assert "ttl-expired" in [r.reason for r in bbmd.fdt_audit]

    # the periodic tick continues the same lease clock through the grace period
    for _ in range(3):
        bbmd.fdt_clock()
    assert bbmd.bbmdFDT == []
    assert "grace-period-elapsed" in [r.reason for r in bbmd.fdt_audit]


# ---------------------------------------------------------------------------
# source validation and administrative API
# ---------------------------------------------------------------------------


async def test_invalid_transport_source_is_rejected(bbmd_factory) -> None:
    bbmd, _codec, _sink = bbmd_factory()

    # a frame with no usable transport source cannot be admitted
    bbmd._fdt_now = 0.0
    assert bbmd.process_register_foreign_device(None, 60) == FDT_RESULT_REGISTRATION_NAK
    assert bbmd.fdt_audit[-1].reason == "invalid-source"

    assert (
        bbmd.process_register_foreign_device(IPv4Address("0.0.0.0:47808"), 60)
        == FDT_RESULT_REGISTRATION_NAK
    )
    assert bbmd.fdt_audit[-1].reason == "invalid-source"
    assert bbmd.bbmdFDT == []
    assert bbmd.fdt_audit_records()[-1]["accepted"] is False


async def test_administrative_registration_bypasses_network_gates(
    bbmd_factory,
) -> None:
    bbmd, _codec, _sink = bbmd_factory(accept_fd_registrations=False)

    # the local API is for provisioning and is not blocked by the wire gate
    assert bbmd.register_foreign_device(A, 60) == FDT_RESULT_OK
    assert [entry.fdAddress for entry in bbmd.bbmdFDT] == [A]
    assert bbmd.fdt_status()[0]["forwarding"] is True

    # but it still enforces the lease contract
    assert bbmd.register_foreign_device(B, 0) == FDT_RESULT_REGISTRATION_NAK
    assert bbmd.fdt_audit[-1].reason == "invalid-ttl"

    # administrative deletion is keyed by the named address
    assert bbmd.delete_foreign_device_table_entry(A) == FDT_RESULT_OK
    assert bbmd.bbmdFDT == []
