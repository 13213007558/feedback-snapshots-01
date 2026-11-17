#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Interleaved VMAC conflict handling on a virtual IPv6 transport
--------------------------------------------------------------

These tests run real ``BIPNormal -> BVLLCodec -> IPv6Node`` stacks on the
in-memory :class:`bacpypes3.vlan.IPv6Network`, so the whole resolution
machinery (broadcast Address-Resolution queries, ACK collection and the
outbound Original-Unicast-NPDU targeting) is exercised without sockets.

The required behavior:

* two devices answering the same VMAC query with different IPv6 addresses
  must produce an explicit :class:`VMACConflictError` on every waiter, never
  an arbitrary target, and the incumbent binding must keep receiving traffic;
* concurrent resolution requests for one VMAC share a single query and a
  single future;
* a legitimate migration confirmed by a fresh, consistent resolution round
  moves the binding and subsequent traffic to the new address.
"""

import asyncio

import pytest

from bacpypes3.comm import Client, Server, bind
from bacpypes3.pdu import IPv6Address, VirtualAddress, PDU
from bacpypes3.vlan import IPv6Network, IPv6Node
from bacpypes3.ipv6.bvll import (
    BVLLCodec,
    AddressResolutionACK,
    OriginalBroadcastNPDU,
)
from bacpypes3.ipv6.service import (
    BIPNormal,
    BVLLServiceElement,
    MappingSource,
    VMACConflictError,
    RESOLUTION_GUARD_TIME,
)


VM_A = VirtualAddress(bytes.fromhex("aaaaaa"))
VM_B = VirtualAddress(bytes.fromhex("bbbbbb"))
VM_T = VirtualAddress(bytes.fromhex("cccccc"))
IP_A = IPv6Address("fd07::a")
IP_B = IPv6Address("fd07::b")
IP_1 = IPv6Address("fd07::1")
IP_2 = IPv6Address("fd07::2")


class UpstreamSink(Server[PDU]):
    """Captures PDUs the link layer hands up to the network layer."""

    def __init__(self) -> None:
        super().__init__()
        self.received: list[PDU] = []

    async def indication(self, pdu: PDU) -> None:  # type: ignore[override]
        self.received.append(pdu)


class FrameRecorder(Client[PDU], Server[PDU]):
    """Pass-through element recording every frame in both directions."""

    def __init__(self) -> None:
        Client.__init__(self)
        Server.__init__(self)
        self.frames: list[PDU] = []

    async def indication(self, pdu: PDU) -> None:  # type: ignore[override]
        self.frames.append(pdu)
        await self.request(pdu)

    async def confirmation(self, pdu: PDU) -> None:  # type: ignore[override]
        await self.response(pdu)


class TappableBIPNormal(BIPNormal):
    """BIP variant that routes upstream PDUs into a recording sink instead
    of requiring a full network layer above it."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.application_sink: UpstreamSink

    async def response(self, pdu: PDU) -> None:  # type: ignore[override]
        await self.application_sink.indication(pdu)


def build_stack(virtual_address, ipv6_address, network):
    node = IPv6Node(ipv6_address, lan=network)
    recorder = FrameRecorder()
    bip = TappableBIPNormal(virtual_address=virtual_address)
    ase = BVLLServiceElement()
    upstream = UpstreamSink()
    bip.application_sink = upstream
    # full chain: ASE <-> BIP <-> codec <-> recorder <-> node
    bind(ase, bip, BVLLCodec(), recorder, node)
    return bip, ase, node, recorder, upstream


@pytest.fixture
async def fabric():
    # VirtualNetwork names are process-global, so make each test's fabric unique
    network = IPv6Network(f"vmac-conflict-fabric-{id(object())}")
    bip_a, ase_a, node_a, rec_a, up_a = build_stack(VM_A, IP_A, network)
    bip_b, ase_b, node_b, rec_b, up_b = build_stack(VM_B, IP_B, network)
    try:
        yield {
            "network": network,
            "a": (bip_a, ase_a, node_a, rec_a, up_a),
            "b": (bip_b, ase_b, node_b, rec_b, up_b),
        }
    finally:
        # make sure no resolution guard timer is left dangling
        for pending in list(ase_a.virtual_address_resolution.values()):
            if pending.guard_handle is not None:
                pending.guard_handle.cancel()
        for pending in list(ase_b.virtual_address_resolution.values()):
            if pending.guard_handle is not None:
                pending.guard_handle.cancel()
        await asyncio.sleep(0)


async def inject_ack(node, vmac, requester_vmac, source_ipv6):
    """Feed a decoded-then-re-encoded ACK into a node as if it arrived on-link."""
    ack = AddressResolutionACK(vmac, requester_vmac, source=source_ipv6)
    await node.response(ack.encode())


async def test_clean_resolution_targets_actual_responders(fabric):
    """A normal query/ACK round resolves and caches the respondent's address."""
    bip_a, ase_a, _node_a, _rec, _up = fabric["a"]
    _bip_b, _ase_b, node_b, _rec_b, _up_b = fabric["b"]

    future = ase_a.resolve_virtual_address(VM_B)
    # let B's stack answer the broadcast query
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.1)

    assert future.done()
    assert future.result() == IP_B
    record = bip_a.vmac_addr_table.get_record(VM_B)
    assert record.ipv6 == IP_B
    assert record.source is MappingSource.query_response
    assert record.observed_source == IP_B


async def test_concurrent_resolutions_share_one_query_and_future(fabric):
    bip_a, ase_a, _node_a, rec_a, _up = fabric["a"]

    first = ase_a.resolve_virtual_address(VM_B)
    second = ase_a.resolve_virtual_address(VM_B)

    assert first is second
    pending = ase_a.virtual_address_resolution[VM_B]
    assert pending.future is first

    # let the create_task() query actually leave the stack
    await asyncio.sleep(0.02)
    broadcast_queries = [
        frame for frame in rec_a.frames if str(frame.pduDestination) == "*"
    ]
    assert len(broadcast_queries) == 1

    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.1)
    assert first.done() and second.done()
    assert first.result() == IP_B


async def test_interleaved_conflicting_acks_fail_explicitly(fabric):
    """Two different IPv6 answers to one VMAC query fail every waiter and
    leave the incumbent mapping in place."""
    bip_a, ase_a, node_a, rec_a, _up = fabric["a"]

    future = ase_a.resolve_virtual_address(VM_T)
    # let the broadcast query leave, then interleave two conflicting ACKs
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_1)
    await inject_ack(node_a, VM_T, VM_A, IP_2)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.1)

    assert future.done()
    with pytest.raises(VMACConflictError) as exc_info:
        future.result()
    err = exc_info.value
    assert err.vmac == VM_T
    assert {err.incumbent, err.challenger} == {IP_1, IP_2}

    # the table exposes the conflict instead of hiding it
    record = bip_a.vmac_addr_table.get_record(VM_T)
    assert record is not None
    assert record.candidate is not None
    assert {record.ipv6, record.candidate} == {IP_1, IP_2}

    # the pending resolution bookkeeping is cleaned up
    assert VM_T not in ase_a.virtual_address_resolution


async def test_traffic_keeps_going_to_incumbent_during_dispute(fabric):
    """Outbound unicast while a dispute is recorded is re-resolved; when the
    re-resolution also conflicts, the packet is dropped rather than sent to an
    arbitrary address."""
    bip_a, ase_a, node_a, rec_a, _up = fabric["a"]

    # establish an incumbent via a first clean answer
    first = ase_a.resolve_virtual_address(VM_T)
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_1)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.05)
    assert first.result() == IP_1

    # a proactive advertisement from a second claimant creates a dispute
    rogue = OriginalBroadcastNPDU(VM_T, b"\x01\x02", source=IP_2).encode()
    await node_a.response(rogue)
    await asyncio.sleep(0.02)
    record = bip_a.vmac_addr_table.get_record(VM_T)
    assert record.ipv6 == IP_1
    assert record.candidate == IP_2

    # unicast before re-resolution: nothing may leave toward the challenger
    rec_a.frames.clear()
    send_task = asyncio.create_task(
        bip_a.indication(PDU(b"data", source=VM_A, destination=VM_T))
    )
    # the re-query goes out and again gets two answers
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_1)
    await inject_ack(node_a, VM_T, VM_A, IP_2)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.1)
    await send_task

    unicast_targets = [
        frame.pduDestination
        for frame in rec_a.frames
        if bytes(frame.pduData).startswith(bytes([0x82, 0x01]))
    ]
    # no Original-Unicast-NPDU was emitted: conflict = explicit failure
    assert unicast_targets == []
    # and the incumbent is still the installed mapping
    assert bip_a.vmac_addr_table[VM_T] == IP_1


async def test_legitimate_migration_is_usable_after_confirmation(fabric):
    """When the device really moved, a fresh round of consistent answers to
    the parked candidate commits the migration and traffic follows it."""
    bip_a, ase_a, node_a, rec_a, _up = fabric["a"]

    # incumbent at IP_1, then a challenger IP_2 parks as candidate
    first = ase_a.resolve_virtual_address(VM_T)
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_1)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.05)
    assert first.result() == IP_1

    dispute = ase_a.resolve_virtual_address(VM_T)
    await asyncio.sleep(0.02)
    # both claimants answer the same query: the round is unresolved
    await inject_ack(node_a, VM_T, VM_A, IP_1)
    await inject_ack(node_a, VM_T, VM_A, IP_2)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.05)
    with pytest.raises(VMACConflictError):
        dispute.result()
    assert bip_a.vmac_addr_table[VM_T] == IP_1

    # a fresh, consistent round confirms the device now lives at IP_2
    confirm = ase_a.resolve_virtual_address(VM_T)
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_2)
    await inject_ack(node_a, VM_T, VM_A, IP_2)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.05)
    assert confirm.done()
    assert confirm.result() == IP_2
    record = bip_a.vmac_addr_table.get_record(VM_T)
    assert record.ipv6 == IP_2
    assert record.candidate is None

    # subsequent traffic is actually addressed to the new location
    rec_a.frames.clear()
    await bip_a.indication(PDU(b"hello", source=VM_A, destination=VM_T))
    unicast_frames = [
        frame for frame in rec_a.frames if isinstance(frame.pduDestination, IPv6Address)
    ]
    assert len(unicast_frames) == 1
    assert unicast_frames[0].pduDestination == IP_2


async def test_unobserved_claimant_cannot_hijack_with_a_single_answer(fabric):
    """A single answer from an address the table never saw as a challenger
    must fail the resolution instead of moving the incumbent's traffic."""
    bip_a, ase_a, node_a, _rec_a, _up = fabric["a"]

    # establish the incumbent at IP_1
    first = ase_a.resolve_virtual_address(VM_T)
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_1)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.05)
    assert first.result() == IP_1

    # one answer from a never-before-seen address: no silent migration
    hijack = ase_a.resolve_virtual_address(VM_T)
    await asyncio.sleep(0.02)
    await inject_ack(node_a, VM_T, VM_A, IP_2)
    await asyncio.sleep(RESOLUTION_GUARD_TIME + 0.05)

    assert hijack.done()
    with pytest.raises(VMACConflictError):
        hijack.result()
    assert bip_a.vmac_addr_table[VM_T] == IP_1
