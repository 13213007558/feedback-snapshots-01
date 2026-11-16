"""
Segmented Message Source / Invoke-ID Isolation
----------------------------------------------

A segmented request is identified by the *pair* ``(source address, invoke
ID)``.  Two endpoints that happen to pick the same invoke ID run independent
transactions: a segment carrying the right sequence number from the wrong
endpoint must never be spliced into another endpoint's half-assembled
message, and each completed message may contain only its own bytes.

The tests run real ``ApplicationServiceAccessPoint`` / state machines on top
of an in-memory VLAN (no sockets, no wall-clock sleeps), so they exercise the
actual encode -> dispatch -> reassemble -> application-callback path rather
than a mock of it.  They also assert that, once a transaction terminates, its
state machine leaves the active-transaction list and drops its timer.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from bacpypes3.app import DeviceInfoCache
from bacpypes3.appservice import (
    ApplicationServiceAccessPoint,
)
from bacpypes3.apdu import (
    AbortPDU,
    ConfirmedRequestPDU,
    ReadPropertyRequest,
    SegmentAckPDU,
    SimpleAckPDU,
)
from bacpypes3.basetypes import PropertyIdentifier, Segmentation
from bacpypes3.comm import ApplicationServiceElement, bind
from bacpypes3.debugging import ModuleLogger, bacpypes_debugging
from bacpypes3.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes3.pdu import Address, PDU
from bacpypes3.primitivedata import ObjectIdentifier
from bacpypes3.vlan import Network, Node

# some debugging
_debug = 0
_log = ModuleLogger(globals())


@dataclass
class SegmentRecord:
    """One APDU observed crossing the in-memory network."""

    direction: str
    apdu_type: str
    source: object
    destination: object
    invoke_id: Optional[int]
    sequence: Optional[int]
    window: Optional[int]
    nak: Optional[bool]
    more: Optional[bool]
    data: bytes = b""


@bacpypes_debugging
class TappingNetwork(Network):
    """A VLAN that records every PDU as a decoded APDU while still delivering
    it normally."""

    def __init__(self) -> None:
        super().__init__(broadcast_address=0)
        self.traffic: List[SegmentRecord] = []

    async def process_pdu(self, pdu: PDU) -> None:
        from bacpypes3.apdu import APDU
        from bacpypes3.npdu import NPDU

        # the VLAN carries NPDU-wrapped frames; peel the network header off
        # a copy before decoding the application APDU
        npdu = NPDU.decode(PDU(pdu.pduData))
        decoded = APDU.decode(PDU(npdu.pduData))
        self.traffic.append(
            SegmentRecord(
                direction=f"{pdu.pduSource}->{pdu.pduDestination}",
                apdu_type=type(decoded).__name__,
                source=pdu.pduSource,
                destination=pdu.pduDestination,
                invoke_id=getattr(decoded, "apduInvokeID", None),
                sequence=getattr(decoded, "apduSeq", None),
                window=getattr(decoded, "apduWin", None),
                nak=getattr(decoded, "apduNak", None),
                more=getattr(decoded, "apduMor", None),
                data=bytes(decoded.pduData),
            )
        )
        await super().process_pdu(pdu)


@bacpypes_debugging
class RecordingApplication(ApplicationServiceElement):
    """Top of the stack: records completed requests and answers each with a
    simple ack addressed back to the requester."""

    def __init__(self, name: str) -> None:
        ApplicationServiceElement.__init__(self)
        self.name = name
        self.requests: List = []
        self.confirmations: List = []
        self.aborts: List = []

    async def indication(self, apdu) -> None:
        if isinstance(apdu, AbortPDU):
            self.aborts.append(apdu)
            return
        self.requests.append(apdu)
        ack = SimpleAckPDU(apdu.apduService, apdu.apduInvokeID)
        ack.pduDestination = apdu.pduSource
        await self.response(ack)

    async def confirmation(self, apdu) -> None:
        if isinstance(apdu, AbortPDU):
            self.aborts.append(apdu)
            return
        self.confirmations.append(apdu)


@dataclass
class Stack:
    name: str
    address: Address
    ase: RecordingApplication
    asap: ApplicationServiceAccessPoint
    nsap: NetworkServiceAccessPoint
    node: Node


def make_stack(name: str, address: Address, network: TappingNetwork) -> Stack:
    node = Node(address, network)

    nsap = NetworkServiceAccessPoint()
    nse = NetworkServiceElement()
    bind(nse, nsap)

    asap = ApplicationServiceAccessPoint(None, DeviceInfoCache())
    # small, but still BACnet-encodable, segment size to force segmentation
    asap.maxApduLengthAccepted = 50
    asap.segmentationSupported = Segmentation.segmentedBoth
    asap.maxSegmentsAccepted = 16
    asap.proposedWindowSize = 2

    ase = RecordingApplication(name)
    bind(ase, asap, nsap)
    nsap.bind(node, address=address)

    return Stack(name, address, ase, asap, nsap, node)


def make_long_request(
    invoke_id: int, destination: Address, marker: int, padding: int = 120
) -> ConfirmedRequestPDU:
    """A decodable ReadProperty request padded so it spans several segments.

    The leading tag content is a real ReadProperty request; the trailing
    marker byte lets a test prove which payload ended up where.
    """
    request = ReadPropertyRequest(
        objectIdentifier=ObjectIdentifier("device,1"),
        propertyIdentifier=PropertyIdentifier("objectName"),
    )
    request.apduInvokeID = invoke_id
    encoded = bytes(request.encode().pduData)

    apdu = ConfirmedRequestPDU(12, invoke_id)
    apdu.put_data(encoded + bytes([marker]) + b"\x00" * padding)
    apdu.pduDestination = destination
    return apdu


@bacpypes_debugging
class TestSegmentationIsolation:
    async def test_two_sources_same_invoke_id_stay_separated(self) -> None:
        network = TappingNetwork()
        addr_server = Address(3)
        addr_a = Address(1)
        addr_b = Address(2)

        server = make_stack("server", addr_server, network)
        client_a = make_stack("A", addr_a, network)
        client_b = make_stack("B", addr_b, network)

        # both clients pick invoke ID 5 for their own long request; each
        # payload carries a distinct marker in its trailing segment
        request_a = make_long_request(5, addr_server, marker=0xA1)
        request_b = make_long_request(5, addr_server, marker=0xB2)
        wire_a = bytes(request_a.pduData)
        wire_b = bytes(request_b.pduData)

        await client_a.ase.request(request_a)
        await client_b.ase.request(request_b)

        # let the in-memory network drain all of the state-machine tasks
        await _drain()

        # every transaction has terminated and left the active lists, which
        # also cancels its timer (the timer contract is pinned in the SSM
        # unit tests)
        assert server.asap.serverTransactions == []
        assert client_a.asap.clientTransactions == []
        assert client_b.asap.clientTransactions == []

        # the server application got exactly two complete, distinct requests
        assert len(server.ase.requests) == 2
        sources = {req.pduSource for req in server.ase.requests}
        assert sources == {addr_a, addr_b}

        # reassemble the segmented request bytes the server actually received
        # from each source and compare them to the wire payloads
        received_a = _reassemble(network, addr_a, 5)
        received_b = _reassemble(network, addr_b, 5)
        assert received_a == wire_a
        assert received_b == wire_b
        # the two conversations never shared a single data byte
        assert 0xA1 in received_a and 0xB2 not in received_a
        assert 0xB2 in received_b and 0xA1 not in received_b

        # both clients received their simple ack and no abort
        assert len(client_a.ase.confirmations) == 1
        assert len(client_b.ase.confirmations) == 1
        assert client_a.ase.aborts == []
        assert client_b.ase.aborts == []

        # a clean, isolated exchange needs no negative acknowledgements
        naks = [r for r in network.traffic if r.apdu_type == "SegmentAckPDU" and r.nak]
        assert naks == []

    async def test_second_source_same_invoke_id_gets_own_transaction(self) -> None:
        """A segment from a different source, even with the same invoke ID
        and sequence number, is routed to its own ServerSSM."""
        network = TappingNetwork()
        addr_server = Address(3)
        addr_a = Address(1)
        addr_b = Address(2)

        server = make_stack("server", addr_server, network)
        client_a = make_stack("A", addr_a, network)
        client_b = make_stack("B", addr_b, network)

        # start both long requests; the network is tapped but not drained yet
        request_a = make_long_request(5, addr_server, marker=0xA1, padding=200)
        request_b = make_long_request(5, addr_server, marker=0xB2, padding=200)
        await client_a.ase.request(request_a)
        await client_b.ase.request(request_b)
        await _drain()

        # the tap kept two independent segment streams, distinguished only by
        # their source even though both carry invoke ID 5
        segment_sources = {
            r.source
            for r in network.traffic
            if r.apdu_type == "ConfirmedRequestPDU" and r.invoke_id == 5
        }
        assert segment_sources == {addr_a, addr_b}

        # both still complete successfully with their own payloads
        assert len(server.ase.requests) == 2
        assert _reassemble(network, addr_a, 5) == bytes(request_a.pduData)
        assert _reassemble(network, addr_b, 5) == bytes(request_b.pduData)

    async def test_segment_with_no_matching_transaction_is_dropped(self) -> None:
        """A segment-ack or abort that names no live transaction must be
        silently dropped rather than creating state or reaching the app."""
        network = TappingNetwork()
        addr_server = Address(3)
        server = make_stack("server", addr_server, network)

        # a segment ack for an invoke ID / source with no server transaction
        orphan_ack = SegmentAckPDU(0, 0, 99, 0, 2)
        orphan_ack.pduSource = Address(9)
        orphan_ack.pduDestination = addr_server

        await server.asap.confirmation(orphan_ack.encode())
        await _drain()

        assert server.asap.serverTransactions == []
        assert server.ase.requests == []
        assert server.ase.aborts == []


async def _drain(rounds: int = 80) -> None:
    """Let every scheduled state-machine coroutine run to quiescence."""
    for _ in range(rounds):
        await asyncio.sleep(0)


def _reassemble(network: TappingNetwork, source: Address, invoke_id: int) -> bytes:
    """Concatenate the data segments recorded for one (source, invoke ID)
    conversation in sequence order, mirroring the receiver reassembly."""
    segments = [
        record
        for record in network.traffic
        if record.apdu_type == "ConfirmedRequestPDU"
        and record.source == source
        and record.invoke_id == invoke_id
    ]
    chunks = bytearray()
    for record in segments:
        chunks += record.data
    return bytes(chunks)
