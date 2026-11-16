"""
Forwarding Preserves Logical and Transport Source Addresses
-----------------------------------------------------------

When a BACnet router forwards an APDU between networks, the application sees
the *logical* source (the originating remote station) while the *actual
transport* next-hop is tracked separately.  The two must never be swapped: an
application must answer to the originator's network/address, not to the
router's local interface.

These tests run two in-memory VLANs joined by a real
``NetworkServiceAccessPoint`` router and assert both the default and the
``route_aware`` address representations.
"""

from __future__ import annotations

import asyncio
from typing import List

from bacpypes3.comm import Client, bind
from bacpypes3.debugging import ModuleLogger, bacpypes_debugging
from bacpypes3.netservice import NetworkServiceAccessPoint, NetworkServiceElement
from bacpypes3.npdu import NPDU
from bacpypes3.pdu import Address, PDU, RemoteStation
from bacpypes3.settings import settings
from bacpypes3.vlan import Network, Node

# some debugging
_debug = 0
_log = ModuleLogger(globals())

NET_1 = 1
NET_2 = 2
ROUTER_N1 = Address(100)
ROUTER_N2 = Address(200)
SENDER = Address(10)
RECEIVER = Address(20)


@bacpypes_debugging
class Sniffer(Client[PDU]):
    """Top of the receiving stack; collects every PDU handed upstream."""

    def __init__(self) -> None:
        super().__init__()
        self.received: List[PDU] = []

    async def confirmation(self, pdu: PDU) -> None:
        self.received.append(pdu)


@bacpypes_debugging
class RoutedHarness:
    def __init__(self) -> None:
        self.vlan1 = Network(broadcast_address=0)
        self.vlan2 = Network(broadcast_address=0)

        # one router NSAP with an adapter on each network
        self.router_nsap = NetworkServiceAccessPoint()
        bind(NetworkServiceElement(), self.router_nsap)
        self.router_nsap.bind(Node(ROUTER_N1, self.vlan1), net=NET_1, address=ROUTER_N1)
        self.router_nsap.bind(Node(ROUTER_N2, self.vlan2), net=NET_2, address=ROUTER_N2)

        # sending stack on network 1
        self.send_nsap = NetworkServiceAccessPoint()
        bind(NetworkServiceElement(), self.send_nsap)
        self.send_nsap.bind(Node(SENDER, self.vlan1), net=NET_1, address=SENDER)

        # receiving stack on network 2, topped by a sniffer
        self.recv_nsap = NetworkServiceAccessPoint()
        bind(NetworkServiceElement(), self.recv_nsap)
        self.recv_nsap.bind(Node(RECEIVER, self.vlan2), net=NET_2, address=RECEIVER)
        self.sniffer = Sniffer()
        bind(self.sniffer, self.recv_nsap)

    async def seed_route(self) -> None:
        """Tell the sender that network 2 is reachable through the router."""
        await self.send_nsap.router_info_cache.update_path_info(
            NET_1, ROUTER_N1, {NET_2}
        )

    async def send_routed(self) -> PDU:
        await self.seed_route()
        npdu = NPDU(b"\x41\x42\x43\x44")
        npdu.pduSource = SENDER
        npdu.pduDestination = RemoteStation(NET_2, RECEIVER.addrAddr)
        await self.send_nsap.indication(npdu)

        for _ in range(40):
            await asyncio.sleep(0)

        assert self.sniffer.received, "the routed PDU never reached the receiver"
        return self.sniffer.received[0]


@bacpypes_debugging
class TestForwardingSourceAddress:
    async def test_logical_source_is_originating_remote_station(self) -> None:
        harness = RoutedHarness()
        pdu = await harness.send_routed()

        # the application sees the originator as a remote station on
        # network 1, never the router's network-2 interface address
        source = pdu.pduSource
        assert isinstance(source, RemoteStation)
        assert source.addrNet == NET_1
        assert source.addrAddr == SENDER.addrAddr
        assert source != ROUTER_N2
        assert source != ROUTER_N1

        # the destination is the receiver's local address
        assert pdu.pduDestination == RECEIVER

    async def test_route_aware_keeps_transport_source_separate(self) -> None:
        original = settings.route_aware
        settings.route_aware = True
        try:
            harness = RoutedHarness()
            pdu = await harness.send_routed()
        finally:
            settings.route_aware = original

        source = pdu.pduSource
        # logical source unchanged ...
        assert isinstance(source, RemoteStation)
        assert source.addrNet == NET_1
        assert source.addrAddr == SENDER.addrAddr

        # ... while the actual transport next-hop rides alongside and is
        # the router's interface on the receiving network
        assert source.addrRoute is not None
        assert source.addrRoute == ROUTER_N2
        assert source.addrRoute != source

    async def test_logical_and_transport_are_not_swapped_in_replies(
        self,
    ) -> None:
        """A reply built from the routed source goes back to the originator
        rather than to the router's local address."""
        original = settings.route_aware
        settings.route_aware = True
        try:
            harness = RoutedHarness()
            pdu = await harness.send_routed()
        finally:
            settings.route_aware = original

        source = pdu.pduSource
        # the originator's logical address is what a reply must target;
        # using addrRoute (the router hop) as the logical destination
        # would misdeliver it
        assert source.addrNet == NET_1
        assert source.addrAddr == SENDER.addrAddr
        assert source.addrRoute == ROUTER_N2

        reply_destination = RemoteStation(source.addrNet, source.addrAddr)
        assert reply_destination.addrNet == NET_1
        assert reply_destination.addrAddr == SENDER.addrAddr
