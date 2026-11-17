#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test routing announcement admission
-----------------------------------

Regression tests for the network layer's handling of routing claims.
Announcements arrive from a port, are recorded as observed, are checked
against a caller-supplied source and port policy, and only then become
routes in the ``RouterInfoCache``.  A rejected announcement must not
leave a subset of its networks behind, and a disconnected port must not
keep supplying a next hop.

The tests build a small virtual internetwork: a router under test with
two recording ports and no real link layer.  A controlled application
PDU is sent through the router and the port that actually received it,
and the address it was sent to, are asserted.  No real building network
is contacted.
"""

from typing import Any, Dict, List, Optional, Tuple

import pytest

from bacpypes3.comm import bind, Server
from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.errors import UnknownRoute
from bacpypes3.pdu import Address, LocalBroadcast, PDU, RemoteStation
from bacpypes3.npdu import IAmRouterToNetwork, NetworkNumberIs, NPDU
from bacpypes3.basetypes import NetworkNumberQuality
from bacpypes3 import netservice
from bacpypes3.netservice import (
    ANNOUNCEMENT_REJECTED_CONFIGURED,
    ANNOUNCEMENT_REJECTED_NETWORK_CONFLICT,
    ANNOUNCEMENT_REJECTED_POLICY,
    ANNOUNCEMENT_REJECTED_PORT_DISCONNECTED,
    NetworkAdapter,
    NetworkServiceAccessPoint,
    NetworkServiceElement,
    ObservedAnnouncement,
    ROUTER_AVAILABLE,
    RouterAnnouncement,
    RouterInfoCache,
    RoutingCacheConflict,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())


class RecordingPort(Server[PDU]):
    """A link layer that records everything the network adapter sends."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: List[PDU] = []

    async def indication(self, pdu: PDU) -> None:
        self.sent.append(pdu)


@bacpypes_debugging
class VirtualInternetwork:
    """
    A router under test with named ports, each bound to a virtual network.

    Announcements are injected through ``adapter.confirmation()``, the same
    path an NPDU takes when it arrives from a link layer, and application
    PDUs are sent through ``nsap.indication()``.  Comparing the two shows
    which next hop the routing claim actually selected.
    """

    nsap: NetworkServiceAccessPoint
    nse: NetworkServiceElement
    local_source: Address
    ports: Dict[str, RecordingPort]
    adapters: Dict[str, NetworkAdapter]

    def __init__(
        self,
        policy: Optional[Any] = None,
        local_source: str = "10.0.0.1",
    ) -> None:
        self.nsap = NetworkServiceAccessPoint(announcement_policy=policy)
        self.nse = NetworkServiceElement()
        bind(self.nse, self.nsap)

        self.local_source = Address(local_source)
        self.ports = {}
        self.adapters = {}

    def add_port(
        self, name: str, net: Optional[int], address: str
    ) -> RecordingPort:
        port = RecordingPort()
        self.nsap.bind(port, net=net, address=Address(address))
        self.ports[name] = port
        adapter = self.nsap.adapter_for_network(net)
        assert adapter is not None
        self.adapters[name] = adapter
        return port

    async def announce(
        self, port_name: str, networks: List[int], source: str
    ) -> ObservedAnnouncement:
        npdu = IAmRouterToNetwork(
            list(networks),
            source=Address(source),
            destination=LocalBroadcast(),
        )
        await self.adapters[port_name].confirmation(npdu.encode())
        return self.nsap.announcements[-1]

    async def network_number_is(
        self,
        port_name: str,
        net: int,
        source: str,
        flag: int = NetworkNumberQuality.learned,
    ) -> ObservedAnnouncement:
        npdu = NetworkNumberIs(
            net,
            flag,
            source=Address(source),
            destination=LocalBroadcast(),
        )
        await self.adapters[port_name].confirmation(npdu.encode())
        return self.nsap.announcements[-1]

    async def send(
        self,
        dnet: int,
        address: int = 1,
        data: bytes = b"controlled",
    ) -> None:
        pdu = PDU(
            data,
            source=self.local_source,
            destination=RemoteStation(dnet, address),
        )
        await self.nsap.indication(pdu)

    def drain(self) -> Dict[str, List[PDU]]:
        """Return and clear everything each port has sent."""
        sent = {name: list(port.sent) for name, port in self.ports.items()}
        for port in self.ports.values():
            port.sent = []
        return sent

    @staticmethod
    def application_pdus(sent: List[PDU]) -> List[Tuple[PDU, NPDU]]:
        """Filter out network layer messages and return NPDU payloads."""
        result = []
        for pdu in sent:
            copy = PDU(
                bytes(pdu.pduData),
                source=pdu.pduSource,
                destination=pdu.pduDestination,
            )
            npdu = NPDU.decode(copy)
            if npdu.npduNetMessage is None:
                result.append((pdu, npdu))
        return result


@pytest.fixture
def short_wirtn_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the Who-Is-Router-To-Network fallback from slowing the tests."""
    monkeypatch.setattr(netservice, "WHO_IS_ROUTER_TO_NETWORK_TIMEOUT", 0.01)


def _pair(policy: Optional[Any] = None) -> VirtualInternetwork:
    harness = VirtualInternetwork(policy=policy)
    harness.add_port("alpha", 1, "10.0.1.1")
    harness.add_port("beta", 2, "10.0.2.1")
    return harness


@bacpypes_debugging
class TestRouterAnnouncementAdmission:
    async def test_announcement_changes_next_hop_and_is_observed(
        self, short_wirtn_timeout: None
    ) -> None:
        """A route declaration changes the path of a controlled send, and
        the observed announcement is kept apart from the accepted route."""
        harness = _pair()

        # before any claim there is no path and nothing leaves the router
        with pytest.raises(UnknownRoute):
            await harness.send(100)
        assert not any(harness.application_pdus(p) for p in harness.drain().values())
        assert harness.nsap.announcements == []

        # alpha claims it can reach network 100
        observed = await harness.announce("alpha", [100], "10.0.1.9")
        assert observed.accepted is True
        assert observed.reason is None
        assert isinstance(observed, ObservedAnnouncement)
        assert isinstance(observed.announcement, RouterAnnouncement)
        assert observed.announcement.kind == "i-am-router-to-network"
        assert observed.announcement.snet == 1
        assert observed.announcement.networks == (100,)
        assert str(observed.announcement.source) == "10.0.1.9"

        # the announcement is not itself a route, but it produced one
        cache = harness.nsap.router_info_cache
        assert cache.path_info[(1, 100)] == (
            Address("10.0.1.9"),
            ROUTER_AVAILABLE,
        )
        assert (2, 100) not in cache.path_info

        # the same controlled data now goes to the announced next hop
        harness.drain()
        await harness.send(100)
        sent = harness.drain()
        alpha_pdus = harness.application_pdus(sent["alpha"])
        assert len(alpha_pdus) == 1
        pdu, npdu = alpha_pdus[0]
        assert str(pdu.pduDestination) == "10.0.1.9"
        assert bytes(npdu.pduData) == b"controlled"
        assert harness.application_pdus(sent["beta"]) == []

    async def test_two_sources_same_network_keeps_first_next_hop(
        self, short_wirtn_timeout: None
    ) -> None:
        """Two ports claiming the same network number produce one accepted
        route and one observed rejection; the next hop does not flip."""
        harness = _pair()

        first = await harness.announce("alpha", [100], "10.0.1.9")
        second = await harness.announce("beta", [100], "10.0.2.9")

        assert first.accepted is True
        assert second.accepted is False
        assert second.reason == ANNOUNCEMENT_REJECTED_NETWORK_CONFLICT

        # both claims were observed, only one became a route
        assert len(harness.nsap.announcements) == 2
        assert harness.nsap.announcements[0].accepted is True
        assert harness.nsap.announcements[1].accepted is False
        assert harness.nsap.router_info_cache.path_info == {
            (1, 100): (Address("10.0.1.9"), ROUTER_AVAILABLE)
        }

        harness.drain()
        await harness.send(100)
        sent = harness.drain()
        assert len(harness.application_pdus(sent["alpha"])) == 1
        assert harness.application_pdus(sent["beta"]) == []
        assert str(sent["alpha"][-1].pduDestination) == "10.0.1.9"

        # a different network from the second source is still usable
        assert (await harness.announce("beta", [200], "10.0.2.9")).accepted
        harness.drain()
        await harness.send(200)
        sent = harness.drain()
        beta_pdus = harness.application_pdus(sent["beta"])
        assert len(beta_pdus) == 1
        assert str(beta_pdus[0][0].pduDestination) == "10.0.2.9"

    async def test_policy_rejects_source_and_valid_alternative_works(
        self, short_wirtn_timeout: None
    ) -> None:
        """The caller-supplied policy rejects a source without poisoning the
        network number, so a legitimate alternative path is still usable."""
        blocked = Address("10.0.1.66")

        def policy(announcement: RouterAnnouncement) -> bool:
            return announcement.source != blocked

        harness = _pair(policy)

        rejected = await harness.announce("alpha", [100], "10.0.1.66")
        assert rejected.accepted is False
        assert rejected.reason == ANNOUNCEMENT_REJECTED_POLICY
        assert harness.nsap.router_info_cache.path_info == {}

        with pytest.raises(UnknownRoute):
            await harness.send(100)

        accepted = await harness.announce("beta", [100], "10.0.2.9")
        assert accepted.accepted is True
        harness.drain()
        await harness.send(100)
        sent = harness.drain()
        beta_pdus = harness.application_pdus(sent["beta"])
        assert len(beta_pdus) == 1
        assert str(beta_pdus[0][0].pduDestination) == "10.0.2.9"
        assert harness.application_pdus(sent["alpha"]) == []

    async def test_rejected_claim_leaves_no_partial_route(
        self, short_wirtn_timeout: None
    ) -> None:
        """A claim with one conflicting network is rejected as a whole; a
        later legitimate claim for the other network still works."""
        harness = _pair()

        await harness.announce("alpha", [100], "10.0.1.9")

        # beta claims an accepted network and a new one together
        rejected = await harness.announce("beta", [100, 300], "10.0.2.9")
        assert rejected.accepted is False
        assert rejected.reason == ANNOUNCEMENT_REJECTED_NETWORK_CONFLICT

        cache = harness.nsap.router_info_cache
        assert (1, 300) not in cache.path_info
        assert (2, 300) not in cache.path_info
        assert all(300 not in dnets for dnets in cache.router_dnets.values())
        assert 300 not in [dnet for (_snet, dnet) in cache.path_info]

        # network 100 is unchanged and still goes to the first source
        harness.drain()
        await harness.send(100)
        sent = harness.drain()
        assert str(sent["alpha"][-1].pduDestination) == "10.0.1.9"
        assert harness.application_pdus(sent["beta"]) == []

        # the legitimate alternate path for 300 is admitted on its own
        accepted = await harness.announce("beta", [300], "10.0.2.10")
        assert accepted.accepted is True
        harness.drain()
        await harness.send(300)
        sent = harness.drain()
        beta_pdus = harness.application_pdus(sent["beta"])
        assert len(beta_pdus) == 1
        assert str(beta_pdus[0][0].pduDestination) == "10.0.2.10"

    async def test_disconnected_port_drops_routes_and_rejects_late_claims(
        self, short_wirtn_timeout: None
    ) -> None:
        """Disconnecting a port removes its routes, and a late announcement
        from it is observed but cannot resurrect the path."""
        harness = _pair()

        await harness.announce("alpha", [100, 200], "10.0.1.9")
        await harness.announce("beta", [300], "10.0.2.9")

        await harness.nsap.disconnect_adapter(harness.adapters["alpha"])

        cache = harness.nsap.router_info_cache
        assert (1, 100) not in cache.path_info
        assert (1, 200) not in cache.path_info
        assert (2, 300) in cache.path_info

        late = await harness.announce("alpha", [100], "10.0.1.9")
        assert late.accepted is False
        assert late.reason == ANNOUNCEMENT_REJECTED_PORT_DISCONNECTED
        assert (1, 100) not in cache.path_info

        # the connected port still supplies its next hop
        harness.drain()
        await harness.send(300)
        sent = harness.drain()
        beta_pdus = harness.application_pdus(sent["beta"])
        assert len(beta_pdus) == 1
        assert str(beta_pdus[0][0].pduDestination) == "10.0.2.9"

        # the disconnected network is no longer reachable
        with pytest.raises(UnknownRoute):
            await harness.send(100)

        # reconnecting and re-announcing makes the path usable again
        harness.nsap.connect_adapter(harness.adapters["alpha"])
        assert (await harness.announce("alpha", [100], "10.0.1.9")).accepted
        harness.drain()
        await harness.send(100)
        sent = harness.drain()
        assert str(sent["alpha"][-1].pduDestination) == "10.0.1.9"


@bacpypes_debugging
class TestNetworkNumberAnnouncements:
    async def test_network_number_is_moves_port_and_routes(
        self, short_wirtn_timeout: None
    ) -> None:
        """Network-Number-Is gives an unknown port its number, after which
        claims heard on that port are keyed by the learned number."""
        harness = VirtualInternetwork()
        harness.add_port("gamma", None, "10.0.3.1")
        harness.add_port("beta", 2, "10.0.2.1")
        gamma = harness.adapters["gamma"]

        learned = await harness.network_number_is("gamma", 7, "10.0.3.9")
        assert learned.accepted is True
        assert learned.announcement.kind == "network-number-is"
        assert learned.announcement.networks == (7,)
        assert gamma.adapterNet == 7
        assert harness.nsap.adapter_for_network(7) is gamma
        assert harness.nsap.adapters.get(None) is None

        claim = await harness.announce("gamma", [100], "10.0.3.9")
        assert claim.accepted is True
        assert claim.announcement.snet == 7
        assert harness.nsap.router_info_cache.path_info[(7, 100)][0] == Address(
            "10.0.3.9"
        )

        harness.drain()
        await harness.send(100)
        sent = harness.drain()
        gamma_pdus = harness.application_pdus(sent["gamma"])
        assert len(gamma_pdus) == 1
        assert str(gamma_pdus[0][0].pduDestination) == "10.0.3.9"
        assert harness.application_pdus(sent["beta"]) == []

    async def test_network_number_is_conflicts_are_rejected(self) -> None:
        """A learned number cannot steal a directly connected number or
        override a configured port's number."""
        harness = VirtualInternetwork()
        harness.add_port("gamma", None, "10.0.3.1")
        harness.add_port("beta", 2, "10.0.2.1")
        gamma = harness.adapters["gamma"]
        beta = harness.adapters["beta"]

        conflict = await harness.network_number_is("gamma", 2, "10.0.3.9")
        assert conflict.accepted is False
        assert conflict.reason == ANNOUNCEMENT_REJECTED_NETWORK_CONFLICT
        assert gamma.adapterNet is None
        assert harness.nsap.adapters.get(None) is gamma

        configured = await harness.network_number_is("beta", 99, "10.0.2.9")
        assert configured.accepted is False
        assert configured.reason == ANNOUNCEMENT_REJECTED_CONFIGURED
        assert beta.adapterNet == 2
        assert harness.nsap.adapters.get(2) is beta
        assert harness.nsap.router_info_cache.path_info == {}


@bacpypes_debugging
class TestRouterInfoCacheAtomicity:
    async def test_conflicting_update_leaves_cache_untouched(self) -> None:
        """An inconsistent cache entry aborts the whole update before any
        network is added, rather than applying part of the claim."""
        cache = RouterInfoCache()
        r1 = Address("1:1")
        r2 = Address("1:2")
        r3 = Address("1:3")

        await cache.update_path_info(1, r1, {100, 200})

        # manufacture the older style inconsistency: a path with no router
        # entry backing it
        cache.path_info[(1, 300)] = (r2, ROUTER_AVAILABLE)

        before_paths = dict(cache.path_info)
        before_routers = {
            key: set(value) for key, value in cache.router_dnets.items()
        }

        with pytest.raises(RoutingCacheConflict):
            await cache.update_path_info(1, r3, {300, 400})

        assert cache.path_info == before_paths
        assert cache.router_dnets == before_routers
        assert (1, 400) not in cache.path_info
        assert (1, r3) not in cache.router_dnets

        # repairing the stale entry lets the same claim apply cleanly
        del cache.path_info[(1, 300)]
        await cache.update_path_info(1, r3, {300, 400})
        assert cache.path_info[(1, 300)][0] == r3
        assert cache.path_info[(1, 400)][0] == r3
        assert cache.router_dnets[(1, r3)] == {300, 400}
