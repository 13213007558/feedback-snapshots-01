#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Forwarded-NPDU provenance replay
--------------------------------

A Forwarded-NPDU carries two sources: the transport source (the BBMD that
actually sent the packet) and the embedded "original" source it vouches
for.  These tests replay legitimate and forged encapsulations against the
B/IP service elements over a virtual link (trap clients/servers standing
in for the layers above and below) and observe both addresses:

* original broadcast — the transport source *is* the original source, no
  embedded claim, nothing to verify;
* forwarded broadcast — only a policy-accepted BBMD may have its embedded
  original source honored; the forwarder is recorded as
  ``pduForwardedBy`` so multi-hop propagation evidence survives;
* foreign device broadcast (Distribute-Broadcast-To-Network) — only a
  registered foreign device may have its broadcast distributed, and the
  BBMD re-originating it is recorded as the forwarder.

A forged Forwarded-NPDU from an arbitrary sender must not put its
embedded address upstream (where it would land in the application device
information cache), and a BBMD must not accept Forwarded-NPDUs from
senders outside its broadcast distribution table.
"""

from typing import List


from bacpypes3.comm import Client, Server, bind
from bacpypes3.pdu import PDU, IPv4Address, LocalBroadcast
from bacpypes3.npdu import NPDU
from bacpypes3.ipv4.bvll import (
    DistributeBroadcastToNetwork,
    ForwardedNPDU,
    OriginalBroadcastNPDU,
    Result,
)
from bacpypes3.ipv4.service import BIPNormal, BIPForeign, BIPBBMD


# ---------------------------------------------------------------------------
# virtual link harness
# ---------------------------------------------------------------------------


class ApplicationTrap(Client[PDU]):
    """Stands in for the network layer above; records what comes up."""

    def __init__(self) -> None:
        super().__init__()
        self.received: List[PDU] = []

    async def confirmation(self, pdu: PDU) -> None:  # type: ignore[override]
        self.received.append(pdu)


class WireTrap(Server):
    """Stands in for the codec/multiplexer below; records what goes down
    and injects LPDUs up as if they arrived from the virtual link."""

    def __init__(self) -> None:
        super().__init__()
        self.sent = []

    async def indication(self, lpdu) -> None:  # type: ignore[override]
        self.sent.append(lpdu)

    async def inject(self, lpdu) -> None:
        """Replay an LPDU as received from the virtual link."""
        await self.response(lpdu)


def normal_stack(**kwargs):
    app, bip, wire = ApplicationTrap(), BIPNormal(**kwargs), WireTrap()
    bind(app, bip)
    bind(bip, wire)
    return app, bip, wire


def bbmd_stack(addr, **kwargs):
    app, bip, wire = ApplicationTrap(), BIPBBMD(addr, **kwargs), WireTrap()
    bip._fdt_clock_handle.cancel()
    bind(app, bip)
    bind(bip, wire)
    return app, bip, wire


# actors on the virtual link
DEVICE = IPv4Address("10.0.0.5:47808")  # a device on the local subnet
BBMD = IPv4Address("10.0.0.1:47808")  # the local BBMD
PEER = IPv4Address("192.0.2.1:47808")  # a peer BBMD on another subnet
EXTERNAL = IPv4Address("192.0.2.5:47808")  # external device behind the peer
IMPOSTOR = IPv4Address("203.0.113.9:47808")  # not a BBMD at all

WHO_IS = b"\x01\x20\xff\xff\x00\xff\x10\x08"


# ---------------------------------------------------------------------------
# original broadcast: transport source is the source
# ---------------------------------------------------------------------------


async def test_original_broadcast_has_no_embedded_claim() -> None:
    app, _bip, wire = normal_stack()

    await wire.inject(
        OriginalBroadcastNPDU(WHO_IS, source=DEVICE, destination=LocalBroadcast())
    )

    (pdu,) = app.received
    assert pdu.pduSource == DEVICE
    assert pdu.pduForwardedBy is None


# ---------------------------------------------------------------------------
# forwarded broadcast: the BBMD vouches for the embedded source
# ---------------------------------------------------------------------------


async def test_forwarded_npdu_from_accepted_bbmd() -> None:
    """Legitimate multi-hop: PEER -> BBMD -> us; both addresses recorded."""
    app, _bip, wire = normal_stack(bbmd_addresses=[BBMD])

    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=BBMD, destination=LocalBroadcast())
    )

    (pdu,) = app.received
    # the application sees the original source ...
    assert pdu.pduSource == EXTERNAL
    # ... and the actual forwarder as propagation evidence
    assert pdu.pduForwardedBy == BBMD


async def test_forwarded_npdu_from_unaccepted_sender_dropped() -> None:
    """Forged encapsulation: the embedded claim never reaches the app."""
    app, _bip, wire = normal_stack(bbmd_addresses=[BBMD])

    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast())
    )

    assert app.received == []


async def test_forwarded_npdu_legacy_default_still_records_forwarder() -> None:
    """No policy configured: accepted (legacy), but the forwarder is on record."""
    app, _bip, wire = normal_stack()

    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast())
    )

    (pdu,) = app.received
    assert pdu.pduSource == EXTERNAL
    assert pdu.pduForwardedBy == IMPOSTOR


async def test_forwarded_npdu_provenance_survives_npdu_decode() -> None:
    """The network layer decodes PDUs into NPDUs; the evidence must survive."""
    app, _bip, wire = normal_stack(bbmd_addresses=[BBMD])

    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=BBMD, destination=LocalBroadcast())
    )

    npdu = NPDU.decode(app.received[0])
    assert npdu.pduSource == EXTERNAL
    assert npdu.pduForwardedBy == BBMD


# ---------------------------------------------------------------------------
# foreign device: registered with the BBMD, checked by the foreign side
# ---------------------------------------------------------------------------


async def test_foreign_device_checks_its_bbmd() -> None:
    app = ApplicationTrap()
    bip = BIPForeign()
    wire = WireTrap()
    bind(app, bip)
    bind(bip, wire)

    # registered with BBMD
    bip.bbmdAddress = BBMD
    bip._registration_event.set()

    # a Forwarded-NPDU from anywhere else is dropped ...
    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast())
    )
    assert app.received == []

    # ... one from the BBMD is honored, with the BBMD on record
    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=BBMD, destination=LocalBroadcast())
    )
    (pdu,) = app.received
    assert pdu.pduSource == EXTERNAL
    assert pdu.pduForwardedBy == BBMD


# ---------------------------------------------------------------------------
# BBMD: only BDT peers may vouch for an embedded source
# ---------------------------------------------------------------------------


async def test_bbmd_accepts_forwarded_npdu_from_peer() -> None:
    app, bip, wire = bbmd_stack(BBMD)
    bip.add_peer(BBMD)
    bip.add_peer(PEER)

    await wire.inject(ForwardedNPDU(EXTERNAL, WHO_IS, source=PEER, destination=BBMD))

    (pdu,) = app.received
    assert pdu.pduSource == EXTERNAL
    assert pdu.pduForwardedBy == PEER


async def test_bbmd_drops_forwarded_npdu_from_non_peer() -> None:
    """A forged Forwarded-NPDU is neither delivered nor re-distributed."""
    app, bip, wire = bbmd_stack(BBMD)
    bip.add_peer(BBMD)
    bip.add_peer(PEER)
    bip.register_foreign_device(IPv4Address("10.0.0.99:47808"), 60)

    await wire.inject(
        ForwardedNPDU(EXTERNAL, WHO_IS, source=IMPOSTOR, destination=BBMD)
    )

    assert app.received == []
    assert wire.sent == []


async def test_bbmd_distribute_broadcast_requires_registration() -> None:
    app, bip, wire = bbmd_stack(BBMD)

    # unregistered sender: NAKed and not distributed
    await wire.inject(
        DistributeBroadcastToNetwork(WHO_IS, source=IMPOSTOR, destination=BBMD)
    )
    assert app.received == []
    (nak,) = wire.sent
    assert isinstance(nak, Result)
    assert nak.bvlciResultCode == 0x0060
    assert nak.pduDestination == IMPOSTOR

    # registered foreign device: distributed, BBMD recorded as forwarder
    wire.sent.clear()
    bip.register_foreign_device(EXTERNAL, 60)
    await wire.inject(
        DistributeBroadcastToNetwork(WHO_IS, source=EXTERNAL, destination=BBMD)
    )
    (pdu,) = app.received
    assert pdu.pduSource == EXTERNAL
    assert pdu.pduForwardedBy == BBMD
