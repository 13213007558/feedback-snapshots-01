#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Forwarded-NPDU provenance replay (BACnet/IPv6)
----------------------------------------------

Same replay as the IPv4 suite: a Forwarded-NPDU carries the transport
source (the BBMD) and an embedded original source (VMAC + IPv6 address).
The embedded claims must not reach the application — or the virtual MAC
address table, the IPv6 side of the device trust cache — unless the
transport source is accepted by policy.
"""

from typing import List

from bacpypes3.comm import Client, Server, bind
from bacpypes3.pdu import PDU, IPv6Address, LocalBroadcast, VirtualAddress
from bacpypes3.ipv6.bvll import ForwardedNPDU
from bacpypes3.ipv6.service import BIPNormal, BIPForeign


class ApplicationTrap(Client[PDU]):
    """Stands in for the network layer above; records what comes up."""

    def __init__(self) -> None:
        super().__init__()
        self.received: List[PDU] = []

    async def confirmation(self, pdu: PDU) -> None:  # type: ignore[override]
        self.received.append(pdu)


class WireTrap(Server):
    """Stands in for the layers below; replays LPDUs from the virtual link."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: List[PDU] = []

    async def indication(self, lpdu) -> None:  # type: ignore[override]
        self.sent.append(lpdu)

    async def inject(self, lpdu) -> None:
        await self.response(lpdu)


# actors on the virtual link
LOCAL_VM = VirtualAddress(bytes.fromhex("010203"))
BBMD = IPv6Address("[fd77:3:a::1]")
EXTERNAL_VM = VirtualAddress(bytes.fromhex("040506"))
EXTERNAL = IPv6Address("[fd77:3:b::5]")
IMPOSTOR = IPv6Address("[fd77:3:c::9]")

WHO_IS = b"\x01\x20\xff\xff\x00\xff\x10\x08"


def normal_stack(**kwargs):
    app = ApplicationTrap()
    bip = BIPNormal(virtual_address=LOCAL_VM, **kwargs)
    wire = WireTrap()
    bind(app, bip)
    bind(bip, wire)
    return app, bip, wire


def foreign_stack(**kwargs):
    app = ApplicationTrap()
    bip = BIPForeign(virtual_address=LOCAL_VM, **kwargs)
    wire = WireTrap()
    bind(app, bip)
    bind(bip, wire)
    # registered with the BBMD
    bip.bbmdAddress = BBMD
    bip._registration_event.set()
    return app, bip, wire


async def test_normal_accepted_bbmd_updates_vmac_table() -> None:
    app, bip, wire = normal_stack(bbmd_addresses=[BBMD])

    await wire.inject(
        ForwardedNPDU(
            EXTERNAL_VM, EXTERNAL, WHO_IS, source=BBMD, destination=LocalBroadcast()
        )
    )

    (pdu,) = app.received
    assert pdu.pduSource == EXTERNAL_VM
    assert pdu.pduForwardedBy == BBMD
    assert bip.vmac_addr_table[EXTERNAL_VM] == EXTERNAL


async def test_normal_unaccepted_sender_no_vmac_poisoning() -> None:
    """Forged encapsulation: dropped before any of its claims are cached."""
    app, bip, wire = normal_stack(bbmd_addresses=[BBMD])

    await wire.inject(
        ForwardedNPDU(
            EXTERNAL_VM, IMPOSTOR, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast()
        )
    )

    assert app.received == []
    assert bip.vmac_addr_table[EXTERNAL_VM] is None


async def test_foreign_unregistered_sender_no_vmac_poisoning() -> None:
    """A forged Forwarded-NPDU must not poison the VMAC table even though
    the packet itself ends up dropped by the registration/BBMD checks."""
    app, bip, wire = foreign_stack()

    # not from the BBMD we are registered with
    await wire.inject(
        ForwardedNPDU(
            EXTERNAL_VM, IMPOSTOR, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast()
        )
    )

    assert app.received == []
    assert bip.vmac_addr_table[EXTERNAL_VM] is None


async def test_foreign_accepts_from_its_bbmd() -> None:
    app, bip, wire = foreign_stack()

    await wire.inject(
        ForwardedNPDU(
            EXTERNAL_VM, EXTERNAL, WHO_IS, source=BBMD, destination=LocalBroadcast()
        )
    )

    (pdu,) = app.received
    assert pdu.pduSource == EXTERNAL_VM
    assert pdu.pduForwardedBy == BBMD
    assert bip.vmac_addr_table[EXTERNAL_VM] == EXTERNAL
