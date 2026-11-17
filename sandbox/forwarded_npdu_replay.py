#!/usr/bin/env python
"""
Forwarded-NPDU replay transcript
================================

Replays legitimate and forged BVLL Forwarded-NPDU encapsulations into a
BIPNormal service element over a virtual link and prints, for each
replay, the source address the application would see (which is what the
device information cache would key on) and the transport address of the
actual forwarder recorded as provenance.

Run:  python sandbox/forwarded_npdu_replay.py
"""

import asyncio

from bacpypes3.comm import Client, Server, bind
from bacpypes3.pdu import PDU, IPv4Address, LocalBroadcast
from bacpypes3.ipv4.bvll import ForwardedNPDU, OriginalBroadcastNPDU
from bacpypes3.ipv4.service import BIPNormal


class ApplicationTrap(Client[PDU]):
    def __init__(self) -> None:
        super().__init__()
        self.received = []

    async def confirmation(self, pdu: PDU) -> None:
        self.received.append(pdu)


class WireTrap(Server):
    async def indication(self, lpdu) -> None:
        pass

    async def inject(self, lpdu) -> None:
        await self.response(lpdu)


DEVICE = IPv4Address("10.0.0.5:47808")
BBMD = IPv4Address("10.0.0.1:47808")
EXTERNAL = IPv4Address("192.0.2.5:47808")
IMPOSTOR = IPv4Address("203.0.113.9:47808")
WHO_IS = b"\x01\x20\xff\xff\x00\xff\x10\x08"


async def replay(title, bip, lpdu):
    app, wire = ApplicationTrap(), WireTrap()
    bind(app, bip)
    bind(bip, wire)
    await wire.inject(lpdu)
    if app.received:
        pdu = app.received[0]
        print(f"{title}\n    app sees source : {pdu.pduSource}")
        print(f"    forwarded by    : {pdu.pduForwardedBy}")
    else:
        print(f"{title}\n    dropped, nothing sent upstream")


async def main():
    await replay(
        "1. original broadcast from local device (no embedded claim)",
        BIPNormal(bbmd_addresses=[BBMD]),
        OriginalBroadcastNPDU(WHO_IS, source=DEVICE, destination=LocalBroadcast()),
    )
    await replay(
        "2. forwarded broadcast from accepted BBMD (external device behind it)",
        BIPNormal(bbmd_addresses=[BBMD]),
        ForwardedNPDU(EXTERNAL, WHO_IS, source=BBMD, destination=LocalBroadcast()),
    )
    await replay(
        "3. forged Forwarded-NPDU from impostor claiming external source",
        BIPNormal(bbmd_addresses=[BBMD]),
        ForwardedNPDU(EXTERNAL, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast()),
    )
    await replay(
        "4. legacy default (no policy): accepted, but forwarder on record",
        BIPNormal(),
        ForwardedNPDU(EXTERNAL, WHO_IS, source=IMPOSTOR, destination=LocalBroadcast()),
    )


if __name__ == "__main__":
    asyncio.run(main())
