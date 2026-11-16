"""
BACnet IPv4 Virtual Link Layer Service
"""

from __future__ import annotations

import asyncio
import dataclasses
import math
from asyncio.exceptions import TimeoutError
from typing import Any, Callable, Dict, List, Optional, cast

from ..debugging import ModuleLogger, DebugContents, bacpypes_debugging
from ..comm import Client, Server, ServiceAccessPoint, ApplicationServiceElement
from ..pdu import Address, LocalBroadcast, IPv4Address, PDU

from .bvll import (
    LPDU,
    DeleteForeignDeviceTableEntry,
    DistributeBroadcastToNetwork,
    FDTEntry,
    ForwardedNPDU,
    OriginalBroadcastNPDU,
    OriginalUnicastNPDU,
    ReadBroadcastDistributionTable,
    ReadBroadcastDistributionTableAck,
    ReadForeignDeviceTable,
    ReadForeignDeviceTableAck,
    RegisterForeignDevice,
    Result,
    WriteBroadcastDistributionTable,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())

# globals
REGISTRATION_TIMEOUT = 2.0
READ_BDT_TIMEOUT = 3.0
READ_FDT_TIMEOUT = 3.0
WRITE_BDT_TIMEOUT = 3.0

# BBMD foreign device table policy
#
# A foreign device registration is granted for its time-to-live (TTL); after
# that deadline the entry is expired and must no longer be a broadcast
# forwarding target.  The grace period only governs how long the expired entry
# is *retained* so a renewal can observe and replace it, never how long it is
# eligible for forwarding.
FDT_GRACE_PERIOD = 5
FDT_MAX_ENTRIES = 128
FDT_AUDIT_MAX_ENTRIES = 256

# result codes used by the IPv4 BBMD registration policy
FDT_RESULT_OK = 0x0000
FDT_RESULT_REGISTRATION_NAK = 0x0030
FDT_RESULT_DELETE_NAK = 0x0050


#
#   _Multiplex Client and Server
#


class _MultiplexClient(Client[PDU]):
    def __init__(self, mux):
        Client.__init__(self)
        self.multiplexer = mux

    async def confirmation(self, pdu: PDU) -> None:
        await self.multiplexer.confirmation(self, pdu)


class _MultiplexServer(Server[PDU]):
    def __init__(self, mux):
        Server.__init__(self)
        self.multiplexer = mux

    async def indication(self, pdu: PDU) -> None:
        await self.multiplexer.indication(self, pdu)


#
#   UDPMultiplexer
#


@bacpypes_debugging
class UDPMultiplexer(Client[PDU]):
    """
    An instance of this class sits above an IPv4DatagramServer and checks the
    upstream packets for Annex H style BACnet Tunneling Router functionality
    or Annex J BACnet/IPv4 functionality.
    """

    _debug: Callable[..., None]
    _warning: Callable[..., None]

    def __init__(self):
        if _debug:
            UDPMultiplexer._debug("__init__")

        # create and bind the Annex H and J servers
        self.annexH = _MultiplexServer(self)
        self.annexJ = _MultiplexServer(self)

    async def indication(self, server, pdu):
        if _debug:
            UDPMultiplexer._debug("indication %r %r", server, pdu)

        await self.request(pdu)

    async def confirmation(self, pdu: PDU) -> None:
        if _debug:
            UDPMultiplexer._debug("confirmation %r", pdu)

        # must have at least one octet
        if not pdu.pduData:
            if _debug:
                UDPMultiplexer._debug("    - no data")
            return

        # extract the first octet
        msg_type = pdu.pduData[0]

        # check for the message type
        if msg_type == 0x01:
            if self.annexH.serverPeer:
                await self.annexH.response(pdu)
        elif msg_type == 0x81:
            if self.annexJ.serverPeer:
                await self.annexJ.response(pdu)
        else:
            UDPMultiplexer._warning("unsupported message")


#
#   BTR
#


@bacpypes_debugging
class BTR(Client[PDU], Server[PDU], DebugContents):
    """
    BACnet Annex H Tunneling Router
    """

    _debug: Callable[..., None]
    _warning: Callable[..., None]
    _debug_contents = ("peers+",)

    peers: Dict[IPv4Address, List[int]]

    def __init__(self, *, cid=None, sid=None) -> None:
        if _debug:
            BTR._debug("__init__ cid=%r sid=%r", cid, sid)
        Client.__init__(self, cid)
        Server.__init__(self, sid)

        # initialize a dicitonary of peers
        self.peers = {}

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BTR._debug("indication %r", pdu)
        assert isinstance(pdu.pduDestination, Address)

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # make sure it is going to a peer
            if pdu.pduDestination not in self.peers:
                ###TODO log this
                return

            # send it downstream
            await self.request(pdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # if route_aware and pdu.pduDestination.addrRoute:
            #     xpdu = PDU(pdu.pduData, destination=pdu.pduDestination.addrRoute)
            #     await self.request(xpdu)
            #     return

            # loop through the peers
            for peerAddr in self.peers.keys():
                xpdu = PDU(pdu.pduData, destination=peerAddr)

                # send it downstream
                await self.request(xpdu)

        else:
            raise RuntimeError("invalid destination address type (2)")

    async def confirmation(self, pdu: PDU) -> None:
        if _debug:
            BTR._debug("confirmation %r", pdu)
        assert isinstance(pdu.pduDestination, Address)

        # make sure it came from a peer
        if pdu.pduSource not in self.peers:
            BTR._warning("not a peer: %r", pdu.pduSource)
            return

        # send it upstream
        await self.response(pdu)

    def add_peer(self, peerAddr: IPv4Address, networks: List[int] = []) -> None:
        """Add a peer and optionally provide a list of the reachable networks."""
        if _debug:
            BTR._debug("add_peer %r networks=%r", peerAddr, networks)

        # see if this is already a peer
        if peerAddr in self.peers:
            # add the (new?) reachable networks
            self.peers[peerAddr].extend(networks)
        else:
            # save the networks
            self.peers[peerAddr] = networks

        ###TODO send a control message upstream that these are reachable

    def delete_peer(self, peerAddr: IPv4Address) -> None:
        """Delete a peer."""
        if _debug:
            BTR._debug("delete_peer %r", peerAddr)

        ###TODO send a control message upstream that these are no longer reachable

        # now delete the peer
        del self.peers[peerAddr]


#
#   BVLLServiceAccessPoint
#


@bacpypes_debugging
class BVLLServiceAccessPoint(Client[LPDU], Server[PDU], ServiceAccessPoint):
    """
    BACnet IPv4 Service Access Point

    An instance of this is stacked on a BVLLCodec, as a server it presents
    PDUs.
    """

    _debug: Callable[..., None]

    def __init__(
        self,
        *,
        sapID: Optional[str] = None,
        cid: Optional[str] = None,
        sid: Optional[str] = None,
    ) -> None:
        if _debug:
            BVLLServiceAccessPoint._debug("__init__")
        Client.__init__(self, cid=cid)
        Server.__init__(self, sid=sid)
        ServiceAccessPoint.__init__(self, sapID=sapID)

    async def sap_indication(self, lpdu: LPDU) -> None:
        if _debug:
            BVLLServiceAccessPoint._debug("sap_indication %r", lpdu)

        # this is a request initiated by the ASE, send this downstream
        await self.request(lpdu)

    async def sap_confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BVLLServiceAccessPoint._debug("sap_confirmation %r", lpdu)

        # this is a response from the ASE, send this downstream
        await self.request(lpdu)


#
#   BIPNormal
#


@bacpypes_debugging
class BIPNormal(BVLLServiceAccessPoint):
    _debug: Callable[..., None]
    _warning: Callable[..., None]

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPNormal._debug("indication %r", pdu)
        assert isinstance(pdu.pduDestination, Address)

        lpdu: LPDU

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # make an original unicast PDU
            lpdu = OriginalUnicastNPDU(
                pdu, destination=pdu.pduDestination, user_data=pdu.pduUserData
            )
            if _debug:
                BIPNormal._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # make an original broadcast PDU
            lpdu = OriginalBroadcastNPDU(
                pdu, destination=pdu.pduDestination, user_data=pdu.pduUserData
            )
            if _debug:
                BIPNormal._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

        else:
            BIPNormal._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPNormal._debug("confirmation %r", lpdu)

        # some kind of response to a request
        if isinstance(lpdu, Result):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ReadForeignDeviceTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, OriginalUnicastNPDU):
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.pduSource,
                destination=lpdu.pduDestination,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            # build a PDU with a local broadcast address
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.pduSource,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, ForwardedNPDU):
            # build a PDU with the source from the real source
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciAddress,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, WriteBroadcastDistributionTable):
            # build a response
            xpdu = Result(code=0x0010, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTable):
            # build a response
            xpdu = Result(code=0x0020, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            # build a response
            xpdu = Result(code=0x0030, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadForeignDeviceTable):
            # build a response
            xpdu = Result(code=0x0040, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            # build a response
            xpdu = Result(code=0x0050, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # build a response
            xpdu = Result(code=0x0060, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        else:
            BIPNormal._warning("invalid pdu type: %s", type(pdu))


#
#   BIPForeign
#


@bacpypes_debugging
class BIPForeign(BVLLServiceAccessPoint, DebugContents):
    _debug: Callable[..., None]
    _warning: Callable[..., None]
    _debug_contents = ("bbmdAddress", "bbmdTimeToLive", "bbmdRegistrationStatus")

    bbmdAddress: Optional[IPv4Address]
    bbmdTimeToLive: Optional[int]
    bbmdRegistrationStatus: int

    _registration_event: asyncio.Event
    _registration_handle: Optional[asyncio.Handle]
    _registration_task: Optional[asyncio.Task]
    _registration_timeout_task: Optional[asyncio.Task]
    _reregistration_timeout_handle: Optional[asyncio.TimerHandle]

    def __init__(self, **kwargs) -> None:
        if _debug:
            BIPForeign._debug("__init__")
        BVLLServiceAccessPoint.__init__(self, **kwargs)

        # clear the BBMD address and time-to-live
        self.bbmdAddress = None
        self.bbmdTimeToLive = None

        # -2=unregistered, -1=in process, 0=OK, >0 error
        self.bbmdRegistrationStatus = -2

        # used in tracking the active registration
        self._registration_event = asyncio.Event()
        self._registration_handle = None
        self._registration_timeout_handle = None
        self._reregistration_timeout_handle = None

        # unregistered
        self._registration_event.clear()

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPForeign._debug("indication %r", pdu)
        assert isinstance(pdu.pduDestination, Address)

        lpdu: LPDU

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # make an original unicast PDU
            lpdu = OriginalUnicastNPDU(
                pdu.pduData, destination=pdu.pduDestination, user_data=pdu.pduUserData
            )
            if _debug:
                BIPForeign._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # check the BBMD registration status
            if self.bbmdRegistrationStatus == -2:
                if _debug:
                    BIPForeign._debug("    - packet dropped, unregistered")
                return

            elif self.bbmdRegistrationStatus == -1:
                try:
                    if _debug:
                        BIPForeign._debug("    - wait for registration response")

                    await asyncio.wait_for(
                        self._registration_event.wait(),
                        timeout=REGISTRATION_TIMEOUT,
                    )
                except TimeoutError:
                    if _debug:
                        BIPForeign._debug("    - packet dropped, unregistered")
                    return

            elif self.bbmdRegistrationStatus == 0:
                pass

            else:
                if _debug:
                    BIPForeign._debug(
                        "    - registration error: %r", self.bbmdRegistrationStatus
                    )
                return  ###TODO raise RuntimeError?

            # make a broadcast PDU
            lpdu = DistributeBroadcastToNetwork(
                pdu, destination=self.bbmdAddress, user_data=pdu.pduUserData
            )
            if _debug:
                BIPForeign._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

        else:
            BIPForeign._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPForeign._debug("confirmation %r", lpdu)

        xpdu: LPDU

        # check for a registration request result
        if isinstance(lpdu, Result):
            # if we have no registration, do nothing
            if self.bbmdRegistrationStatus == -2:
                return

            if _debug:
                BIPForeign._debug("    - registration: %r", self._registration_handle)
            if not self._registration_handle:
                # we received this ack but we haven't requested one
                return
            self._registration_handle = None

            # make sure the result is from the bbmd
            if lpdu.pduSource != self.bbmdAddress:
                if _debug:
                    BIPForeign._debug("    - packet dropped, not from the BBMD")
                return

            # save the result code as the status
            self.bbmdRegistrationStatus = cast(int, lpdu.bvlciResultCode)

            # if successful, start tracking the registration
            if self.bbmdRegistrationStatus == 0:
                self._registration_event.set()
                self._start_tracking_registration()

        elif isinstance(lpdu, OriginalUnicastNPDU):
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.pduSource,
                destination=lpdu.pduDestination,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, ForwardedNPDU):
            # check the BBMD registration status, we may not be registered
            if not self._registration_event.is_set():
                if _debug:
                    BIPForeign._debug("    - packet dropped, unregistered")
                return

            # make sure the forwarded PDU from the bbmd
            if lpdu.pduSource != self.bbmdAddress:
                if _debug:
                    BIPForeign._debug("    - packet dropped, not from the BBMD")
                return

            # build a PDU with the source from the real source
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciAddress,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ReadForeignDeviceTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, WriteBroadcastDistributionTable):
            # build a response
            xpdu = Result(code=0x0010, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTable):
            # build a response
            xpdu = Result(code=0x0020, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            # build a response
            xpdu = Result(code=0x0030, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadForeignDeviceTable):
            # build a response
            xpdu = Result(code=0x0040, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            # build a response
            xpdu = Result(code=0x0050, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # build a response
            xpdu = Result(code=0x0060, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            if _debug:
                BIPForeign._debug("    - packet dropped")

        else:
            BIPForeign._warning("invalid pdu type: %s", type(lpdu))

    def register(self, addr: IPv4Address, ttl: int) -> None:
        """Start the foreign device registration process with the given BBMD.

        Registration will be renewed periodically according to the ttl value
        until explicitly stopped by a call to `unregister`.
        """
        if _debug:
            BIPForeign._debug("register %r %r", addr, ttl)

        # a little error checking
        if not isinstance(addr, IPv4Address):
            raise TypeError("addr must be an IPv4Address")
        if ttl <= 0:
            raise ValueError("time-to-live must be greater than zero")
        if self._registration_handle:
            if _debug:
                BIPForeign._debug("    - registration already scheduled")
            return

        # save the BBMD address and time-to-live
        self.bbmdAddress = addr
        self.bbmdTimeToLive = ttl

        # start the registration process when you get a chance
        loop = asyncio.get_event_loop()
        self._registration_handle = loop.call_soon(self._start_registration)

    def unregister(self):
        """Stop the foreign device registration process.

        Immediately drops active foreign device registration and stops further
        registration renewals.
        """
        if _debug:
            BIPForeign._debug("unregister")

        # if we are already doing nothing, skip the rest
        if self.bbmdRegistrationStatus == -2:
            if _debug:
                BIPForeign._debug("    - nothing to do")
            return

        # stop tracking the registration
        self._stop_tracking_registration()

        # if the event loop is still running, stop the registration
        if asyncio.get_event_loop().is_running():
            asyncio.ensure_future(self._stop_registration(self.bbmdAddress))

        # change the status to unregistered
        self.bbmdRegistrationStatus = -2
        self._registration_event.clear()

        # clear the BBMD address and time-to-live
        self.bbmdAddress = None
        self.bbmdTimeToLive = None

    def _start_registration(self) -> None:
        """Scheduled when the registration request is being initiated or
        renewed, task saved in self._registration_task."""
        if _debug:
            BIPForeign._debug("_start_registration")
            BIPForeign._debug(
                "    - registration status: %r", self.bbmdRegistrationStatus
            )

        if self.bbmdRegistrationStatus == -2:
            self.bbmdRegistrationStatus = -1  # in process

        # form a registration request
        pdu = RegisterForeignDevice(self.bbmdTimeToLive, destination=self.bbmdAddress)
        if _debug:
            BIPForeign._debug("    - pdu: %r", pdu)

        # send it downstream
        registration_task = asyncio.create_task(self.request(pdu))
        if _debug:
            BIPForeign._debug("    - registration request: %r", registration_task)

        # get the loop to schedule another attempt
        loop = asyncio.get_event_loop()
        if _debug:
            BIPForeign._debug("    - loop time: %r", loop.time())

        # schedule another (faster) registration attempt
        self._reregistration_timeout_handle = loop.call_later(
            min(5, cast(int, self.bbmdTimeToLive)), self._start_registration
        )
        if _debug:
            BIPForeign._debug(
                "    - re-registration timeout: %r", self._reregistration_timeout_handle
            )

    async def _stop_registration(self, bbmdAddress: IPv4Address) -> None:
        """Scheduled when the registration is being canceled."""
        if _debug:
            BIPForeign._debug("_stop_registration")

        pdu = RegisterForeignDevice(0, destination=bbmdAddress)

        # send it downstream
        await self.request(pdu)

    def _start_tracking_registration(self):
        # From J.5.2.3 Foreign Device Table Operation (paraphrasing): if a
        # foreign device does not renew its registration 30 seconds after its
        # TTL expired then it will be removed from the BBMD's FDT.
        #
        # Thus, if we're registered and don't get a response to a subsequent
        # renewal request 30 seconds after our TTL expired then we're
        # definitely not registered anymore.
        # self._registration_timeout_task.install_task(delta=self.bbmdTimeToLive + 30)
        if _debug:
            BIPForeign._debug("_start_tracking_registration")
            BIPForeign._debug(
                "    - _registration_handle: %r", self._registration_handle
            )
            BIPForeign._debug(
                "    - _registration_timeout_handle: %r",
                self._registration_timeout_handle,
            )

        # stop any current tracking
        self._stop_tracking_registration()

        # get the loop for call_later()
        loop = asyncio.get_event_loop()

        # schedule a registration to refresh it
        self._registration_handle = loop.call_later(
            self.bbmdTimeToLive, self._start_registration
        )
        if _debug:
            BIPForeign._debug(
                "    - new _registration_handle: %r", self._registration_handle
            )

        # schedule the registration timeout
        self._registration_timeout_handle = loop.call_later(
            self.bbmdTimeToLive + 30, self._registration_expired
        )
        if _debug:
            BIPForeign._debug(
                "    - new _registration_timeout_handle: %r",
                self._registration_timeout_handle,
            )

    def _stop_tracking_registration(self):
        if _debug:
            BIPForeign._debug("_stop_tracking_registration")

        if self._registration_handle:
            if _debug:
                BIPForeign._debug("        - canceling %r", self._registration_handle)
            self._registration_handle.cancel()
            self._registration_handle = None

        if self._registration_timeout_handle:
            if _debug:
                BIPForeign._debug(
                    "        - canceling %r", self._registration_timeout_handle
                )
            self._registration_timeout_handle.cancel()
            self._registration_timeout_handle = None

        if self._reregistration_timeout_handle:
            if _debug:
                BIPForeign._debug(
                    "        - canceling %r", self._reregistration_timeout_handle
                )
            self._reregistration_timeout_handle.cancel()
            self._reregistration_timeout_handle = None

    def _registration_expired(self):
        """Called when detecting that foreign device registration has
        definitely expired.
        """
        if _debug:
            BIPForeign._debug("_registration_expired")

        self.bbmdRegistrationStatus = -2  # unregistered
        self._registration_event.clear()
        self._stop_tracking_registration()


#
#   BIPBBMD
#


@dataclasses.dataclass
class FDTAuditRecord:
    """
    One decision made by the BBMD foreign device registration policy.

    ``timestamp`` and ``deadline`` are event loop times.  ``source`` is the
    address the frame actually arrived from; ``address`` is the address the
    request named (or the address being expired).  ``reason`` is a stable
    machine-readable token, suitable for logs and tests.
    """

    timestamp: float
    action: str
    source: Optional[str]
    address: Optional[str]
    accepted: bool
    reason: str
    ttl: Optional[int]
    deadline: Optional[float]
    remaining: Optional[int]
    entries: int

    def as_dict(self) -> Dict[str, Any]:
        """Return the record as a JSON-serializable dictionary."""
        return dataclasses.asdict(self)


@bacpypes_debugging
class BIPBBMD(BVLLServiceAccessPoint, DebugContents):
    """
    BACnet/IPv4 Broadcast Broadcast Management Device.

    Foreign device admission is based on the transport source of the request,
    never on an address carried in the request body.  A registration is a
    lease: it is eligible for broadcast forwarding from the moment it is
    accepted until its TTL deadline.  An expired entry is retained for
    ``fdt_grace_period`` seconds so the same source can renew it, but it is
    not a forwarding target during that grace period.  Deleting an entry is
    also source-bound: a request may only remove the entry of the address it
    actually came from.  New sources are refused when the table is full; live
    entries are never evicted to make room.  Every accept/reject decision is
    appended to ``fdt_audit`` with a reason and, when applicable, the lease
    deadline.
    """

    _debug: Callable[..., None]
    _warning: Callable[..., None]
    _debug_contents = ("bbmdAddress", "bbmdBDT+", "bbmdFDT+")

    bbmdAddress: IPv4Address
    bbmdBDT: List[IPv4Address]
    bbmdFDT: List[FDTEntry]
    fdt_audit: List[FDTAuditRecord]
    fdtCapacity: int
    fdtGracePeriod: int
    acceptFDRegistrations: bool

    _fdt_clock_handle: asyncio.Handle

    def __init__(
        self,
        addr: IPv4Address,
        *,
        fdt_capacity: int = FDT_MAX_ENTRIES,
        fdt_grace_period: int = FDT_GRACE_PERIOD,
        accept_fd_registrations: bool = True,
        **kwargs,
    ):
        if _debug:
            BIPBBMD._debug("__init__ %r", addr)
        BVLLServiceAccessPoint.__init__(self, **kwargs)

        self.bbmdAddress = addr
        self.bbmdBDT = []
        self.bbmdFDT = []
        self.fdt_audit = []
        self.fdtCapacity = max(1, int(fdt_capacity))
        self.fdtGracePeriod = max(0, int(fdt_grace_period))
        self.acceptFDRegistrations = bool(accept_fd_registrations)

        # lease clock: the event loop clock.  A tick that arrives without the
        # loop clock having advanced (a manually driven clock in deterministic
        # tests) still counts as one second, so expiry never depends on
        # wall-clock time passing between ticks.
        loop = asyncio.get_event_loop()
        self._fdt_now = loop.time()
        self._fdt_tick_time = self._fdt_now - 1

        # schedule the clock to run
        self._fdt_clock_handle = loop.call_soon(self.fdt_clock)

    def _fdt_time(self) -> float:
        """Return the clock used for lease deadlines."""
        self._fdt_now = max(asyncio.get_event_loop().time(), self._fdt_now)
        return self._fdt_now

    def advance_fdt_clock(self, seconds: int = 1) -> None:
        """
        Advance the lease clock by ``seconds`` and expire leases.

        The periodic ``fdt_clock`` task is driven by the event loop; this entry
        point makes the same transition explicit for deterministic tests and
        for hosts that want to drive lease bookkeeping themselves.
        """
        if seconds < 0:
            raise ValueError("advance must not be negative")
        self._fdt_now += seconds
        self._fdt_tick_time = asyncio.get_event_loop().time()
        self._fdt_sweep(self._fdt_now)

    @staticmethod
    def _valid_fdt_source(addr: Any) -> bool:
        """Return true if the transport source can identify a foreign device."""
        if not isinstance(addr, IPv4Address):
            return False
        if addr.addrPort == 0:
            return False
        ip = addr.ip
        if ip.is_unspecified or ip.is_multicast:
            return False
        if ip.packed == b"\xff\xff\xff\xff":
            return False
        return True

    def _audit_fdt(
        self,
        action: str,
        source: Optional[Address],
        address: Optional[Address],
        accepted: bool,
        reason: str,
        *,
        ttl: Optional[int] = None,
        deadline: Optional[float] = None,
        remaining: Optional[int] = None,
    ) -> FDTAuditRecord:
        record = FDTAuditRecord(
            timestamp=self._fdt_time(),
            action=action,
            source=str(source) if source is not None else None,
            address=str(address) if address is not None else None,
            accepted=accepted,
            reason=reason,
            ttl=ttl,
            deadline=deadline,
            remaining=remaining,
            entries=len(self.bbmdFDT),
        )
        self.fdt_audit.append(record)
        overflow = len(self.fdt_audit) - FDT_AUDIT_MAX_ENTRIES
        if overflow > 0:
            del self.fdt_audit[:overflow]
        if not accepted:
            self._warning(
                "foreign device %s rejected: %s (source %r, address %r)",
                action,
                reason,
                record.source,
                record.address,
            )
        return record

    def fdt_audit_records(self) -> List[Dict[str, Any]]:
        """Return the registration audit trail as dictionaries."""
        return [record.as_dict() for record in self.fdt_audit]

    def fdt_status(self) -> List[Dict[str, Any]]:
        """
        Return the foreign device table with lease state for each entry.

        ``deadline`` is when the entry stops being a broadcast forwarding
        target; ``grace_remaining`` is how long the expired entry will still be
        retained so its owner can renew it; ``forwarding`` is the effective
        eligibility used when selecting broadcast targets.
        """
        now = self._fdt_time()
        status = []
        for fdte in self.bbmdFDT:
            deadline = fdte.fdDeadline if fdte.fdDeadline is not None else now
            removal_deadline = (
                fdte.fdRemovalDeadline
                if fdte.fdRemovalDeadline is not None
                else deadline
            )
            status.append(
                {
                    "address": str(fdte.fdAddress),
                    "ttl": fdte.fdTTL,
                    "remaining": max(0, math.ceil(deadline - now)),
                    "deadline": fdte.fdDeadline,
                    "grace_remaining": max(0, math.ceil(removal_deadline - now)),
                    "forwarding": self._fdt_entry_is_live(fdte, now),
                    "expired": fdte.fdExpired,
                    "renewals": fdte.fdRenewals,
                }
            )
        return status

    def _find_fdt_entry(self, addr: Address) -> Optional[FDTEntry]:
        for fdte in self.bbmdFDT:
            if addr == fdte.fdAddress:
                return fdte
        return None

    def _fdt_entry_is_live(self, fdte: FDTEntry, now: Optional[float] = None) -> bool:
        if fdte.fdExpired or fdte.fdDeadline is None:
            return False
        if now is None:
            now = self._fdt_time()
        return now < fdte.fdDeadline

    def _fdt_forward_targets(self) -> List[FDTEntry]:
        """Return only entries whose lease has not expired."""
        now = self._fdt_time()
        return [fdte for fdte in self.bbmdFDT if self._fdt_entry_is_live(fdte, now)]

    def _expire_fdt_entry(self, fdte: FDTEntry, now: float) -> None:
        fdte.fdExpired = True
        if fdte.fdRemovalDeadline is not None:
            fdte.fdRemain = max(0, math.ceil(fdte.fdRemovalDeadline - now))
        else:
            fdte.fdRemain = 0
        self._audit_fdt(
            "expire",
            fdte.fdAddress,
            fdte.fdAddress,
            False,
            "ttl-expired",
            ttl=fdte.fdTTL,
            deadline=fdte.fdDeadline,
            remaining=0,
        )

    def _purge_fdt(self, now: float) -> None:
        for i in range(len(self.bbmdFDT) - 1, -1, -1):
            fdte = self.bbmdFDT[i]

            # make sure an expiring entry is recorded even if the periodic
            # clock has not ticked since its deadline passed
            if not fdte.fdExpired and not self._fdt_entry_is_live(fdte, now):
                self._expire_fdt_entry(fdte, now)

            if fdte.fdRemovalDeadline is not None and now >= fdte.fdRemovalDeadline:
                if _debug:
                    BIPBBMD._debug("foreign device removed: %r", fdte.fdAddress)
                del self.bbmdFDT[i]
                self._audit_fdt(
                    "purge",
                    fdte.fdAddress,
                    fdte.fdAddress,
                    True,
                    "grace-period-elapsed",
                    ttl=fdte.fdTTL,
                    deadline=fdte.fdDeadline,
                    remaining=0,
                )

    def _reclaim_expired_fdt_entry(self, now: float) -> Optional[FDTEntry]:
        """
        Remove the longest-expired entry to make room for a new source.

        Only entries whose lease has already lapsed are eligible; a live lease
        is never evicted for a newcomer.  If several have lapsed the one that
        expired first is reclaimed first.
        """
        expired = [
            fdte for fdte in self.bbmdFDT if not self._fdt_entry_is_live(fdte, now)
        ]
        if not expired:
            return None

        victim = min(
            expired,
            key=lambda fdte: (
                fdte.fdDeadline if fdte.fdDeadline is not None else float("-inf")
            ),
        )
        self.bbmdFDT.remove(victim)
        self._audit_fdt(
            "reclaim",
            victim.fdAddress,
            victim.fdAddress,
            True,
            "expired-entry-reclaimed",
            ttl=victim.fdTTL,
            deadline=victim.fdDeadline,
            remaining=0,
        )
        return victim

    def _refresh_fdt_remaining(self, now: Optional[float] = None) -> None:
        """Update the wire-visible remaining time from each retention deadline."""
        if now is None:
            now = self._fdt_time()
        for fdte in self.bbmdFDT:
            if fdte.fdRemovalDeadline is None:
                fdte.fdRemain = 0
            else:
                fdte.fdRemain = max(0, math.ceil(fdte.fdRemovalDeadline - now))

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPBBMD._debug("indication %r", pdu)
        assert isinstance(pdu.pduDestination, Address)

        lpdu: LPDU

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # make an original unicast PDU
            lpdu = OriginalUnicastNPDU(
                pdu.pduData, destination=pdu.pduDestination, user_data=pdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # make an original broadcast PDU
            lpdu = OriginalBroadcastNPDU(
                pdu.pduData, destination=pdu.pduDestination, user_data=pdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

            # make a forwarded PDU
            lpdu = ForwardedNPDU(
                self.bbmdAddress, pdu.pduData, user_data=pdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - forwarded lpdu: %r", lpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    lpdu.pduDestination = IPv4Address(bdte.addrBroadcastTuple)
                    BIPBBMD._debug("    - sending to peer: %r", lpdu.pduDestination)
                    await self.request(lpdu)

            # send it to the registered foreign devices
            for fdte in self._fdt_forward_targets():
                lpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", lpdu.pduDestination
                    )
                await self.request(lpdu)

        else:
            BIPBBMD._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPBBMD._debug("confirmation %r", lpdu)

        xpdu: LPDU

        # some kind of response to a request
        if isinstance(lpdu, Result):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, WriteBroadcastDistributionTable):
            # build a response
            xpdu = Result(
                code=0x0010, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTable):
            # build a response
            xpdu = ReadBroadcastDistributionTableAck(
                self.bbmdBDT, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ForwardedNPDU):
            # send it upstream if there is a network layer
            if self.serverPeer:
                # build a PDU with a local broadcast address
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.bvlciAddress,
                    destination=LocalBroadcast(),
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - upstream pdu: %r", pdu)

                await self.response(pdu)

            # build a forwarded NPDU to send out
            xpdu = ForwardedNPDU(
                lpdu.bvlciAddress,
                lpdu.pduData,
                destination=None,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # if this was unicast to us, do next hop
            assert isinstance(lpdu.pduDestination, Address)
            if lpdu.pduDestination.addrType == Address.localStationAddr:
                if _debug:
                    BIPBBMD._debug("    - unicast message")

                # if this BBMD is listed in its BDT, send a local broadcast
                if self.bbmdAddress in self.bbmdBDT:
                    xpdu.pduDestination = LocalBroadcast()
                    if _debug:
                        BIPBBMD._debug("    - local broadcast")
                    await self.request(xpdu)

            elif lpdu.pduDestination.addrType == Address.localBroadcastAddr:
                if _debug:
                    BIPBBMD._debug("    - directed broadcast message")

            else:
                BIPBBMD._warning("invalid destination address: %r", lpdu.pduDestination)

            # send it to the registered foreign devices
            for fdte in self._fdt_forward_targets():
                xpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            # foreign device admission is decided by the transport source of
            # the frame, not by any address carried in the request payload;
            # a zero TTL is the protocol's unregister request
            if lpdu.bvlciTimeToLive == 0:
                stat = self.process_delete_foreign_device(
                    lpdu.pduSource, lpdu.pduSource
                )
            else:
                stat = self.process_register_foreign_device(
                    lpdu.pduSource, lpdu.bvlciTimeToLive
                )

            # build a response
            xpdu = Result(
                code=stat, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadForeignDeviceTable):
            # report the table as it stands, expired-but-retained entries
            # included, so an operator can see leases that are not forwarding
            self._refresh_fdt_remaining()
            xpdu = ReadForeignDeviceTableAck(
                self.bbmdFDT, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadForeignDeviceTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            # deletion is source-bound: the entry removed is the one owned by
            # the address the request actually came from
            stat = self.process_delete_foreign_device(lpdu.pduSource, lpdu.bvlciAddress)

            # build a response
            xpdu = Result(
                code=stat, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPBBMD._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # only a foreign device with a live lease may inject broadcasts
            now = self._fdt_time()
            self._purge_fdt(now)
            fdte = self._find_fdt_entry(lpdu.pduSource)
            if fdte is None or not self._fdt_entry_is_live(fdte, now):
                self._audit_fdt(
                    "distribute",
                    lpdu.pduSource,
                    lpdu.pduSource,
                    False,
                    "entry-not-found" if fdte is None else "ttl-expired",
                    ttl=fdte.fdTTL if fdte is not None else None,
                    deadline=fdte.fdDeadline if fdte is not None else None,
                    remaining=fdte.fdRemain if fdte is not None else None,
                )
                await self.request(
                    Result(
                        code=0x0060,
                        destination=lpdu.pduSource,
                        user_data=lpdu.pduUserData,
                    )
                )
                return

            # send it upstream if there is a network layer
            if self.serverPeer:
                # build a PDU with a local broadcast address
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.pduSource,
                    destination=LocalBroadcast(),
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - upstream pdu: %r", pdu)

                await self.response(pdu)

            # build a forwarded NPDU to send out
            xpdu = ForwardedNPDU(lpdu.pduSource, lpdu, user_data=lpdu.pduUserData)
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte == self.bbmdAddress:
                    xpdu.pduDestination = LocalBroadcast()
                    if _debug:
                        BIPBBMD._debug("    - local broadcast")
                    await self.request(xpdu)
                else:
                    xpdu.pduDestination = IPv4Address(bdte.addrBroadcastTuple)
                    if _debug:
                        BIPBBMD._debug("    - sending to peer: %r", xpdu.pduDestination)
                    await self.request(xpdu)

            # send it to the other registered foreign devices
            for fdte in self._fdt_forward_targets():
                if fdte.fdAddress != lpdu.pduSource:
                    xpdu.pduDestination = fdte.fdAddress
                    if _debug:
                        BIPBBMD._debug(
                            "    - sending to foreign device: %r", xpdu.pduDestination
                        )
                    await self.request(xpdu)

        elif isinstance(lpdu, OriginalUnicastNPDU):
            # send it upstream if there is a network layer
            if self.serverPeer:
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.pduSource,
                    destination=lpdu.pduDestination,
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - upstream pdu: %r", pdu)

                await self.response(pdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            # send it upstream if there is a network layer
            if self.serverPeer:
                # build a PDU with a local broadcast address
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.pduSource,
                    destination=LocalBroadcast(),
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - upstream pdu: %r", pdu)

                await self.response(pdu)

            # make a forwarded PDU
            xpdu = ForwardedNPDU(lpdu.pduSource, lpdu, user_data=lpdu.pduUserData)
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    xpdu.pduDestination = IPv4Address(bdte.addrBroadcastTuple)
                    if _debug:
                        BIPBBMD._debug("    - sending to peer: %r", xpdu.pduDestination)
                    await self.request(xpdu)

            # send it to the registered foreign devices
            for fdte in self._fdt_forward_targets():
                xpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

        else:
            BIPBBMD._warning("invalid pdu type: %s", type(lpdu))

    def register_foreign_device(self, addr: IPv4Address, ttl: int) -> int:
        """
        Administrative registration, identified by ``addr``.

        This is the local API used when provisioning a BBMD programmatically;
        requests arriving on the wire go through ``process_register_foreign_device``
        and are identified by their transport source instead.
        """
        return self.process_register_foreign_device(addr, ttl, administrative=True)

    def process_register_foreign_device(
        self,
        source: Optional[Address],
        ttl: int,
        *,
        administrative: bool = False,
    ) -> int:
        """
        Apply the admission policy to a registration from ``source``.

        Returns 0x0000 when the source now holds a live lease and a result code
        otherwise.  Every decision, accepted or rejected, is recorded in the
        audit trail with a reason and the lease deadline when one exists.

        Wire requests (``administrative=False``) are subject to the full
        policy.  The administrative API bypasses the network-facing gates
        (disabled registrations, source shape) but still validates the TTL.
        """
        if _debug:
            BIPBBMD._debug("process_register_foreign_device %r %r", source, ttl)

        now = self._fdt_time()
        self._purge_fdt(now)

        if not administrative:
            if not self.acceptFDRegistrations:
                self._audit_fdt(
                    "register",
                    source,
                    source,
                    False,
                    "registrations-disabled",
                    ttl=ttl,
                )
                return FDT_RESULT_REGISTRATION_NAK

            if not self._valid_fdt_source(source):
                self._audit_fdt(
                    "register", source, source, False, "invalid-source", ttl=ttl
                )
                return FDT_RESULT_REGISTRATION_NAK

        if not isinstance(ttl, int) or ttl <= 0:
            self._audit_fdt("register", source, source, False, "invalid-ttl", ttl=ttl)
            return FDT_RESULT_REGISTRATION_NAK

        fdte = self._find_fdt_entry(source)
        if fdte is None:
            # a new source may not displace a live lease; an expired row that
            # is only being retained for a possible renewal may be reclaimed
            if len(self.bbmdFDT) >= self.fdtCapacity:
                if self._reclaim_expired_fdt_entry(now) is None:
                    self._audit_fdt(
                        "register",
                        source,
                        source,
                        False,
                        "table-full",
                        ttl=ttl,
                    )
                    return FDT_RESULT_REGISTRATION_NAK

            fdte = FDTEntry()
            fdte.fdAddress = source
            fdte.fdRegisteredAt = now
            self.bbmdFDT.append(fdte)
            action = "register"
            reason = "new-registration"
        else:
            action = "renew"
            reason = "renewal"

        # a renewal replaces the lease but keeps the identity (the source
        # address); the new deadline starts now, not from the old deadline
        fdte.fdTTL = ttl
        fdte.fdDeadline = now + ttl
        fdte.fdRemovalDeadline = fdte.fdDeadline + self.fdtGracePeriod
        # the wire-visible "remaining time" counts down through the grace
        # period, as in Annex J, while forwarding stops at the TTL deadline
        fdte.fdRemain = ttl + self.fdtGracePeriod
        fdte.fdExpired = False
        fdte.fdRenewals = (fdte.fdRenewals or 0) + (
            0 if reason == "new-registration" else 1
        )

        self._audit_fdt(
            action,
            source,
            source,
            True,
            reason,
            ttl=ttl,
            deadline=fdte.fdDeadline,
            remaining=ttl,
        )

        # return success
        return FDT_RESULT_OK

    def delete_foreign_device_table_entry(self, addr: IPv4Address) -> int:
        """
        Administrative deletion, identified by ``addr``.

        Wire requests use ``process_delete_foreign_device`` so a request can
        only remove its own entry.
        """
        if _debug:
            BIPBBMD._debug("delete_foreign_device_table_entry %r", addr)

        return self.process_delete_foreign_device(addr, addr, administrative=True)

    def process_delete_foreign_device(
        self,
        source: Optional[Address],
        requested: Optional[Address],
        *,
        administrative: bool = False,
    ) -> int:
        """
        Apply the deletion policy to a request from ``source`` naming
        ``requested``.  A wire request may only remove its own entry; a named
        address that does not match the transport source is rejected and the
        table is left untouched.
        """
        if _debug:
            BIPBBMD._debug(
                "process_delete_foreign_device source=%r requested=%r",
                source,
                requested,
            )

        now = self._fdt_time()
        self._purge_fdt(now)

        if not administrative and not self._valid_fdt_source(source):
            self._audit_fdt("delete", source, requested, False, "invalid-source")
            return FDT_RESULT_DELETE_NAK

        if not administrative and requested is not None and source != requested:
            self._audit_fdt("delete", source, requested, False, "source-mismatch")
            return FDT_RESULT_DELETE_NAK

        fdte = self._find_fdt_entry(source)
        if fdte is None:
            self._audit_fdt("delete", source, requested, False, "entry-not-found")
            return FDT_RESULT_DELETE_NAK

        self.bbmdFDT.remove(fdte)
        self._audit_fdt(
            "delete",
            source,
            fdte.fdAddress,
            True,
            "deleted",
            ttl=fdte.fdTTL,
            deadline=fdte.fdDeadline,
            remaining=0,
        )

        # return success
        return FDT_RESULT_OK

    def _fdt_sweep(self, now: float) -> None:
        """Expire and purge FDT entries as of ``now``."""
        # look for foreign device registrations that have expired
        self._refresh_fdt_remaining(now)
        for fdte in self.bbmdFDT:
            if not fdte.fdExpired and not self._fdt_entry_is_live(fdte, now):
                self._expire_fdt_entry(fdte, now)

        # remove entries whose grace period has elapsed
        self._purge_fdt(now)

    def fdt_clock(self) -> None:
        loop_now = asyncio.get_event_loop().time()
        if loop_now > self._fdt_tick_time:
            # the real (or virtual) clock moved on; never move backwards, even
            # if the lease clock was advanced explicitly ahead of the loop
            self._fdt_now = max(loop_now, self._fdt_now)
        else:
            # a manual tick with no clock movement counts as one second
            self._fdt_now += 1
        self._fdt_tick_time = loop_now

        self._fdt_sweep(self._fdt_now)

        # again, again!
        self._fdt_clock_handle = asyncio.get_event_loop().call_later(1, self.fdt_clock)

    def add_peer(self, addr: IPv4Address) -> None:
        if _debug:
            BIPBBMD._debug("add_peer %r", addr)

        # see if it's already there
        for bdte in self.bbmdBDT:
            if addr == bdte:
                break
        else:
            self.bbmdBDT.append(addr)

    def delete_peer(self, addr: IPv4Address) -> None:
        if _debug:
            BIPBBMD._debug("delete_peer %r", addr)

        # look for the peer address
        for i in range(len(self.bbmdBDT) - 1, -1, -1):
            if addr == self.bbmdBDT[i]:
                del self.bbmdBDT[i]
                break
        else:
            pass


#
#   BIPNAT
#


@bacpypes_debugging
class BIPNAT(BVLLServiceAccessPoint, DebugContents):
    _debug: Callable[..., None]
    _warning: Callable[..., None]
    _debug_contents = ("bbmdAddress", "bbmdBDT+", "bbmdFDT+")

    bbmdAddress: IPv4Address
    bbmdBDT: List[IPv4Address]
    bbmdFDT: List[FDTEntry]

    def __init__(self, addr, **kwargs):
        """A BBMD node that is the destination for NATed traffic."""
        if _debug:
            BIPNAT._debug("__init__ %r", addr)
        BVLLServiceAccessPoint.__init__(self, **kwargs)

        raise NotImplementedError()

        # RecurringTask.__init__(self, 1000.0)

        self.bbmdAddress = addr
        self.bbmdBDT = []
        self.bbmdFDT = []

        # install so process_task runs
        self.install_task()

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPNAT._debug("indication %r", pdu)
        assert isinstance(pdu.pduDestination, Address)

        lpdu: LPDU

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            ###TODO the destination should be a peer or a registered foreign device

            # make an original unicast PDU
            lpdu = OriginalUnicastNPDU(
                pdu, destination=pdu.pduDestination, user_data=pdu.pduUserData
            )
            if _debug:
                BIPNAT._debug("    - lpdu: %r", lpdu)

            # send it downstream
            await self.request(lpdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # make a forwarded PDU
            lpdu = ForwardedNPDU(self.bbmdAddress, pdu, user_data=pdu.pduUserData)
            if _debug:
                BIPNAT._debug("    - forwarded lpdu: %r", lpdu)

            # send it to the peers, all of them have all F's mask
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    lpdu.pduDestination = Address(bdte.addrTuple)
                    if _debug:
                        BIPNAT._debug(
                            "        - sending to peer: %r", lpdu.pduDestination
                        )
                    self.request(lpdu)

            # send it to the registered foreign devices
            for fdte in self.bbmdFDT:
                lpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPNAT._debug(
                        "        - sending to foreign device: %r", lpdu.pduDestination
                    )
                self.request(lpdu)

        else:
            BIPNAT._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPNAT._debug("confirmation %r", lpdu)

        xpdu: LPDU

        # some kind of response to a request
        if isinstance(lpdu, Result):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, WriteBroadcastDistributionTable):
            ###TODO verify this is from a management network/address

            # build a response
            xpdu = Result(code=99, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTable):
            ###TODO verify this is from a management network/address

            # build a response
            xpdu = ReadBroadcastDistributionTableAck(
                self.bbmdBDT, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource
            if _debug:
                BIPNAT._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadBroadcastDistributionTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ForwardedNPDU):
            ###TODO verify this is from a peer

            # build a PDU with the source from the real source
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciAddress,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNAT._debug("    - upstream pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

            # build a forwarded NPDU to send out
            xpdu = ForwardedNPDU(
                lpdu.bvlciAddress, lpdu, destination=None, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPNAT._debug("    - forwarded xpdu: %r", xpdu)

            # send it to the registered foreign devices
            for fdte in self.bbmdFDT:
                xpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPNAT._debug(
                        "        - sending to foreign device: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            ###TODO verify this is from an acceptable address

            # process the request
            stat = self.register_foreign_device(lpdu.pduSource, lpdu.bvlciTimeToLive)

            # build a response
            xpdu = Result(
                code=stat, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPNAT._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadForeignDeviceTable):
            ###TODO verify this is from a management network/address

            # build a response
            xpdu = ReadForeignDeviceTableAck(
                self.bbmdFDT, destination=lpdu.pduSource, user_data=lpdu.pduUserData
            )
            if _debug:
                BIPNAT._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ReadForeignDeviceTableAck):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            ###TODO verify this is from a management network/address

            # process the request
            stat = self.delete_foreign_device_table_entry(lpdu.bvlciAddress)

            # build a response
            xpdu = Result(code=stat, user_data=lpdu.pduUserData)
            xpdu.pduDestination = lpdu.pduSource
            if _debug:
                BIPNAT._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            ###TODO verify this is from a registered foreign device

            # build a PDU with a local broadcast address
            pdu = PDU(
                pdu.pduData,
                source=pdu.pduSource,
                destination=LocalBroadcast(),
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPNAT._debug("    - upstream pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

            # build a forwarded NPDU to send out
            xpdu = ForwardedNPDU(lpdu.pduSource, lpdu, user_data=lpdu.pduUserData)
            if _debug:
                BIPNAT._debug("    - forwarded xpdu: %r", xpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte == self.bbmdAddress:
                    if _debug:
                        BIPNAT._debug("        - no local broadcast")
                else:
                    xpdu.pduDestination = Address(bdte.addrTuple)
                    if _debug:
                        BIPNAT._debug(
                            "        - sending to peer: %r", xpdu.pduDestination
                        )
                    await self.request(xpdu)

            # send it to the other registered foreign devices
            for fdte in self.bbmdFDT:
                if fdte.fdAddress != pdu.pduSource:
                    xpdu.pduDestination = fdte.fdAddress
                    if _debug:
                        BIPNAT._debug(
                            "        - sending to foreign device: %r",
                            xpdu.pduDestination,
                        )
                    await self.request(xpdu)

        elif isinstance(lpdu, OriginalUnicastNPDU):
            ###TODO verify this is from a peer

            # build a vanilla PDU
            pdu = PDU(
                pdu.pduData,
                source=pdu.pduSource,
                destination=pdu.pduDestination,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPNAT._debug("    - upstream pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            if _debug:
                BIPNAT._debug("    - original broadcast dropped")

        else:
            BIPNAT._warning("invalid pdu type: %s", type(lpdu))

    def register_foreign_device(self, addr, ttl):
        """Add a foreign device to the FDT."""
        if _debug:
            BIPNAT._debug("register_foreign_device %r %r", addr, ttl)

        # see if it is an address or make it one
        if isinstance(addr, Address):
            pass
        elif isinstance(addr, str):
            addr = Address(addr)
        else:
            raise TypeError("addr must be a string or an Address")

        for fdte in self.bbmdFDT:
            if addr == fdte.fdAddress:
                break
        else:
            fdte = FDTEntry()
            fdte.fdAddress = addr
            self.bbmdFDT.append(fdte)

        fdte.fdTTL = ttl
        fdte.fdRemain = ttl + 5

        # return success
        return 0

    def delete_foreign_device_table_entry(self, addr):
        if _debug:
            BIPNAT._debug("delete_foreign_device_table_entry %r", addr)

        # see if it is an address or make it one
        if isinstance(addr, Address):
            pass
        elif isinstance(addr, str):
            addr = Address(addr)
        else:
            raise TypeError("addr must be a string or an Address")

        # find it and delete it
        stat = 0
        for i in range(len(self.bbmdFDT) - 1, -1, -1):
            if addr == self.bbmdFDT[i].fdAddress:
                del self.bbmdFDT[i]
                break
        else:
            stat = 99  ### entry not found

        # return status
        return stat

    def process_task(self):
        # look for foreign device registrations that have expired
        for i in range(len(self.bbmdFDT) - 1, -1, -1):
            fdte = self.bbmdFDT[i]
            fdte.fdRemain -= 1

            # delete it if it expired
            if fdte.fdRemain <= 0:
                if _debug:
                    BIPNAT._debug("foreign device expired: %r", fdte.fdAddress)
                del self.bbmdFDT[i]

    def add_peer(self, addr):
        if _debug:
            BIPNAT._debug("add_peer %r", addr)

        # see if it is an address or make it one
        if isinstance(addr, Address):
            pass
        elif isinstance(addr, str):
            addr = Address(addr)
        else:
            raise TypeError("addr must be a string or an Address")

        # if it's this BBMD, make it the first one
        if self.bbmdBDT and (addr == self.bbmdAddress):
            raise RuntimeError("add self to BDT as first address")

        # see if it's already there
        for bdte in self.bbmdBDT:
            if addr == bdte:
                break
        else:
            self.bbmdBDT.append(addr)

    def delete_peer(self, addr):
        if _debug:
            BIPNAT._debug("delete_peer %r", addr)

        # see if it is an address or make it one
        if isinstance(addr, Address):
            pass
        elif isinstance(addr, str):
            addr = Address(addr)
        else:
            raise TypeError("addr must be a string or an Address")

        # look for the peer address
        for i in range(len(self.bbmdBDT) - 1, -1, -1):
            if addr == self.bbmdBDT[i]:
                del self.bbmdBDT[i]
                break
        else:
            pass


#
#   BVLLServiceElement
#


@bacpypes_debugging
class BVLLServiceElement(ApplicationServiceElement):
    _debug: Callable[..., None]
    _warning: Callable[..., None]

    def __init__(self, *, aseID=None) -> None:
        if _debug:
            BVLLServiceElement._debug("__init__ aseID=%r", aseID)
        ApplicationServiceElement.__init__(self, aseID=aseID)

        self.read_bdt_future = None
        self.read_bdt_timeout_handle = None
        self.read_bdt_address = None
        self.read_fdt_future = None
        self.read_fdt_timeout_handle = None
        self.read_fdt_address = None
        self.write_bdt_future = None
        self.write_bdt_timeout_handle = None
        self.write_bdt_address = None

    async def indication(self, lpdu: LPDU) -> None:
        if _debug:
            BVLLServiceElement._debug("indication %r", lpdu)

        # redirect
        fn = lpdu.__class__.__name__
        if hasattr(self, fn):
            await getattr(self, fn)(lpdu)
        else:
            BVLLServiceElement._warning("no handler for %s", fn)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BVLLServiceElement._debug("confirmation %r", lpdu)

        # redirect
        fn = lpdu.__class__.__name__
        if hasattr(self, fn):
            await getattr(self, fn)(lpdu)
        else:
            BVLLServiceElement._warning("no handler for %s", fn)

    def _clear_request(self, kind: str, future: asyncio.Future) -> None:
        # An old callback must not clear a new request.
        if getattr(self, kind + "_future") is not future:
            return
        handle = getattr(self, kind + "_timeout_handle")
        if handle is not None:
            handle.cancel()
        setattr(self, kind + "_future", None)
        setattr(self, kind + "_timeout_handle", None)
        setattr(self, kind + "_address", None)

    async def Result(self, pdu: Result) -> None:
        if _debug:
            BVLLServiceElement._debug("Result %r", pdu)

        if pdu.bvlciResultCode == 0x0020:
            kind = "read_bdt"
        elif pdu.bvlciResultCode == 0x0040:
            kind = "read_fdt"
        elif pdu.bvlciResultCode in (0x0000, 0x0010):
            kind = "write_bdt"
        else:
            return

        future = getattr(self, kind + "_future")
        if (
            future is None
            or future.done()
            or pdu.pduSource != getattr(self, kind + "_address")
        ):
            return
        future.set_exception(pdu)
        self._clear_request(kind, future)

    def read_broadcast_distribution_table(
        self, address: IPv4Address, timeout: float = READ_BDT_TIMEOUT
    ) -> asyncio.Future:
        """
        Read the broadcast distribution table from a BBMD, returns a list of
        IPv4Address's (check the mask!) or None if there is no response.
        """
        if _debug:
            BVLLServiceElement._debug(
                "read_broadcast_distribution_table %r %r", address, timeout
            )

        # one at a time please
        if self.read_bdt_future is not None:
            if not self.read_bdt_future.done():
                raise RuntimeError("request pending")
            self._clear_request("read_bdt", self.read_bdt_future)

        self.read_bdt_future = asyncio.Future()
        self.read_bdt_address = address
        self.read_bdt_future.add_done_callback(
            lambda future: self._clear_request("read_bdt", future)
        )
        if _debug:
            BVLLServiceElement._debug("    - read_bdt_future: %r", self.read_bdt_future)

        # get the loop to schedule a time to stop looking
        loop = asyncio.get_event_loop()
        if _debug:
            BVLLServiceElement._debug("    - loop time: %r", loop.time())

        # schedule a timeout
        self.read_bdt_timeout_handle = loop.call_later(
            timeout, self._read_bdt_timeout, self.read_bdt_future
        )
        if _debug:
            BVLLServiceElement._debug(
                "    - read_bdt_timeout_handle: %r", self.read_bdt_timeout_handle
            )

        asyncio.ensure_future(
            self.request(ReadBroadcastDistributionTable(destination=address))
        )

        return self.read_bdt_future

    def _read_bdt_timeout(self, future: asyncio.Future):
        if _debug:
            BVLLServiceElement._debug("_read_bdt_timeout")
        if self.read_bdt_future is future and not future.done():
            future.set_result(None)
        self._clear_request("read_bdt", future)

    async def ReadBroadcastDistributionTableAck(
        self, pdu: ReadBroadcastDistributionTableAck
    ) -> None:
        if _debug:
            BVLLServiceElement._debug("confirmation %r", pdu)

        future = self.read_bdt_future
        if future is None or future.done() or pdu.pduSource != self.read_bdt_address:
            return
        future.set_result(pdu.bvlciBDT)
        self._clear_request("read_bdt", future)

    def write_broadcast_distribution_table(
        self,
        address: IPv4Address,
        bdt: List[IPv4Address],
        timeout: float = WRITE_BDT_TIMEOUT,
    ) -> asyncio.Future:
        """
        Read the broadcast distribution table from a BBMD, returns a list of
        IPv4Address's (check the mask!) or None if there is no response.
        """
        if _debug:
            BVLLServiceElement._debug(
                "write_broadcast_distribution_table %r %r", address, timeout
            )

        # one at a time please
        if self.write_bdt_future is not None:
            if not self.write_bdt_future.done():
                raise RuntimeError("request pending")
            self._clear_request("write_bdt", self.write_bdt_future)

        self.write_bdt_future = asyncio.Future()
        self.write_bdt_address = address
        self.write_bdt_future.add_done_callback(
            lambda future: self._clear_request("write_bdt", future)
        )
        if _debug:
            BVLLServiceElement._debug(
                "    - write_bdt_future: %r", self.write_bdt_future
            )

        # get the loop to schedule a time to stop looking
        loop = asyncio.get_event_loop()
        if _debug:
            BVLLServiceElement._debug("    - loop time: %r", loop.time())

        # schedule a timeout
        self.write_bdt_timeout_handle = loop.call_later(
            timeout, self._write_bdt_timeout, self.write_bdt_future
        )
        if _debug:
            BVLLServiceElement._debug(
                "    - write_bdt_timeout_handle: %r", self.write_bdt_timeout_handle
            )

        asyncio.ensure_future(
            self.request(WriteBroadcastDistributionTable(bdt, destination=address))
        )

        return self.write_bdt_future

    def _write_bdt_timeout(self, future: asyncio.Future):
        if _debug:
            BVLLServiceElement._debug("_write_bdt_timeout")
        if self.write_bdt_future is future and not future.done():
            future.set_result(None)
        self._clear_request("write_bdt", future)

    def read_foreign_device_table(
        self, address: IPv4Address, timeout: float = READ_FDT_TIMEOUT
    ) -> asyncio.Future:
        """
        Read the foreign device table from a BBMD, returns a list of FDTEntry's
        or None if there is no response.
        """
        if _debug:
            BVLLServiceElement._debug(
                "read_foreign_device_table %r %r", address, timeout
            )

        # one at a time please
        if self.read_fdt_future is not None:
            if not self.read_fdt_future.done():
                raise RuntimeError("request pending")
            self._clear_request("read_fdt", self.read_fdt_future)

        self.read_fdt_future = asyncio.Future()
        self.read_fdt_address = address
        self.read_fdt_future.add_done_callback(
            lambda future: self._clear_request("read_fdt", future)
        )
        if _debug:
            BVLLServiceElement._debug("    - read_bdt_future: %r", self.read_bdt_future)

        # get the loop to schedule a time to stop looking
        loop = asyncio.get_event_loop()
        if _debug:
            BVLLServiceElement._debug("    - loop time: %r", loop.time())

        # schedule a timeout
        self.read_fdt_timeout_handle = loop.call_later(
            timeout, self._read_fdt_timeout, self.read_fdt_future
        )
        if _debug:
            BVLLServiceElement._debug(
                "    - read_fdt_timeout_handle: %r", self.read_fdt_timeout_handle
            )

        asyncio.ensure_future(self.request(ReadForeignDeviceTable(destination=address)))

        return self.read_fdt_future

    def _read_fdt_timeout(self, future: asyncio.Future):
        if _debug:
            BVLLServiceElement._debug("_read_fdt_timeout")
        if self.read_fdt_future is future and not future.done():
            future.set_result(None)
        self._clear_request("read_fdt", future)

    async def ReadForeignDeviceTableAck(self, pdu: ReadForeignDeviceTableAck) -> None:
        if _debug:
            BVLLServiceElement._debug("confirmation %r", pdu)

        future = self.read_fdt_future
        if future is None or future.done() or pdu.pduSource != self.read_fdt_address:
            return
        future.set_result(pdu.bvlciFDT)
        self._clear_request("read_fdt", future)
