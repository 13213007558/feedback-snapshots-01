"""
BACnet IPv6 Virtual Link Layer Service
"""

from __future__ import annotations

import asyncio
import enum
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Union

from ..debugging import ModuleLogger, DebugContents, bacpypes_debugging

from ..comm import Client, Server, ServiceAccessPoint, ApplicationServiceElement
from ..pdu import Address, LocalBroadcast, IPv6Address, VirtualAddress, PDU

from .bvll import (
    LPDU,
    FDTEntry,
    Result,
    OriginalUnicastNPDU,
    OriginalBroadcastNPDU,
    AddressResolution,
    ForwardedAddressResolution,
    AddressResolutionACK,
    VirtualAddressResolution,
    VirtualAddressResolutionACK,
    ForwardedNPDU,
    RegisterForeignDevice,
    DeleteForeignDeviceTableEntry,
    DistributeBroadcastToNetwork,
)

if TYPE_CHECKING:
    # class is declared as generic in stubs but not at runtime
    IPv6AddressFuture = asyncio.Future[IPv6Address]
    VirtualAddressFuture = asyncio.Future[VirtualAddress]
else:
    IPv6AddressFuture = asyncio.Future
    VirtualAddressFuture = asyncio.Future


# some debugging
_debug = 0
_log = ModuleLogger(globals())

#
#   VMAC admission policy
#


class VMACConflictError(RuntimeError):
    """
    Raised when two different IPv6 addresses claim the same virtual MAC
    address and the conflict has not been resolved by a fresh, on-link
    confirmation.  The stack never picks a winner on its own.
    """

    def __init__(
        self,
        vmac: VirtualAddress,
        incumbent: IPv6Address,
        challenger: IPv6Address,
    ) -> None:
        self.vmac = vmac
        self.incumbent = incumbent
        self.challenger = challenger
        super().__init__(
            f"VMAC {vmac!r} conflict: incumbent {incumbent!r} vs challenger"
            f" {challenger!r}"
        )


class MappingSource(enum.Enum):
    """
    How a VMAC -> IPv6 binding was learned, ordered by evidential weight.

    query_response
        An Address-Resolution-ACK received while a local resolution for the
        VMAC was outstanding — a direct answer to our own query.
    proactive_advertisement
        An Original-Unicast/Broadcast-NPDU or a Forwarded-NPDU that carries
        a source binding nobody asked for.
    existing_update
        Another observation of a binding that was already installed; used to
        refresh its validity period.
    """

    query_response = "query_response"
    proactive_advertisement = "proactive_advertisement"
    existing_update = "existing_update"


class AdmissionResult(enum.Enum):
    """Outcome of running the admission policy on a claimed binding."""

    admitted = "admitted"
    refreshed = "refreshed"
    migration = "migration"
    conflict = "conflict"


# default validity period for an installed binding, in seconds; repeated
# observations of the same binding refresh the deadline
DEFAULT_VMAC_TTL = 300.0

# how long the service element collects answers to one resolution query
# before deciding whether the answers agree
RESOLUTION_GUARD_TIME = 0.25

# how long a foreign device waits for an in-progress registration answer
REGISTRATION_TIMEOUT = 5.0


@dataclass
class VMACMappingRecord:
    """
    One side of a VMAC <-> IPv6 binding with everything needed to audit why
    the local stack believes it.
    """

    vmac: VirtualAddress
    ipv6: IPv6Address
    source: MappingSource
    accepted_basis: str
    observed_source: Optional[IPv6Address]
    ttl: float
    expires_at: float
    candidate: Optional[IPv6Address] = None
    candidate_basis: Optional[str] = None
    candidate_observed_source: Optional[IPv6Address] = None
    candidate_expires_at: float = 0.0

    def is_expired(self, now: Optional[float] = None) -> bool:
        if now is None:
            now = time.monotonic()
        return now >= self.expires_at

    def debug_contents(
        self,
        indent: int = 1,
        file=None,
        _ids: Optional[List[object]] = None,
    ) -> None:
        print(f"{'    ' * indent}{self!r}", file=file)


#
#   VirtualMACAddressTable
#


class VirtualMACAddressTable(DebugContents):
    """
    The Virtual MAC Address Table is used to provide source and destination
    information to the upper layers of the application because the 18-octet
    IPv6 addresses are too large for most BACnet applications that expect
    at most 6-octet Ethernet or IPv4 addresses.

    See Clause U.5.

    Every binding is admitted through :meth:`admit` which applies a
    conflict-visible policy: a claim that disagrees with the installed
    binding never silently overwrites it.  Query responses, proactive
    advertisements and refreshes of an existing mapping are kept apart via
    the :class:`MappingSource` on the stored record, together with the
    observed source of the claim, its validity period and the local reason
    the binding was accepted.
    """

    _debug: Callable[..., None]
    _debug_contents = ("vmac_to_ipv6+", "ipv6_to_vmac+")

    vmac_to_ipv6: Dict[VirtualAddress, VMACMappingRecord]
    ipv6_to_vmac: Dict[IPv6Address, VMACMappingRecord]

    def __init__(
        self,
        default_ttl: float = DEFAULT_VMAC_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if default_ttl <= 0:
            raise ValueError("default_ttl must be greater than zero")
        self.default_ttl = default_ttl
        self.clock = clock
        self.vmac_to_ipv6 = {}
        self.ipv6_to_vmac = {}

    def __getitem__(
        self, item: Union[VirtualAddress, IPv6Address]
    ) -> Union[VirtualAddress, IPv6Address, None]:
        now = self.clock()
        if isinstance(item, VirtualAddress):
            record = self.vmac_to_ipv6.get(item, None)
            if record is None:
                return None
            if record.is_expired(now):
                self._remove_record(record)
                return None
            return record.ipv6
        elif isinstance(item, IPv6Address):
            record = self.ipv6_to_vmac.get(item, None)
            if record is None:
                return None
            if record.is_expired(now):
                self._remove_record(record)
                return None
            return record.vmac
        else:
            raise TypeError(f"item: {item!r}")

    def get_record(self, vmac: VirtualAddress) -> Optional[VMACMappingRecord]:
        """Return the full audit record for a VMAC, or None."""
        record = self.vmac_to_ipv6.get(vmac, None)
        if record is None:
            return None
        if record.is_expired(self.clock()):
            self._remove_record(record)
            return None
        return record

    def admit(
        self,
        vmac: VirtualAddress,
        ipv6: IPv6Address,
        source: MappingSource,
        *,
        observed_source: Optional[IPv6Address] = None,
        ttl: Optional[float] = None,
        basis: Optional[str] = None,
        now: Optional[float] = None,
    ) -> AdmissionResult:
        """
        Run the admission policy for a claim that ``vmac`` lives at ``ipv6``.

        Returns the :class:`AdmissionResult`; conflicting claims return
        :attr:`AdmissionResult.conflict` and leave the incumbent binding in
        place, with the challenger parked on the record as a candidate
        instead of overwriting it.
        """
        if _debug:
            VirtualMACAddressTable._debug(
                "admit %r %r %r observed=%r ttl=%r",
                vmac,
                ipv6,
                source,
                observed_source,
                ttl,
            )

        if not isinstance(vmac, VirtualAddress):
            raise TypeError("vmac must be a VirtualAddress")
        if not isinstance(ipv6, IPv6Address):
            raise TypeError("ipv6 must be an IPv6Address")
        if now is None:
            now = self.clock()
        if ttl is None:
            ttl = self.default_ttl
        if ttl <= 0:
            raise ValueError("ttl must be greater than zero")
        if basis is None:
            basis = source.value

        record = self.vmac_to_ipv6.get(vmac, None)
        if (record is not None) and record.is_expired(now):
            self._remove_record(record)
            record = None

        # brand new binding
        if record is None:
            # an IPv6 address cannot back two different VMACs at once
            other = self.ipv6_to_vmac.get(ipv6, None)
            if other is not None:
                if other.is_expired(now):
                    self._remove_record(other)
                else:
                    raise VMACConflictError(other.vmac, other.ipv6, ipv6)

            record = VMACMappingRecord(
                vmac=vmac,
                ipv6=ipv6,
                source=source,
                accepted_basis=basis,
                observed_source=observed_source,
                ttl=ttl,
                expires_at=now + ttl,
            )
            self.vmac_to_ipv6[vmac] = record
            self.ipv6_to_vmac[ipv6] = record
            return AdmissionResult.admitted

        # another observation of the same binding: refresh it
        if isinstance(record.ipv6, IPv6Address) and record.ipv6 == ipv6:
            record.source = source
            record.accepted_basis = basis
            record.observed_source = observed_source
            record.ttl = ttl
            record.expires_at = now + ttl
            # an observation from the incumbent address clears any dispute
            record.candidate = None
            record.candidate_basis = None
            record.candidate_observed_source = None
            record.candidate_expires_at = 0.0
            return AdmissionResult.refreshed

        # a different IPv6 claims this VMAC: never overwrite silently
        if isinstance(record.candidate, IPv6Address) and record.candidate == ipv6:
            # repeat challenger: keep the dispute alive and refreshed
            record.candidate_basis = basis
            record.candidate_observed_source = observed_source
            record.candidate_expires_at = now + ttl
        else:
            record.candidate = ipv6
            record.candidate_basis = basis
            record.candidate_observed_source = observed_source
            record.candidate_expires_at = now + ttl
        return AdmissionResult.conflict

    def confirm_migration(
        self,
        vmac: VirtualAddress,
        ipv6: IPv6Address,
        *,
        observed_source: Optional[IPv6Address] = None,
        ttl: Optional[float] = None,
        basis: str = "confirmed query response after migration",
        now: Optional[float] = None,
    ) -> AdmissionResult:
        """
        Commit a migration that a fresh on-link query response has
        corroborated.  Only the parked candidate can move the binding, so a
        single stray answer can never hijack traffic.
        """
        if _debug:
            VirtualMACAddressTable._debug("confirm_migration %r %r", vmac, ipv6)

        record = self.vmac_to_ipv6.get(vmac, None)
        if record is None:
            return self.admit(
                vmac,
                ipv6,
                MappingSource.query_response,
                observed_source=observed_source,
                ttl=ttl,
                basis=basis,
                now=now,
            )
        if now is None:
            now = self.clock()
        if ttl is None:
            ttl = self.default_ttl

        if isinstance(record.ipv6, IPv6Address) and record.ipv6 == ipv6:
            return self.admit(
                vmac,
                ipv6,
                MappingSource.query_response,
                observed_source=observed_source,
                ttl=ttl,
                basis=basis,
                now=now,
            )
        if not (isinstance(record.candidate, IPv6Address) and record.candidate == ipv6):
            return AdmissionResult.conflict
        if record.is_expired(now):
            return AdmissionResult.conflict

        old_ipv6 = record.ipv6
        del self.vmac_to_ipv6[vmac]
        del self.ipv6_to_vmac[old_ipv6]

        migrated = VMACMappingRecord(
            vmac=vmac,
            ipv6=ipv6,
            source=MappingSource.query_response,
            accepted_basis=basis,
            observed_source=observed_source,
            ttl=ttl,
            expires_at=now + ttl,
        )
        self.vmac_to_ipv6[vmac] = migrated
        self.ipv6_to_vmac[ipv6] = migrated
        return AdmissionResult.migration

    def expire(self, now: Optional[float] = None) -> List[VirtualAddress]:
        """Purge every binding whose validity period has elapsed."""
        if now is None:
            now = self.clock()
        expired = [
            vmac
            for vmac, record in list(self.vmac_to_ipv6.items())
            if record.is_expired(now)
        ]
        for vmac in expired:
            self._remove_record(self.vmac_to_ipv6[vmac])
        return expired

    def _remove_record(self, record: VMACMappingRecord) -> None:
        self.vmac_to_ipv6.pop(record.vmac, None)
        self.ipv6_to_vmac.pop(record.ipv6, None)


#
#   BVLLServiceAccessPoint
#


@bacpypes_debugging
class BVLLServiceAccessPoint(Client[LPDU], Server[PDU], ServiceAccessPoint):
    """
    BACnet IPv6 Service Access Point

    An instance of this is stacked on a BVLLCodec, as a server it presents
    PDUs.
    """

    _debug_contents = ("virtual_address", "vmac_addr_table")

    virtual_address: VirtualAddress  # see Clause H.7.2
    vmac_addr_table: VirtualMACAddressTable

    def __init__(
        self,
        *,
        virtual_address: VirtualAddress,
        sapID: Optional[str] = None,
        cid: Optional[str] = None,
        sid: Optional[str] = None,
        vmac_ttl: float = DEFAULT_VMAC_TTL,
        vmac_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if _debug:
            BVLLServiceAccessPoint._debug("__init__")
        Client.__init__(self, cid=cid)
        Server.__init__(self, sid=sid)
        ServiceAccessPoint.__init__(self, sapID=sapID)

        self.virtual_address = virtual_address
        self.vmac_addr_table = VirtualMACAddressTable(
            default_ttl=vmac_ttl, clock=vmac_clock
        )

    def _admit_observed_binding(
        self,
        vmac: VirtualAddress,
        ipv6: IPv6Address,
        source: MappingSource,
        basis: str,
        observed_source: Optional[IPv6Address],
    ) -> AdmissionResult:
        """
        Feed a binding learned from inbound traffic through the conflict
        admission policy.  Conflicts are logged and made visible instead of
        silently redirecting traffic.
        """
        result = self.vmac_addr_table.admit(
            vmac,
            ipv6,
            source,
            observed_source=observed_source,
            basis=basis,
        )
        if result is AdmissionResult.conflict:
            BVLLServiceAccessPoint._warning(
                "VMAC conflict for %r: incumbent %r, challenger %r (%s)",
                vmac,
                self.vmac_addr_table.get_record(vmac).ipv6,
                self.vmac_addr_table.get_record(vmac).candidate,
                basis,
            )
        return result

    def _admit_forwarded_binding(
        self,
        vmac: VirtualAddress,
        claimed_ipv6: IPv6Address,
        observer: IPv6Address,
        basis: str,
    ) -> AdmissionResult:
        """
        Admit a binding carried inside a forwarded message.  The observed
        source of the frame (the BBMD/peer that forwarded it) is recorded
        separately from the IPv6 address the originator claimed for itself.
        """
        return self._admit_observed_binding(
            vmac,
            claimed_ipv6,
            MappingSource.proactive_advertisement,
            basis,
            observer,
        )

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
class BIPNormal(BVLLServiceAccessPoint, DebugContents):
    _debug: Callable[..., None]
    _warning: Callable[..., None]

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPNormal._debug("indication %r", pdu)

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # destination address is a VirtualAddress
            record = self.vmac_addr_table.get_record(pdu.pduDestination)
            destination_ipv6_address: Optional[IPv6Address] = (
                record.ipv6 if record is not None else None
            )

            # if there is a service element, let it resolve it; a disputed
            # binding must be re-confirmed rather than trusted blindly
            if (not destination_ipv6_address) or (
                record is not None and record.candidate is not None
            ):
                try:
                    destination_ipv6_address = await asyncio.wait_for(
                        self.serviceElement.resolve_virtual_address(pdu.pduDestination),
                        timeout=5,
                    )
                except asyncio.TimeoutError:
                    return
                except VMACConflictError as err:
                    BIPNormal._warning("resolution failed, packet dropped: %s", err)
                    return
            if _debug:
                BIPNormal._debug(
                    "    - destination_ipv6_address: %r", destination_ipv6_address
                )

            # make an original unicast PDU
            xpdu = OriginalUnicastNPDU(
                self.virtual_address,
                pdu.pduDestination,
                pdu,
                destination=destination_ipv6_address,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # make an original broadcast PDU
            xpdu = OriginalBroadcastNPDU(
                self.virtual_address,
                pdu,
                destination=pdu.pduDestination,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        else:
            BIPNormal._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPNormal._debug("confirmation %r", lpdu)

        # some kind of response to a request
        if isinstance(lpdu, Result):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, OriginalUnicastNPDU):
            if lpdu.bvlciDestinationVirtualAddress != self.virtual_address:
                if _debug:
                    BIPNormal._debug("    - not for us")
                return

            # admit the source binding learned from this unicast
            self._admit_observed_binding(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.pduSource,
                MappingSource.proactive_advertisement,
                "Original-Unicast-NPDU source",
                lpdu.pduSource,
            )

            # build a PDU
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciSourceVirtualAddress,
                destination=self.virtual_address,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            if lpdu.bvlciSourceVirtualAddress == self.virtual_address:
                if _debug:
                    BIPNormal._debug("    - from us")
                return

            # admit the source binding learned from this broadcast
            self._admit_observed_binding(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.pduSource,
                MappingSource.proactive_advertisement,
                "Original-Broadcast-NPDU source",
                lpdu.pduSource,
            )

            # build a PDU with a local broadcast address
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciSourceVirtualAddress,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, AddressResolution):
            if lpdu.bvlciSourceVirtualAddress == self.virtual_address:
                if _debug:
                    BIPNormal._debug("    - from us")
                return
            if lpdu.bvlciTargetVirtualAddress != self.virtual_address:
                if _debug:
                    BIPNormal._debug("    - not for us")
                return

            xpdu = AddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciSourceVirtualAddress,
                destination=lpdu.pduSource,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ForwardedAddressResolution):
            if lpdu.bvlciTargetVirtualAddress != self.virtual_address:
                if _debug:
                    BIPNormal._debug("    - not for us")
                return

            xpdu = AddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciOriginalSourceVirtualAddress,
                destination=lpdu.bvlciOriginalSourceIPv6Address,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, AddressResolutionACK):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, VirtualAddressResolution):
            # send back an ACK
            xpdu = VirtualAddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciSourceVirtualAddress,
                destination=lpdu.pduSource,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPNormal._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, VirtualAddressResolutionACK):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ForwardedNPDU):
            # admit the binding carried in the forwarded frame, keeping the
            # actual frame source separate from the claimed origin address
            self._admit_forwarded_binding(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.bvlciSourceIPv6Address,
                lpdu.pduSource,
                "Forwarded-NPDU source",
            )

            # build a PDU with the source from the real source
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciSourceVirtualAddress,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            # if route_aware:
            #     xpdu.pduSource.addrRoute = pdu.pduSource

            if _debug:
                BIPNormal._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            # build a response
            xpdu = Result(
                self.virtual_address, result_code=0x0090, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            # build a response
            xpdu = Result(
                self.virtual_address, result_code=0x00A0, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # build a response
            xpdu = Result(
                self.virtual_address, result_code=0x00C0, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        else:
            BIPNormal._warning("invalid pdu type: %s", type(lpdu))


#
#   BIPForeign
#


@bacpypes_debugging
class BIPForeign(BVLLServiceAccessPoint, DebugContents):
    _debug: Callable[..., None]
    _warning: Callable[..., None]
    _debug_contents = ("bbmdAddress", "bbmdTimeToLive", "bbmdRegistrationStatus")

    bbmdAddress: Optional[IPv6Address]
    bbmdTimeToLive: Optional[int]
    bbmdRegistrationStatus: int

    _registration_event: asyncio.Event
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

    async def sap_indication(self, lpdu: LPDU) -> None:
        if _debug:
            BIPForeign._debug("sap_indication %r", lpdu)

        # check for local stations
        if lpdu.pduDestination.addrType == Address.localStationAddr:
            # send it downstream
            await self.request(lpdu)

        # check for broadcasts, redirect them to the BBMD
        elif lpdu.pduDestination.addrType == Address.localBroadcastAddr:
            # check the BBMD registration status, we may not be registered
            if self.bbmdRegistrationStatus != 0:
                if _debug:
                    BIPForeign._debug("    - packet dropped, unregistered")
                return

            # redirect it to the BBMD
            lpdu.pduDestination = self.bbmdAddress

            # send it downstream
            await self.request(lpdu)

        else:
            BIPForeign._warning("invalid destination address: %r", lpdu.pduDestination)

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPForeign._debug("indication %r", pdu)

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # destination address is a VirtualAddress
            record = self.vmac_addr_table.get_record(pdu.pduDestination)
            destination_ipv6_address: Optional[IPv6Address] = (
                record.ipv6 if record is not None else None
            )

            # if there is a service element, let it resolve it; a disputed
            # binding must be re-confirmed rather than trusted blindly
            if (not destination_ipv6_address) or (
                record is not None and record.candidate is not None
            ):
                try:
                    destination_ipv6_address = await asyncio.wait_for(
                        self.serviceElement.resolve_virtual_address(pdu.pduDestination),
                        timeout=5,
                    )
                except asyncio.TimeoutError:
                    return
                except VMACConflictError as err:
                    BIPForeign._warning("resolution failed, packet dropped: %s", err)
                    return
            if _debug:
                BIPNormal._debug(
                    "    - destination_ipv6_address: %r", destination_ipv6_address
                )

            # make an original unicast PDU
            xpdu = OriginalUnicastNPDU(
                self.virtual_address,
                pdu.pduDestination,
                pdu.pduData,
                destination=destination_ipv6_address,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

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
                    return  ###TODO raise TimeoutError?

            elif self.bbmdRegistrationStatus == 0:
                pass

            else:
                if _debug:
                    BIPForeign._debug(
                        "    - registration error: %r", self.bbmdRegistrationStatus
                    )
                return  ###TODO raise RuntimeError?

            # make a broadcast PDU
            xpdu = DistributeBroadcastToNetwork(
                self.virtual_address,
                pdu.pduData,
                destination=self.bbmdAddress,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        else:
            BIPForeign._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPForeign._debug("confirmation %r", lpdu)

        # some kind of response to a request
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
            self.bbmdRegistrationStatus = lpdu.bvlciResultCode

            # if successful, start tracking the registration
            if self.bbmdRegistrationStatus == 0:
                self._registration_event.set()
                self._start_tracking_registration()

        elif isinstance(lpdu, OriginalUnicastNPDU):
            if lpdu.bvlciDestinationVirtualAddress != self.virtual_address:
                if _debug:
                    BIPForeign._debug("    - not for us")
                return

            # admit the source binding learned from this unicast
            self._admit_observed_binding(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.pduSource,
                MappingSource.proactive_advertisement,
                "Original-Unicast-NPDU source",
                lpdu.pduSource,
            )

            # build a PDU
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciSourceVirtualAddress,
                destination=self.virtual_address,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            if _debug:
                BIPForeign._debug("    - packet dropped")

        elif isinstance(lpdu, AddressResolution):
            if lpdu.bvlciTargetVirtualAddress != self.virtual_address:
                if _debug:
                    BIPForeign._debug("    - not for us")
                return

            xpdu = AddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciSourceVirtualAddress,
                destination=lpdu.pduSource,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, ForwardedAddressResolution):
            if lpdu.bvlciTargetVirtualAddress != self.virtual_address:
                if _debug:
                    BIPForeign._debug("    - not for us")
                return

            xpdu = AddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciOriginalSourceVirtualAddress,
                destination=lpdu.bvlciOriginalSourceIPv6Address,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, AddressResolutionACK):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, VirtualAddressResolution):
            # send back an ACK
            xpdu = VirtualAddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciSourceVirtualAddress,
                destination=lpdu.pduSource,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, VirtualAddressResolutionACK):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ForwardedNPDU):
            # admit the binding carried in the forwarded frame, keeping the
            # BBMD's frame source separate from the claimed origin address
            self._admit_forwarded_binding(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.bvlciSourceIPv6Address,
                lpdu.pduSource,
                "Forwarded-NPDU via BBMD",
            )

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

            # build a PDU with the source from the source virtual address
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciSourceVirtualAddress,
                destination=LocalBroadcast(),
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPForeign._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            # build a response
            xpdu = Result(
                self.virtual_address, result_code=0x0090, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            # build a response
            xpdu = Result(
                self.virtual_address, result_code=0x00A0, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # build a response
            xpdu = Result(
                self.virtual_address, result_code=0x00C0, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        else:
            BIPForeign._warning("invalid pdu type: %s", type(lpdu))

    def register(self, addr: IPv6Address, ttl: int) -> None:
        """Start the foreign device registration process with the given BBMD.

        Registration will be renewed periodically according to the ttl value
        until explicitly stopped by a call to `unregister`.
        """
        if _debug:
            BIPForeign._debug("register %r %r", addr, ttl)

        # a little error checking
        if not isinstance(addr, IPv6Address):
            raise TypeError("addr must be an IPv6Address")
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

        # stop tracking the registration, and there might not be one
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
        pdu = RegisterForeignDevice(
            self.virtual_address, self.bbmdTimeToLive, destination=self.bbmdAddress
        )
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
            min(5, self.bbmdTimeToLive), self._start_registration
        )
        if _debug:
            BIPForeign._debug(
                "    - re-registration timeout: %r", self._reregistration_timeout_handle
            )

    async def _stop_registration(self, bbmdAddress: IPv6Address) -> None:
        """Scheduled when the registration is being canceled."""
        if _debug:
            BIPForeign._debug("_stop_registration")

        pdu = RegisterForeignDevice(self.virtual_address, 0, destination=bbmdAddress)

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
            BIPForeign._debug("    _stop_tracking_registration")

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


@bacpypes_debugging
class BIPBBMD(BVLLServiceAccessPoint, DebugContents):
    _debug: Callable[..., None]
    _warning: Callable[..., None]
    _debug_contents = ("bbmdAddress", "bbmdBDT+", "bbmdFDT++")

    bbmdAddress: IPv6Address
    bbmdBDT: List[IPv6Address]
    bbmdFDT: List[FDTEntry]

    _fdt_clock_handle: asyncio.TimerHandle

    def __init__(self, bbmd_address: IPv6Address, **kwargs):
        if _debug:
            BIPBBMD._debug("__init__ %r", bbmd_address)
        BVLLServiceAccessPoint.__init__(self, **kwargs)

        self.bbmdAddress = bbmd_address
        self.bbmdBDT = []
        self.bbmdFDT = []

        # schedule the clock to run
        self._fdt_clock_handle = asyncio.get_event_loop().call_soon(self.fdt_clock)

    async def sap_indication(self, lpdu: LPDU) -> None:
        if _debug:
            BIPBBMD._debug("sap_indication %r", lpdu)

        # check for local stations
        if lpdu.pduDestination.addrType == Address.localStationAddr:
            if _debug:
                BIPBBMD._debug("    - unicast")

            # send it downstream
            await self.request(lpdu)

        # check for broadcasts, redirect them to the BBMD
        elif lpdu.pduDestination.addrType == Address.localBroadcastAddr:
            # if route_aware and pdu.pduDestination.addrRoute:
            #     xpdu.pduDestination = pdu.pduDestination.addrRoute
            if _debug:
                BIPBBMD._debug("    - local broadcast")

            # send it downstream
            await self.request(lpdu)

            # skip other processing if the route was provided
            # if settings.route_aware and pdu.pduDestination.addrRoute:
            #     return
            if _debug:
                BIPBBMD._debug("    - forwarded lpdu: %r", lpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    lpdu.pduDestination = bdte
                    BIPBBMD._debug("    - sending to peer: %r", lpdu.pduDestination)
                    await self.request(lpdu)

            # send it to the registered foreign devices
            for fdte in self.bbmdFDT:
                lpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", lpdu.pduDestination
                    )
                await self.request(lpdu)

        else:
            BIPBBMD._warning("invalid destination address: %r", lpdu.pduDestination)

    async def indication(self, pdu: PDU) -> None:
        if _debug:
            BIPBBMD._debug("indication %r", pdu)

        # check for local stations
        if pdu.pduDestination.addrType == Address.localStationAddr:
            # destination address is a VirtualAddress
            record = self.vmac_addr_table.get_record(pdu.pduDestination)
            destination_ipv6_address: Optional[IPv6Address] = (
                record.ipv6 if record is not None else None
            )

            # if there is a service element, let it resolve it; a disputed
            # binding must be re-confirmed rather than trusted blindly
            if (not destination_ipv6_address) or (
                record is not None and record.candidate is not None
            ):
                try:
                    destination_ipv6_address = await asyncio.wait_for(
                        self.serviceElement.resolve_virtual_address(pdu.pduDestination),
                        timeout=5,
                    )
                except asyncio.TimeoutError:
                    return
                except VMACConflictError as err:
                    BIPBBMD._warning("resolution failed, packet dropped: %s", err)
                    return
            if _debug:
                BIPBBMD._debug(
                    "    - destination_ipv6_address: %r", destination_ipv6_address
                )

            # make an original unicast PDU
            xpdu = OriginalUnicastNPDU(
                self.virtual_address,
                pdu.pduDestination,
                pdu.pduData,
                destination=destination_ipv6_address,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - original unicast xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        # check for broadcasts
        elif pdu.pduDestination.addrType == Address.localBroadcastAddr:
            # make an original broadcast PDU
            xpdu = OriginalBroadcastNPDU(
                self.virtual_address,
                pdu.pduData,
                destination=pdu.pduDestination,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - original broadcast xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

            # skip other processing if the route was provided
            # if settings.route_aware and pdu.pduDestination.addrRoute:
            #     return

            xpdu = ForwardedNPDU(
                self.virtual_address,
                self.bbmdAddress,
                pdu.pduData,
                user_data=pdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    xpdu.pduDestination = bdte
                    BIPBBMD._debug("    - sending to peer: %r", xpdu.pduDestination)
                    await self.request(xpdu)

            # send it to the registered foreign devices
            for fdte in self.bbmdFDT:
                xpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

        else:
            BIPBBMD._warning("invalid destination address: %r", pdu.pduDestination)

    async def confirmation(self, lpdu: LPDU) -> None:
        if _debug:
            BIPBBMD._debug("confirmation %r", lpdu)

        # some kind of response to a request
        if isinstance(lpdu, Result):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, OriginalUnicastNPDU):
            if lpdu.bvlciDestinationVirtualAddress != self.virtual_address:
                if _debug:
                    BIPBBMD._debug("    - not for us")
                return

            # admit the source binding learned from this unicast
            self._admit_observed_binding(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.pduSource,
                MappingSource.proactive_advertisement,
                "Original-Unicast-NPDU source",
                lpdu.pduSource,
            )

            # build a PDU
            pdu = PDU(
                lpdu.pduData,
                source=lpdu.bvlciSourceVirtualAddress,
                destination=self.virtual_address,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - pdu: %r", pdu)

            # send it upstream
            await self.response(pdu)

        elif isinstance(lpdu, OriginalBroadcastNPDU):
            if lpdu.bvlciSourceVirtualAddress == self.virtual_address:
                if _debug:
                    BIPBBMD._debug("    - from us")
                return

            # send it upstream if there is a network layer
            if self.serverPeer:
                # admit the source binding learned from this broadcast
                self._admit_observed_binding(
                    lpdu.bvlciSourceVirtualAddress,
                    lpdu.pduSource,
                    MappingSource.proactive_advertisement,
                    "Original-Broadcast-NPDU source",
                    lpdu.pduSource,
                )

                # build a PDU with a local broadcast address
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.bvlciSourceVirtualAddress,
                    destination=LocalBroadcast(),
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - pdu: %r", pdu)

                # send it upstream
                await self.response(pdu)

            # make a forwarded PDU
            xpdu = ForwardedNPDU(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.pduSource,
                lpdu.pduData,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    xpdu.pduDestination = bdte
                    if _debug:
                        BIPBBMD._debug("    - sending to peer: %r", xpdu.pduDestination)
                    await self.request(xpdu)

            # send it to the registered foreign devices
            for fdte in self.bbmdFDT:
                xpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

        elif isinstance(lpdu, AddressResolution):
            if lpdu.bvlciTargetVirtualAddress == self.virtual_address:
                if _debug:
                    BIPBBMD._debug("    - looking for us")

                xpdu = AddressResolutionACK(
                    source_virtual_address=self.virtual_address,
                    destination_virtual_address=lpdu.bvlciSourceVirtualAddress,
                    destination=lpdu.pduSource,
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - xpdu: %r", xpdu)

                # send it downstream
                await self.request(xpdu)

            else:
                if _debug:
                    BIPBBMD._debug("    - looking for someone else")

                # make a forwarded address resolution
                xpdu = ForwardedAddressResolution(
                    lpdu.bvlciSourceVirtualAddress,
                    lpdu.bvlciTargetVirtualAddress,
                    lpdu.pduSource,
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - forwarded address resolution xpdu: %r", xpdu)

                # make a local broadcast
                xpdu.pduDestination = LocalBroadcast()
                if _debug:
                    BIPBBMD._debug(
                        "    - sending local broadcast: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

                # send it to the peers
                for bdte in self.bbmdBDT:
                    if bdte != self.bbmdAddress:
                        xpdu.pduDestination = bdte
                        if _debug:
                            BIPBBMD._debug(
                                "    - sending to peer: %r", xpdu.pduDestination
                            )
                        await self.request(xpdu)

                # send it to the registered foreign devices
                for fdte in self.bbmdFDT:
                    xpdu.pduDestination = fdte.fdAddress
                    if _debug:
                        BIPBBMD._debug(
                            "    - sending to foreign device: %r", xpdu.pduDestination
                        )
                    await self.request(xpdu)

        elif isinstance(lpdu, ForwardedAddressResolution):
            if lpdu.bvlciTargetVirtualAddress == self.virtual_address:
                if _debug:
                    BIPBBMD._debug("    - this is us")

                xpdu = AddressResolutionACK(
                    source_virtual_address=self.virtual_address,
                    destination_virtual_address=lpdu.bvlciOriginalSourceVirtualAddress,
                    destination=lpdu.bvlciOriginalSourceIPv6Address,
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - xpdu: %r", xpdu)

                # send it downstream
                await self.request(xpdu)

            else:
                # make sure it is from a peer
                for bdte in self.bbmdBDT:
                    if bdte == lpdu.pduSource:
                        break
                else:
                    if _debug:
                        BIPBBMD._debug("    - not from a peer")
                    return

                # make a local broadcast
                lpdu.pduDestination = LocalBroadcast()
                if _debug:
                    BIPBBMD._debug(
                        "    - sending local broadcast: %r", lpdu.pduDestination
                    )
                await self.request(lpdu)

                # send it to the registered foreign devices
                for fdte in self.bbmdFDT:
                    lpdu.pduDestination = fdte.fdAddress
                    if _debug:
                        BIPBBMD._debug(
                            "    - sending to foreign device: %r", lpdu.pduDestination
                        )
                    await self.request(lpdu)

        elif isinstance(lpdu, AddressResolutionACK):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, VirtualAddressResolution):
            # send back an ACK
            xpdu = VirtualAddressResolutionACK(
                source_virtual_address=self.virtual_address,
                destination_virtual_address=lpdu.bvlciSourceVirtualAddress,
                destination=lpdu.pduSource,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - xpdu: %r", xpdu)

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, VirtualAddressResolutionACK):
            # send this to the service access point
            await self.sap_response(lpdu)

        elif isinstance(lpdu, ForwardedNPDU):
            # make sure it is from a peer
            for bdte in self.bbmdBDT:
                if bdte == lpdu.pduSource:
                    break
            else:
                if _debug:
                    BIPBBMD._debug("    - not from a peer")
                return

            # send it upstream if there is a network layer
            if self.serverPeer:
                # admit the peer-forwarded binding, keeping the peer's frame
                # source separate from the claimed origin address
                self._admit_forwarded_binding(
                    lpdu.bvlciSourceVirtualAddress,
                    lpdu.bvlciSourceIPv6Address,
                    lpdu.pduSource,
                    "peer Forwarded-NPDU source",
                )

                # build a PDU with a local broadcast address
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.bvlciSourceVirtualAddress,
                    destination=LocalBroadcast(),
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPNormal._debug("    - pdu: %r", pdu)

                # send it upstream
                await self.response(pdu)

            # make a forwarded PDU
            xpdu = ForwardedNPDU(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.bvlciSourceIPv6Address,
                lpdu.pduData,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # broadcast it locally
            xpdu.pduDestination = LocalBroadcast()
            if _debug:
                BIPBBMD._debug("    - local broadcast")
            await self.request(xpdu)

            # send it to the registered foreign devices
            for fdte in self.bbmdFDT:
                xpdu.pduDestination = fdte.fdAddress
                if _debug:
                    BIPBBMD._debug(
                        "    - sending to foreign device: %r", xpdu.pduDestination
                    )
                await self.request(xpdu)

        elif isinstance(lpdu, RegisterForeignDevice):
            # process the request
            if lpdu.bvlciTimeToLive == 0:
                stat = self.delete_foreign_device_table_entry(lpdu.pduSource)
            else:
                stat = self.register_foreign_device(
                    lpdu.pduSource, lpdu.bvlciTimeToLive
                )

            # build a response
            xpdu = Result(
                self.virtual_address, result_code=stat, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DeleteForeignDeviceTableEntry):
            # process the request
            stat = self.delete_foreign_device_table_entry(lpdu.bvlciFDTEntry)

            # build a response
            xpdu = Result(
                self.virtual_address, result_code=stat, user_data=lpdu.pduUserData
            )
            xpdu.pduDestination = lpdu.pduSource

            # send it downstream
            await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # send it to the other registered foreign devices
            for fdte in self.bbmdFDT:
                if fdte.fdAddress == lpdu.pduSource:
                    break
            else:
                if _debug:
                    BIPBBMD._debug("    - not from a registered foreign device")
                await self.request(
                    Result(
                        self.virtual_address,
                        result_code=0x00C0,
                        destination=lpdu.pduSource,
                        user_data=lpdu.pduUserData,
                    )
                )
                return

            # send it upstream if there is a network layer
            if self.serverPeer:
                # admit the binding claimed by a registered foreign device
                self._admit_observed_binding(
                    lpdu.bvlciSourceVirtualAddress,
                    lpdu.pduSource,
                    MappingSource.proactive_advertisement,
                    "Distribute-Broadcast-to-Network source",
                    lpdu.pduSource,
                )

                # build a PDU with a local broadcast address
                pdu = PDU(
                    lpdu.pduData,
                    source=lpdu.bvlciSourceVirtualAddress,
                    destination=LocalBroadcast(),
                    user_data=lpdu.pduUserData,
                )
                if _debug:
                    BIPBBMD._debug("    - pdu: %r", pdu)

                # send it upstream
                await self.response(pdu)

            # make a forwarded PDU
            xpdu = ForwardedNPDU(
                lpdu.bvlciSourceVirtualAddress,
                lpdu.pduSource,
                lpdu.pduData,
                user_data=lpdu.pduUserData,
            )
            if _debug:
                BIPBBMD._debug("    - forwarded xpdu: %r", xpdu)

            # broadcast it locally
            xpdu.pduDestination = LocalBroadcast()
            if _debug:
                BIPBBMD._debug("    - local broadcast")
            await self.request(xpdu)

            # send it to the peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    xpdu.pduDestination = bdte
                    if _debug:
                        BIPBBMD._debug("    - sending to peer: %r", xpdu.pduDestination)
                    await self.request(xpdu)

            # send it to the other registered foreign devices
            for fdte in self.bbmdFDT:
                if fdte.fdAddress != lpdu.pduSource:
                    xpdu.pduDestination = fdte.fdAddress
                    if _debug:
                        BIPBBMD._debug(
                            "    - sending to foreign device: %r", xpdu.pduDestination
                        )
                    await self.request(xpdu)

        else:
            BIPBBMD._warning("invalid pdu type: %s", type(lpdu))

    def register_foreign_device(self, addr: IPv6Address, ttl: int) -> int:
        """Add a foreign device to the FDT."""
        if _debug:
            BIPBBMD._debug("register_foreign_device %r %r", addr, ttl)

        for fdte in self.bbmdFDT:
            if addr == fdte.fdAddress:
                break
        else:
            fdte = FDTEntry()
            fdte.fdAddress = addr
            self.bbmdFDT.append(fdte)

        fdte.fdTTL = ttl
        fdte.fdRemain = ttl + 30

        # return success
        return 0

    def delete_foreign_device_table_entry(self, addr: IPv6Address) -> int:
        if _debug:
            BIPBBMD._debug("delete_foreign_device_table_entry %r", addr)

        # find it and delete it
        stat = 0
        for i in range(len(self.bbmdFDT) - 1, -1, -1):
            if addr == self.bbmdFDT[i].fdAddress:
                del self.bbmdFDT[i]
                break
        else:
            stat = 0x00A0  # IPv6 Delete-Foreign-Device-Table-Entry NAK

        # return status
        return stat

    def fdt_clock(self) -> None:
        # look for foreign device registrations that have expired
        for i in range(len(self.bbmdFDT) - 1, -1, -1):
            fdte = self.bbmdFDT[i]
            fdte.fdRemain -= 1

            # delete it if it expired
            if fdte.fdRemain <= 0:
                if _debug:
                    BIPBBMD._debug("foreign device expired: %r", fdte.fdAddress)
                del self.bbmdFDT[i]

        # again, again!
        self._fdt_clock_handle = asyncio.get_event_loop().call_later(1, self.fdt_clock)

    def add_peer(self, addr: IPv6Address) -> None:
        if _debug:
            BIPBBMD._debug("add_peer %r", addr)

        # see if it's already there
        for bdte in self.bbmdBDT:
            if addr == bdte:
                break
        else:
            self.bbmdBDT.append(addr)

    def delete_peer(self, addr: IPv6Address) -> None:
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
#   BVLLServiceElement
#


@dataclass
class PendingResolution:
    """Bookkeeping for one outstanding virtual-address resolution query."""

    address: VirtualAddress
    future: IPv6AddressFuture
    answers: Dict[IPv6Address, int] = field(default_factory=dict)
    answer_sources: Dict[IPv6Address, Optional[IPv6Address]] = field(
        default_factory=dict
    )
    guard_handle: Optional[asyncio.TimerHandle] = None
    finalizing: bool = False
    # whether the table already recorded a candidate for this VMAC when the
    # round started: only a pre-existing dispute can be confirmed as a
    # migration, never a candidate parked by the current round itself
    had_prior_candidate: bool = False


@bacpypes_debugging
class BVLLServiceElement(ApplicationServiceElement):
    _debug: Callable[..., None]
    _warning: Callable[..., None]

    virtual_address_resolution: Dict[VirtualAddress, PendingResolution]

    def __init__(self, *, aseID=None) -> None:
        if _debug:
            BVLLServiceElement._debug("__init__ aseID=%r", aseID)
        ApplicationServiceElement.__init__(self, aseID=aseID)

        # empty dictionary of pending address resolution requests
        self.virtual_address_resolution = {}

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

    def resolve_virtual_address(self, address: VirtualAddress) -> IPv6AddressFuture:
        """
        This function returns a future which is awaitable and will be completed
        when the virtual address resolution response comes back.

        Concurrent callers for the same VMAC share one query and one future;
        the future fails with :class:`VMACConflictError` if the answers
        collected during the resolution round disagree.
        """
        if _debug:
            BVLLServiceElement._debug("resolve_virtual_address %r", address)

        pending = self.virtual_address_resolution.get(address, None)
        if pending is not None:
            return pending.future

        # create a future and the bookkeeping for this resolution round
        future = IPv6AddressFuture()
        future.add_done_callback(
            lambda done_future: self._resolve_virtual_address_done(address, done_future)
        )
        prior_record = self.elementService.vmac_addr_table.get_record(address)
        pending = PendingResolution(
            address=address,
            future=future,
            had_prior_candidate=(
                prior_record is not None and prior_record.candidate is not None
            ),
        )
        self.virtual_address_resolution[address] = pending

        # create a request to resolve it and create a task to send it
        address_resolution = AddressResolution(
            source_virtual_address=self.elementService.virtual_address,
            target_virtual_address=address,
            destination=LocalBroadcast(),
        )
        asyncio.create_task(self.request(address_resolution))

        # return the future
        return future

    def _resolve_virtual_address_done(
        self, address: VirtualAddress, future: IPv6AddressFuture
    ) -> None:
        if _debug:
            BVLLServiceElement._debug(
                "_resolve_virtual_address_done %r %r", address, future
            )

        pending = self.virtual_address_resolution.get(address, None)
        if pending is None:
            if _debug:
                BVLLServiceElement._debug("    - nothing pending")
            return

        # the guard timer must not fire after the round is gone
        if pending.guard_handle is not None:
            pending.guard_handle.cancel()
        if future.cancelled():
            if _debug:
                BVLLServiceElement._debug("    - note: future has been cancelled")

        # remove it from the pending dictionary
        self.virtual_address_resolution.pop(address, None)

    async def AddressResolutionACK(self, lpdu: AddressResolutionACK) -> None:
        if _debug:
            BVLLServiceElement._debug("AddressResolutionACK %r", lpdu)

        address = lpdu.bvlciSourceVirtualAddress
        pending = self.virtual_address_resolution.get(address, None)
        if pending is None:
            if _debug:
                BVLLServiceElement._debug("    - nothing pending")
            return
        if pending.finalizing:
            if _debug:
                BVLLServiceElement._debug("    - round already finalizing")
            return

        answer = lpdu.pduSource
        pending.answers[answer] = pending.answers.get(answer, 0) + 1
        pending.answer_sources[answer] = lpdu.pduSource

        # feed the answer through the table admission policy immediately so
        # the audit trail reflects the query-response provenance
        table = self.elementService.vmac_addr_table
        try:
            result = table.admit(
                address,
                answer,
                MappingSource.query_response,
                observed_source=lpdu.pduSource,
                basis="Address-Resolution-ACK to local query",
            )
        except VMACConflictError as err:
            # the answer's IPv6 address is already bound to another VMAC:
            # an unambiguous failure, never an arbitrary target choice
            BVLLServiceElement._warning("resolution rejected: %s", err)
            pending.finalizing = True
            if pending.guard_handle is not None:
                pending.guard_handle.cancel()
                pending.guard_handle = None
            if not pending.future.done():
                pending.future.set_exception(err)
            return
        if _debug:
            BVLLServiceElement._debug("    - admission result: %r", result)

        # distinct answers are arriving: settle the round once the guard
        # window has elapsed instead of letting the last writer win
        if pending.guard_handle is None:
            pending.guard_handle = asyncio.get_event_loop().call_later(
                RESOLUTION_GUARD_TIME,
                lambda: asyncio.ensure_future(self._finalize_resolution(address)),
            )

        if len(pending.answers) > 1:
            if _debug:
                BVLLServiceElement._debug(
                    "    - conflicting answers so far: %r", pending.answers
                )

    async def _finalize_resolution(self, address: VirtualAddress) -> None:
        """Decide one resolution round once the answer guard window closes."""
        if _debug:
            BVLLServiceElement._debug("_finalize_resolution %r", address)

        pending = self.virtual_address_resolution.get(address, None)
        if pending is None:
            return
        pending.finalizing = True
        pending.guard_handle = None

        table = self.elementService.vmac_addr_table
        record = table.get_record(address)
        answers = pending.answers

        if len(answers) > 1:
            incumbent = record.ipv6 if record is not None else next(iter(answers))
            challengers = [a for a in answers if a != incumbent]
            challenger = challengers[0]
            err = VMACConflictError(address, incumbent, challenger)
            if _debug:
                BVLLServiceElement._warning(
                    "unresolved VMAC conflict for %r: %r", address, answers
                )
            if not pending.future.done():
                pending.future.set_exception(err)
            return

        answer = next(iter(answers))

        # no incumbent: the first answer for an unknown VMAC is accepted
        if record is None:
            if not pending.future.done():
                pending.future.set_result(answer)
            return

        # an answer matching the incumbent is always fine
        if isinstance(record.ipv6, IPv6Address) and record.ipv6 == answer:
            if not pending.future.done():
                pending.future.set_result(answer)
            return

        # a disagreeing answer is evidence of a dispute; a single round can
        # never move traffic.  Migration is only possible when the candidate
        # was already parked by an earlier round and this round corroborates
        # it with consistent answers.
        if not (
            pending.had_prior_candidate
            and isinstance(record.candidate, IPv6Address)
            and record.candidate == answer
        ):
            if not pending.future.done():
                pending.future.set_exception(
                    VMACConflictError(address, record.ipv6, answer)
                )
            return

        # the candidate predates this round and the round is consistent:
        # commit the migration
        migration = table.confirm_migration(
            address,
            answer,
            observed_source=pending.answer_sources.get(answer),
        )
        if migration is AdmissionResult.migration:
            if not pending.future.done():
                pending.future.set_result(answer)
        elif not pending.future.done():
            pending.future.set_exception(
                VMACConflictError(address, record.ipv6, answer)
            )
