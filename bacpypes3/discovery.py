"""
Discovery Conflict Inventory

When the same BACnet device instance answers Who-Is / announces I-Am from
more than one address - or one address starts claiming a different vendor
or instance - an asset backend must not let the last claim to arrive
overwrite the established device record.  A device that genuinely moved
and an attacker spoofing its instance number produce the *same* I-Am
traffic shape; they can only be told apart by evidence, so this module
keeps the evidence and refuses to auto-decide.

Pieces:

- ``IAmClaim`` - one immutable, traceable observation of an I-Am: address,
  vendor, APDU capabilities, observation time and source path (active
  discovery answer vs. passively received announcement).

- ``DiscoveryConflictInventory`` - an append-only log of claims plus the
  conflicts derived from them (same instance / many addresses, same
  address / many identities, same binding / changed vendor).  Conflicts
  carry the claim ids they are derived from and observation windows so an
  operator can judge migration vs. impersonation; nothing is auto-routed.

- ``ConflictAwareDeviceInfoCache`` - a ``DeviceInfoCache`` that records
  every claim in the inventory but never lets a conflicting claim
  overwrite an established binding, so subsequent writes keep going to
  the established address until an operator calls ``force_binding()``.

- ``DiscoveryApplication`` - an ``Application`` that classifies incoming
  I-Ams as active (matched a pending Who-Is) or passive (unsolicited)
  and feeds the cache; a claim is never considered trustworthy merely
  because the local cache already holds a record for it.
"""

from __future__ import annotations

import enum
import time

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .debugging import ModuleLogger, bacpypes_debugging

from .pdu import Address
from .apdu import IAmRequest
from .basetypes import Segmentation
from .app import Application, DeviceInfo, DeviceInfoCache

# some debugging
_debug = 0
_log = ModuleLogger(globals())


class ClaimSource(enum.Enum):
    """How an I-Am claim arrived."""

    active = "active"  # answer to a Who-Is this application sent
    passive = "passive"  # unsolicited I-Am heard on the wire


class ConflictKind(enum.Enum):
    """Shapes of conflicting claims; never a verdict, only evidence."""

    instance_address_conflict = "instance-address-conflict"
    address_identity_conflict = "address-identity-conflict"
    vendor_change = "vendor-change"


@bacpypes_debugging
@dataclass(frozen=True)
class IAmClaim:
    """One raw I-Am observation; the unit of traceability."""

    claim_id: int
    observed_at: float
    device_instance: int
    device_address: Address
    vendor_identifier: int
    max_apdu_length_accepted: int
    segmentation_supported: str
    source: ClaimSource

    def as_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "observed_at": self.observed_at,
            "observed_at_iso": _iso(self.observed_at),
            "device_instance": self.device_instance,
            "device_address": str(self.device_address),
            "vendor_identifier": self.vendor_identifier,
            "max_apdu_length_accepted": self.max_apdu_length_accepted,
            "segmentation_supported": self.segmentation_supported,
            "source": self.source.value,
        }


@bacpypes_debugging
@dataclass
class BindingObservation:
    """Observation window for one (instance, address) binding."""

    device_instance: int
    device_address: Address
    first_seen: float
    last_seen: float
    claim_ids: List[int] = field(default_factory=list)
    sources: Set[ClaimSource] = field(default_factory=set)
    vendors: Set[int] = field(default_factory=set)

    def observe(self, claim: IAmClaim) -> None:
        self.first_seen = min(self.first_seen, claim.observed_at)
        self.last_seen = max(self.last_seen, claim.observed_at)
        self.claim_ids.append(claim.claim_id)
        self.sources.add(claim.source)
        self.vendors.add(claim.vendor_identifier)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "device_instance": self.device_instance,
            "device_address": str(self.device_address),
            "first_seen": self.first_seen,
            "first_seen_iso": _iso(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_iso": _iso(self.last_seen),
            "claim_ids": list(self.claim_ids),
            "sources": sorted(source.value for source in self.sources),
            "vendors": sorted(self.vendors),
        }


@bacpypes_debugging
@dataclass
class Conflict:
    """
    A set of mutually inconsistent claims.  ``details`` carries the
    evidence (observation windows, source paths, vendors, whether the
    windows overlap) so an operator can judge device migration vs.
    identity spoofing - the inventory deliberately does not decide.
    """

    conflict_id: str
    kind: ConflictKind
    subject: str
    first_seen: float
    last_seen: float
    claim_ids: List[int] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_note: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "kind": self.kind.value,
            "subject": self.subject,
            "first_seen": self.first_seen,
            "first_seen_iso": _iso(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_iso": _iso(self.last_seen),
            "claim_ids": list(self.claim_ids),
            "details": self.details,
            "resolved": self.resolved,
            "resolution_note": self.resolution_note,
        }


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


#
#   DiscoveryConflictInventory
#


@bacpypes_debugging
class DiscoveryConflictInventory:
    """
    Append-only log of I-Am claims and the conflicts derived from them.

    Every claim is kept so results stay traceable to each raw claim;
    conflicts are re-derived incrementally and never auto-resolved.
    """

    _debug: Callable[..., None]

    claims: List[IAmClaim]
    observations: Dict[Tuple[int, Address], BindingObservation]
    conflicts: Dict[str, Conflict]

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        if _debug:
            DiscoveryConflictInventory._debug("__init__")

        self.clock = clock
        self.claims = []
        self.observations = {}
        self.conflicts = {}

        # secondary indexes over the claim log
        self._by_instance: Dict[int, List[int]] = {}
        self._by_address: Dict[Address, List[int]] = {}

    def record_claim(self, apdu: IAmRequest, source: ClaimSource) -> IAmClaim:
        """
        Append the claim carried by an I-Am to the log and re-derive any
        conflict it participates in.  Returns the recorded claim.
        """
        if _debug:
            DiscoveryConflictInventory._debug("record_claim %r %r", apdu, source)

        if not isinstance(apdu, IAmRequest):
            raise ValueError("not an IAmRequest: %r" % (apdu,))

        claim = IAmClaim(
            claim_id=len(self.claims) + 1,
            observed_at=self.clock(),
            device_instance=apdu.iAmDeviceIdentifier[1],
            device_address=apdu.pduSource,
            vendor_identifier=apdu.vendorID,
            max_apdu_length_accepted=apdu.maxAPDULengthAccepted,
            segmentation_supported=apdu.segmentationSupported.attr,
            source=source,
        )
        self.claims.append(claim)
        self._by_instance.setdefault(claim.device_instance, []).append(claim.claim_id)
        self._by_address.setdefault(claim.device_address, []).append(claim.claim_id)

        # update the observation window for this binding
        binding_key = (claim.device_instance, claim.device_address)
        observation = self.observations.get(binding_key)
        if observation is None:
            observation = BindingObservation(
                device_instance=claim.device_instance,
                device_address=claim.device_address,
                first_seen=claim.observed_at,
                last_seen=claim.observed_at,
            )
            self.observations[binding_key] = observation
        observation.observe(claim)

        # (re)derive the conflicts this claim may participate in
        self._derive_instance_conflict(claim.device_instance)
        self._derive_address_conflict(claim.device_address)
        self._derive_vendor_conflict(binding_key)

        return claim

    def _derive_instance_conflict(self, device_instance: int) -> None:
        """One instance claiming more than one address."""
        addresses = {
            self.claims[claim_id - 1].device_address
            for claim_id in self._by_instance[device_instance]
        }
        if len(addresses) < 2:
            return

        conflict_id = f"instance-address-conflict:{device_instance}"
        windows = {}
        for address in sorted(addresses, key=str):
            observation = self.observations[(device_instance, address)]
            windows[str(address)] = observation.as_dict()
        claim_ids = sorted(
            claim_id
            for address in addresses
            for claim_id in self.observations[(device_instance, address)].claim_ids
        )
        details = {
            "device_instance": device_instance,
            "addresses": windows,
            "windows_overlap": _windows_overlap(
                [
                    (observation.first_seen, observation.last_seen)
                    for addr in addresses
                    for observation in [self.observations[(device_instance, addr)]]
                ]
            ),
            "assessment": (
                "overlapping windows mean the addresses claimed the instance "
                "concurrently (consistent with spoofing or a duplicate "
                "device); disjoint windows are consistent with migration - "
                "neither is conclusive from I-Am evidence alone"
            ),
        }
        self._update_conflict(
            conflict_id,
            ConflictKind.instance_address_conflict,
            str(device_instance),
            claim_ids,
            details,
        )

    def _derive_address_conflict(self, device_address: Address) -> None:
        """One address claiming more than one device instance."""
        instances = {
            self.claims[claim_id - 1].device_instance
            for claim_id in self._by_address[device_address]
        }
        if len(instances) < 2:
            return

        conflict_id = f"address-identity-conflict:{device_address}"
        claim_ids = sorted(self._by_address[device_address])
        details = {
            "device_address": str(device_address),
            "device_instances": sorted(instances),
            "assessment": (
                "one address announced more than one device instance; "
                "consistent with address reuse after reconfiguration or "
                "with impersonation - not conclusive from I-Am evidence alone"
            ),
        }
        self._update_conflict(
            conflict_id,
            ConflictKind.address_identity_conflict,
            str(device_address),
            claim_ids,
            details,
        )

    def _derive_vendor_conflict(self, binding_key: Tuple[int, Address]) -> None:
        """One (instance, address) binding reporting more than one vendor."""
        observation = self.observations[binding_key]
        if len(observation.vendors) < 2:
            return

        device_instance, device_address = binding_key
        conflict_id = f"vendor-change:{device_instance}@{device_address}"
        details = {
            "device_instance": device_instance,
            "device_address": str(device_address),
            "vendors": sorted(observation.vendors),
            "assessment": (
                "the same binding reported different vendor identifiers; "
                "consistent with firmware/hardware replacement or with "
                "impersonation - not conclusive from I-Am evidence alone"
            ),
        }
        self._update_conflict(
            conflict_id,
            ConflictKind.vendor_change,
            f"{device_instance}@{device_address}",
            sorted(observation.claim_ids),
            details,
        )

    def _update_conflict(
        self,
        conflict_id: str,
        kind: ConflictKind,
        subject: str,
        claim_ids: List[int],
        details: Dict[str, Any],
    ) -> None:
        if _debug:
            DiscoveryConflictInventory._debug(
                "_update_conflict %r %r", conflict_id, claim_ids
            )

        seen = [self.claims[claim_id - 1].observed_at for claim_id in claim_ids]
        conflict = self.conflicts.get(conflict_id)
        if conflict is None:
            conflict = Conflict(
                conflict_id=conflict_id,
                kind=kind,
                subject=subject,
                first_seen=min(seen),
                last_seen=max(seen),
            )
            self.conflicts[conflict_id] = conflict
            _log.info("discovery conflict %s (%s)", conflict_id, kind.value)
        conflict.claim_ids = claim_ids
        conflict.first_seen = min(seen)
        conflict.last_seen = max(seen)
        conflict.details = details

    def resolve(self, conflict_id: str, note: Optional[str] = None) -> Conflict:
        """Mark a conflict as resolved by an operator, with a note."""
        if _debug:
            DiscoveryConflictInventory._debug("resolve %r %r", conflict_id, note)

        conflict = self.conflicts[conflict_id]
        conflict.resolved = True
        conflict.resolution_note = note
        return conflict

    # ----- queries

    def claims_for_instance(self, device_instance: int) -> List[IAmClaim]:
        return [
            self.claims[claim_id - 1]
            for claim_id in self._by_instance.get(device_instance, [])
        ]

    def claims_for_address(self, device_address: Address) -> List[IAmClaim]:
        return [
            self.claims[claim_id - 1]
            for claim_id in self._by_address.get(device_address, [])
        ]

    def report(self) -> Dict[str, Any]:
        """The full inventory: every claim, every window, every conflict."""
        if _debug:
            DiscoveryConflictInventory._debug("report")

        return {
            "claims": [claim.as_dict() for claim in self.claims],
            "observations": [
                observation.as_dict()
                for observation in sorted(
                    self.observations.values(),
                    key=lambda obs: (obs.device_instance, str(obs.device_address)),
                )
            ],
            "conflicts": [
                conflict.as_dict()
                for conflict in sorted(
                    self.conflicts.values(), key=lambda c: c.conflict_id
                )
            ],
        }


def _windows_overlap(windows: List[Tuple[float, float]]) -> bool:
    ordered = sorted(windows)
    return any(earlier[1] >= later[0] for earlier, later in zip(ordered, ordered[1:]))


#
#   ConflictAwareDeviceInfoCache
#


@bacpypes_debugging
class ConflictAwareDeviceInfoCache(DeviceInfoCache):
    """
    A DeviceInfoCache that logs every I-Am claim into a
    DiscoveryConflictInventory and applies a non-overwrite policy:

    - a claim for an unknown instance/address establishes a binding;
    - a claim matching the established binding refreshes APDU
      capabilities (a vendor change is flagged and ignored instead);
    - a conflicting claim (instance moved, address reused) is recorded
      as evidence but the established binding is kept, so subsequent
      writes are never auto-routed to the new address.

    ``set_device_info`` defaults to ``ClaimSource.active`` because its
    only in-stack caller is ``WhoIsFuture.match``; unsolicited I-Ams
    arrive via ``DiscoveryApplication.do_IAmRequest`` which passes
    ``ClaimSource.passive`` explicitly.
    """

    _debug: Callable[..., None]

    inventory: DiscoveryConflictInventory

    def __init__(
        self,
        device_info_class=DeviceInfo,
        inventory: Optional[DiscoveryConflictInventory] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if _debug:
            ConflictAwareDeviceInfoCache._debug("__init__")
        super().__init__(device_info_class=device_info_class)

        self.inventory = inventory or DiscoveryConflictInventory(clock=clock)

    async def set_device_info(
        self, apdu: IAmRequest, source: ClaimSource = ClaimSource.active
    ) -> Optional[DeviceInfo]:
        if _debug:
            ConflictAwareDeviceInfoCache._debug("set_device_info %r %r", apdu, source)

        if not isinstance(apdu, IAmRequest):
            raise ValueError("not an IAmRequest: %r" % (apdu,))

        # every claim is evidence, recorded whether or not it is accepted
        claim = self.inventory.record_claim(apdu, source)

        device_address = apdu.pduSource
        device_instance = apdu.iAmDeviceIdentifier[1]

        info_by_address = self.address_cache.get(device_address, None)
        info_by_instance = self.instance_cache.get(device_instance, None)

        # no existing binding: establish one
        if (info_by_address is None) and (info_by_instance is None):
            device_info = self.device_info_class(device_instance, device_address)
            self._refresh_capabilities(device_info, apdu)
            self.address_cache[device_address] = device_info
            self.instance_cache[device_instance] = device_info
            if _debug:
                ConflictAwareDeviceInfoCache._debug(
                    "    - established: %r", device_info
                )
            return device_info

        # claim matches the established binding
        if (
            (info_by_instance is not None)
            and (info_by_instance.device_address == device_address)
            and (info_by_address is info_by_instance)
        ):
            if info_by_instance.vendor_identifier != apdu.vendorID:
                # vendor-change conflict already logged by the inventory;
                # keep the established record untouched
                _log.warning(
                    "I-Am from %s, device %d: vendor %r conflicts with "
                    "established vendor %r (claim %d) - binding unchanged",
                    device_address,
                    device_instance,
                    apdu.vendorID,
                    info_by_instance.vendor_identifier,
                    claim.claim_id,
                )
                return info_by_instance

            # ordinary duplicate: refresh APDU capabilities
            self._refresh_capabilities(info_by_instance, apdu)
            return info_by_instance

        # conflicting claim: record-only, keep the established binding so
        # writes are not auto-routed to the new address
        _log.warning(
            "I-Am from %s, device %d conflicts with established binding(s) "
            "(claim %d) - binding unchanged",
            device_address,
            device_instance,
            claim.claim_id,
        )
        return info_by_instance or info_by_address

    def _refresh_capabilities(self, device_info: DeviceInfo, apdu: IAmRequest) -> None:
        device_info.max_apdu_length_accepted = apdu.maxAPDULengthAccepted
        device_info.segmentation_supported = apdu.segmentationSupported
        device_info.vendor_identifier = apdu.vendorID

    def force_binding(
        self,
        device_instance: int,
        device_address: Address,
        note: Optional[str] = None,
    ) -> DeviceInfo:
        """
        Operator action: after reviewing the conflict evidence, rebind an
        instance to an address.  Requires at least one recorded claim for
        exactly this (instance, address) pair so the decision stays
        traceable to a raw claim; resolves the related conflicts.
        """
        if _debug:
            ConflictAwareDeviceInfoCache._debug(
                "force_binding %r %r", device_instance, device_address
            )

        observation = self.inventory.observations.get((device_instance, device_address))
        if observation is None:
            raise ValueError(
                f"no claim on record for device {device_instance} "
                f"at {device_address}"
            )

        # drop stale mappings in both directions
        for cache, key in (
            (self.instance_cache, device_instance),
            (self.address_cache, device_address),
        ):
            stale = cache.pop(key, None)
            if stale is not None:
                if cache is self.instance_cache:
                    self.address_cache.pop(stale.device_address, None)
                else:
                    self.instance_cache.pop(stale.device_instance, None)

        # rebuild the record from the latest claim for this binding
        latest_claim = self.inventory.claims[observation.claim_ids[-1] - 1]
        device_info = self.device_info_class(device_instance, device_address)
        device_info.max_apdu_length_accepted = latest_claim.max_apdu_length_accepted
        device_info.segmentation_supported = Segmentation(
            latest_claim.segmentation_supported
        )
        device_info.vendor_identifier = latest_claim.vendor_identifier
        self.address_cache[device_address] = device_info
        self.instance_cache[device_instance] = device_info

        # resolve the conflicts this decision settles
        for conflict_id in (
            f"instance-address-conflict:{device_instance}",
            f"address-identity-conflict:{device_address}",
            f"vendor-change:{device_instance}@{device_address}",
        ):
            if conflict_id in self.inventory.conflicts:
                self.inventory.resolve(conflict_id, note)

        return device_info

    def report(self) -> Dict[str, Any]:
        """Inventory report plus the established (routing) bindings."""
        report = self.inventory.report()
        report["established_bindings"] = [
            {
                "device_instance": device_info.device_instance,
                "device_address": str(device_info.device_address),
                "vendor_identifier": device_info.vendor_identifier,
                "max_apdu_length_accepted": device_info.max_apdu_length_accepted,
                "segmentation_supported": (
                    device_info.segmentation_supported.attr
                    if isinstance(device_info.segmentation_supported, Segmentation)
                    else str(device_info.segmentation_supported)
                ),
            }
            for device_info in sorted(
                self.instance_cache.values(), key=lambda info: info.device_instance
            )
        ]
        return report


#
#   DiscoveryApplication
#


def _who_is_future_matches(who_is_future, apdu: IAmRequest) -> bool:
    """
    Pure predicate mirroring WhoIsFuture.match()'s filters, used to tell
    whether an I-Am is an (active) answer to a pending Who-Is before the
    futures are actually notified.
    """
    if apdu.iAmDeviceIdentifier is None:
        return False
    if who_is_future.only_one and who_is_future.future.done():
        return False
    if (who_is_future.address is not None) and (
        apdu.pduSource != who_is_future.address
    ):
        return False
    device_instance = apdu.iAmDeviceIdentifier[1]
    if (who_is_future.low_limit is not None) and (
        device_instance < who_is_future.low_limit
    ):
        return False
    if (who_is_future.high_limit is not None) and (
        device_instance > who_is_future.high_limit
    ):
        return False
    return True


@bacpypes_debugging
class DiscoveryApplication(Application):
    """
    An Application that separates actively discovered I-Ams (answers to
    our Who-Is) from passively received ones, and records both in a
    ConflictAwareDeviceInfoCache.  A pre-existing cache record is never
    treated as proof that a new claim is trustworthy.
    """

    _debug: Callable[..., None]

    device_info_cache: ConflictAwareDeviceInfoCache

    def __init__(self, *args, **kwargs) -> None:
        cache = kwargs.get("device_info_cache", None)
        if cache is None:
            kwargs["device_info_cache"] = ConflictAwareDeviceInfoCache()
        elif not isinstance(cache, ConflictAwareDeviceInfoCache):
            raise ValueError(
                "DiscoveryApplication requires a ConflictAwareDeviceInfoCache"
            )
        super().__init__(*args, **kwargs)

    async def do_IAmRequest(self, apdu) -> None:
        if _debug:
            DiscoveryApplication._debug("do_IAmRequest %r", apdu)

        if not hasattr(self, "_who_is_futures"):
            self._who_is_futures = []

        # an I-Am is "active" evidence only if it answers a Who-Is that
        # is still pending; matched futures record it via the cache's
        # default active source
        solicited = any(
            _who_is_future_matches(who_is_future, apdu)
            for who_is_future in self._who_is_futures
        )

        await super().do_IAmRequest(apdu)

        if not solicited:
            # unsolicited announcement: passive evidence, recorded but
            # still subject to the non-overwrite policy
            await self.device_info_cache.set_device_info(
                apdu, source=ClaimSource.passive
            )

    def discovery_report(self) -> Dict[str, Any]:
        """The discovery conflict inventory for this application."""
        return self.device_info_cache.report()
