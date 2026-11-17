#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Discovery Conflict Inventory tests
----------------------------------

Same device instance answering I-Am from two addresses, one address
changing vendor, and ordinary duplicate replies must be told apart by
evidence - never by letting the last claim overwrite the established
device record.
"""

import asyncio
from typing import Callable

import pytest

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier
from bacpypes3.apdu import IAmRequest

from bacpypes3.discovery import (
    ClaimSource,
    ConflictAwareDeviceInfoCache,
    ConflictKind,
    DiscoveryApplication,
)

# some debugging
_debug = 0
_log = ModuleLogger(globals())


def _i_am(
    address: str,
    instance: int = 100,
    vendor: int = 999,
    max_apdu: int = 1024,
    segmentation: str = "noSegmentation",
) -> IAmRequest:
    """Build an I-Am as if it had just arrived from `address`."""
    return IAmRequest(
        iAmDeviceIdentifier=ObjectIdentifier(("device", instance)),
        maxAPDULengthAccepted=max_apdu,
        segmentationSupported=segmentation,
        vendorID=vendor,
        source=Address(address),
    )


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@bacpypes_debugging
class TestInstanceAddressConflict:
    """Same device instance, two different addresses."""

    _debug: Callable[..., None]

    @pytest.mark.asyncio
    async def test_last_claim_does_not_overwrite(self) -> None:
        if _debug:
            TestInstanceAddressConflict._debug("test_last_claim_does_not_overwrite")

        cache = ConflictAwareDeviceInfoCache()

        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        await cache.set_device_info(_i_am("10.0.0.2", instance=100))

        # the established binding wins: writes keep routing to 10.0.0.1
        device_info = await cache.get_device_info(100)
        assert device_info is not None
        assert device_info.device_address == Address("10.0.0.1")

        # the new address was not bound
        assert await cache.get_device_info(Address("10.0.0.2")) is None

    @pytest.mark.asyncio
    async def test_conflict_traceable_to_raw_claims(self) -> None:
        if _debug:
            TestInstanceAddressConflict._debug("test_conflict_traceable_to_raw_claims")

        cache = ConflictAwareDeviceInfoCache()

        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        await cache.set_device_info(_i_am("10.0.0.2", instance=100))

        conflicts = list(cache.inventory.conflicts.values())
        assert len(conflicts) == 1
        conflict = conflicts[0]
        assert conflict.kind is ConflictKind.instance_address_conflict
        assert conflict.claim_ids == [1, 2]
        assert not conflict.resolved

        # every raw claim is retained with its evidence fields
        claims = cache.inventory.claims_for_instance(100)
        assert [claim.claim_id for claim in claims] == [1, 2]
        assert claims[0].device_address == Address("10.0.0.1")
        assert claims[1].device_address == Address("10.0.0.2")
        for claim in claims:
            assert claim.vendor_identifier == 999
            assert claim.max_apdu_length_accepted == 1024
            assert claim.segmentation_supported == "noSegmentation"

        # observation windows exist per (instance, address) binding
        report = cache.report()
        observations = {obs["device_address"]: obs for obs in report["observations"]}
        assert set(observations) == {"10.0.0.1", "10.0.0.2"}
        for obs in observations.values():
            assert obs["first_seen"] <= obs["last_seen"]
            assert obs["sources"] == ["active"]

    @pytest.mark.asyncio
    async def test_migration_vs_spoofing_is_evidence_only(self) -> None:
        """
        Sequential windows (old address goes quiet, then a new one claims
        the instance) are consistent with migration; overlapping windows
        are consistent with concurrent/spoofed claims.  The inventory
        reports the overlap as evidence and takes no side.
        """
        if _debug:
            TestInstanceAddressConflict._debug(
                "test_migration_vs_spoofing_is_evidence_only"
            )

        # sequential: looks like migration, still only evidence
        clock = _FakeClock()
        cache = ConflictAwareDeviceInfoCache(clock=clock)
        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        clock.advance(60)
        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        clock.advance(3600)
        await cache.set_device_info(_i_am("10.0.0.2", instance=100))

        conflict = cache.inventory.conflicts["instance-address-conflict:100"]
        assert conflict.details["windows_overlap"] is False
        assert "conclusive" in conflict.details["assessment"]

        # overlapping: both addresses alive at the same time
        clock2 = _FakeClock()
        cache2 = ConflictAwareDeviceInfoCache(clock=clock2)
        await cache2.set_device_info(_i_am("10.0.0.1", instance=100))
        clock2.advance(5)
        await cache2.set_device_info(_i_am("10.0.0.2", instance=100))
        clock2.advance(5)
        await cache2.set_device_info(_i_am("10.0.0.1", instance=100))

        conflict2 = cache2.inventory.conflicts["instance-address-conflict:100"]
        assert conflict2.details["windows_overlap"] is True
        # three raw claims behind one conflict, all retained
        assert conflict2.claim_ids == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_force_binding_is_operator_action(self) -> None:
        if _debug:
            TestInstanceAddressConflict._debug("test_force_binding_is_operator_action")

        cache = ConflictAwareDeviceInfoCache()
        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        await cache.set_device_info(_i_am("10.0.0.2", instance=100))

        # cannot bind to an address with no claim on record
        with pytest.raises(ValueError):
            cache.force_binding(100, Address("10.0.0.9"))

        device_info = cache.force_binding(
            100, Address("10.0.0.2"), note="operator verified migration"
        )
        assert device_info.device_address == Address("10.0.0.2")
        assert (await cache.get_device_info(100)).device_address == Address("10.0.0.2")
        assert await cache.get_device_info(Address("10.0.0.1")) is None

        conflict = cache.inventory.conflicts["instance-address-conflict:100"]
        assert conflict.resolved
        assert conflict.resolution_note == "operator verified migration"


@bacpypes_debugging
class TestAddressIdentityConflict:
    """Same address, changed vendor or changed instance."""

    _debug: Callable[..., None]

    @pytest.mark.asyncio
    async def test_vendor_change_flagged_not_applied(self) -> None:
        if _debug:
            TestAddressIdentityConflict._debug("test_vendor_change_flagged_not_applied")

        cache = ConflictAwareDeviceInfoCache()
        await cache.set_device_info(_i_am("10.0.0.1", instance=100, vendor=1))
        await cache.set_device_info(_i_am("10.0.0.1", instance=100, vendor=2))

        # established vendor kept, conflict recorded
        device_info = await cache.get_device_info(100)
        assert device_info.vendor_identifier == 1

        conflict = cache.inventory.conflicts["vendor-change:100@10.0.0.1"]
        assert conflict.kind is ConflictKind.vendor_change
        assert conflict.claim_ids == [1, 2]
        assert conflict.details["vendors"] == [1, 2]

    @pytest.mark.asyncio
    async def test_address_reuse_by_other_instance(self) -> None:
        if _debug:
            TestAddressIdentityConflict._debug("test_address_reuse_by_other_instance")

        cache = ConflictAwareDeviceInfoCache()
        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        await cache.set_device_info(_i_am("10.0.0.1", instance=200))

        # the address stays bound to the established device
        device_info = await cache.get_device_info(Address("10.0.0.1"))
        assert device_info.device_instance == 100
        assert await cache.get_device_info(200) is None

        conflict = cache.inventory.conflicts["address-identity-conflict:10.0.0.1"]
        assert conflict.kind is ConflictKind.address_identity_conflict
        assert conflict.details["device_instances"] == [100, 200]


@bacpypes_debugging
class TestPlainDuplicate:
    """Ordinary repeated I-Am replies are not conflicts."""

    _debug: Callable[..., None]

    @pytest.mark.asyncio
    async def test_duplicate_extends_window_without_conflict(self) -> None:
        if _debug:
            TestPlainDuplicate._debug("test_duplicate_extends_window_without_conflict")

        clock = _FakeClock()
        cache = ConflictAwareDeviceInfoCache(clock=clock)

        await cache.set_device_info(_i_am("10.0.0.1", instance=100))
        clock.advance(30)
        await cache.set_device_info(_i_am("10.0.0.1", instance=100))

        assert cache.inventory.conflicts == {}

        claims = cache.inventory.claims_for_instance(100)
        assert len(claims) == 2

        observation = cache.inventory.observations[(100, Address("10.0.0.1"))]
        assert observation.first_seen == 1000.0
        assert observation.last_seen == 1030.0
        assert observation.claim_ids == [1, 2]

    @pytest.mark.asyncio
    async def test_duplicate_refreshes_apdu_capabilities(self) -> None:
        if _debug:
            TestPlainDuplicate._debug("test_duplicate_refreshes_apdu_capabilities")

        cache = ConflictAwareDeviceInfoCache()
        await cache.set_device_info(_i_am("10.0.0.1", instance=100, max_apdu=1024))
        await cache.set_device_info(
            _i_am(
                "10.0.0.1",
                instance=100,
                max_apdu=1476,
                segmentation="segmentedBoth",
            )
        )

        device_info = await cache.get_device_info(100)
        assert device_info.max_apdu_length_accepted == 1476
        assert device_info.segmentation_supported.attr == "segmentedBoth"
        assert cache.inventory.conflicts == {}


@bacpypes_debugging
class TestActivePassiveSeparation:
    """Active discovery answers and passive announcements stay separate."""

    _debug: Callable[..., None]

    @pytest.mark.asyncio
    async def test_unsolicited_i_am_is_passive(self) -> None:
        if _debug:
            TestActivePassiveSeparation._debug("test_unsolicited_i_am_is_passive")

        app = DiscoveryApplication()
        try:
            await app.do_IAmRequest(_i_am("10.0.0.1", instance=100))

            claims = app.device_info_cache.inventory.claims
            assert len(claims) == 1
            assert claims[0].source is ClaimSource.passive
        finally:
            app.close()

    @pytest.mark.asyncio
    async def test_who_is_answer_is_active(self) -> None:
        if _debug:
            TestActivePassiveSeparation._debug("test_who_is_answer_is_active")

        app = DiscoveryApplication()
        try:
            who_is_future = app.who_is(address=Address("10.0.0.1"), timeout=3.0)
            await app.do_IAmRequest(_i_am("10.0.0.1", instance=100))
            # WhoIsFuture.match() records via ensure_future
            await asyncio.sleep(0)

            result = await who_is_future
            assert len(result) == 1

            claims = app.device_info_cache.inventory.claims
            assert len(claims) == 1
            assert claims[0].source is ClaimSource.active
        finally:
            app.close()

    @pytest.mark.asyncio
    async def test_cache_record_does_not_make_claim_trusted(self) -> None:
        """
        A passive claim that happens to match an established binding is
        still recorded as passive; a passive claim from a *new* address
        for a known instance is a conflict, not a silent update.
        """
        if _debug:
            TestActivePassiveSeparation._debug(
                "test_cache_record_does_not_make_claim_trusted"
            )

        app = DiscoveryApplication()
        try:
            # active discovery establishes the binding
            who_is_future = app.who_is(address=Address("10.0.0.1"), timeout=3.0)
            await app.do_IAmRequest(_i_am("10.0.0.1", instance=100))
            await asyncio.sleep(0)
            await who_is_future

            # passive announcement for the same binding: fine, but passive
            await app.do_IAmRequest(_i_am("10.0.0.1", instance=100))
            # passive announcement from a new address: conflict, no reroute
            await app.do_IAmRequest(_i_am("10.0.0.2", instance=100))

            inventory = app.device_info_cache.inventory
            sources = [claim.source for claim in inventory.claims]
            assert sources == [
                ClaimSource.active,
                ClaimSource.passive,
                ClaimSource.passive,
            ]
            assert "instance-address-conflict:100" in inventory.conflicts

            # writes still route to the established address
            device_info = await app.get_device_info(100)
            assert device_info.device_address == Address("10.0.0.1")
        finally:
            app.close()

    @pytest.mark.asyncio
    async def test_report_separates_sources(self) -> None:
        if _debug:
            TestActivePassiveSeparation._debug("test_report_separates_sources")

        app = DiscoveryApplication()
        try:
            who_is_future = app.who_is(address=Address("10.0.0.1"), timeout=3.0)
            await app.do_IAmRequest(_i_am("10.0.0.1", instance=100))
            await asyncio.sleep(0)
            await who_is_future
            await app.do_IAmRequest(_i_am("10.0.0.2", instance=200))

            report = app.discovery_report()
            by_source = {}
            for claim in report["claims"]:
                by_source.setdefault(claim["source"], []).append(claim)
            assert [c["device_instance"] for c in by_source["active"]] == [100]
            assert [c["device_instance"] for c in by_source["passive"]] == [200]

            # established bindings are the routing view, kept apart from
            # the raw claim log
            assert len(report["established_bindings"]) == 2
        finally:
            app.close()
