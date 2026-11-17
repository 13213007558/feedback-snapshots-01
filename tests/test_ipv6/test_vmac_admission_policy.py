#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
VMAC -> IPv6 mapping admission policy
-------------------------------------

The virtual MAC address table of a BACnet/IPv6 link layer must never hand
the traffic of an incumbent device to a new claimant just because that
claimant's packet arrived last.  These tests pin down the conflict-visible
admission policy of ``bacpypes3.ipv6.service.VirtualMACAddressTable``:

* query responses, proactive advertisements and refreshes of an existing
  mapping are recorded with distinct provenance, the observed source of the
  claim and a validity period;
* a conflicting claim parks a challenger instead of overwriting the
  incumbent, and is reported as ``AdmissionResult.conflict``;
* only a fresh query response corroborating the parked challenger commits a
  migration;
* expired bindings are purged rather than treated as current.
"""

import pytest

from bacpypes3.pdu import IPv6Address, VirtualAddress
from bacpypes3.ipv6.service import (
    AdmissionResult,
    MappingSource,
    VMACConflictError,
    VirtualMACAddressTable,
)


VM = VirtualAddress(bytes.fromhex("010203"))
OTHER_VM = VirtualAddress(bytes.fromhex("090909"))
IP1 = IPv6Address("fd00::1")
IP2 = IPv6Address("fd00::2")
IP3 = IPv6Address("fd00::3")
OBSERVER = IPv6Address("fd00::bbbb")


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


def test_first_binding_is_admitted_with_audit_trail():
    table = VirtualMACAddressTable(default_ttl=10.0)

    result = table.admit(
        VM,
        IP1,
        MappingSource.query_response,
        observed_source=IP1,
        basis="Address-Resolution-ACK to local query",
    )

    assert result is AdmissionResult.admitted
    assert table[VM] == IP1
    assert table[IP1] == VM

    record = table.get_record(VM)
    assert record is not None
    assert record.ipv6 == IP1
    assert record.source is MappingSource.query_response
    assert record.observed_source == IP1
    assert record.accepted_basis == "Address-Resolution-ACK to local query"
    assert record.ttl == 10.0
    assert record.expires_at > 0


def test_proactive_advertisement_is_distinguished_from_query():
    table = VirtualMACAddressTable(clock=FakeClock())

    result = table.admit(
        VM,
        IP1,
        MappingSource.proactive_advertisement,
        observed_source=IP1,
        basis="Original-Broadcast-NPDU source",
    )

    assert result is AdmissionResult.admitted
    record = table.get_record(VM)
    assert record.source is MappingSource.proactive_advertisement
    assert record.accepted_basis == "Original-Broadcast-NPDU source"


def test_repeated_observation_refreshes_ttl_and_clears_dispute():
    clock = FakeClock()
    table = VirtualMACAddressTable(default_ttl=100.0, clock=clock)
    table.admit(VM, IP1, MappingSource.query_response)

    # park a challenger first
    conflict = table.admit(
        VM, IP2, MappingSource.proactive_advertisement, observed_source=IP2
    )
    assert conflict is AdmissionResult.conflict
    assert table.get_record(VM).candidate == IP2

    first_deadline = table.get_record(VM).expires_at
    clock.advance(10.0)
    refresh = table.admit(
        VM,
        IP1,
        MappingSource.existing_update,
        observed_source=IP1,
        basis="Original-Unicast-NPDU source",
    )

    assert refresh is AdmissionResult.refreshed
    record = table.get_record(VM)
    assert record.ipv6 == IP1
    assert record.source is MappingSource.existing_update
    assert record.expires_at > first_deadline
    assert record.candidate is None
    assert table[VM] == IP1


def test_conflicting_claim_never_overwrites_incumbent():
    table = VirtualMACAddressTable(clock=FakeClock())
    table.admit(VM, IP1, MappingSource.query_response, observed_source=IP1)

    result = table.admit(
        VM,
        IP2,
        MappingSource.proactive_advertisement,
        observed_source=IP2,
        basis="Original-Broadcast-NPDU source",
    )

    assert result is AdmissionResult.conflict
    # traffic still resolves to the incumbent
    assert table[VM] == IP1
    record = table.get_record(VM)
    assert record.ipv6 == IP1
    assert record.candidate == IP2
    assert record.candidate_basis == "Original-Broadcast-NPDU source"
    assert record.candidate_observed_source == IP2
    # reverse direction remains the incumbent's binding
    assert table[IP1] == VM
    assert table[IP2] is None


def test_last_writer_does_not_win_under_repeated_conflicts():
    table = VirtualMACAddressTable(clock=FakeClock())
    table.admit(VM, IP1, MappingSource.proactive_advertisement)

    for addr in (IP2, IP3, IP2, IP3):
        result = table.admit(
            VM, addr, MappingSource.proactive_advertisement, observed_source=addr
        )
        assert result is AdmissionResult.conflict
        assert table[VM] == IP1

    # the most recent challenger is the one retained for confirmation
    assert table.get_record(VM).candidate == IP3


def test_an_ipv6_address_cannot_back_two_vmacs():
    table = VirtualMACAddressTable(clock=FakeClock())
    table.admit(VM, IP1, MappingSource.query_response)

    with pytest.raises(VMACConflictError):
        table.admit(OTHER_VM, IP1, MappingSource.query_response)


def test_migration_requires_confirmed_candidate():
    clock = FakeClock()
    table = VirtualMACAddressTable(default_ttl=100.0, clock=clock)
    table.admit(VM, IP1, MappingSource.proactive_advertisement, observed_source=IP1)
    table.admit(VM, IP2, MappingSource.proactive_advertisement, observed_source=IP2)

    # an address that was never seen as challenger cannot force a migration
    assert (
        table.confirm_migration(VM, IP3, observed_source=IP3)
        is AdmissionResult.conflict
    )
    assert table[VM] == IP1

    # the parked challenger, corroborated by a fresh query response, can move
    result = table.confirm_migration(VM, IP2, observed_source=IP2)
    assert result is AdmissionResult.migration
    assert table[VM] == IP2
    assert table[IP2] == VM
    assert table[IP1] is None
    record = table.get_record(VM)
    assert record.source is MappingSource.query_response
    assert "migration" in record.accepted_basis


def test_expired_binding_is_purged_and_accepts_fresh_claim():
    clock = FakeClock(start=100.0)
    table = VirtualMACAddressTable(default_ttl=1.0, clock=clock)
    table.admit(VM, IP1, MappingSource.query_response)

    # still valid immediately after admission
    assert table.get_record(VM) is not None

    clock.advance(2.0)
    expired = table.expire()
    assert expired == [VM]
    assert table[VM] is None

    # the address can now be claimed cleanly by a different device
    result = table.admit(VM, IP2, MappingSource.query_response, observed_source=IP2)
    assert result is AdmissionResult.admitted
    assert table[VM] == IP2


def test_lookup_lazily_expires_stale_binding():
    clock = FakeClock(start=0.0)
    table = VirtualMACAddressTable(default_ttl=5.0, clock=clock)
    table.admit(VM, IP1, MappingSource.query_response)
    clock.advance(6.0)

    assert table[VM] is None
    assert VM not in table.vmac_to_ipv6
