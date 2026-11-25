"""End-to-end tests for the scope-gated shared archive service.

A single pynetdicom SCP serves two archive routes. Local clients register
read-only and write-only scopes. The tests prove, via the gateway's
handler-reach log, at which stage each blocked message was stopped.
"""

import pytest
from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind as QRFind,
    SecondaryCaptureImageStorage,
)

from scope_gate.client import connect, find_identifier, synthetic_instance
from scope_gate.registry import ScopeRegistry
from scope_gate.server import (
    STATUS_DENIED,
    STAGE_DIMSE,
    STAGE_NEGOTIATION,
    ScopedArchiveServer,
)


@pytest.fixture
def gateway():
    registry = ScopeRegistry()
    try:
        server = ScopedArchiveServer(registry)
    except PermissionError:
        pytest.skip("local port binding is not permitted in this sandbox")
    yield registry, server
    server.shutdown()


def _find_all(assoc, patient_id=""):
    return list(assoc.send_c_find(find_identifier(patient_id), QRFind))


def test_read_only_client_write_blocked_at_negotiation(gateway):
    registry, server = gateway
    registry.register("READER_A", ["read:ARCHIVE_A"])
    seed = synthetic_instance(patient_id="SEED001")
    server.archives["ARCHIVE_A"][seed.SOPInstanceUID] = seed

    assoc = connect("READER_A", server.port, "ARCHIVE_A",
                    want_read=True, want_write=True)
    assert assoc.is_established

    # The association carries the approved role/scope from negotiation.
    negotiation = [r for r in server.reached("EVT_REQUESTED")
                   if r.decision == "allowed"]
    assert negotiation and "role=read-only" in negotiation[0].detail

    # Read context accepted, write context refused during negotiation.
    accepted = {cx.abstract_syntax for cx in assoc.accepted_contexts}
    assert QRFind in accepted
    assert SecondaryCaptureImageStorage not in accepted
    assert any(
        cx.abstract_syntax == SecondaryCaptureImageStorage
        for cx in assoc.rejected_contexts
    )

    # Read works: the C-FIND handler was reached and allowed.
    results = _find_all(assoc)
    pending = [ident for status, ident in results
               if status and status.Status == 0xFF00]
    assert [ds.PatientID for ds in pending] == ["SEED001"]
    assert results[-1][0].Status == 0x0000
    assert [r.decision for r in server.reached("EVT_C_FIND")] == ["allowed"]

    # Write has no presentation context: the client is stopped before any
    # DIMSE message goes out and the C-STORE handler is never reached.
    with pytest.raises(ValueError):
        assoc.send_c_store(synthetic_instance())
    assert server.reached("EVT_C_STORE") == []
    drops = [r for r in server.blocked() if r.decision == "context-dropped"]
    assert drops and all(r.stage == STAGE_NEGOTIATION for r in drops)

    assoc.release()


def test_write_revoked_mid_association_blocked_at_dimse_handler(gateway):
    registry, server = gateway
    registry.register("WRITER_A", ["write:ARCHIVE_A"])

    assoc = connect("WRITER_A", server.port, "ARCHIVE_A",
                    want_read=False, want_write=True)
    assert assoc.is_established

    status = assoc.send_c_store(synthetic_instance(patient_id="W001"))
    assert status.Status == 0x0000
    assert len(server.archives["ARCHIVE_A"]) == 1

    # Withdraw the write scope while the association stays open.
    registry.revoke("WRITER_A", "write:ARCHIVE_A")

    # The next C-STORE on the same connection reaches the handler, which
    # re-checks the live registry and refuses it.
    status = assoc.send_c_store(synthetic_instance(patient_id="W002"))
    assert status.Status == STATUS_DENIED
    assert len(server.archives["ARCHIVE_A"]) == 1

    stores = server.reached("EVT_C_STORE")
    assert [r.decision for r in stores] == ["allowed", "denied"]
    assert stores[-1].stage == STAGE_DIMSE

    # A fresh association no longer even negotiates the write context.
    assoc2 = connect("WRITER_A", server.port, "ARCHIVE_A",
                     want_read=False, want_write=True)
    assert assoc2.is_established
    assert not assoc2.accepted_contexts
    drops = [r for r in server.blocked() if r.decision == "context-dropped"]
    assert drops and all(r.stage == STAGE_NEGOTIATION for r in drops)

    assoc.release()
    assoc2.release()


def test_read_revoked_mid_association_blocked_at_dimse_handler(gateway):
    registry, server = gateway
    registry.register("READER_A", ["read:ARCHIVE_A"])
    seed = synthetic_instance(patient_id="SEED002")
    server.archives["ARCHIVE_A"][seed.SOPInstanceUID] = seed

    assoc = connect("READER_A", server.port, "ARCHIVE_A", want_read=True)
    assert assoc.is_established
    assert _find_all(assoc)[-1][0].Status == 0x0000

    registry.revoke("READER_A", "read:ARCHIVE_A")

    results = _find_all(assoc)
    assert len(results) == 1
    assert results[0][0].Status == STATUS_DENIED

    finds = server.reached("EVT_C_FIND")
    assert [r.decision for r in finds] == ["allowed", "denied"]
    assert finds[-1].stage == STAGE_DIMSE

    assoc.release()


def test_unregistered_caller_rejected_at_negotiation(gateway):
    registry, server = gateway
    registry.register("READER_A", ["read:ARCHIVE_A"])

    assoc = connect("STRANGER", server.port, "ARCHIVE_A")
    assert assoc.is_rejected

    rejections = [r for r in server.blocked()
                  if r.decision == "association-rejected"]
    assert rejections and rejections[0].stage == STAGE_NEGOTIATION
    assert server.reached("EVT_C_FIND") == []
    assert server.reached("EVT_C_STORE") == []


def test_scope_is_per_route(gateway):
    registry, server = gateway
    registry.register("READER_A", ["read:ARCHIVE_A"])

    # read:ARCHIVE_A does not cover the ARCHIVE_B route.
    assoc = connect("READER_A", server.port, "ARCHIVE_B", want_read=True)
    assert assoc.is_established
    assert not assoc.accepted_contexts

    with pytest.raises(ValueError):
        _find_all(assoc)
    assert server.reached("EVT_C_FIND") == []

    drops = [r for r in server.blocked() if r.decision == "context-dropped"]
    assert drops and all(r.stage == STAGE_NEGOTIATION for r in drops)

    assoc.release()


def test_block_report_names_the_stage(gateway):
    registry, server = gateway
    registry.register("WRITER_A", ["write:ARCHIVE_A"])

    assoc = connect("WRITER_A", server.port, "ARCHIVE_A",
                    want_read=False, want_write=True)
    assert assoc.send_c_store(synthetic_instance()).Status == 0x0000
    registry.revoke("WRITER_A", "write:ARCHIVE_A")
    assert assoc.send_c_store(synthetic_instance()).Status == STATUS_DENIED
    assoc.release()

    report = server.block_report()
    assert any(STAGE_DIMSE in line and "EVT_C_STORE" in line for line in report)
