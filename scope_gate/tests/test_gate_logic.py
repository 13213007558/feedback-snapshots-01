"""Socket-free unit tests for the scope gate decision logic.

These drive the gateway's event handlers with lightweight fakes, so they
verify the same decisions the networked tests do - approved role/scope
snapshot at negotiation, live re-check after revocation, and the stage at
which each blocked message stops - without needing to bind a local port.
"""

from types import SimpleNamespace

from pynetdicom.presentation import PresentationContext
from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind as QRFind,
    SecondaryCaptureImageStorage,
)

from scope_gate.client import find_identifier, synthetic_instance
from scope_gate.registry import ScopeRegistry
from scope_gate.server import (
    STATUS_DENIED,
    STAGE_DIMSE,
    STAGE_NEGOTIATION,
    ScopedArchiveServer,
)


class FakeACSE:
    def __init__(self):
        self.rejected = None

    def send_reject(self, result, source, diagnostic):
        self.rejected = (result, source, diagnostic)


class FakeAssoc:
    """Just enough Association for the gate handlers."""

    def __init__(self, caller, route):
        self.requestor = SimpleNamespace(
            primitive=SimpleNamespace(
                calling_ae_title=caller,
                called_ae_title=route,
                presentation_context_definition_list=[],
            )
        )
        self.acceptor = SimpleNamespace(supported_contexts=[])
        self.acse = FakeACSE()


def make_server():
    registry = ScopeRegistry()
    server = ScopedArchiveServer.__new__(ScopedArchiveServer)
    server.registry = registry
    server.archives = {"ARCHIVE_A": {}, "ARCHIVE_B": {}}
    server.handler_log = []
    import threading

    server._lock = threading.Lock()
    return registry, server


def _context(sop):
    cx = PresentationContext()
    cx.abstract_syntax = sop
    return cx


def make_request_event(caller, route, requested_sops):
    assoc = FakeAssoc(caller, route)
    assoc.requestor.primitive.presentation_context_definition_list = [
        _context(sop) for sop in requested_sops
    ]
    assoc.acceptor.supported_contexts = [
        _context(sop) for sop in (QRFind, SecondaryCaptureImageStorage)
    ]
    return SimpleNamespace(assoc=assoc)


def test_negotiation_stamps_role_and_narrows_contexts():
    registry, server = make_server()
    registry.register("READER_A", ["read:ARCHIVE_A"])

    event = make_request_event("READER_A", "ARCHIVE_A",
                               [QRFind, SecondaryCaptureImageStorage])
    server._on_requested(event)

    assoc = event.assoc
    assert assoc.approved_role == "read-only"
    assert assoc.granted_scopes == frozenset({"read:ARCHIVE_A"})
    assert assoc.archive_route == "ARCHIVE_A"

    # Only the read SOP class survives on this association.
    remaining = {cx.abstract_syntax for cx in assoc.acceptor.supported_contexts}
    assert remaining == {QRFind}

    drops = [r for r in server.blocked() if r.decision == "context-dropped"]
    assert len(drops) == 1
    assert drops[0].stage == STAGE_NEGOTIATION
    assert "write:ARCHIVE_A" in drops[0].detail


def test_negotiation_rejects_unregistered_caller():
    registry, server = make_server()
    registry.register("READER_A", ["read:ARCHIVE_A"])

    event = make_request_event("STRANGER", "ARCHIVE_A", [QRFind])
    server._on_requested(event)

    assert event.assoc.acse.rejected == (0x01, 0x01, 0x03)
    rejections = [r for r in server.blocked()
                  if r.decision == "association-rejected"]
    assert rejections and rejections[0].stage == STAGE_NEGOTIATION


def test_negotiation_rejects_unknown_route():
    registry, server = make_server()
    registry.register("READER_A", ["read:ARCHIVE_A"])

    event = make_request_event("READER_A", "NOWHERE", [QRFind])
    server._on_requested(event)

    assert event.assoc.acse.rejected == (0x01, 0x01, 0x07)


def _dimse_event(assoc, **kwargs):
    return SimpleNamespace(assoc=assoc, **kwargs)


def _negotiated_assoc(server, caller, route):
    event = make_request_event(caller, route, [])
    server._on_requested(event)
    return event.assoc


def test_store_denied_after_revocation_on_open_association():
    registry, server = make_server()
    registry.register("WRITER_A", ["write:ARCHIVE_A"])
    assoc = _negotiated_assoc(server, "WRITER_A", "ARCHIVE_A")

    ok = server._on_c_store(_dimse_event(assoc, dataset=synthetic_instance()))
    assert ok == 0x0000
    assert len(server.archives["ARCHIVE_A"]) == 1

    registry.revoke("WRITER_A", "write:ARCHIVE_A")

    denied = server._on_c_store(_dimse_event(assoc, dataset=synthetic_instance()))
    assert denied == STATUS_DENIED
    assert len(server.archives["ARCHIVE_A"]) == 1

    stores = server.reached("EVT_C_STORE")
    assert [r.decision for r in stores] == ["allowed", "denied"]
    assert stores[-1].stage == STAGE_DIMSE


def test_find_denied_after_revocation_on_open_association():
    registry, server = make_server()
    registry.register("READER_A", ["read:ARCHIVE_A"])
    seed = synthetic_instance(patient_id="SEED")
    server.archives["ARCHIVE_A"][seed.SOPInstanceUID] = seed
    assoc = _negotiated_assoc(server, "READER_A", "ARCHIVE_A")

    first = list(server._on_c_find(_dimse_event(assoc, identifier=find_identifier())))
    assert first[-1][0] == 0xFF00  # pending with the seeded match

    registry.revoke("READER_A", "read:ARCHIVE_A")

    second = list(server._on_c_find(_dimse_event(assoc, identifier=find_identifier())))
    assert second == [(STATUS_DENIED, None)]

    finds = server.reached("EVT_C_FIND")
    assert [r.decision for r in finds] == ["allowed", "denied"]
    assert finds[-1].stage == STAGE_DIMSE


def test_scope_is_per_route():
    registry, server = make_server()
    registry.register("READER_A", ["read:ARCHIVE_A"])

    event = make_request_event("READER_A", "ARCHIVE_B", [QRFind])
    server._on_requested(event)

    assert event.assoc.approved_role == "none"
    assert event.assoc.acceptor.supported_contexts == []
    drops = [r for r in server.blocked() if r.decision == "context-dropped"]
    assert drops and all(r.stage == STAGE_NEGOTIATION for r in drops)


def test_block_report_names_stage_and_handler():
    registry, server = make_server()
    registry.register("WRITER_A", ["write:ARCHIVE_A"])
    assoc = _negotiated_assoc(server, "WRITER_A", "ARCHIVE_A")
    server._on_c_store(_dimse_event(assoc, dataset=synthetic_instance()))
    registry.revoke("WRITER_A", "write:ARCHIVE_A")
    server._on_c_store(_dimse_event(assoc, dataset=synthetic_instance()))

    report = server.block_report()
    assert len(report) == 1
    assert STAGE_DIMSE in report[0] and "EVT_C_STORE" in report[0]
    assert "WRITER_A" in report[0]
