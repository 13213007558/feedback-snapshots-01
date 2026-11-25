"""Runnable end-to-end demo of the scope-gated shared archive service.

Story:
  1. One pynetdicom SCP serves two archive routes (ARCHIVE_A / ARCHIVE_B).
  2. READER_A registers a read-only scope, WRITER_A a write-only scope.
  3. The association carries the approved role/scope from negotiation;
     out-of-scope presentation contexts never get accepted.
  4. WRITER_A's write scope is revoked *while its association is open*;
     the next C-STORE on that same connection is stopped at the
     DIMSE-handler stage, and the gateway's handler-reach log says so.

Run from the repository root:  .venv/bin/python -m scope_gate.demo
"""

from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind as QRFind,
)

from scope_gate.client import connect, find_identifier, synthetic_instance
from scope_gate.registry import ScopeRegistry
from scope_gate.server import ScopedArchiveServer


def main():
    registry = ScopeRegistry()
    registry.register("READER_A", ["read:ARCHIVE_A"])   # read-only client
    registry.register("WRITER_A", ["write:ARCHIVE_A"])  # one write permission

    server = ScopedArchiveServer(registry)
    print(f"shared SCP on 127.0.0.1:{server.port} "
          f"routes={list(server.archives)}")

    # -- read-only client: read allowed, write refused at negotiation -------
    reader = connect("READER_A", server.port, "ARCHIVE_A",
                     want_read=True, want_write=True)
    accepted = [cx.abstract_syntax.name for cx in reader.accepted_contexts]
    print(f"\nREADER_A established, accepted contexts: {accepted}")
    try:
        reader.send_c_store(synthetic_instance())
    except ValueError as exc:
        print(f"READER_A C-STORE stopped client-side: {exc}")

    # -- writer stores one synthetic instance -------------------------------
    writer = connect("WRITER_A", server.port, "ARCHIVE_A",
                     want_read=False, want_write=True)
    status = writer.send_c_store(synthetic_instance(patient_id="W001"))
    print(f"\nWRITER_A C-STORE #1 -> status 0x{status.Status:04X}")

    # -- reader sees it -------------------------------------------------------
    results = list(reader.send_c_find(find_identifier(), QRFind))
    found = [ds.PatientID for s, ds in results if s and s.Status == 0xFF00]
    print(f"READER_A C-FIND found PatientIDs: {found}")

    # -- revoke write while the writer's association is still open ------------
    registry.revoke("WRITER_A", "write:ARCHIVE_A")
    print("\n>> write:ARCHIVE_A revoked while WRITER_A stays connected")
    status = writer.send_c_store(synthetic_instance(patient_id="W002"))
    print(f"WRITER_A C-STORE #2 -> status 0x{status.Status:04X} "
          f"(refused on the still-open association)")

    reader.release()
    writer.release()

    print("\n-- handler-reach log (what the gateway actually touched) --")
    for r in server.handler_log:
        print(f"  {r.handler:<14} {r.stage:<24} {r.caller:<9} {r.decision}")
    print("\n-- block report: where each stopped message was caught --")
    for line in server.block_report():
        print(f"  {line}")

    server.shutdown()


if __name__ == "__main__":
    main()
