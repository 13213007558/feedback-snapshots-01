"""A single pynetdicom SCP serving several archive routes behind a scope gate.

Negotiation time (``EVT_REQUESTED``)
    The gate resolves the calling AE title against a :class:`ScopeRegistry`,
    stamps the *approved role* and *granted scope snapshot* onto the
    association itself, and narrows the association's own supported
    presentation contexts to whatever the grant covers. Requests outside the
    approved scope therefore fail at the association-negotiation stage (the
    peer gets a well-formed A-ASSOCIATE-AC with those contexts rejected).

Request time (``EVT_C_FIND`` / ``EVT_C_STORE``)
    Every incoming DIMSE request is re-checked against the *live* registry,
    so a scope revoked after the association was established still blocks
    later requests on that same connection - this time at the DIMSE-handler
    stage.

Every handler the gateway actually reaches is recorded in ``handler_log``;
reports about where traffic was stopped are derived from that log alone.
"""

import threading
from dataclasses import dataclass

from pynetdicom import AE, evt
from pynetdicom.sop_class import (
    PatientRootQueryRetrieveInformationModelFind,
    SecondaryCaptureImageStorage,
)

#: Stage names used in the handler log / block reports.
STAGE_NEGOTIATION = "association-negotiation"
STAGE_DIMSE = "dimse-handler"

#: SOP class UID -> operation keyword used in scope strings.
_OPERATION_BY_SOP = {
    PatientRootQueryRetrieveInformationModelFind: "read",
    SecondaryCaptureImageStorage: "write",
}

#: DIMSE failure status returned when a request is denied at handler stage.
STATUS_DENIED = 0x0122  # SOP class not supported (refused by the gate)


@dataclass
class HandlerRecord:
    """One entry in the gateway's handler-reach log."""

    handler: str
    stage: str
    caller: str
    route: str
    decision: str  # "allowed" | "context-dropped" | "association-rejected" | "denied"
    detail: str = ""


def _role_for(scopes, route):
    """Human-readable approved role for *scopes* limited to *route*."""
    can_read = f"read:{route}" in scopes
    can_write = f"write:{route}" in scopes
    if can_read and can_write:
        return "read-write"
    if can_read:
        return "read-only"
    if can_write:
        return "write-only"
    return "none"


class ScopedArchiveServer:
    """One SCP, several archive routes, scope-gated at two stages."""

    def __init__(self, registry, routes=("ARCHIVE_A", "ARCHIVE_B"), port=0):
        self.registry = registry
        self.archives: dict[str, dict[str, object]] = {r: {} for r in routes}
        self.handler_log: list[HandlerRecord] = []
        self._lock = threading.Lock()

        self.ae = AE(ae_title="SCOPE_GATE")
        for sop_uid in _OPERATION_BY_SOP:
            self.ae.add_supported_context(sop_uid)

        handlers = [
            (evt.EVT_REQUESTED, self._on_requested),
            (evt.EVT_C_FIND, self._on_c_find),
            (evt.EVT_C_STORE, self._on_c_store),
        ]
        self._server = self.ae.start_server(
            ("127.0.0.1", port), block=False, evt_handlers=handlers
        )

    @property
    def port(self):
        return self._server.server_address[1]

    def shutdown(self):
        self._server.shutdown()

    # -- logging / reporting -------------------------------------------------

    def _record(self, handler, stage, caller, route, decision, detail=""):
        with self._lock:
            self.handler_log.append(
                HandlerRecord(handler, stage, caller, route, decision, detail)
            )

    def reached(self, handler):
        """All log entries for *handler* - proof the handler was reached."""
        return [r for r in self.handler_log if r.handler == handler]

    def blocked(self):
        """Log entries where traffic was stopped, in arrival order."""
        return [r for r in self.handler_log if r.decision != "allowed"]

    def block_report(self):
        """One line per blocked message: who, what and at which stage."""
        return [
            f"[{r.stage}] {r.handler}: {r.caller} -> {r.route} "
            f"{r.decision} ({r.detail})"
            for r in self.blocked()
        ]

    # -- negotiation-stage gate ----------------------------------------------

    def _on_requested(self, event):
        assoc = event.assoc
        primitive = assoc.requestor.primitive
        caller = primitive.calling_ae_title.strip()
        route = primitive.called_ae_title.strip()

        if route not in self.archives:
            self._record(
                "EVT_REQUESTED", STAGE_NEGOTIATION, caller, route,
                "association-rejected", "unknown archive route",
            )
            assoc.acse.send_reject(0x01, 0x01, 0x07)
            return

        granted = self.registry.scopes_for(caller)
        if granted is None:
            self._record(
                "EVT_REQUESTED", STAGE_NEGOTIATION, caller, route,
                "association-rejected", "unregistered calling AE title",
            )
            assoc.acse.send_reject(0x01, 0x01, 0x03)
            return

        # The association itself carries the approved role and the scope
        # snapshot it was negotiated under.
        assoc.approved_role = _role_for(granted, route)
        assoc.granted_scopes = granted
        assoc.archive_route = route

        # Narrow this association's supported contexts to the granted scope;
        # anything else the peer asked for comes back rejected in the AC.
        allowed_sops = {
            sop
            for sop, operation in _OPERATION_BY_SOP.items()
            if f"{operation}:{route}" in granted
        }
        for cx in primitive.presentation_context_definition_list:
            operation = _OPERATION_BY_SOP.get(cx.abstract_syntax)
            need = f"{operation}:{route}" if operation else None
            if need is None or need not in granted:
                self._record(
                    "EVT_REQUESTED", STAGE_NEGOTIATION, caller, route,
                    "context-dropped",
                    f"{cx.abstract_syntax.name} requires scope "
                    f"'{need or 'unsupported-sop-class'}'",
                )
        assoc.acceptor.supported_contexts = [
            cx
            for cx in assoc.acceptor.supported_contexts
            if cx.abstract_syntax in allowed_sops
        ]

        self._record(
            "EVT_REQUESTED", STAGE_NEGOTIATION, caller, route, "allowed",
            f"role={assoc.approved_role} scopes={sorted(granted)}",
        )

    # -- request-stage gate ----------------------------------------------------

    def _live_check(self, event, operation):
        """Re-check the *current* registry state for this association."""
        assoc = event.assoc
        caller = assoc.requestor.primitive.calling_ae_title.strip()
        route = assoc.archive_route
        need = f"{operation}:{route}"
        live = self.registry.scopes_for(caller) or frozenset()
        return caller, route, need, need in live

    def _on_c_find(self, event):
        caller, route, need, ok = self._live_check(event, "read")
        if not ok:
            self._record(
                "EVT_C_FIND", STAGE_DIMSE, caller, route, "denied",
                f"scope '{need}' not currently granted",
            )
            yield STATUS_DENIED, None
            return

        self._record("EVT_C_FIND", STAGE_DIMSE, caller, route, "allowed")
        identifier = event.identifier
        for stored in list(self.archives[route].values()):
            if _matches(stored, identifier):
                reply = type(identifier)()
                for elem in identifier:
                    if elem.keyword and elem.keyword in stored:
                        reply.add(stored[elem.keyword])
                yield 0xFF00, reply

    def _on_c_store(self, event):
        caller, route, need, ok = self._live_check(event, "write")
        if not ok:
            self._record(
                "EVT_C_STORE", STAGE_DIMSE, caller, route, "denied",
                f"scope '{need}' not currently granted",
            )
            return STATUS_DENIED

        ds = event.dataset
        self.archives[route][ds.SOPInstanceUID] = ds
        self._record(
            "EVT_C_STORE", STAGE_DIMSE, caller, route, "allowed",
            f"stored SOPInstanceUID={ds.SOPInstanceUID}",
        )
        return 0x0000


def _matches(stored, identifier):
    """True if *stored* matches every non-empty value in *identifier*."""
    for elem in identifier:
        if elem.keyword == "QueryRetrieveLevel":
            continue
        if elem.value in (None, "", "*"):
            continue
        if str(getattr(stored, elem.keyword, "")) != str(elem.value):
            return False
    return True
