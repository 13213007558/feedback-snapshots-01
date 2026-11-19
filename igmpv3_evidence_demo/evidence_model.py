"""Finite offline evidence model for IGMPv3 membership reports.

The model deliberately reconstructs only what an IGMPv3 receiver interface
state (RFC 3376 section 4.2) looks like through the reports observed on one
ingress port. It is not a multicast forwarding table: queries, other
receivers, Layer 2 snooping internals and the actual data plane are outside
the transcript.

Record kinds follow RFC 3376:
  * Current-State Records (CSR): rtype 1 MODE_IS_INCLUDE, 2 MODE_IS_EXCLUDE.
  * State-Change Records (SCR): rtype 3 CHANGE_TO_INCLUDE_MODE,
    4 CHANGE_TO_EXCLUDE_MODE, 5 ALLOW_NEW_SOURCES, 6 BLOCK_OLD_SOURCES.

ALLOW/BLOCK are incremental edits to the source set of the *current*
interface state, not new interface states:
  * ALLOW_NEW_SOURCES adds the listed sources.
  * BLOCK_OLD_SOURCES removes the listed sources.
  * CHANGE_TO_* replaces both filter mode and source set outright.
"""

from dataclasses import dataclass, field

MODE_IS_INCLUDE = 1
MODE_IS_EXCLUDE = 2
CHANGE_TO_INCLUDE_MODE = 3
CHANGE_TO_EXCLUDE_MODE = 4
ALLOW_NEW_SOURCES = 5
BLOCK_OLD_SOURCES = 6

CURRENT_STATE_RECORDS = frozenset({MODE_IS_INCLUDE, MODE_IS_EXCLUDE})
STATE_CHANGE_RECORDS = frozenset(
    {
        CHANGE_TO_INCLUDE_MODE,
        CHANGE_TO_EXCLUDE_MODE,
        ALLOW_NEW_SOURCES,
        BLOCK_OLD_SOURCES,
    }
)

RTYPE_NAME = {
    MODE_IS_INCLUDE: "MODE_IS_INCLUDE",
    MODE_IS_EXCLUDE: "MODE_IS_EXCLUDE",
    CHANGE_TO_INCLUDE_MODE: "CHANGE_TO_INCLUDE_MODE",
    CHANGE_TO_EXCLUDE_MODE: "CHANGE_TO_EXCLUDE_MODE",
    ALLOW_NEW_SOURCES: "ALLOW_NEW_SOURCES",
    BLOCK_OLD_SOURCES: "BLOCK_OLD_SOURCES",
}

INCLUDE = "INCLUDE"
EXCLUDE = "EXCLUDE"


@dataclass(frozen=True)
class RecordObservation:
    """One group record decoded from an IGMPv3 membership report frame."""

    frame_id: str
    timestamp: int
    port_id: str
    rtype: int
    group: str
    sources: frozenset[str]
    sender_ip: str

    @property
    def is_current_state(self) -> bool:
        return self.rtype in CURRENT_STATE_RECORDS

    def signature(self) -> tuple[str, int, frozenset[str]]:
        """Identity used to detect retransmitted state-change records."""
        return (self.group, self.rtype, self.sources)


@dataclass(frozen=True)
class QueryObservation:
    """A membership query seen on the wire. Queries prove no membership."""

    frame_id: str
    timestamp: int
    group: str


@dataclass
class GapObservation:
    """A trusted capture-gap marker for a port, in seconds."""

    frame_id: str
    timestamp: int
    port_id: str
    lost_seconds: int


@dataclass
class GroupEvidence:
    """Reconstructed, evidence-bounded state for one (port, group).

    The state is anchored by Current-State Records. Before the first anchor,
    or while the timer is expired, or after an un-repaired capture gap, the
    interface state cannot be proved from the transcript.
    """

    port_id: str
    group: str
    filter_mode: str | None = None
    source_set: frozenset[str] = frozenset()
    anchor_frame_id: str | None = None
    anchor_timestamp: int | None = None
    last_report_timestamp: int | None = None
    unanchored_scr: list[RecordObservation] = field(default_factory=list)
    pending_edits: list[RecordObservation] = field(default_factory=list)
    seen_scr_signatures: set[tuple[str, int, frozenset[str]]] = field(
        default_factory=set
    )
    gap_open: bool = False
    gap_frame_id: str | None = None
    facts: list[RecordObservation] = field(default_factory=list)

    def membership_expiry(self, gmi: int) -> int | None:
        if self.last_report_timestamp is None:
            return None
        return self.last_report_timestamp + gmi


@dataclass
class Verdict:
    """Authorization conclusion for one (port, group, source) at one time."""

    timestamp: int
    port_id: str
    group: str
    source: str
    decision: str
    reason: str
    evidence_refs: list[str]
    preconditions: list[str]


class MembershipEvidenceEngine:
    """Fixed-clock, transcript-driven membership evidence engine.

    Time only moves through :meth:`advance`, so expiry is reproducible and
    independent of the wall clock.
    """

    def __init__(self, group_membership_interval: int):
        self.gmi = group_membership_interval
        self.now = 0
        self.states: dict[tuple[str, str], GroupEvidence] = {}
        self.port_gaps: dict[str, GapObservation] = {}
        self.query_log: list[QueryObservation] = []
        self.gap_log: list[GapObservation] = []

    def _state(self, port_id: str, group: str) -> GroupEvidence:
        key = (port_id, group)
        state = self.states.get(key)
        if state is None:
            state = GroupEvidence(port_id, group)
            self.states[key] = state
            gap = self.port_gaps.get(port_id)
            if gap is not None:
                # The group is first mentioned after loss was already signaled.
                state.gap_open = True
                state.gap_frame_id = gap.frame_id
        return state

    def advance(self, timestamp: int) -> None:
        """Move the fixed clock; expiry is evaluated lazily on read."""
        if timestamp < self.now:
            raise ValueError("the fixed clock cannot move backwards")
        self.now = timestamp

    def record_gap(self, gap: GapObservation) -> None:
        self.advance(gap.timestamp)
        self.gap_log.append(gap)
        self.port_gaps[gap.port_id] = gap
        # A port-wide gap invalidates every group already seen on that port.
        for (port_id, _), state in self.states.items():
            if port_id == gap.port_id:
                state.gap_open = True
                state.gap_frame_id = gap.frame_id

    def record_query(self, query: QueryObservation) -> None:
        self.advance(query.timestamp)
        self.query_log.append(query)

    def ingest_record(self, record: RecordObservation) -> None:
        self.advance(record.timestamp)
        state = self._state(record.port_id, record.group)
        state.facts.append(record)
        state.last_report_timestamp = record.timestamp
        if record.is_current_state:
            self._apply_current_state(state, record)
        else:
            self._apply_state_change(state, record)

    def _apply_current_state(
        self, state: GroupEvidence, record: RecordObservation
    ) -> None:
        # A CSR is the receiver's full current snapshot: it replaces the
        # modeled mode/source set, re-anchors the state and repairs the gap.
        state.filter_mode = (
            INCLUDE if record.rtype == MODE_IS_INCLUDE else EXCLUDE
        )
        state.source_set = frozenset(record.sources)
        state.anchor_frame_id = record.frame_id
        state.anchor_timestamp = record.timestamp
        state.gap_open = False
        state.gap_frame_id = None
        state.pending_edits = []
        state.unanchored_scr = []
        self.port_gaps.pop(state.port_id, None)

    def _apply_state_change(
        self, state: GroupEvidence, record: RecordObservation
    ) -> None:
        signature = record.signature()
        duplicate = signature in state.seen_scr_signatures
        if duplicate:
            # Retransmission of an SCR (RFC 3376 robustness retransmission):
            # the receiver repeats the delta, it must not be applied twice.
            return
        state.seen_scr_signatures.add(signature)
        if state.anchor_frame_id is None:
            # No CSR has ever anchored this group; a delta cannot describe the
            # base state it edits. Hold it until a snapshot arrives.
            state.unanchored_scr.append(record)
            return
        if state.gap_open:
            # Edits that land after an un-repaired capture loss cannot be
            # placed relative to the missed frames.
            state.pending_edits.append(record)
            return
        self._edit_state(state, record)

    @staticmethod
    def _edit_state(
        state: GroupEvidence, record: RecordObservation
    ) -> None:
        if record.rtype == CHANGE_TO_INCLUDE_MODE:
            state.filter_mode = INCLUDE
            state.source_set = frozenset(record.sources)
        elif record.rtype == CHANGE_TO_EXCLUDE_MODE:
            state.filter_mode = EXCLUDE
            state.source_set = frozenset(record.sources)
        elif record.rtype == ALLOW_NEW_SOURCES:
            state.source_set = state.source_set | record.sources
        else:  # BLOCK_OLD_SOURCES
            state.source_set = state.source_set - record.sources

    def _boundary(
        self, state: GroupEvidence
    ) -> tuple[str | None, str | None, list[str]]:
        """Return (boundary code, boundary frame, applicable preconditions)."""
        if state.anchor_frame_id is None:
            return (
                "NO_CURRENT_STATE_ANCHOR",
                None,
                [
                    "No Current-State Record anchors this (port, group); "
                    "state-change deltas alone cannot establish the base "
                    "interface state.",
                ],
            )
        if state.gap_open:
            return (
                "CAPTURE_GAP_UNREPAIRED",
                state.gap_frame_id,
                [
                    "The capture gap marker is still open for this port; "
                    "frames inside the gap are absent from the transcript.",
                    "State-change records after the gap are held as pending "
                    "until the next Current-State Record.",
                ],
            )
        expiry = state.membership_expiry(self.gmi)
        if expiry is not None and self.now >= expiry:
            return (
                "MEMBERSHIP_TIMER_EXPIRED",
                state.anchor_frame_id,
                [
                    f"No report for this (port, group) refreshed the timer "
                    f"within the fixed GMI of {self.gmi} s; expiry at t={expiry}.",
                    "Timer expiry means membership is no longer provable, not "
                    "that the receiver demonstrably left the group.",
                ],
            )
        return None, None, []

    def evaluate(
        self,
        port_id: str,
        group: str,
        source: str,
        policy_reason: str,
    ) -> Verdict:
        """Combine trusted provisioning with the evidence-bounded state."""
        state = self.states.get((port_id, group))
        refs: list[str] = []
        preconditions: list[str] = []
        if state is not None:
            refs = [fact.frame_id for fact in state.facts]
        if policy_reason != "PERMITTED":
            # Authorization fails closed regardless of what was reported.
            return Verdict(
                self.now,
                port_id,
                group,
                source,
                "DENY",
                policy_reason,
                refs,
                [
                    "The port/group/source triple is absent from the trusted "
                    "provisioning; receiver-reported addresses carry no "
                    "authorization.",
                ],
            )
        if state is None:
            return Verdict(
                self.now,
                port_id,
                group,
                source,
                "NOT_PROVABLE",
                "NO_REPORT_OBSERVED",
                refs,
                [
                    "No membership report for this (port, group) exists in the "
                    "transcript at or before this time.",
                ],
            )
        boundary, boundary_frame, boundary_pre = self._boundary(state)
        if boundary is not None:
            evidence = [boundary_frame] if boundary_frame else []
            return Verdict(
                self.now,
                port_id,
                group,
                source,
                "NOT_PROVABLE",
                boundary,
                evidence,
                boundary_pre,
            )
        preconditions = [
            f"State is anchored by Current-State Record {state.anchor_frame_id} "
            f"at t={state.anchor_timestamp}.",
            f"Membership timer last refreshed at t={state.last_report_timestamp}, "
            f"expires at t={state.membership_expiry(self.gmi)}.",
            "The capture is complete for this port between the anchor and now "
            "(no open gap marker).",
        ]
        if state.filter_mode == INCLUDE:
            if source in state.source_set:
                return Verdict(
                    self.now,
                    port_id,
                    group,
                    source,
                    "ALLOW",
                    "INCLUDE_MATCH",
                    refs,
                    preconditions,
                )
            return Verdict(
                self.now,
                port_id,
                group,
                source,
                "DENY",
                "SOURCE_NOT_IN_INCLUDE_SET",
                refs,
                preconditions,
            )
        # EXCLUDE: membership of the group is provable, but the source set is
        # the explicit exclusion list rather than an enumeration of senders.
        if source in state.source_set:
            return Verdict(
                self.now,
                port_id,
                group,
                source,
                "DENY",
                "SOURCE_IN_EXCLUDE_SET",
                refs,
                preconditions,
            )
        return Verdict(
            self.now,
            port_id,
            group,
            source,
            "ALLOW",
            "EXCLUDE_NOT_BLOCKED",
            refs,
            preconditions,
        )
