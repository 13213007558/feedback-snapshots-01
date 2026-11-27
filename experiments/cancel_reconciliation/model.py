"""Append-only reconciliation ledger and the verdict rules.

The model deliberately keeps the three evidence channels independent.  Every
observation is written once and never mutated; reconciliation is a pure,
re-runnable function over the ledger.  That mirrors how an on-call engineer
would reconstruct an incident from immutable logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


class Channel(str, Enum):
    API = 'api'
    CONTROL = 'control'
    EVENT = 'event'


# Verdict labels.  Anything other than INTERRUPTED / SUCCEEDED is a form of
# "the evidence in hand cannot decide the question".
class Verdict(str, Enum):
    INTERRUPTED = 'INTERRUPTED'                 # an attempt ended in REVOKED
    SUCCEEDED = 'SUCCEEDED'                     # an attempt ended in SUCCESS
    CONFLICTED = 'CONFLICTED'                   # different attempts ended
                                                # differently (retry ambiguity)
    AMBIGUOUS_TERMINAL = 'AMBIGUOUS_TERMINAL'   # two terminals for ONE attempt
                                                # (reorder / duplicate; the
                                                # last-arrived wins in Celery)
    CANCEL_REQUESTED_ONLY = 'CANCEL_REQUESTED_ONLY'  # accepted, no terminal
    NO_EVIDENCE = 'NO_EVIDENCE'                 # nothing recorded for the id


# Celery terminal event types that close an attempt.
TERMINAL_EVENTS = frozenset({'task-succeeded', 'task-failed',
                             'task-revoked', 'task-rejected'})
REVOKED_EVENT = 'task-revoked'
SUCCEEDED_EVENT = 'task-succeeded'


@dataclass(frozen=True)
class Attempt:
    """Identity of one concrete execution.

    ``task_id`` alone is not a unique attempt key in Celery: a retry reuses
    the same id and a late result from a previous attempt carries the same id
    too.  ``attempt_no`` is the extra correlation the platform must record
    (see docs) to tell those executions apart.
    """

    task_id: str
    attempt_no: int = 0

    def __str__(self) -> str:
        return f'{self.task_id}#attempt{self.attempt_no}'


@dataclass(frozen=True)
class EvidenceRecord:
    """One immutable observation pulled from a single channel."""

    seq: int                    # local append order (arrival order)
    task_id: str
    channel: Channel
    kind: str                   # api: revoke-http; control: revoke-reply;
                                # event: task-* event type
    observed_at: float          # monotonic local receive time
    attempt_no: Optional[int] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    # Logical ordering hint carried by events (celery ``clock``).  None when
    # the channel cannot supply one (HTTP reply, control reply without clock).
    clock: Optional[int] = None
    # True when the record is known to be a re-delivery / duplicate, only
    # knowable if the transport tags an idempotency / delivery id.
    duplicate: bool = False


class Ledger:
    """Append-only store of evidence records keyed by task id."""

    def __init__(self) -> None:
        self._rows: List[EvidenceRecord] = []
        self._by_task: Dict[str, List[EvidenceRecord]] = {}

    def append(self, task_id: str, channel: Channel, kind: str,
               observed_at: float, *, attempt_no: Optional[int] = None,
               payload: Optional[Dict[str, Any]] = None,
               clock: Optional[int] = None,
               duplicate: bool = False) -> EvidenceRecord:
        record = EvidenceRecord(
            seq=len(self._rows), task_id=task_id, channel=channel,
            kind=kind, observed_at=observed_at, attempt_no=attempt_no,
            payload=dict(payload or {}), clock=clock, duplicate=duplicate)
        self._rows.append(record)
        self._by_task.setdefault(task_id, []).append(record)
        return record

    def records(self, task_id: str) -> List[EvidenceRecord]:
        return list(self._by_task.get(task_id, ()))

    def all_records(self) -> List[EvidenceRecord]:
        return list(self._rows)

    def __len__(self) -> int:
        return len(self._rows)


@dataclass
class Reconciliation:
    task_id: str
    verdict: Verdict
    # What each channel independently supports, for the incident write-up.
    channel_evidence: Dict[str, List[str]]
    # Time bounds inside which the outcome genuinely cannot be decided.
    undecidable_windows: List[Dict[str, float]] = field(default_factory=list)
    # Extra records that would collapse an undecidable window into a verdict.
    missing_records: List[str] = field(default_factory=list)
    # Terminal attempts actually observed, keyed by attempt number (last
    # terminal kind seen for that attempt).
    terminals: Dict[int, str] = field(default_factory=dict)


class Reconciler:
    """Pure functions turning a ledger into per-task reconciliations."""

    def reconcile(self, ledger: Ledger, task_id: str) -> Reconciliation:
        rows = ledger.records(task_id)
        if not rows:
            return Reconciliation(
                task_id, Verdict.NO_EVIDENCE,
                channel_evidence={c.value: [] for c in Channel},
                missing_records=['any observation for this task id'])

        channel_evidence: Dict[str, List[str]] = {
            Channel.API.value: [], Channel.CONTROL.value: [],
            Channel.EVENT.value: []}
        # attempt_no -> every terminal kind observed for that attempt, in
        # arrival order.  More than one entry for a single attempt is the
        # reorder / late-duplicate signature.
        terminals: Dict[int, List[str]] = {}
        revoke_reply_seen = False
        http_accept_seen = False

        for row in rows:
            if row.channel == Channel.API and row.kind == 'revoke-http':
                http_accept_seen = True
                channel_evidence[Channel.API.value].append(
                    f'seq{row.seq}: revoke request accepted locally '
                    f'(HTTP {row.payload.get("status")})')
            elif row.channel == Channel.CONTROL and row.kind == 'revoke-reply':
                revoke_reply_seen = True
                channel_evidence[Channel.CONTROL.value].append(
                    f'seq{row.seq}: worker {row.payload.get("worker")} '
                    f'processed revoke command (ok={row.payload.get("ok")})')
            elif row.channel == Channel.EVENT and row.kind in TERMINAL_EVENTS:
                attempt = row.attempt_no or 0
                terminals.setdefault(attempt, []).append(row.kind)
                channel_evidence[Channel.EVENT.value].append(
                    f'seq{row.seq}: {row.kind} for attempt {attempt} '
                    f'(clock={row.clock}, duplicate={row.duplicate})')

        verdict = self._verdict(http_accept_seen, revoke_reply_seen, terminals)
        windows = self._undecidable_windows(rows, terminals)
        missing = self._missing_records(
            http_accept_seen, revoke_reply_seen, terminals)

        return Reconciliation(
            task_id, verdict, channel_evidence,
            undecidable_windows=windows, missing_records=missing,
            terminals={attempt: kinds[-1] for attempt, kinds in
                       terminals.items()})

    @staticmethod
    def _verdict(http_accept: bool, control_reply: bool,
                 terminals: Dict[int, List[str]]) -> Verdict:
        # 1) A single attempt carrying two different terminals cannot be read
        #    as one clean outcome: Celery keeps the last-arrived state, but
        #    causal order is unknown. This is the C/D reorder ambiguity.
        for kinds in terminals.values():
            distinct = set(kinds)
            if len(distinct) > 1:
                return Verdict.AMBIGUOUS_TERMINAL

        flat = {kind for kinds in terminals.values() for kind in kinds}
        has_revoked = REVOKED_EVENT in flat
        has_success = SUCCEEDED_EVENT in flat
        # 2) Different attempts with different terminals: a retry/late result
        #    under the same id.  The id-level answer is conflicted.
        if has_revoked and has_success:
            return Verdict.CONFLICTED
        if has_revoked:
            return Verdict.INTERRUPTED
        if has_success or flat:
            return Verdict.SUCCEEDED
        if http_accept or control_reply:
            return Verdict.CANCEL_REQUESTED_ONLY
        return Verdict.NO_EVIDENCE

    @staticmethod
    def _undecidable_windows(rows: Iterable[EvidenceRecord],
                             terminals: Dict[int, List[str]]
                             ) -> List[Dict[str, float]]:
        rows = list(rows)
        first = rows[0].observed_at
        terminal_rows = [r for r in rows if r.kind in TERMINAL_EVENTS]
        if not terminal_rows:
            # The whole observation window stays undecidable: no terminal.
            return [{'from': first, 'to': rows[-1].observed_at,
                     'reason': 'no terminal event ever observed'}]
        last_terminal = max(r.observed_at for r in terminal_rows)
        # Gap between the first local accept and the first terminal: in that
        # interval the API/control success already happened but the task's own
        # fate was still unknown.
        first_accept = min((r.observed_at for r in rows
                            if r.kind in ('revoke-http', 'revoke-reply')),
                           default=None)
        if first_accept is not None and first_accept < last_terminal:
            return [{'from': first_accept, 'to': last_terminal,
                     'reason': 'cancel acknowledged before task terminal was '
                               'observed; interruption not yet provable'}]
        return []

    @staticmethod
    def _missing_records(http_accept: bool, control_reply: bool,
                         terminals: Dict[int, List[str]]) -> List[str]:
        missing: List[str] = []
        if not terminals:
            missing.append(
                'terminal task event (task-revoked/task-succeeded) with '
                'attempt correlation id')
        if any(len(set(kinds)) > 1 for kinds in terminals.values()):
            missing.append(
                'worker-side authoritative terminal + delivery id to choose '
                'between reordered/duplicated terminals on one attempt')
        if not control_reply:
            missing.append(
                'control-bus reply with reply=True (proves a worker handled '
                'the revoke command)')
        if not http_accept:
            missing.append('HTTP accept record from the revoke API call')
        # The retry / late-result ambiguity can only be broken with an
        # attempt-scoped correlation on every event and backend result.
        missing.append(
            'attempt_no / delivery id on each event and result-backend entry '
            'to disambiguate retries and late duplicate results')
        return missing
