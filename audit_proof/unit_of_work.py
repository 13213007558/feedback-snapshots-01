"""
Committed state and the atomic completion/outbox unit of work.

``CommittedState`` is the simulated durable source of truth. It only ever
contains facts whose transaction committed. A completion fact and its outbox
message are staged together in :class:`AuditUnitOfWork` and become visible
atomically on commit; a rollback leaves neither behind.

This mirrors the production recommendation: write the job result, the audit
fact and the outbox row in one database transaction; publish the public event
only from the outbox after commit.
"""

from __future__ import annotations

import dataclasses

from .model import (
    PublicCompletionEvent,
    completion_idempotency_key,
    stable_event_id,
    utc_now_iso,
)

PENDING = "pending"
PUBLISHED = "published"


class SaveRolledBack(RuntimeError):
    """Raised to simulate a failure that rolls the save transaction back."""


@dataclasses.dataclass(frozen=True)
class CompletionFact:
    """The committed truth about how a job ended."""

    job_id: str
    task_id: str
    outcome: str
    event_id: str
    outbox_id: str
    producer_id: str
    seq: int
    idempotency_key: str
    result_ref: str | None
    result_digest: str | None
    finished_at: str
    committed_at: str
    scheduler_id: str | None = None
    schedule_id: str | None = None


@dataclasses.dataclass
class OutboxMessage:
    """A replayable public event stored atomically with the completion fact."""

    outbox_id: str
    event_id: str
    job_id: str
    producer_id: str
    seq: int
    event: PublicCompletionEvent
    status: str = PENDING
    attempts: int = 0
    last_error: str | None = None
    created_at: str = dataclasses.field(default_factory=utc_now_iso)
    published_at: str | None = None

    def mark_attempt(self, error: BaseException | None = None) -> None:
        self.attempts += 1
        if error is None:
            self.status = PUBLISHED
            self.published_at = utc_now_iso()
            self.last_error = None
        else:
            self.status = PENDING
            self.last_error = f"{type(error).__name__}: {error}"


class CommittedState:
    """In memory simulation of the durable ledger + transactional outbox."""

    def __init__(self) -> None:
        self.facts: dict[str, CompletionFact] = {}
        self.outbox: dict[str, OutboxMessage] = {}
        self._seq_by_producer: dict[str, int] = {}
        self.commits: list[str] = []
        self.rollbacks: list[str] = []

    def next_seq(self, producer_id: str) -> int:
        self._seq_by_producer[producer_id] = (
            self._seq_by_producer.get(producer_id, 0) + 1
        )
        return self._seq_by_producer[producer_id]

    def preview_seq(self, producer_id: str, staged_count: int) -> int:
        return self._seq_by_producer.get(producer_id, 0) + staged_count + 1

    def outbox_for_job(self, job_id: str) -> list[OutboxMessage]:
        return [m for m in self.outbox.values() if m.job_id == job_id]

    def outbox_by_seq(self, producer_id: str, seq: int) -> OutboxMessage | None:
        for message in self.outbox.values():
            if message.producer_id == producer_id and message.seq == seq:
                return message
        return None

    def apply(
        self,
        facts: dict[str, CompletionFact],
        messages: dict[str, OutboxMessage],
    ) -> None:
        self.facts.update(facts)
        self.outbox.update(messages)
        for message in messages.values():
            current = self._seq_by_producer.get(message.producer_id, 0)
            if message.seq > current:
                self._seq_by_producer[message.producer_id] = message.seq
        self.commits.append(utc_now_iso())

    def note_rollback(self, label: str) -> None:
        self.rollbacks.append(label)


class AuditUnitOfWork:
    """
    Stage a completion fact plus its outbox event in one transaction.

    Usage::

        with AuditUnitOfWork(state, producer_id="scheduler-1") as uow:
            event = uow.stage_completion(job_id=..., ...)
            # ... any other transactional writes ...
            # raise here (or pass fail_save=True) => rollback, nothing visible

    On clean exit the staged fact/outbox row are applied atomically.
    """

    def __init__(
        self,
        state: CommittedState,
        *,
        producer_id: str,
        ledger_revision: str = "commit-1",
        label: str = "completion",
    ) -> None:
        self.state = state
        self.producer_id = producer_id
        self.ledger_revision = ledger_revision
        self.label = label
        self._facts: dict[str, CompletionFact] = {}
        self._messages: dict[str, OutboxMessage] = {}
        self._closed = False

    def __enter__(self) -> AuditUnitOfWork:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._closed = True
        if exc is not None:
            self._facts.clear()
            self._messages.clear()
            self.state.note_rollback(self.label)
            return False
        self.state.apply(self._facts, self._messages)
        return False

    def stage_completion(
        self,
        *,
        job_id: str,
        task_id: str,
        outcome: str,
        result_ref: str | None = None,
        result_digest: str | None = None,
        schedule_id: str | None = None,
        scheduler_id: str | None = None,
        finished_at: str | None = None,
        fail_save: bool = False,
    ) -> PublicCompletionEvent:
        """Stage the completion fact and matching outbox row."""
        if self._closed:
            raise RuntimeError("cannot stage on a closed unit of work")

        staged_for_producer = sum(
            1 for m in self._messages.values() if m.producer_id == self.producer_id
        )
        seq = self.state.preview_seq(self.producer_id, staged_for_producer)
        idempotency_key = completion_idempotency_key(
            producer_id=self.producer_id,
            job_id=job_id,
            outcome=outcome,
            ledger_revision=self.ledger_revision,
        )
        event_id = stable_event_id(idempotency_key)
        outbox_id = f"outbox-{self.producer_id}-{seq:04d}"
        now = utc_now_iso()
        finished = finished_at or now

        event = PublicCompletionEvent(
            event_id=event_id,
            job_id=job_id,
            task_id=task_id,
            outcome=outcome,
            producer_id=self.producer_id,
            seq=seq,
            idempotency_key=idempotency_key,
            outbox_id=outbox_id,
            result_ref=result_ref,
            result_digest=result_digest,
            schedule_id=schedule_id,
            finished_at=finished,
            committed_at=now,
        )
        fact = CompletionFact(
            job_id=job_id,
            task_id=task_id,
            outcome=outcome,
            event_id=event_id,
            outbox_id=outbox_id,
            producer_id=self.producer_id,
            seq=seq,
            idempotency_key=idempotency_key,
            result_ref=result_ref,
            result_digest=result_digest,
            finished_at=finished,
            committed_at=now,
            scheduler_id=scheduler_id or self.producer_id,
            schedule_id=schedule_id,
        )
        message = OutboxMessage(
            outbox_id=outbox_id,
            event_id=event_id,
            job_id=job_id,
            producer_id=self.producer_id,
            seq=seq,
            event=event,
        )

        if fail_save:
            raise SaveRolledBack("injected failure while saving completion")

        self._facts[job_id] = fact
        self._messages[outbox_id] = message
        return event


def make_unbound_early_event(
    *,
    job_id: str,
    task_id: str,
    outcome: str,
    producer_id: str,
    seq: int,
) -> PublicCompletionEvent:
    """
    Build the unsafe notification a caller may emit before commit.

    It looks like a normal job-finished event but has no ledger/outbox binding
    and no commit timestamp. If the save then rolls back, reconcilers classify
    it as an early/phantom event rather than proof of completion.
    """
    key = f"early|{producer_id}|{job_id}|{outcome}|{seq}"
    return PublicCompletionEvent(
        event_id=stable_event_id(key),
        job_id=job_id,
        task_id=task_id,
        outcome=outcome,
        producer_id=producer_id,
        seq=seq,
        idempotency_key=key,
        kind="JobReleased",
        outbox_id=None,
        result_ref=None,
        result_digest=None,
        committed_at=None,
    )
