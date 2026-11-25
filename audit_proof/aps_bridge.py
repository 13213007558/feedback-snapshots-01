"""
Bridge between the stdlib audit envelope and real APScheduler events.

Importing this module requires APScheduler and its dependencies (installed in
the task's ``.venv``). It demonstrates that the low sensitivity proof event:

* can be produced from a real :class:`apscheduler.JobReleased` /
  :class:`apscheduler.JobResult` without copying the result body or exception
  details;
* is a native :class:`apscheduler.JobCompletionProof`, so the stock external
  event broker framing (``generate_notification`` /
  ``_reconstitute_event``) can serialize and reconstitute it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from apscheduler import JobCompletionProof, JobReleased, JobResult
from apscheduler.eventbrokers.base import BaseExternalEventBroker
from apscheduler.serializers.json import JSONSerializer

from .model import PublicCompletionEvent, canonical_result_digest, result_reference


class _ReconstitutionProbe(BaseExternalEventBroker):
    async def publish(self, event) -> None:  # pragma: no cover - unused
        raise NotImplementedError


def to_native(event: PublicCompletionEvent) -> JobCompletionProof:
    """Convert the stdlib envelope to the native APScheduler proof event."""
    return JobCompletionProof(
        event_id=UUID(event.event_id),
        job_id=UUID(event.job_id)
        if _is_uuid(event.job_id)
        else _uuid5_job(event.job_id),
        task_id=event.task_id,
        outcome=event.outcome,
        producer_id=event.producer_id,
        sequence=event.seq,
        ledger_ref=event.outbox_id or event.idempotency_key,
        result_ref=event.result_ref,
        result_digest=event.result_digest,
        schedule_id=event.schedule_id,
        finished_at=datetime.fromisoformat(event.finished_at),
        committed_at=(
            datetime.fromisoformat(event.committed_at)
            if event.committed_at
            else datetime.now(UTC)
        ),
    )


def from_native(proof: JobCompletionProof) -> PublicCompletionEvent:
    """Convert a native proof event back to the stdlib envelope."""
    return PublicCompletionEvent(
        event_id=str(proof.event_id),
        job_id=str(proof.job_id),
        task_id=proof.task_id,
        outcome=(
            proof.outcome.name if hasattr(proof.outcome, "name") else str(proof.outcome)
        ),
        producer_id=proof.producer_id,
        seq=proof.sequence,
        idempotency_key=proof.ledger_ref,
        outbox_id=proof.ledger_ref,
        result_ref=proof.result_ref,
        result_digest=proof.result_digest,
        schedule_id=proof.schedule_id,
        finished_at=proof.finished_at.isoformat(),
        committed_at=proof.committed_at.isoformat() if proof.committed_at else None,
    )


def proof_from_committed_result(
    result: JobResult,
    released: JobReleased | None = None,
    *,
    event_id: UUID,
    producer_id: str,
    sequence: int,
    ledger_ref: str,
    task_id: str,
    committed_at: datetime | None = None,
    include_result_digest: bool = True,
) -> JobCompletionProof:
    """
    Build a redacted proof from a committed :class:`JobResult`.

    The result's ``return_value`` and ``exception`` never leave this function
    through the proof event; at most a digest of a successful return value is
    attached for an separately authorized consumer.
    """
    committed = committed_at or datetime.now(UTC)
    digest = None
    result_ref = None
    if include_result_digest and result.return_value is not None:
        digest = canonical_result_digest(result.return_value)
        result_ref = result_reference(str(result.job_id))

    return JobCompletionProof.from_result(
        result,
        event_id=event_id,
        producer_id=producer_id,
        sequence=sequence,
        ledger_ref=ledger_ref,
        committed_at=committed,
        task_id=task_id,
        scheduler_id=released.scheduler_id if released else producer_id,
        schedule_id=released.schedule_id if released else None,
        result_ref=result_ref,
        result_digest=digest,
    )


def stock_broker_roundtrip(proof: JobCompletionProof) -> JobCompletionProof:
    """
    Serialize via the stock external-broker framing and reconstitute it.

    Exercises ``BaseExternalEventBroker.generate_notification`` and
    ``reconstitute_event`` (the latter internally calls
    ``_reconstitute_event``).
    """
    broker = _ReconstitutionProbe(serializer=JSONSerializer())
    frame = broker.generate_notification(proof)
    restored = broker.reconstitute_event(frame)
    if not isinstance(restored, JobCompletionProof):
        raise AssertionError(f"reconstitution returned {type(restored)!r}")
    return restored


def stock_broker_roundtrip_str(proof: JobCompletionProof) -> JobCompletionProof:
    broker = _ReconstitutionProbe(serializer=JSONSerializer())
    frame = broker.generate_notification_str(proof)
    restored = broker.reconstitute_event_str(frame)
    if not isinstance(restored, JobCompletionProof):
        raise AssertionError(f"reconstitution returned {type(restored)!r}")
    return restored


def frame_contains_secret(proof: JobCompletionProof, secret: str) -> bool:
    """Return whether the stock wire frame leaks the given secret material."""
    broker = _ReconstitutionProbe(serializer=JSONSerializer())
    frame = broker.generate_notification(proof)
    return secret.encode("utf-8") in frame


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _uuid5_job(job_id: str) -> UUID:
    from uuid import NAMESPACE_URL, uuid5

    return uuid5(NAMESPACE_URL, f"audit-proof-job/{job_id}")
