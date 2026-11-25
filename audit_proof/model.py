"""
Low sensitivity public event model for job completion audit.

The event in this module is the *only* thing a subscriber on the public event
bus needs to receive. It carries correlation and integrity material, but
never the business result body. The core model uses only the Python standard
library so the simulation can run in any Python 3.12 interpreter; the optional
APScheduler integration lives in :mod:`audit_proof.aps_bridge`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

PROOF_KIND = "JobCompletionProof"
EARLY_KIND = "JobReleased"
SCHEMA_VERSION = 1

_NAMESPACE = uuid.UUID("7f3c9a14-2b6e-4d8a-9c51-6f0e2a7b8d11")


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def stable_event_id(idempotency_key: str) -> str:
    """
    Derive the stable wire event id from an idempotency key.

    Redeliveries of the same logical event derive the same id, which is what
    lets consumers distinguish duplicates from distinct completions.
    """
    return str(uuid.uuid5(_NAMESPACE, idempotency_key))


def completion_idempotency_key(
    *, producer_id: str, job_id: str, outcome: str, ledger_revision: str
) -> str:
    """Build the deterministic idempotency key for one job completion."""
    return f"completion|{producer_id}|{job_id}|{outcome}|{ledger_revision}"


def canonical_result_digest(result_body: Any) -> str:
    """
    Compute the integrity digest of a business result body.

    The digest lets an separately authorized caller confirm that the body they
    fetched is the exact one the proof references, without putting the body on
    the event bus.
    """
    canonical = json.dumps(
        result_body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def result_reference(job_id: str) -> str:
    """Return the opaque, authorization gated reference for a job result."""
    return f"apscheduler://job-results/{job_id}"


class Outcome(str, Enum):
    """Job outcomes relevant to the audit demonstration."""

    success = "success"
    error = "error"
    abandoned = "abandoned"
    cancelled = "cancelled"
    missed_start_deadline = "missed_start_deadline"


@dataclasses.dataclass(frozen=True)
class PublicCompletionEvent:
    """
    Result free, replayable public event.

    ``event_id`` is stable for the logical event; ``seq`` (scoped by
    ``producer_id``) exposes gaps; ``outbox_id`` binds the event to the
    committed ledger/outbox entry. An event without ``outbox_id`` /
    ``committed_at`` is an early/unbound notification and must not, by itself,
    be taken as proof that the completion committed.
    """

    event_id: str
    job_id: str
    task_id: str
    outcome: str
    producer_id: str
    seq: int
    idempotency_key: str
    kind: str = PROOF_KIND
    schema_version: int = SCHEMA_VERSION
    outbox_id: str | None = None
    result_ref: str | None = None
    result_digest: str | None = None
    schedule_id: str | None = None
    finished_at: str = dataclasses.field(default_factory=utc_now_iso)
    committed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)

    def to_wire(self) -> bytes:
        """Serialize the event the way an external broker would transport it."""
        return (self.kind + " ").encode("ascii") + self.to_json().encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicCompletionEvent:
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})

    @classmethod
    def from_json(cls, payload: str | bytes) -> PublicCompletionEvent:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        return cls.from_dict(json.loads(payload))

    @classmethod
    def from_wire(cls, frame: bytes) -> PublicCompletionEvent:
        _, serialized = frame.split(b" ", 1)
        return cls.from_json(serialized)

    def redacted_preview(self) -> dict[str, Any]:
        """Return the exact safe projection that may be shown to investigators."""
        return {
            "kind": self.kind,
            "event_id": self.event_id,
            "job_id": self.job_id,
            "task_id": self.task_id,
            "outcome": self.outcome,
            "producer_id": self.producer_id,
            "seq": self.seq,
            "outbox_id": self.outbox_id,
            "result_ref": self.result_ref,
            "result_digest": self.result_digest,
            "finished_at": self.finished_at,
            "committed_at": self.committed_at,
        }
