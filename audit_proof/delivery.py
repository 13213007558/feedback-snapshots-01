"""
At-least-once delivery simulation and the idempotent subscriber inbox.

The inbox is the audit subscriber's reception book. It keeps every raw
delivery (so duplicates are visible), deduplicates by stable ``event_id``
(so redeliveries trigger the business effect once), and tracks per-producer
sequence gaps (so missing events are detectable even before reconciliation
against the ledger).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from .model import PublicCompletionEvent


class PublishError(RuntimeError):
    """Simulates a broken event broker / failed publish."""


@dataclasses.dataclass
class Gap:
    producer_id: str
    missing_seq: int
    seen_seqs: list[int]


class Inbox:
    """Idempotent, audit friendly subscriber endpoint."""

    def __init__(self, name: str = "investigation-subscriber") -> None:
        self.name = name
        self.raw_deliveries: list[PublicCompletionEvent] = []
        self.delivery_count_by_event: dict[str, int] = {}
        self.first_seen: dict[str, int] = {}
        self.accepted_event_ids: set[str] = set()
        self.seen_seqs_by_producer: dict[str, set[int]] = {}
        self.gaps: list[Gap] = []

    def receive(self, event: PublicCompletionEvent) -> str:
        """
        Record one inbound event and deduplicate by stable ``event_id``.

        :returns: ``"accepted"`` on first delivery, ``"duplicate"`` afterwards.
        """
        position = len(self.raw_deliveries)
        self.raw_deliveries.append(event)
        count = self.delivery_count_by_event.get(event.event_id, 0) + 1
        self.delivery_count_by_event[event.event_id] = count

        if count > 1 or event.event_id in self.accepted_event_ids:
            self._refresh_gaps(event.producer_id)
            return "duplicate"

        self.first_seen[event.event_id] = position
        self.accepted_event_ids.add(event.event_id)

        seqs = self.seen_seqs_by_producer.setdefault(event.producer_id, set())
        seqs.add(event.seq)
        self._refresh_gaps(event.producer_id)
        return "accepted"

    def _refresh_gaps(self, producer_id: str) -> None:
        seqs = self.seen_seqs_by_producer.get(producer_id, set())
        if len(seqs) < 2:
            self.gaps = [g for g in self.gaps if g.producer_id != producer_id]
            return

        low, high = min(seqs), max(seqs)
        missing = [seq for seq in range(low, high + 1) if seq not in seqs]
        self.gaps = [g for g in self.gaps if g.producer_id != producer_id] + [
            Gap(producer_id, seq, sorted(seqs)) for seq in missing
        ]

    def events_for_job(self, job_id: str) -> list[PublicCompletionEvent]:
        return [e for e in self.raw_deliveries if e.job_id == job_id]

    def duplicate_event_ids(self) -> dict[str, int]:
        return {
            event_id: count
            for event_id, count in self.delivery_count_by_event.items()
            if count > 1
        }

    @property
    def duplicate_copy_count(self) -> int:
        """Number of deliveries that were repeats of an already seen event."""
        return sum(count - 1 for count in self.delivery_count_by_event.values())


class ControllableBroker:
    """
    Deterministic in-process broker with injectable failure modes.

    * ``fail_next_publishes`` makes the next publish calls raise, modelling the
      "save committed but publish failed" window;
    * ``duplicate_next_deliveries`` makes the next fan-out deliver twice with
      the same event id, modelling an ack loss / producer retry;
    * a subscriber may be wrapped in :class:`LossyForwarder` to model an event
      the broker accepted but the subscriber never received.
    """

    def __init__(self, name: str = "test-broker") -> None:
        self.name = name
        self.subscribers: list[Callable[[PublicCompletionEvent], None]] = []
        self.fail_next_publishes = 0
        self.duplicate_next_deliveries = 0
        self.publish_attempts: list[str] = []
        self.accepted_event_ids: list[str] = []

    def subscribe(self, callback: Callable[[PublicCompletionEvent], None]) -> None:
        self.subscribers.append(callback)

    def publish(self, event: PublicCompletionEvent) -> None:
        self.publish_attempts.append(event.event_id)
        if self.fail_next_publishes > 0:
            self.fail_next_publishes -= 1
            raise PublishError(f"broker {self.name!r} unavailable")

        self.accepted_event_ids.append(event.event_id)
        copies = 1
        if self.duplicate_next_deliveries > 0:
            self.duplicate_next_deliveries -= 1
            copies = 2

        for _ in range(copies):
            for callback in list(self.subscribers):
                callback(event)


class LossyForwarder:
    """Forward events to a sink while silently dropping selected event ids."""

    def __init__(
        self,
        sink: Callable[[PublicCompletionEvent], object],
        drop_event_ids: set[str] | None = None,
    ) -> None:
        self.sink = sink
        self.drop_event_ids = set(drop_event_ids or ())
        self.dropped: list[str] = []

    def __call__(self, event: PublicCompletionEvent) -> None:
        if event.event_id in self.drop_event_ids:
            self.dropped.append(event.event_id)
            return
        self.sink(event)


class VerifyingConsumer:
    """
    Exactly once effect gate that additionally binds events to committed truth.

    Deduplication by ``event_id`` prevents repeated effects from redelivery,
    but it cannot tell a genuine completion from an early/phantom event. This
    gate only applies a business effect when the event matches a committed
    ledger fact; unbound first deliveries are quarantined for investigation
    instead of being acted on.
    """

    def __init__(self, inbox: Inbox, state) -> None:
        self.inbox = inbox
        self.state = state
        self.applied_effects: list[str] = []
        self.quarantined: list[str] = []

    def is_bound(self, event: PublicCompletionEvent) -> bool:
        fact = self.state.facts.get(event.job_id)
        if fact is None or fact.event_id != event.event_id:
            return False
        if event.outbox_id is not None and event.outbox_id not in self.state.outbox:
            return False
        return True

    def handle(self, event: PublicCompletionEvent) -> str:
        decision = self.inbox.receive(event)
        if decision == "duplicate":
            return "duplicate"
        if self.is_bound(event):
            self.applied_effects.append(event.idempotency_key)
            return "applied"
        self.quarantined.append(event.event_id)
        return "quarantined_unbound"

    def recheck_quarantine(self) -> list[str]:
        """Re-evaluate quarantined events against the current committed state."""
        still_quarantined: list[str] = []
        recovered: list[str] = []
        by_id = {event.event_id: event for event in self.inbox.raw_deliveries}
        for event_id in self.quarantined:
            event = by_id[event_id]
            if self.is_bound(event):
                self.applied_effects.append(event.idempotency_key)
                recovered.append(event_id)
            else:
                still_quarantined.append(event_id)
        self.quarantined = still_quarantined
        return recovered


class OutboxRelay:
    """Publish pending outbox messages at least once."""

    def __init__(self, state, broker: ControllableBroker) -> None:
        self.state = state
        self.broker = broker

    def publish_pending(self) -> list[str]:
        acted_on: list[str] = []
        for message in list(self.state.outbox.values()):
            if message.status == "published":
                continue
            acted_on.append(message.outbox_id)
            try:
                self.broker.publish(message.event)
            except PublishError as exc:
                message.mark_attempt(exc)
            else:
                message.mark_attempt(None)
        return acted_on

    def replay(self, outbox_id: str, sink: Inbox | VerifyingConsumer) -> str:
        """Explicitly replay one outbox message at an inbox or consumer."""
        message = self.state.outbox[outbox_id]
        return (
            sink.receive(message.event)
            if isinstance(sink, Inbox)
            else sink.handle(message.event)
        )
