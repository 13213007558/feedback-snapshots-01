"""Audit trail for scheduler dispatches and cancellations."""

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class ScheduleAuditOutcome(str, enum.Enum):
    """Possible outcomes of a due schedule occurrence."""

    PUBLISHED = "published"
    CANCELLED = "cancelled"
    FAILED = "failed"

    def __str__(self) -> str:
        """Return the plain outcome value."""
        return self.value


@dataclass(frozen=True)
class ScheduleAuditRecord:
    """One immutable audit entry."""

    occurrence: str
    identity: str
    task_name: str
    schedule_id: str
    source_name: str
    source_role: str
    dispatch_allowed: bool
    outcome: ScheduleAuditOutcome
    task_id: str | None = None
    reason: str | None = None
    recorded_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
    )

    @property
    def published(self) -> bool:
        """Whether this occurrence actually reached the broker."""
        return self.outcome is ScheduleAuditOutcome.PUBLISHED


class ScheduleAuditLedger:
    """
    Append-only ledger of schedule occurrences.

    The ledger is keyed by occurrence, so a later merge of the same source
    data does not duplicate an already handled occurrence. The latest
    record for an occurrence wins when reading the audit view.
    """

    def __init__(self) -> None:
        self._records: list[ScheduleAuditRecord] = []
        self._latest: dict[str, ScheduleAuditRecord] = {}
        self._published: dict[str, ScheduleAuditRecord] = {}
        self._handled: set[str] = set()

    def record(self, entry: ScheduleAuditRecord) -> None:
        """Append a record and make it the latest for its occurrence."""
        self._records.append(entry)
        self._latest[entry.occurrence] = entry
        if entry.published:
            self._published[entry.occurrence] = entry
        if entry.outcome in (
            ScheduleAuditOutcome.PUBLISHED,
            ScheduleAuditOutcome.CANCELLED,
        ):
            self._handled.add(entry.occurrence)

    def is_handled(self, occurrence: str) -> bool:
        """Whether an occurrence was already sent or cancelled."""
        return occurrence in self._handled

    def was_published(self, occurrence: str) -> bool:
        """Whether an occurrence actually reached the broker."""
        return occurrence in self._published

    def published_record(self, occurrence: str) -> ScheduleAuditRecord | None:
        """Return the successful publish record of an occurrence."""
        return self._published.get(occurrence)

    def latest(self, occurrence: str) -> ScheduleAuditRecord | None:
        """Return the latest record of an occurrence."""
        return self._latest.get(occurrence)

    def records(self) -> tuple[ScheduleAuditRecord, ...]:
        """Return every record in append order."""
        return tuple(self._records)

    def published(self) -> tuple[ScheduleAuditRecord, ...]:
        """Return every record that resulted in a real dispatch."""
        return tuple(self._published.values())

    def view(
        self,
        *,
        outcome: ScheduleAuditOutcome | None = None,
        source_name: str | None = None,
    ) -> tuple[ScheduleAuditRecord, ...]:
        """
        Return the audit view.

        Each occurrence appears once, using its latest record, so a
        cancelled occurrence is not shadowed by an earlier dispatch attempt
        of the same slot.

        :param outcome: filter by outcome.
        :param source_name: filter by source name.
        :return: matching records.
        """
        records = list(self._latest.values())
        if outcome is not None:
            records = [item for item in records if item.outcome is outcome]
        if source_name is not None:
            records = [item for item in records if item.source_name == source_name]
        return tuple(records)
