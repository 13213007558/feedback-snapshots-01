from __future__ import annotations

from datetime import UTC, datetime
from functools import partial
from traceback import format_tb
from typing import Any, TypeVar
from uuid import UUID

import attrs
from attrs.converters import optional

from ._converters import as_aware_datetime, as_enum, as_uuid
from ._enums import JobOutcome
from ._structures import Job, JobResult
from ._utils import qualified_name

T_Event = TypeVar("T_Event", bound="Event")


@attrs.define(kw_only=True, frozen=True)
class Event:
    """
    Base class for all events.

    :ivar timestamp: the time when the event occurred
    """

    timestamp: datetime = attrs.field(
        factory=partial(datetime.now, UTC), converter=as_aware_datetime
    )

    def marshal(self) -> dict[str, Any]:
        return attrs.asdict(self)

    @classmethod
    def unmarshal(cls, marshalled: dict[str, Any]) -> Event:
        return cls(**marshalled)


#
# Data store events
#


@attrs.define(kw_only=True, frozen=True)
class DataStoreEvent(Event):
    """Base class for events originating from a data store."""


@attrs.define(kw_only=True, frozen=True)
class TaskAdded(DataStoreEvent):
    """
    Signals that a new task was added to the store.

    :ivar task_id: ID of the task that was added
    """

    task_id: str


@attrs.define(kw_only=True, frozen=True)
class TaskUpdated(DataStoreEvent):
    """
    Signals that a task was updated in a data store.

    :ivar task_id: ID of the task that was updated
    """

    task_id: str


@attrs.define(kw_only=True, frozen=True)
class TaskRemoved(DataStoreEvent):
    """
    Signals that a task was removed from the store.

    :ivar task_id: ID of the task that was removed
    """

    task_id: str


@attrs.define(kw_only=True, frozen=True)
class ScheduleAdded(DataStoreEvent):
    """
    Signals that a new schedule was added to the store.

    :ivar schedule_id: ID of the schedule that was added
    :ivar task_id: ID of the task the schedule belongs to
    :ivar next_fire_time: the first run time calculated for the schedule
    """

    schedule_id: str
    task_id: str
    next_fire_time: datetime | None = attrs.field(converter=optional(as_aware_datetime))


@attrs.define(kw_only=True, frozen=True)
class ScheduleUpdated(DataStoreEvent):
    """
    Signals that a schedule has been updated in the store.

    :ivar schedule_id: ID of the schedule that was updated
    :ivar task_id: ID of the task the schedule belongs to
    :ivar next_fire_time: the next time the schedule will run
    """

    schedule_id: str
    task_id: str
    next_fire_time: datetime | None = attrs.field(converter=optional(as_aware_datetime))


@attrs.define(kw_only=True, frozen=True)
class ScheduleRemoved(DataStoreEvent):
    """
    Signals that a schedule was removed from the store.

    :ivar schedule_id: ID of the schedule that was removed
    :ivar task_id: ID of the task the schedule belongs to
    :ivar finished: ``True`` if the schedule was removed automatically because its
        trigger had no more fire times left
    """

    schedule_id: str
    task_id: str
    finished: bool


@attrs.define(kw_only=True, frozen=True)
class JobAdded(DataStoreEvent):
    """
    Signals that a new job was added to the store.

    :ivar job_id: ID of the job that was added
    :ivar task_id: ID of the task the job would run
    :ivar schedule_id: ID of the schedule the job was created from
    """

    job_id: UUID = attrs.field(converter=as_uuid)
    task_id: str
    schedule_id: str | None


@attrs.define(kw_only=True, frozen=True)
class JobRemoved(DataStoreEvent):
    """
    Signals that a job was removed from the store.

    :ivar job_id: ID of the job that was removed
    :ivar task_id: ID of the task the job would have run

    """

    job_id: UUID = attrs.field(converter=as_uuid)
    task_id: str


@attrs.define(kw_only=True, frozen=True)
class ScheduleDeserializationFailed(DataStoreEvent):
    """
    Signals that the deserialization of a schedule has failed.

    :ivar schedule_id: ID of the schedule that failed to deserialize
    :ivar exception: the exception that was raised during deserialization
    """

    schedule_id: str
    exception: BaseException


@attrs.define(kw_only=True, frozen=True)
class JobDeserializationFailed(DataStoreEvent):
    """
    Signals that the deserialization of a job has failed.

    :ivar job_id: ID of the job that failed to deserialize
    :ivar exception: the exception that was raised during deserialization
    """

    job_id: UUID = attrs.field(converter=as_uuid)
    exception: BaseException


#
# Scheduler events
#


@attrs.define(kw_only=True, frozen=True)
class SchedulerEvent(Event):
    """Base class for events originating from a scheduler."""


@attrs.define(kw_only=True, frozen=True)
class SchedulerStarted(SchedulerEvent):
    pass


@attrs.define(kw_only=True, frozen=True)
class SchedulerStopped(SchedulerEvent):
    """
    Signals that a scheduler has stopped.

    :ivar exception: the exception that caused the scheduler to stop, if any
    """

    exception: BaseException | None = None


@attrs.define(kw_only=True, frozen=True)
class JobAcquired(SchedulerEvent):
    """
    Signals that a scheduler has acquired a job for processing.

    :param job_id: the ID of the job that was acquired
    :param scheduler_id: the ID of the scheduler that acquired the job
    :param task_id: ID of the task the job belongs to
    :param schedule_id: ID of the schedule that
    :param scheduled_start: the time the job was scheduled to start via a schedule (if
        any)
    """

    job_id: UUID = attrs.field(converter=as_uuid)
    scheduler_id: str
    task_id: str
    schedule_id: str | None = None
    scheduled_start: datetime | None = attrs.field(converter=as_aware_datetime)

    @classmethod
    def from_job(cls, job: Job, scheduler_id: str) -> JobAcquired:
        """
        Create a new job-acquired event from a job and a scheduler ID.

        :param job: the job that was acquired
        :param scheduler_id: the ID of the scheduler that acquired the job
        :return: a new job-acquired event

        """
        return cls(
            job_id=job.id,
            scheduler_id=scheduler_id,
            task_id=job.task_id,
            schedule_id=job.schedule_id,
            scheduled_start=job.scheduled_fire_time,
        )


@attrs.define(kw_only=True, frozen=True)
class JobReleased(SchedulerEvent):
    """
    Signals that a scheduler has finished processing of a job.

    :param uuid.UUID job_id: the ID of the job that was released
    :param scheduler_id: the ID of the scheduler that released the job
    :param task_id: ID of the task run by the job
    :param schedule_id: ID of the schedule (if any) that created the job
    :param scheduled_start: the time the job was scheduled to start via the schedule (if
        any)
    :param started_at: the time the executor actually started running the job (``None``
        if the job was skipped due to missing its start deadline)
    :param outcome: the outcome of the job
    :param exception_type: the fully qualified name of the exception if ``outcome`` is
        :attr:`JobOutcome.error`
    :param exception_message: the result of ``str(exception)`` if ``outcome`` is
        :attr:`JobOutcome.error`
    :param exception_traceback: the traceback lines from the exception if ``outcome`` is
        :attr:`JobOutcome.error`
    """

    job_id: UUID = attrs.field(converter=as_uuid)
    scheduler_id: str
    task_id: str
    schedule_id: str | None = None
    scheduled_start: datetime | None = attrs.field(converter=as_aware_datetime)
    started_at: datetime | None = attrs.field(converter=as_aware_datetime)
    outcome: JobOutcome = attrs.field(converter=as_enum(JobOutcome))
    exception_type: str | None = None
    exception_message: str | None = None
    exception_traceback: list[str] | None = None

    @classmethod
    def from_result(
        cls,
        result: JobResult,
        scheduler_id: str,
        task_id: str,
        schedule_id: str | None,
        scheduled_fire_time: datetime | None = None,
    ) -> JobReleased:
        """
        Create a new job-released event from a job, the job result and a scheduler ID.

        :param result: the result of the job
        :param scheduler_id: the ID of the scheduler that acquired the job
        :param task_id: the job's task ID
        :param schedule_id: ID of the schedule (if any) from which the job was spawned
        :param scheduled_fire_time: the time the job was scheduled to start (if the job
            was spawned from a schedule)
        :return: a new job-released event

        """
        if result.exception is not None:
            exception_type: str | None = qualified_name(result.exception.__class__)
            exception_message: str | None = str(result.exception)
            exception_traceback: list[str] | None = format_tb(
                result.exception.__traceback__
            )
        else:
            exception_type = exception_message = exception_traceback = None

        return cls(
            timestamp=result.finished_at,
            job_id=result.job_id,
            scheduler_id=scheduler_id,
            task_id=task_id,
            schedule_id=schedule_id,
            outcome=result.outcome,
            scheduled_start=scheduled_fire_time,
            started_at=result.started_at,
            exception_type=exception_type,
            exception_message=exception_message,
            exception_traceback=exception_traceback,
        )

    def marshal(self) -> dict[str, Any]:
        marshalled = super().marshal()
        return marshalled


@attrs.define(kw_only=True, frozen=True)
class JobCompletionProof(SchedulerEvent):
    """
    Public, low sensitivity proof that a job completion was durably committed.

    Unlike :class:`JobReleased`, this event is designed for audit and
    reconciliation pipelines:

    * it never carries the job's return value, and never carries exception
      messages or tracebacks, so the result body can stay separately
      authorized;
    * ``event_id`` is stable across redeliveries of the same logical event,
      letting subscribers deduplicate replays;
    * ``sequence`` (scoped by ``producer_id``) lets subscribers detect gaps in
      the event stream;
    * ``ledger_ref`` binds the event to a committed outbox/ledger entry, so an
      investigator can tell a real completion apart from an event that arrived
      before (or without) a commit;
    * ``result_ref`` and ``result_digest`` point authorized consumers at the
      result body and let them verify its integrity, without exposing it on
      the event bus.

    The intended production wiring is the transactional outbox pattern: the
    completion fact and the outbox row are committed together, and this event
    is relayed from that row only after commit. Publishing failures then leave
    a replayable outbox row instead of a lost notification.

    :ivar event_id: stable identifier of the logical event (same on redelivery)
    :ivar job_id: ID of the job this proof belongs to
    :ivar task_id: ID of the task the job ran
    :ivar outcome: the committed outcome of the job
    :ivar producer_id: identity of the producer that assigned ``sequence``
    :ivar sequence: monotonic sequence number within ``producer_id``
    :ivar ledger_ref: reference to the committed ledger/outbox entry
    :ivar result_ref: opaque reference for fetching the separately authorized
        result body (``None`` when no result was retained)
    :ivar result_digest: digest of the canonical result body for integrity
        verification (e.g. ``sha256:...``), or ``None``
    :ivar scheduler_id: ID of the scheduler that processed the job, if any
    :ivar schedule_id: ID of the schedule that created the job, if any
    :ivar finished_at: time the job finished executing
    :ivar committed_at: time the completion fact was durably committed
    """

    event_id: UUID = attrs.field(converter=as_uuid)
    job_id: UUID = attrs.field(converter=as_uuid)
    task_id: str
    outcome: JobOutcome = attrs.field(converter=as_enum(JobOutcome))
    producer_id: str
    sequence: int
    ledger_ref: str
    result_ref: str | None = None
    result_digest: str | None = None
    scheduler_id: str | None = None
    schedule_id: str | None = None
    finished_at: datetime = attrs.field(converter=as_aware_datetime)
    committed_at: datetime | None = attrs.field(
        default=None, converter=optional(as_aware_datetime)
    )

    @classmethod
    def from_result(
        cls,
        result: JobResult,
        *,
        event_id: UUID,
        producer_id: str,
        sequence: int,
        ledger_ref: str,
        committed_at: datetime,
        task_id: str,
        scheduler_id: str | None = None,
        schedule_id: str | None = None,
        result_ref: str | None = None,
        result_digest: str | None = None,
    ) -> JobCompletionProof:
        """
        Build a result free proof event from a committed :class:`JobResult`.

        The ``return_value`` and ``exception`` fields of ``result`` are
        intentionally not copied onto the proof.

        :param result: the committed job result to prove
        :param event_id: stable identifier of the logical event
        :param producer_id: identity of the sequence producer
        :param sequence: monotonic sequence number within ``producer_id``
        :param ledger_ref: reference to the committed ledger/outbox entry
        :param committed_at: when the completion fact was committed
        :param task_id: ID of the task the job ran
        :param scheduler_id: scheduler that processed the job
        :param schedule_id: schedule that created the job, if any
        :param result_ref: opaque reference to the authorized result body
        :param result_digest: digest of the canonical result body
        :return: a new result free proof event
        """
        return cls(
            timestamp=committed_at,
            event_id=event_id,
            job_id=result.job_id,
            task_id=task_id,
            outcome=result.outcome,
            producer_id=producer_id,
            sequence=sequence,
            ledger_ref=ledger_ref,
            result_ref=result_ref,
            result_digest=result_digest,
            scheduler_id=scheduler_id,
            schedule_id=schedule_id,
            finished_at=result.finished_at,
            committed_at=committed_at,
        )
