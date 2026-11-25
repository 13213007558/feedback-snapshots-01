from logging import getLogger
from typing import TYPE_CHECKING

from taskiq.exceptions import ScheduledTaskCancelledError
from taskiq.kicker import AsyncKicker
from taskiq.scheduler.audit import (
    ScheduleAuditLedger,
    ScheduleAuditOutcome,
    ScheduleAuditRecord,
)
from taskiq.scheduler.scheduled_task import ScheduledTask
from taskiq.scheduler.source_rules import (
    ScheduleSourceRole,
    ScheduleSourceRules,
    current_dispatch,
    schedule_identity,
    schedule_occurrence,
)
from taskiq.utils import maybe_awaitable

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping
    from datetime import datetime

    from taskiq.abc.broker import AsyncBroker
    from taskiq.abc.schedule_source import ScheduleSource
    from taskiq.scheduler.source_rules import ScheduleSourceRule

logger = getLogger(__name__)


class TaskiqScheduler:
    """Scheduler class."""

    def __init__(
        self,
        broker: "AsyncBroker",
        sources: list["ScheduleSource"],
        *,
        source_rules: (
            "ScheduleSourceRules | Mapping[ScheduleSource, ScheduleSourceRule] | None"
        ) = None,
        audit_ledger: ScheduleAuditLedger | None = None,
    ) -> None:  # pragma: no cover
        self.broker = broker
        self.sources = sources
        if isinstance(source_rules, ScheduleSourceRules):
            self.source_rules = source_rules
        else:
            self.source_rules = ScheduleSourceRules(source_rules)
        self.audit_ledger = audit_ledger or ScheduleAuditLedger()

    async def startup(self) -> None:  # pragma: no cover
        """
        This method is called on startup.

        Here you can do stuff, like creating
        connections or anything you'd like.
        """
        await self.broker.startup()

    async def on_ready(
        self,
        source: "ScheduleSource",
        task: ScheduledTask,
        *,
        occurrence: str | None = None,
        now: "datetime | None" = None,
    ) -> None:
        """
        This method is called when task is ready to be enqueued.

        It's triggered on proper time depending on `task.cron`, `task.interval`
        or `task.time` attribute.

        Observation-only sources are never sent. A dispatch source is
        re-checked after ``pre_send`` returns, so revoking it while
        ``pre_send`` is awaiting cancels the dispatch. Both real publishes
        and cancellations are written to the audit ledger under one
        occurrence key, letting later merges recognise the same due item.

        :param source: source that triggered this event.
        :param task: task to send.
        :param occurrence: occurrence key of this due item.
        :param now: scheduler time used to build the occurrence key.
        """
        context = current_dispatch.get()
        resolved = context.resolved if context is not None else None
        role = (
            resolved.role
            if resolved is not None
            else self.source_rules.rule_for(source).role
        )
        source_name = (
            resolved.source_name
            if resolved is not None
            else self._source_name(source)
        )
        identity = (
            resolved.identity if resolved is not None else schedule_identity(task)
        )

        if occurrence is None and context is not None:
            occurrence = context.occurrence
        if occurrence is None:
            if now is None:
                from datetime import datetime, timezone

                now = datetime.now(tz=timezone.utc)
            occurrence = schedule_occurrence(task, now)

        if role is ScheduleSourceRole.OBSERVE:
            logger.debug(
                "Schedule %s from observation source %s is display-only.",
                task.task_name,
                source_name,
            )
            return

        if not self.source_rules.is_dispatch_allowed(source):
            logger.info(
                "Schedule %s from source %s is not allowed to dispatch.",
                task.task_name,
                source_name,
            )
            return

        base = ScheduleAuditRecord(
            occurrence=occurrence,
            identity=identity,
            task_name=task.task_name,
            schedule_id=task.schedule_id,
            source_name=source_name,
            source_role=str(role),
            dispatch_allowed=True,
            outcome=ScheduleAuditOutcome.FAILED,
        )

        try:
            await maybe_awaitable(source.pre_send(task))
        except ScheduledTaskCancelledError:
            logger.info("Scheduled task %s has been cancelled.", task.task_name)
            self.audit_ledger.record(
                self._with_outcome(
                    base,
                    ScheduleAuditOutcome.CANCELLED,
                    reason="pre_send cancelled the dispatch",
                ),
            )
            return
        except Exception:
            self.audit_ledger.record(
                self._with_outcome(
                    base,
                    ScheduleAuditOutcome.FAILED,
                    reason="pre_send raised an error",
                ),
            )
            raise

        if not self.source_rules.is_dispatch_allowed(source):
            logger.info(
                "Schedule %s from source %s was revoked before dispatch.",
                task.task_name,
                source_name,
            )
            self.audit_ledger.record(
                self._with_outcome(
                    base,
                    ScheduleAuditOutcome.CANCELLED,
                    reason="source revoked before dispatch",
                ),
            )
            return

        try:
            kicked = await (
                AsyncKicker(task.task_name, self.broker, dict(task.labels))
                .with_labels(
                    schedule_id=task.schedule_id,
                    schedule_source=source_name,
                    schedule_source_role=str(role),
                    schedule_occurrence=occurrence,
                )
                .with_task_id(task_id=task.task_id)
                .kiq(
                    *task.args,
                    **task.kwargs,
                )
            )
        except Exception:
            self.audit_ledger.record(
                self._with_outcome(
                    base,
                    ScheduleAuditOutcome.FAILED,
                    reason="broker rejected the dispatch",
                ),
            )
            raise

        self.audit_ledger.record(
            self._with_outcome(
                base,
                ScheduleAuditOutcome.PUBLISHED,
                task_id=kicked.task_id,
            ),
        )
        await maybe_awaitable(source.post_send(task))

    def _source_name(self, source: "ScheduleSource") -> str:
        """Return the display name of a source."""
        try:
            index = self.sources.index(source)
        except ValueError:
            index = -1
        return self.source_rules.display_name(source, index)

    @staticmethod
    def _with_outcome(
        base: ScheduleAuditRecord,
        outcome: ScheduleAuditOutcome,
        *,
        task_id: str | None = None,
        reason: str | None = None,
    ) -> ScheduleAuditRecord:
        """Return a copy of a record with a final outcome."""
        return ScheduleAuditRecord(
            occurrence=base.occurrence,
            identity=base.identity,
            task_name=base.task_name,
            schedule_id=base.schedule_id,
            source_name=base.source_name,
            source_role=base.source_role,
            dispatch_allowed=base.dispatch_allowed,
            outcome=outcome,
            task_id=task_id,
            reason=reason,
        )

    def audit_view(
        self,
        *,
        outcome: ScheduleAuditOutcome | None = None,
        source_name: str | None = None,
    ) -> tuple[ScheduleAuditRecord, ...]:
        """Return the latest audit record of every handled occurrence."""
        return self.audit_ledger.view(outcome=outcome, source_name=source_name)

    async def shutdown(self) -> None:
        """Shutdown the scheduler process."""
        await self.broker.shutdown()
