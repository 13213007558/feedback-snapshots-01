import asyncio
from datetime import datetime, timedelta, timezone

from taskiq.abc.schedule_source import ScheduleSource
from taskiq.cli.scheduler.run import SchedulerLoop
from taskiq.message import BrokerMessage
from taskiq.scheduler.audit import ScheduleAuditOutcome
from taskiq.scheduler.scheduled_task import ScheduledTask
from taskiq.scheduler.scheduler import TaskiqScheduler
from taskiq.scheduler.source_rules import (
    ScheduleSourceRules,
    dispatch_rule,
    observe_rule,
)
from tests.utils import AsyncQueueBroker


class RecordingBroker(AsyncQueueBroker):
    """Broker that records every dispatched message."""

    def __init__(self) -> None:
        super().__init__()
        self.sent: list[BrokerMessage] = []

    async def kick(self, message: BrokerMessage) -> None:
        self.sent.append(message)


class PausableSource(ScheduleSource):
    """In-memory source whose refresh can be paused by the test."""

    def __init__(self, schedules: list[ScheduledTask]) -> None:
        self.schedules = schedules
        self.refresh_started = asyncio.Event()
        self.release_refresh = asyncio.Event()
        self._pause_next_refresh = False

    def pause_next_refresh(self) -> None:
        self._pause_next_refresh = True

    async def get_schedules(self) -> list[ScheduledTask]:
        if self._pause_next_refresh:
            self._pause_next_refresh = False
            self.refresh_started.set()
            await self.release_refresh.wait()
        return list(self.schedules)


class HoldingSource(PausableSource):
    """Source whose pre-send can be held open and then released."""

    def __init__(self, schedules: list[ScheduledTask]) -> None:
        super().__init__(schedules)
        self.pre_send_started = asyncio.Event()
        self.release_pre_send = asyncio.Event()
        self.hold_pre_send = False
        self.pre_send_calls = 0

    def hold_next_pre_send(self) -> None:
        self.hold_pre_send = True

    async def pre_send(self, task: ScheduledTask) -> None:
        self.pre_send_calls += 1
        if not self.hold_pre_send:
            return
        self.hold_pre_send = False
        self.pre_send_started.set()
        await self.release_pre_send.wait()


def plan(task_name: str, schedule_id: str, at: datetime) -> ScheduledTask:
    return ScheduledTask(
        task_name=task_name,
        labels={"channel": "release"},
        args=[task_name],
        kwargs={},
        time=at,
        schedule_id=schedule_id,
    )


async def wait_for_running(loop: SchedulerLoop) -> None:
    while loop.running_occurrences:
        await asyncio.gather(*list(loop.running_occurrences.values()))


async def test_interleaved_refresh_and_dispatch_with_revocation() -> None:
    now = datetime.now(timezone.utc)
    first_due = plan("publish:nightly", "release-first", now)
    revoked_due = plan(
        "publish:nightly-followup",
        "release-second",
        now + timedelta(hours=1),
    )
    followup_due = plan(
        "publish:compliant",
        "compliance-plan",
        now + timedelta(hours=2),
    )

    release = HoldingSource([first_due, revoked_due])
    audit = PausableSource(
        [
            plan("publish:nightly", "audit-first", first_due.time),
            plan("publish:nightly-followup", "audit-second", revoked_due.time),
        ],
    )
    compliance = PausableSource([followup_due])
    rules = ScheduleSourceRules(
        {
            release: dispatch_rule("release-config"),
            audit: observe_rule("audit-register"),
            compliance: dispatch_rule("compliance-config"),
        },
    )
    broker = RecordingBroker()
    loop = SchedulerLoop(
        TaskiqScheduler(
            broker,
            [release, audit, compliance],
            source_rules=rules,
        ),
    )

    # First refresh: both in-memory sources are held in flight at once.
    release.pause_next_refresh()
    audit.pause_next_refresh()
    refreshing = asyncio.create_task(loop.refresh())
    await asyncio.wait_for(release.refresh_started.wait(), timeout=1)
    await asyncio.wait_for(audit.refresh_started.wait(), timeout=1)
    release.release_refresh.set()
    audit.release_refresh.set()
    await asyncio.wait_for(refreshing, timeout=1)

    # First dispatch: publication is allowed for the due plan.
    loop.dispatch_due(now)
    await wait_for_running(loop)
    assert len(broker.sent) == 1
    published = broker.sent[0]
    assert published.labels["schedule_source"] == "release-config"
    assert published.labels["schedule_source_role"] == "dispatch"
    occurrence = published.labels["schedule_occurrence"]
    assert loop.scheduler.audit_ledger.was_published(occurrence) is True
    assert occurrence in published.labels["schedule_occurrence"]

    # A later merge of the same due item must not dispatch it again.
    await loop.refresh()
    loop.dispatch_due(now)
    await wait_for_running(loop)
    assert len(broker.sent) == 1
    assert len(
        loop.scheduler.audit_ledger.view(
            outcome=ScheduleAuditOutcome.PUBLISHED,
        ),
    ) == 1

    # Second dispatch: the approved source is revoked after the scheduling
    # decision but while its pre_send is still on the stack.
    release.hold_next_pre_send()
    await loop.refresh()
    loop.dispatch_due(now + timedelta(hours=1))
    await asyncio.wait_for(release.pre_send_started.wait(), timeout=1)
    rules.revoke(release)
    release.release_pre_send.set()
    await wait_for_running(loop)

    assert len(broker.sent) == 1
    cancelled = loop.scheduler.audit_ledger.view(
        outcome=ScheduleAuditOutcome.CANCELLED,
    )
    assert len(cancelled) == 1
    assert cancelled[0].source_name == "release-config"
    assert cancelled[0].task_name == "publish:nightly-followup"
    assert all(
        msg.labels["schedule_source"] != "audit-register" for msg in broker.sent
    )
    assert all(
        record.source_name != "audit-register"
        for record in loop.scheduler.audit_ledger.published()
    )

    # The revoked plan stays visible in the observation view, and a replay
    # of the cancelled due item is not treated as a fresh one.
    observed_by_source = {
        entry.source_name for entry in loop.observed_plans()
    }
    assert observed_by_source == {
        "release-config",
        "audit-register",
        "compliance-config",
    }
    loop.dispatch_due(now + timedelta(hours=1))
    assert loop.running_occurrences == {}
    assert len(broker.sent) == 1

    # A compliant later plan still sends normally.
    loop.dispatch_due(now + timedelta(hours=2))
    await wait_for_running(loop)
    assert len(broker.sent) == 2
    assert broker.sent[1].labels["schedule_source"] == "compliance-config"
    assert broker.sent[1].task_id != published.task_id


async def test_display_only_source_never_publishes() -> None:
    now = datetime.now(timezone.utc)
    shared = plan("publish:shared", "release-shared", now)
    published = PausableSource([shared])
    audit = PausableSource([plan("publish:shared", "audit-shared", now)])
    rules = ScheduleSourceRules(
        {
            published: dispatch_rule("release-config"),
            audit: observe_rule("audit-register"),
        },
    )
    broker = RecordingBroker()
    loop = SchedulerLoop(
        TaskiqScheduler(broker, [published, audit], source_rules=rules),
    )
    await loop.refresh()

    loop.dispatch_due(now)
    await wait_for_running(loop)

    assert len(broker.sent) == 1
    assert broker.sent[0].labels["schedule_source"] == "release-config"
    assert loop.scheduler.audit_ledger.view(source_name="audit-register") == ()
    assert [entry.source_name for entry in loop.observed_plans()] == [
        "release-config",
        "audit-register",
    ]
