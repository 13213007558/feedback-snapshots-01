from datetime import datetime, timezone

from taskiq.abc.schedule_source import ScheduleSource
from taskiq.scheduler.scheduled_task import ScheduledTask
from taskiq.scheduler.source_rules import (
    ScheduleSourceRole,
    ScheduleSourceRules,
    dispatch_rule,
    observe_rule,
    schedule_identity,
    schedule_occurrence,
)


class StubSource(ScheduleSource):
    async def get_schedules(self) -> list[ScheduledTask]:
        return []


def make_task(
    name: str = "publish:task",
    schedule_id: str = "schedule-a",
    minute: int = 10,
    args: list | None = None,
) -> ScheduledTask:
    return ScheduledTask(
        task_name=name,
        labels={},
        args=args or [],
        kwargs={},
        time=datetime(2030, 1, 1, 12, minute, tzinfo=timezone.utc),
        schedule_id=schedule_id,
    )


def test_observation_plan_is_kept_but_never_dispatched() -> None:
    published = StubSource()
    audit = StubSource()
    rules = ScheduleSourceRules(
        {
            published: dispatch_rule("release-config"),
            audit: observe_rule("audit-register"),
        },
    )
    plan = make_task()

    resolved = rules.resolve([(published, [plan]), (audit, [plan])])

    assert [entry.source_name for entry in resolved.observed] == [
        "release-config",
        "audit-register",
    ]
    assert [entry.source_name for entry in resolved.dispatch] == ["release-config"]
    assert resolved.conflicts == ()


def test_first_dispatch_source_wins_a_duplicate_and_is_reported() -> None:
    first = StubSource()
    second = StubSource()
    rules = ScheduleSourceRules(
        {
            first: dispatch_rule("first"),
            second: dispatch_rule("second"),
        },
    )
    resolved = rules.resolve(
        [
            (first, [make_task(schedule_id="one")]),
            (second, [make_task(schedule_id="two")]),
        ],
    )

    assert [entry.source_name for entry in resolved.dispatch] == ["first"]
    assert resolved.conflicts[0].source_names == ("first", "second")
    assert resolved.conflicts[0].chosen_source == "first"


def test_source_without_rule_dispatches_under_class_name() -> None:
    source = StubSource()
    rules = ScheduleSourceRules()

    resolved = rules.resolve([(source, [make_task()])])

    assert resolved.dispatch[0].role is ScheduleSourceRole.DISPATCH
    assert resolved.dispatch[0].source_name == "StubSource[0]"


def test_revoked_source_leaves_observation_view_intact() -> None:
    source = StubSource()
    rules = ScheduleSourceRules({source: dispatch_rule("release-config")})
    rules.revoke(source)

    resolved = rules.resolve([(source, [make_task()])])

    assert rules.is_dispatch_allowed(source) is False
    assert resolved.dispatch == ()
    assert [entry.source_name for entry in resolved.observed] == ["release-config"]


def test_identity_ignores_source_specific_schedule_id() -> None:
    assert schedule_identity(make_task("task", "one")) == schedule_identity(
        make_task("task", "two"),
    )


def test_occurrence_is_stable_for_the_same_slot() -> None:
    task = make_task(minute=10)
    assert schedule_occurrence(task, datetime(2030, 1, 1, 12, 10, 1)) == (
        schedule_occurrence(task, datetime(2030, 1, 1, 12, 10, 59))
    )


def test_occurrence_differs_for_different_cron_slots() -> None:
    task = ScheduledTask(
        task_name="cron:task",
        labels={},
        args=[],
        kwargs={},
        cron="* * * * *",
        schedule_id="cron-a",
    )
    assert schedule_occurrence(task, datetime(2030, 1, 1, 12, 10, 5)) != (
        schedule_occurrence(task, datetime(2030, 1, 1, 12, 11, 5))
    )
