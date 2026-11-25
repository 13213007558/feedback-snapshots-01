from taskiq.scheduler.audit import (
    ScheduleAuditLedger,
    ScheduleAuditOutcome,
    ScheduleAuditRecord,
)


def record(
    occurrence: str = "task@slot",
    outcome: ScheduleAuditOutcome = ScheduleAuditOutcome.PUBLISHED,
    source_name: str = "release-config",
    task_id: str | None = "task-id",
) -> ScheduleAuditRecord:
    return ScheduleAuditRecord(
        occurrence=occurrence,
        identity="task-identity",
        task_name="publish:task",
        schedule_id="schedule-id",
        source_name=source_name,
        source_role="dispatch",
        dispatch_allowed=True,
        outcome=outcome,
        task_id=task_id,
    )


def test_handled_occurrence_is_not_a_new_one_after_merge() -> None:
    ledger = ScheduleAuditLedger()
    ledger.record(record())

    assert ledger.is_handled("task@slot") is True
    assert ledger.was_published("task@slot") is True
    assert ledger.published_record("task@slot") is not None
    assert ledger.published_record("task@slot").task_id == "task-id"


def test_cancelled_occurrence_is_handled_but_not_published() -> None:
    ledger = ScheduleAuditLedger()
    ledger.record(record(outcome=ScheduleAuditOutcome.CANCELLED, task_id=None))

    assert ledger.is_handled("task@slot") is True
    assert ledger.was_published("task@slot") is False
    assert ledger.published() == ()


def test_latest_view_shows_cancellation_not_the_earlier_publish() -> None:
    ledger = ScheduleAuditLedger()
    ledger.record(record())
    ledger.record(
        ScheduleAuditRecord(
            occurrence="task@slot",
            identity="task-identity",
            task_name="publish:task",
            schedule_id="schedule-id",
            source_name="release-config",
            source_role="dispatch",
            dispatch_allowed=True,
            outcome=ScheduleAuditOutcome.CANCELLED,
            reason="source revoked before dispatch",
        ),
    )

    assert [item.outcome for item in ledger.view()] == [
        ScheduleAuditOutcome.CANCELLED,
    ]
    assert [item.task_id for item in ledger.published()] == ["task-id"]


def test_view_filters_by_source_and_outcome() -> None:
    ledger = ScheduleAuditLedger()
    ledger.record(record("a@slot", source_name="release-config"))
    ledger.record(
        record(
            "b@slot",
            outcome=ScheduleAuditOutcome.CANCELLED,
            source_name="release-config",
            task_id=None,
        ),
    )
    ledger.record(record("c@slot", source_name="other"))

    assert len(ledger.view(source_name="release-config")) == 2
    cancelled = ledger.view(outcome=ScheduleAuditOutcome.CANCELLED)
    assert [item.occurrence for item in cancelled] == ["b@slot"]
