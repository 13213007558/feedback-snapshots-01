"""
Tests for the offline Schedule control-path audit.

The fixtures build BACpypes3 object snapshots directly from the library's
BACnet type classes, then exercise every layer the audit must explain:
effectivePeriod, weeklySchedule, exceptionSchedule (inline and calendar
reference), scheduleDefault, the write priority, and the target point's
priorityArray.
"""

from __future__ import annotations

import copy

import pytest

from bacpypes3.basetypes import (
    CalendarEntry,
    DailySchedule,
    DateRange,
    SpecialEvent,
    SpecialEventPeriod,
    TimeValue,
)
from bacpypes3.json import sequence_to_json
from bacpypes3.object import CalendarObject, ScheduleObject
from bacpypes3.primitivedata import (
    Date,
    Integer,
    ObjectIdentifier,
    Time,
)

from sandbox.schedule_audit import analyze_point, load_snapshot
from sandbox.schedule_audit.analyzer import AuditConfigurationError
from sandbox.schedule_audit.model import (
    Conclusion,
    PendingReason,
    PointVerdict,
    ScheduleVerdict,
)
from sandbox.schedule_audit.snapshot import SnapshotError

TZ = "+08:00"


def _time_value(hour: int, minute: int, value) -> TimeValue:
    return TimeValue(time=Time((hour, minute, 0, 0)), value=value)


def _weekday_schedule() -> list:
    occupied = DailySchedule(
        daySchedule=[
            _time_value(8, 0, Integer(1)),
            _time_value(17, 0, Integer(0)),
        ]
    )
    closed = DailySchedule(daySchedule=[_time_value(0, 0, Integer(0))])
    return [occupied] * 5 + [closed] * 2


def _holiday_calendar() -> CalendarObject:
    return CalendarObject(
        objectIdentifier=("calendar", 1),
        objectName="Holiday-Calendar",
        presentValue=False,
        dateList=[CalendarEntry(date=Date("2026-12-25"))],
    )


def _holiday_schedule(write_priority: int = 10) -> ScheduleObject:
    special_event = SpecialEvent(
        period=SpecialEventPeriod(calendarReference=ObjectIdentifier(("calendar", 1))),
        listOfTimeValues=[_time_value(0, 0, Integer(0))],
        eventPriority=1,
    )
    from bacpypes3.basetypes import DeviceObjectPropertyReference

    return ScheduleObject(
        objectIdentifier=("schedule", 1),
        objectName="Office-Hours",
        presentValue=Integer(0),
        effectivePeriod=DateRange(
            startDate=Date("2026-01-01"),
            endDate=Date("2027-12-31"),
        ),
        weeklySchedule=_weekday_schedule(),
        exceptionSchedule=[special_event],
        scheduleDefault=Integer(0),
        listOfObjectPropertyReferences=[
            DeviceObjectPropertyReference(
                objectIdentifier=ObjectIdentifier(("binaryValue", 1)),
                propertyIdentifier="presentValue",
            )
        ],
        priorityForWriting=write_priority,
        outOfService=False,
    )


def _point_json(
    active_slot_index: int = None,
    schedule_slot_index: int = 9,
    schedule_value: str = "inactive",
) -> dict:
    array = [None] * 16
    if active_slot_index is not None:
        array[active_slot_index] = {"enumerated": "active"}
    if schedule_slot_index != active_slot_index:
        array[schedule_slot_index] = {"enumerated": schedule_value}
    return {
        "object-identifier": "binary-value,1",
        "object-name": "occupied-bv",
        "out-of-service": False,
        "present-value": "active" if active_slot_index is not None else "inactive",
        "current-command-priority": (
            active_slot_index + 1 if active_slot_index is not None else None
        ),
        "relinquish-default": "inactive",
        "priority-array": array,
    }


def _document(
    schedule: ScheduleObject,
    instant: str,
    calendar: CalendarObject = None,
    point: dict = None,
) -> dict:
    objects = [schedule]
    if calendar is not None:
        objects = [calendar, schedule]
    document = {
        "evaluation-instant": instant,
        "objects": [sequence_to_json(obj) for obj in objects],
        "points": [point] if point is not None else [],
    }
    # sequence_to_json encodes Any-typed slots (presentValue, scheduleDefault,
    # TimeValue.value) as raw tag lists; replace them with the plain integer
    # literals the audit snapshot loader accepts.
    sched_json = document["objects"][-1]
    sched_json["present-value"] = int(schedule.presentValue.get_value())
    sched_json["schedule-default"] = int(schedule.scheduleDefault.get_value())
    for day_json, day_obj in zip(
        sched_json["weekly-schedule"], schedule.weeklySchedule
    ):
        for tv_json, tv_obj in zip(day_json["day-schedule"], day_obj.daySchedule):
            tv_json["value"] = int(tv_obj.value.get_value())
    for event_json, event_obj in zip(
        sched_json.get("exception-schedule", []),
        schedule.exceptionSchedule or [],
    ):
        for tv_json, tv_obj in zip(
            event_json["list-of-time-values"], event_obj.listOfTimeValues
        ):
            tv_json["value"] = int(tv_obj.value.get_value())
    return document


def test_weekly_schedule_then_exception_then_override():
    """The headline scenario: exception day beats weekly, priority 8 beats
    the schedule's priority 10 write."""
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()
    point = _point_json(active_slot_index=7)

    # Friday 2026-12-25 10:30, a calendar holiday.
    document = _document(
        schedule, f"2026-12-25T10:30:00{TZ}", calendar=calendar, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["schedule-verdict"] == ScheduleVerdict.EXCEPTION.value
    assert result["declared-schedule-value"] == 0
    assert result["point-verdict"] == PointVerdict.HIGHER_PRIORITY_ACTIVE.value
    assert result["conclusion"] == Conclusion.HIGHER_PRIORITY_OVERRIDE.value
    assert result["active-command-priority"] == 8
    assert result["schedule-write-priority"] == 10
    assert result["effective-point-value"] == "active"

    sources = {item.source for item in report.evidence}
    assert "calendar,1 dateList" in sources
    assert "schedule,1 exceptionSchedule" in sources
    assert "binary-value,1 priorityArray[7]" in sources
    assert "binary-value,1 priorityArray[9]" in sources

    # every evidence item is classified as declaration or execution
    for item in report.evidence:
        assert item.declared_vs_executed in ("declared", "executed")
    executed = [
        item for item in report.evidence if item.declared_vs_executed == "executed"
    ]
    assert any("priorityArray" in item.source for item in executed)


def test_weekly_schedule_controls_on_normal_day():
    """Same device, ordinary Wednesday: weekly schedule is the declaration."""
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()
    # schedule's own priority-10 slot is the active command
    point = _point_json(active_slot_index=9, schedule_value="active")

    document = _document(
        schedule, f"2026-12-23T10:30:00{TZ}", calendar=calendar, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["schedule-verdict"] == ScheduleVerdict.WEEKLY.value
    assert result["declared-schedule-value"] == 1
    assert result["conclusion"] == Conclusion.SCHEDULE_IN_COMMAND.value
    assert result["active-command-priority"] == 10

    # no exception evidence on a normal day
    assert not any(
        item.source == "schedule,1 exceptionSchedule" for item in report.evidence
    )


def test_missing_calendar_keeps_exception_question_pending():
    """Referenced calendar absent from the snapshot: pending, never guessed."""
    schedule = _holiday_schedule()
    point = _point_json(active_slot_index=9, schedule_value="inactive")

    document = _document(
        schedule, f"2026-12-25T10:30:00{TZ}", calendar=None, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    pending_reasons = {item["reason"] for item in result["pending"]}
    assert PendingReason.MISSING_CALENDAR.value in pending_reasons
    # the weekly schedule can still be evaluated as a fallback declaration
    assert result["schedule-verdict"] == ScheduleVerdict.WEEKLY.value


def test_missing_target_point_keeps_execution_pending():
    """Declaration resolves; actual execution stays pending without the
    point's observed priority array."""
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()

    document = _document(
        schedule, f"2026-12-25T10:30:00{TZ}", calendar=calendar, point=None
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["schedule-verdict"] == ScheduleVerdict.EXCEPTION.value
    assert result["point-verdict"] == PointVerdict.NOT_OBSERVED.value
    assert result["conclusion"] == Conclusion.PENDING.value
    pending_reasons = {item["reason"] for item in result["pending"]}
    assert PendingReason.MISSING_POINT.value in pending_reasons


def test_outside_effective_period_short_circuits():
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()
    point = _point_json(active_slot_index=9)
    document = _document(
        schedule, "2030-06-01T10:30:00+08:00", calendar=calendar, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["schedule-verdict"] == (
        ScheduleVerdict.OUTSIDE_EFFECTIVE_PERIOD.value
    )
    assert result["conclusion"] == (Conclusion.OUTSIDE_EFFECTIVE_PERIOD.value)
    assert result["declared-schedule-value"] is None
    assert any(item.source == "schedule,1 effectivePeriod" for item in report.evidence)


def test_schedule_default_when_no_time_value_active():
    """Before the first daily TimeValue, scheduleDefault governs."""
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()
    point = _point_json(active_slot_index=9, schedule_value="inactive")
    # Wednesday 06:00, before the 08:00 occupied command
    document = _document(
        schedule, f"2026-12-23T06:00:00{TZ}", calendar=calendar, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["schedule-verdict"] == ScheduleVerdict.DEFAULT.value
    assert result["declared-schedule-value"] == 0
    assert any(item.source == "schedule,1 scheduleDefault" for item in report.evidence)


def test_inline_calendar_entry_exception():
    """An exception defined inline (no calendar reference) resolves fully."""
    schedule = _holiday_schedule()
    schedule.exceptionSchedule = [
        SpecialEvent(
            period=SpecialEventPeriod(
                calendarEntry=CalendarEntry(date=Date("2026-12-25"))
            ),
            listOfTimeValues=[_time_value(0, 0, Integer(0))],
            eventPriority=1,
        )
    ]
    point = _point_json(active_slot_index=9, schedule_value="inactive")
    document = _document(
        schedule, f"2026-12-25T10:30:00{TZ}", calendar=None, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["schedule-verdict"] == ScheduleVerdict.EXCEPTION.value
    assert result["conclusion"] == Conclusion.SCHEDULE_IN_COMMAND.value
    assert result["pending"] == []


def test_relinquished_point_falls_to_default_state():
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()
    point = _point_json(active_slot_index=None)
    point["priority-array"] = [None] * 16
    document = _document(
        schedule, f"2026-12-23T10:30:00{TZ}", calendar=calendar, point=point
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["point-verdict"] == PointVerdict.NO_WRITE_ACTIVE.value
    assert result["conclusion"] == (Conclusion.SCHEDULE_RELINQUISHED.value)


def test_naive_instant_is_rejected():
    """The audit must never substitute the host timezone."""
    schedule = _holiday_schedule()
    document = _document(schedule, "2026-12-23T10:30:00", calendar=_holiday_calendar())
    with pytest.raises(AuditConfigurationError, match="timezone-aware"):
        analyze_point(load_snapshot(document))


def test_timezone_offset_changes_the_device_local_day():
    """Same absolute instant, different supplied offset -> different local
    weekday, hence a different schedule branch."""
    schedule = _holiday_schedule()
    calendar = _holiday_calendar()

    evening = _document(schedule, "2026-12-23T20:00:00+08:00", calendar=calendar)
    # five hours west, the same instant is still Wednesday 15:00 local
    west = copy.deepcopy(evening)
    west["evaluation-instant"] = "2026-12-23T15:00:00+03:00"
    report_east = analyze_point(load_snapshot(evening))
    report_west = analyze_point(load_snapshot(west))

    # 20:00 local is after the 17:00 unoccupied command -> default 0
    assert report_east.declared_value == 0
    # 15:00 local is inside occupied hours -> weekly 1
    assert report_west.declared_value == 1


def test_snapshot_without_instant_is_rejected():
    document = _document(
        _holiday_schedule(),
        "2026-12-23T10:30:00+08:00",
        calendar=_holiday_calendar(),
    )
    del document["evaluation-instant"]
    with pytest.raises(SnapshotError, match="evaluation-instant"):
        load_snapshot(document)


def test_priority_array_must_have_16_slots():
    schedule = _holiday_schedule()
    point = _point_json(active_slot_index=7)
    point["priority-array"] = point["priority-array"][:15]
    document = _document(
        schedule,
        "2026-12-23T10:30:00+08:00",
        calendar=_holiday_calendar(),
        point=point,
    )
    with pytest.raises(SnapshotError, match="16 slots"):
        load_snapshot(document)


def test_schedule_object_out_of_service_makes_no_writes():
    schedule = _holiday_schedule()
    schedule.outOfService = True
    point = _point_json(active_slot_index=7)
    document = _document(
        schedule,
        "2026-12-25T10:30:00+08:00",
        calendar=_holiday_calendar(),
        point=point,
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["conclusion"] == Conclusion.SCHEDULE_OUT_OF_SERVICE.value
    assert any(item.source == "schedule,1 outOfService" for item in report.evidence)


def test_point_out_of_service_is_reported_separately():
    schedule = _holiday_schedule()
    point = _point_json(active_slot_index=7)
    point["out-of-service"] = True
    document = _document(
        schedule,
        "2026-12-25T10:30:00+08:00",
        calendar=_holiday_calendar(),
        point=point,
    )
    report = analyze_point(load_snapshot(document))
    result = report.as_dict()

    assert result["point-verdict"] == PointVerdict.OUT_OF_SERVICE.value
    assert result["conclusion"] == Conclusion.POINT_OUT_OF_SERVICE.value
