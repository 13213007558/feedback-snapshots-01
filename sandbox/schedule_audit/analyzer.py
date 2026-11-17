"""
Offline Schedule control-path analysis.

The evaluation reuses the pure matching functions from
:mod:`bacpypes3.local.schedule` (``match_date``, ``match_date_range``,
``match_weeknday``, ``date_in_calendar_entry``) so the audit follows the same
date semantics as a running BACpypes3 device, without instantiating any local
object or touching the host clock.

Every evaluation is anchored to a timezone-aware instant supplied by the
caller; that instant is interpreted as the device-local wall clock.  The
analysis machine's own calendar and timezone are never read as device facts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from bacpypes3.basetypes import CalendarEntry, SpecialEvent
from bacpypes3.local.schedule import (
    date_in_calendar_entry,
    match_date_range,
)
from bacpypes3.object import CalendarObject, ScheduleObject
from bacpypes3.primitivedata import Date, Null, ObjectIdentifier, Time

from .model import (
    AuditInput,
    AuditReport,
    Conclusion,
    Evidence,
    PendingReason,
    PointVerdict,
    ScheduleVerdict,
)

_DAY_NAMES = {
    1: "Monday",
    2: "Tuesday",
    3: "Wednesday",
    4: "Thursday",
    5: "Friday",
    6: "Saturday",
    7: "Sunday",
}


class AuditConfigurationError(ValueError):
    """Raised when the snapshot is structurally unsuitable for analysis."""


def _parse_instant(instant_text: str) -> Tuple[Date, Time, datetime]:
    """
    Parse the caller-supplied instant.  A UTC offset (or explicit UTC) is
    mandatory: silently adopting the analysis host's timezone would turn a
    host setting into a device fact.
    """
    try:
        instant = datetime.fromisoformat(instant_text)
    except ValueError as err:
        raise AuditConfigurationError(
            f"evaluation-instant must be ISO 8601: {instant_text!r}"
        ) from err

    if instant.tzinfo is None or instant.utcoffset() is None:
        raise AuditConfigurationError(
            "evaluation-instant must be timezone-aware "
            "(e.g. '2026-12-25T10:30:00+08:00'); the audit never assumes the "
            "host timezone"
        )

    edate = Date(
        (instant.year - 1900, instant.month, instant.day, instant.weekday() + 1)
    )
    etime = Time(
        (instant.hour, instant.minute, instant.second, int(instant.microsecond / 10000))
    )
    return edate, etime, instant


def _atomic_literal(value: Any) -> Any:
    """Render a BACnet atomic (or null) as a plain report value."""
    if value is None:
        return None
    if isinstance(value, Null):
        return None
    getter = getattr(value, "get_value", None)
    if callable(getter):
        resolved = getter()
        return getattr(resolved, "name", resolved)
    return getattr(value, "name", value)


def _find_schedule(
    input_data: AuditInput, schedule_id: Optional[str]
) -> ScheduleObject:
    schedules = [obj for obj in input_data.objects if isinstance(obj, ScheduleObject)]
    if schedule_id is not None:
        target = ObjectIdentifier(schedule_id)
        for schedule in schedules:
            if schedule.objectIdentifier == target:
                return schedule
        raise AuditConfigurationError(
            f"schedule object {schedule_id!r} not present in snapshot"
        )
    if len(schedules) == 1:
        return schedules[0]
    if not schedules:
        raise AuditConfigurationError("snapshot contains no schedule object")
    raise AuditConfigurationError(
        "multiple schedule objects in snapshot; schedule_id is required"
    )


def _index_objects(input_data: AuditInput) -> Dict[ObjectIdentifier, Any]:
    return {obj.objectIdentifier: obj for obj in input_data.objects}


def _index_points(input_data: AuditInput) -> Dict[ObjectIdentifier, dict]:
    return {point["objectIdentifier"]: point for point in input_data.points}


def _calendar_matches(
    calendar: CalendarObject,
    edate: Date,
    schedule_id: str,
    calendar_ref: ObjectIdentifier,
    evidence: List[Evidence],
    pending: List[dict],
) -> Optional[bool]:
    """Evaluate a calendar reference; return None when it stays pending."""
    for entry in calendar.dateList:
        if date_in_calendar_entry(edate, entry):
            evidence.append(
                Evidence(
                    source=f"{calendar_ref} dateList",
                    detail=f"calendar entry {_render_calendar_entry(entry)} "
                    f"matches {edate}",
                    declared_vs_executed="declared",
                    basis="calendar object referenced by "
                    f"{schedule_id} exceptionSchedule",
                )
            )
            return True
    return False


def _render_calendar_entry(entry: CalendarEntry) -> str:
    if entry.date is not None:
        return f"date({entry.date})"
    if entry.dateRange is not None:
        return f"dateRange({entry.dateRange.startDate}.." f"{entry.dateRange.endDate})"
    return f"weekNDay({entry.weekNDay})"


def _evaluate_exception_schedule(
    schedule: ScheduleObject,
    objects_by_id: Dict[ObjectIdentifier, Any],
    edate: Date,
    etime: Time,
    evidence: List[Evidence],
    pending: List[dict],
) -> Optional[Tuple[Any, SpecialEvent, str]]:
    """
    Evaluate exceptionSchedule following BACpypes3 semantics: special events
    are stored in eventPriority order; the first matching event with an active
    (non-relinquished) value wins over both lower event priorities and the
    weekly schedule.

    Returns (value, special_event, match_basis) or None when no exception is
    in effect at the instant.  Missing calendar objects are recorded as
    pending and the event is skipped.
    """
    if not schedule.exceptionSchedule:
        return None

    schedule_id = str(schedule.objectIdentifier)

    for special_event in schedule.exceptionSchedule:
        period = special_event.period
        if period is None:
            continue

        matched = False
        basis = ""
        if period.calendarEntry is not None:
            entry = period.calendarEntry
            matched = date_in_calendar_entry(edate, entry)
            basis = (
                f"inline calendarEntry {_render_calendar_entry(entry)} "
                f"(eventPriority {special_event.eventPriority})"
            )
        else:
            calendar_ref = period.calendarReference
            calendar = objects_by_id.get(calendar_ref)
            if calendar is None or not isinstance(calendar, CalendarObject):
                pending.append(
                    {
                        "reason": PendingReason.MISSING_CALENDAR.value,
                        "reference": str(calendar_ref),
                        "detail": f"{schedule_id} exceptionSchedule references "
                        f"calendar {calendar_ref} which is absent from "
                        "the snapshot; whether this exception applies "
                        "cannot be decided offline",
                    }
                )
                evidence.append(
                    Evidence(
                        source=f"{schedule_id} exceptionSchedule.period",
                        detail=f"calendarReference {calendar_ref} unresolved",
                        declared_vs_executed="declared",
                        basis="missing referenced calendar object",
                    )
                )
                continue

            result = _calendar_matches(
                calendar, edate, schedule_id, calendar_ref, evidence, pending
            )
            matched = bool(result)
            basis = (
                f"calendarReference {calendar_ref} "
                f"(eventPriority {special_event.eventPriority})"
            )

        if not matched:
            continue

        evidence.append(
            Evidence(
                source=f"{schedule_id} exceptionSchedule",
                detail=f"special event period matches {edate}: {basis}",
                declared_vs_executed="declared",
                basis="exceptionSchedule period override per BACnet Clause 12.24",
            )
        )

        active_value = _active_time_value(
            special_event.listOfTimeValues,
            etime,
            f"{schedule_id} exceptionSchedule",
            evidence,
        )
        if active_value is None:
            # A Null TimeValue relinquishes the exception: per BACpypes3 the
            # event slot is cleared and evaluation falls through to the
            # weekly schedule / default.
            evidence.append(
                Evidence(
                    source=f"{schedule_id} exceptionSchedule",
                    detail="matching special event relinquishes at/ before "
                    f"{etime} (Null value); falling back to weekly schedule",
                    declared_vs_executed="declared",
                    basis="Null TimeValue in special event listOfTimeValues",
                )
            )
            continue

        return active_value, special_event, basis

    return None


def _active_time_value(
    time_values: Any,
    etime: Time,
    source: str,
    evidence: List[Evidence],
) -> Optional[Any]:
    """
    Return the value of the last TimeValue whose time is at or before the
    evaluation time, mirroring ScheduleObject.eval().  Null means relinquish
    and is returned as None.
    """
    active: Any = None
    for time_value in time_values:
        if time_value.time <= etime:
            if isinstance(time_value.value, Null):
                active = None
            else:
                active = time_value.value
                evidence.append(
                    Evidence(
                        source=source,
                        detail=f"TimeValue at {time_value.time} <= {etime} "
                        f"commands {_atomic_literal(time_value.value)}",
                        declared_vs_executed="declared",
                        basis="last time-value not later than evaluation time",
                    )
                )
        else:
            break
    return active


def _evaluate_weekly(
    schedule: ScheduleObject,
    edate: Date,
    etime: Time,
    evidence: List[Evidence],
) -> Tuple[Any, str]:
    """
    Evaluate weeklySchedule for the evaluation weekday.  Returns the value
    and a human basis; falls back to scheduleDefault.
    """
    schedule_id = str(schedule.objectIdentifier)
    day_of_week = edate[3]

    if not schedule.weeklySchedule:
        default = schedule.scheduleDefault
        evidence.append(
            Evidence(
                source=f"{schedule_id} scheduleDefault",
                detail=f"no weeklySchedule present; default "
                f"{_atomic_literal(default)} applies",
                declared_vs_executed="declared",
                basis="scheduleDefault fallback",
            )
        )
        return default, "scheduleDefault"

    # BACnet weekday is 1=Monday..7=Sunday; arrays are zero-based.
    daily_schedule = schedule.weeklySchedule[day_of_week - 1]
    day_name = _DAY_NAMES[day_of_week]
    evidence.append(
        Evidence(
            source=f"{schedule_id} weeklySchedule[{day_of_week - 1}]",
            detail=f"{edate} is {day_name}; selected that daily schedule",
            declared_vs_executed="declared",
            basis="weeklySchedule array index = dayOfWeek - 1",
        )
    )

    active: Any = None
    for time_value in daily_schedule.daySchedule:
        if time_value.time <= etime:
            if isinstance(time_value.value, Null):
                active = None
            else:
                active = time_value.value
                evidence.append(
                    Evidence(
                        source=f"{schedule_id} weeklySchedule {day_name}",
                        detail=f"TimeValue at {time_value.time} <= {etime} "
                        f"commands {_atomic_literal(time_value.value)}",
                        declared_vs_executed="declared",
                        basis="last time-value not later than evaluation time",
                    )
                )
        else:
            break

    if active is not None:
        return active, f"weeklySchedule/{day_name}"

    default = schedule.scheduleDefault
    evidence.append(
        Evidence(
            source=f"{schedule_id} scheduleDefault",
            detail=f"no active weekly TimeValue at {etime}; default "
            f"{_atomic_literal(default)} applies",
            declared_vs_executed="declared",
            basis="scheduleDefault fallback within an active day",
        )
    )
    return default, "scheduleDefault"


def _evaluate_point_execution(
    schedule: ScheduleObject,
    reference: Any,
    points_by_id: Dict[ObjectIdentifier, dict],
    declared_value: Any,
    evidence: List[Evidence],
    pending: List[dict],
) -> Tuple[PointVerdict, Conclusion, Optional[int], Any]:
    """
    Compare the Schedule's declared write (priorityForWriting into the
    referenced point/property) against the point's observed priority array.
    """
    schedule_id = str(schedule.objectIdentifier)
    target_id = reference.objectIdentifier
    write_priority = int(schedule.priorityForWriting)

    evidence.append(
        Evidence(
            source=f"{schedule_id} listOfObjectPropertyReferences",
            detail=f"writes {reference.propertyIdentifier}"
            + (
                f"[{reference.propertyArrayIndex}]"
                if reference.propertyArrayIndex is not None
                else ""
            )
            + f" of {target_id} at priority {write_priority}",
            declared_vs_executed="declared",
            basis="listOfObjectPropertyReferences + priorityForWriting",
        )
    )
    evidence.append(
        Evidence(
            source=f"{schedule_id} priorityForWriting",
            detail=f"schedule writes target at BACnet priority {write_priority} "
            f"(priorityArray index {write_priority - 1})",
            declared_vs_executed="declared",
            basis="BACnet 16-level priority array",
        )
    )

    point = points_by_id.get(target_id)
    if point is None:
        pending.append(
            {
                "reason": PendingReason.MISSING_POINT.value,
                "reference": str(target_id),
                "detail": f"{schedule_id} targets {target_id} but the point's "
                "observed state is absent from the snapshot; actual "
                "execution (override vs. schedule) cannot be verified",
            }
        )
        return (PointVerdict.NOT_OBSERVED, Conclusion.PENDING, None, None)

    if point["outOfService"]:
        evidence.append(
            Evidence(
                source=f"{target_id} outOfService",
                detail="point is outOfService; priority-array commanding is "
                "suspended and presentValue is manually set",
                declared_vs_executed="executed",
                basis="observed outOfService property",
            )
        )
        return (
            PointVerdict.OUT_OF_SERVICE,
            Conclusion.POINT_OUT_OF_SERVICE,
            None,
            point["observedPresentValue"],
        )

    priority_array = point["priorityArray"]
    if priority_array is None:
        pending.append(
            {
                "reason": PendingReason.MISSING_PRIORITY_ARRAY.value,
                "reference": str(target_id),
                "detail": f"point {target_id} snapshot lacks priorityArray; the "
                "active command priority cannot be compared",
            }
        )
        return (
            PointVerdict.PENDING,
            Conclusion.PENDING,
            None,
            point["observedPresentValue"],
        )

    # Find the highest-priority (lowest index) non-null slot.
    active_index: Optional[int] = None
    active_slot = None
    for index, slot in enumerate(priority_array):
        if slot.null is None:
            active_index = index
            active_slot = slot
            break

    if active_index is None:
        evidence.append(
            Evidence(
                source=f"{target_id} priorityArray",
                detail="all 16 priority slots are Null; the point rests on "
                f"relinquishDefault {point['relinquishDefault']!r}",
                declared_vs_executed="executed",
                basis="observed priorityArray snapshot",
            )
        )
        return (
            PointVerdict.NO_WRITE_ACTIVE,
            Conclusion.SCHEDULE_RELINQUISHED,
            None,
            point["observedPresentValue"],
        )

    active_priority = active_index + 1
    evidence.append(
        Evidence(
            source=f"{target_id} priorityArray[{active_index}]",
            detail=f"highest-priority non-Null slot is priority "
            f"{active_priority} with value "
            f"{_atomic_literal(getattr(active_slot, active_slot._choice))}",
            declared_vs_executed="executed",
            basis="priorityArray scan, first non-Null slot wins",
        )
    )

    schedule_slot = priority_array[write_priority - 1]
    schedule_slot_active = schedule_slot.null is None
    evidence.append(
        Evidence(
            source=f"{target_id} priorityArray[{write_priority - 1}]",
            detail="schedule write slot "
            + (
                "is occupied by "
                f"{_atomic_literal(getattr(schedule_slot, schedule_slot._choice))}"
                if schedule_slot_active
                else "is Null (relinquished)"
            ),
            declared_vs_executed="executed",
            basis=f"priorityForWriting {write_priority} maps to this slot",
        )
    )

    if active_priority < write_priority:
        evidence.append(
            Evidence(
                source=f"{target_id} priorityArray",
                detail=f"priority {active_priority} outranks the schedule write "
                f"priority {write_priority}; the schedule's command is "
                "shadowed even though its slot may remain occupied",
                declared_vs_executed="executed",
                basis="lower priority number = higher precedence",
            )
        )
        return (
            PointVerdict.HIGHER_PRIORITY_ACTIVE,
            Conclusion.HIGHER_PRIORITY_OVERRIDE,
            active_priority,
            point["observedPresentValue"],
        )

    if active_priority == write_priority and schedule_slot_active:
        evidence.append(
            Evidence(
                source=f"{target_id} priorityArray",
                detail=f"the schedule's own priority {write_priority} slot is the "
                "active command; point value follows the schedule",
                declared_vs_executed="executed",
                basis="active slot equals priorityForWriting",
            )
        )
        return (
            PointVerdict.SCHEDULE_PRIORITY_ACTIVE,
            Conclusion.SCHEDULE_IN_COMMAND,
            active_priority,
            point["observedPresentValue"],
        )

    # A higher-priority slot should have been caught above; reaching here
    # means the active slot is numerically lower precedence than the schedule
    # slot yet the schedule slot is Null.
    evidence.append(
        Evidence(
            source=f"{target_id} priorityArray",
            detail=f"active priority {active_priority} is below the schedule "
            f"write priority {write_priority}, whose slot is Null; "
            "schedule is not commanding",
            declared_vs_executed="executed",
            basis="schedule slot relinquished",
        )
    )
    return (
        PointVerdict.HIGHER_PRIORITY_ACTIVE,
        Conclusion.HIGHER_PRIORITY_OVERRIDE,
        active_priority,
        point["observedPresentValue"],
    )


def analyze_point(
    input_data: AuditInput, schedule_id: Optional[str] = None
) -> AuditReport:
    """
    Produce an :class:`AuditReport` explaining why the point targeted by a
    Schedule is controlled the way it is at the caller-supplied instant.
    """
    edate, etime, instant = _parse_instant(input_data.instant_text)
    schedule = _find_schedule(input_data, schedule_id)
    objects_by_id = _index_objects(input_data)
    points_by_id = _index_points(input_data)

    schedule_id_text = str(schedule.objectIdentifier)
    evidence: List[Evidence] = []
    pending: List[dict] = []

    evidence.append(
        Evidence(
            source="caller-supplied evaluation-instant",
            detail=f"{input_data.instant_text} interpreted as device-local "
            f"date {edate} ({_DAY_NAMES[edate[3]]}), time {etime}; host "
            "clock and host timezone are not consulted",
            declared_vs_executed="declared",
            basis="explicit timezone-aware caller input",
        )
    )

    if schedule.outOfService:
        evidence.append(
            Evidence(
                source=f"{schedule_id_text} outOfService",
                detail="schedule object is outOfService; it performs no writes",
                declared_vs_executed="executed",
                basis="observed schedule property",
            )
        )
        return AuditReport(
            evaluation_instant=input_data.instant_text,
            device_local_datetime=str(instant),
            schedule_identifier=schedule_id_text,
            schedule_verdict=ScheduleVerdict.PENDING,
            point_identifier=None,
            point_verdict=PointVerdict.PENDING,
            conclusion=Conclusion.SCHEDULE_OUT_OF_SERVICE,
            declared_value=None,
            effective_value=None,
            schedule_write_priority=(
                int(schedule.priorityForWriting)
                if schedule.priorityForWriting is not None
                else None
            ),
            active_command_priority=None,
            evidence=evidence,
            pending=pending,
        )

    # Step 1: effectivePeriod gates every other declaration.
    if not match_date_range(edate, schedule.effectivePeriod):
        evidence.append(
            Evidence(
                source=f"{schedule_id_text} effectivePeriod",
                detail=f"{edate} is outside "
                f"{schedule.effectivePeriod.startDate}.."
                f"{schedule.effectivePeriod.endDate}; the schedule makes "
                "no command (BACpypes3 eval() returns no value)",
                declared_vs_executed="declared",
                basis="effectivePeriod date-range gate",
            )
        )
        return AuditReport(
            evaluation_instant=input_data.instant_text,
            device_local_datetime=str(instant),
            schedule_identifier=schedule_id_text,
            schedule_verdict=ScheduleVerdict.OUTSIDE_EFFECTIVE_PERIOD,
            point_identifier=None,
            point_verdict=PointVerdict.PENDING,
            conclusion=Conclusion.OUTSIDE_EFFECTIVE_PERIOD,
            declared_value=None,
            effective_value=None,
            schedule_write_priority=(
                int(schedule.priorityForWriting)
                if schedule.priorityForWriting is not None
                else None
            ),
            active_command_priority=None,
            evidence=evidence,
            pending=pending,
        )

    evidence.append(
        Evidence(
            source=f"{schedule_id_text} effectivePeriod",
            detail=f"{edate} is within "
            f"{schedule.effectivePeriod.startDate}.."
            f"{schedule.effectivePeriod.endDate}",
            declared_vs_executed="declared",
            basis="effectivePeriod date-range gate",
        )
    )

    # Step 2: exception schedule (calendar entry inline or calendar reference).
    exception_result = _evaluate_exception_schedule(
        schedule, objects_by_id, edate, etime, evidence, pending
    )
    if exception_result is not None:
        declared_value, special_event, basis = exception_result
        schedule_verdict = ScheduleVerdict.EXCEPTION
        evidence.append(
            Evidence(
                source=f"{schedule_id_text} exceptionSchedule",
                detail=f"exception (eventPriority {special_event.eventPriority}, "
                f"{basis}) overrides weeklySchedule; declared value "
                f"{_atomic_literal(declared_value)}",
                declared_vs_executed="declared",
                basis="matching special event takes precedence over weekly "
                "schedule per BACnet Clause 12.24.5",
            )
        )
    else:
        # Step 3: weekly schedule, then scheduleDefault.
        declared_value, weekly_basis = _evaluate_weekly(
            schedule, edate, etime, evidence
        )
        schedule_verdict = (
            ScheduleVerdict.WEEKLY
            if weekly_basis.startswith("weeklySchedule")
            else ScheduleVerdict.DEFAULT
        )

    # Step 4: resolve the target reference and compare against the observed
    # priority array to distinguish declaration from execution.
    references = schedule.listOfObjectPropertyReferences
    if not references:
        evidence.append(
            Evidence(
                source=f"{schedule_id_text} listOfObjectPropertyReferences",
                detail="schedule has no object property references; it declares "
                "a presentValue but writes nothing",
                declared_vs_executed="declared",
                basis="empty reference list",
            )
        )
        return AuditReport(
            evaluation_instant=input_data.instant_text,
            device_local_datetime=str(instant),
            schedule_identifier=schedule_id_text,
            schedule_verdict=schedule_verdict,
            point_identifier=None,
            point_verdict=PointVerdict.NOT_OBSERVED,
            conclusion=(
                Conclusion.PENDING if pending else Conclusion.SCHEDULE_RELINQUISHED
            ),
            declared_value=_atomic_literal(declared_value),
            effective_value=None,
            schedule_write_priority=(
                int(schedule.priorityForWriting)
                if schedule.priorityForWriting is not None
                else None
            ),
            active_command_priority=None,
            evidence=evidence,
            pending=pending,
        )

    if len(references) > 1:
        pending.append(
            {
                "reason": PendingReason.INVALID_REFERENCE.value,
                "reference": ", ".join(str(ref.objectIdentifier) for ref in references),
                "detail": "schedule references more than one point; this audit "
                "evaluates one control path at a time",
            }
        )

    reference = references[0]
    point_verdict, conclusion, active_priority, effective_value = (
        _evaluate_point_execution(
            schedule, reference, points_by_id, declared_value, evidence, pending
        )
    )

    # Pending calendar evidence can downgrade an otherwise-resolved execution
    # conclusion: the declaration itself is solid, but a competing exception
    # may exist. Keep the execution verdict, mark the overall conclusion
    # pending only when nothing executable could be confirmed.
    if pending and conclusion not in (
        Conclusion.HIGHER_PRIORITY_OVERRIDE,
        Conclusion.SCHEDULE_IN_COMMAND,
    ):
        conclusion = Conclusion.PENDING

    return AuditReport(
        evaluation_instant=input_data.instant_text,
        device_local_datetime=str(instant),
        schedule_identifier=schedule_id_text,
        schedule_verdict=schedule_verdict,
        point_identifier=str(reference.objectIdentifier),
        point_verdict=point_verdict,
        conclusion=conclusion,
        declared_value=_atomic_literal(declared_value),
        effective_value=effective_value,
        schedule_write_priority=int(schedule.priorityForWriting),
        active_command_priority=active_priority,
        evidence=evidence,
        pending=pending,
    )
