"""
Data model for the offline Schedule audit.

The report types deliberately separate two layers of evidence:

* **schedule declarations** — what the device configuration says the
  Schedule should command at the evaluation instant (weekly schedule,
  exception schedule, calendar references, effective period, default);
* **observed device execution** — what the target point's priority array and
  command priority show the device has actually applied.

A declaration can be fully resolved while the execution question remains
pending, for example when the referenced point was not captured in the
snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional


class PendingReason(str, Enum):
    """Why a conclusion could not be fully resolved offline."""

    MISSING_CALENDAR = "missing-calendar-object"
    MISSING_POINT = "missing-referenced-point"
    MISSING_PRIORITY_ARRAY = "missing-point-priority-array"
    INVALID_REFERENCE = "unresolvable-object-property-reference"


class Conclusion(str, Enum):
    """Top-level verdict for the point at the evaluation instant."""

    SCHEDULE_IN_COMMAND = "schedule-in-command"
    HIGHER_PRIORITY_OVERRIDE = "higher-priority-override"
    SCHEDULE_RELINQUISHED = "schedule-relinquished-to-default"
    OUTSIDE_EFFECTIVE_PERIOD = "outside-effective-period"
    SCHEDULE_OUT_OF_SERVICE = "schedule-out-of-service"
    POINT_OUT_OF_SERVICE = "point-out-of-service"
    PENDING = "pending"


class ScheduleVerdict(str, Enum):
    """What the Schedule configuration itself declares."""

    WEEKLY = "weekly-schedule"
    EXCEPTION = "exception-schedule"
    DEFAULT = "schedule-default"
    OUTSIDE_EFFECTIVE_PERIOD = "outside-effective-period"
    PENDING = "pending"


class PointVerdict(str, Enum):
    """What the observed point state shows about actual execution."""

    SCHEDULE_PRIORITY_ACTIVE = "schedule-write-priority-active"
    HIGHER_PRIORITY_ACTIVE = "higher-priority-write-active"
    NO_WRITE_ACTIVE = "no-priority-write-active"
    OUT_OF_SERVICE = "point-out-of-service"
    NOT_OBSERVED = "point-not-observed"
    PENDING = "pending"


@dataclass
class Evidence:
    """
    One configuration fact supporting a conclusion.

    ``source`` identifies the object and property the fact comes from,
    ``detail`` renders the matching values, and ``declared_vs_executed``
    marks whether this is a device configuration declaration or an observed
    execution fact.
    """

    source: str
    detail: str
    declared_vs_executed: str  # "declared" | "executed"
    basis: str

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "detail": self.detail,
            "evidence-class": self.declared_vs_executed,
            "basis": self.basis,
        }


@dataclass
class AuditInput:
    """Hydrated snapshot plus the caller-supplied evaluation instant."""

    instant_text: str
    objects: List[Any]
    points: List[dict]
    raw: dict = field(default_factory=dict)


@dataclass
class AuditReport:
    """Full audit result for one Schedule/point evaluation."""

    evaluation_instant: str
    device_local_datetime: str
    schedule_identifier: str
    schedule_verdict: ScheduleVerdict
    point_identifier: Optional[str]
    point_verdict: PointVerdict
    conclusion: Conclusion
    declared_value: Any
    effective_value: Any
    schedule_write_priority: Optional[int]
    active_command_priority: Optional[int]
    evidence: List[Evidence] = field(default_factory=list)
    pending: List[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "evaluation-instant": self.evaluation_instant,
            "device-local-datetime": self.device_local_datetime,
            "schedule": self.schedule_identifier,
            "schedule-verdict": self.schedule_verdict.value,
            "point": self.point_identifier,
            "point-verdict": self.point_verdict.value,
            "conclusion": self.conclusion.value,
            "declared-schedule-value": self.declared_value,
            "effective-point-value": self.effective_value,
            "schedule-write-priority": self.schedule_write_priority,
            "active-command-priority": self.active_command_priority,
            "evidence": [item.as_dict() for item in self.evidence],
            "pending": self.pending,
        }
