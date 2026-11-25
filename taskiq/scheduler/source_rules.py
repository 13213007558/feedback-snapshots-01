"""Rules that decide which schedule source may dispatch a plan."""

import enum
import json
from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from taskiq.scheduler.scheduled_task import ScheduledTask

if TYPE_CHECKING:  # pragma: no cover
    from taskiq.abc.schedule_source import ScheduleSource


class ScheduleSourceRole(str, enum.Enum):
    """Role of a schedule source in the scheduler."""

    DISPATCH = "dispatch"
    """The source is allowed to publish due tasks."""

    OBSERVE = "observe"
    """The source is registered for display/audit purposes only."""

    def __str__(self) -> str:
        """Return the plain role value."""
        return self.value


@dataclass(frozen=True)
class ScheduleSourceRule:
    """Rule assigned to a single schedule source."""

    role: ScheduleSourceRole = ScheduleSourceRole.DISPATCH
    name: str | None = None
    """Stable name shown in audit records and message labels."""


@dataclass(frozen=True)
class ResolvedSchedule:
    """A schedule together with the source that produced it."""

    source: "ScheduleSource"
    task: ScheduledTask
    source_name: str
    role: ScheduleSourceRole
    dispatch_allowed: bool
    identity: str

    @property
    def is_observational(self) -> bool:
        """Whether this plan is only displayed and never published."""
        return not self.dispatch_allowed


@dataclass(frozen=True)
class ScheduleConflict:
    """Two or more allowed sources offered the same due item."""

    identity: str
    source_names: tuple[str, ...]
    chosen_source: str


@dataclass(frozen=True)
class ResolvedSchedules:
    """The dispatch plan and the full observation view of all sources."""

    dispatch: tuple[ResolvedSchedule, ...]
    observed: tuple[ResolvedSchedule, ...]
    conflicts: tuple[ScheduleConflict, ...]

    def dispatch_plans(self) -> list[tuple["ScheduleSource", list[ScheduledTask]]]:
        """Group the dispatch-ready entries by source."""
        plans: list[tuple[ScheduleSource, list[ScheduledTask]]] = []
        for entry in self.dispatch:
            if plans and plans[-1][0] is entry.source:
                plans[-1][1].append(entry.task)
            else:
                plans.append((entry.source, [entry.task]))
        return plans

    def by_source(self, source_name: str) -> tuple[ResolvedSchedule, ...]:
        """Return every observed plan attributed to a source name."""
        return tuple(
            entry for entry in self.observed if entry.source_name == source_name
        )


def _as_utc(value: datetime) -> datetime:
    """Return a timezone-aware datetime in UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def schedule_identity(task: ScheduledTask) -> str:
    """
    Build a stable identity for a plan.

    The identity deliberately ignores the source and ``schedule_id``:
    the same plan can be registered by several sources under different
    ids and must still be recognised as one due item after a refresh.

    :param task: schedule to describe.
    :return: stable identity string.
    """
    if task.time is not None:
        trigger = f"time:{_as_utc(task.time).isoformat()}"
    elif task.cron is not None:
        trigger = f"cron:{task.cron}:{task.cron_offset or 'UTC'}"
    else:
        trigger = f"interval:{task.interval}"

    payload = json.dumps(
        {"args": task.args, "kwargs": task.kwargs},
        sort_keys=True,
        default=str,
    )
    return f"{task.task_name}|{trigger}|{payload}"


def schedule_occurrence(task: ScheduledTask, now: datetime) -> str:
    """
    Build the key of one concrete due occurrence.

    For cron and time plans the key identifies the due slot. For interval
    plans the current second is part of the key, so each interval tick is
    a distinct occurrence.

    :param task: schedule that is due.
    :param now: current scheduler time.
    :return: occurrence key.
    """
    identity = schedule_identity(task)
    if task.time is not None:
        slot = _as_utc(task.time).isoformat()
    elif task.cron is not None:
        slot = _as_utc(now).replace(second=0, microsecond=0).isoformat()
    else:
        slot = _as_utc(now).replace(microsecond=0).isoformat()
    return f"{identity}@{slot}"


@dataclass(frozen=True)
class DispatchContext:
    """Scheduler bookkeeping attached to one dispatch attempt."""

    occurrence: str
    resolved: ResolvedSchedule


current_dispatch: ContextVar[DispatchContext | None] = ContextVar(
    "taskiq_current_dispatch",
    default=None,
)


class ScheduleSourceRules:
    """Optional rules for a mixed dispatch/observation source setup."""

    def __init__(
        self,
        rules: Mapping["ScheduleSource", ScheduleSourceRule] | None = None,
    ) -> None:
        """
        Create a rule set.

        Sources without an explicit rule default to the ``DISPATCH`` role
        and are named after their class and position.

        :param rules: mapping of source to its rule.
        """
        self._rules: dict[int, ScheduleSourceRule] = {}
        self._sources: dict[int, ScheduleSource] = {}
        self._revoked: set[int] = set()
        for source, rule in (rules or {}).items():
            self._rules[id(source)] = rule
            self._sources[id(source)] = source

    def rule_for(self, source: "ScheduleSource") -> ScheduleSourceRule:
        """Return the rule assigned to a source."""
        return self._rules.get(id(source), ScheduleSourceRule())

    def set_rule(self, source: "ScheduleSource", rule: ScheduleSourceRule) -> None:
        """Assign or replace the rule of a source."""
        self._rules[id(source)] = rule
        self._sources[id(source)] = source

    def display_name(self, source: "ScheduleSource", index: int) -> str:
        """Return the stable display name of a source."""
        rule_name = self.rule_for(source).name
        if rule_name is not None:
            return rule_name
        if index < 0:
            return source.__class__.__name__
        return f"{source.__class__.__name__}[{index}]"

    def revoke(self, source: "ScheduleSource") -> None:
        """Stop a source from dispatching without removing its plans."""
        self._sources[id(source)] = source
        self._revoked.add(id(source))

    def restore(self, source: "ScheduleSource") -> None:
        """Allow a previously revoked source to dispatch again."""
        self._revoked.discard(id(source))

    def is_revoked(self, source: "ScheduleSource") -> bool:
        """Whether the source has been revoked."""
        return id(source) in self._revoked

    def is_dispatch_allowed(self, source: "ScheduleSource") -> bool:
        """Whether the source may currently publish due tasks."""
        return (
            self.rule_for(source).role is ScheduleSourceRole.DISPATCH
            and not self.is_revoked(source)
        )

    def resolve(
        self,
        schedules: Sequence[tuple["ScheduleSource", list[ScheduledTask]]],
    ) -> ResolvedSchedules:
        """
        Split raw source schedules into dispatch and observation plans.

        Every source contributes to ``observed``; only sources whose rule
        allows dispatching contribute to ``dispatch``. When several allowed
        sources offer the same identity, the first one wins and the
        collision is reported in ``conflicts``.

        :param schedules: `(source, tasks)` pairs as returned by the loop.
        :return: resolved plans.
        """
        observed: list[ResolvedSchedule] = []
        for index, (source, tasks) in enumerate(schedules):
            rule = self.rule_for(source)
            source_name = self.display_name(source, index)
            allowed = self.is_dispatch_allowed(source)
            for task in tasks:
                observed.append(
                    ResolvedSchedule(
                        source=source,
                        task=task,
                        source_name=source_name,
                        role=rule.role,
                        dispatch_allowed=allowed,
                        identity=schedule_identity(task),
                    ),
                )

        dispatch: list[ResolvedSchedule] = []
        chosen: dict[str, ResolvedSchedule] = {}
        candidates: dict[str, list[ResolvedSchedule]] = {}
        for entry in observed:
            if not entry.dispatch_allowed:
                continue
            candidates.setdefault(entry.identity, []).append(entry)
            if entry.identity not in chosen:
                chosen[entry.identity] = entry
                dispatch.append(entry)

        conflicts: list[ScheduleConflict] = []
        for identity, entries in candidates.items():
            distinct_sources = {id(entry.source) for entry in entries}
            if len(distinct_sources) <= 1:
                continue
            conflicts.append(
                ScheduleConflict(
                    identity=identity,
                    source_names=tuple(
                        dict.fromkeys(entry.source_name for entry in entries),
                    ),
                    chosen_source=chosen[identity].source_name,
                ),
            )

        return ResolvedSchedules(
            dispatch=tuple(dispatch),
            observed=tuple(observed),
            conflicts=tuple(conflicts),
        )


def dispatch_rule(name: str | None = None) -> ScheduleSourceRule:
    """Build a rule for a source that may publish due plans."""
    return ScheduleSourceRule(role=ScheduleSourceRole.DISPATCH, name=name)


def observe_rule(name: str | None = None) -> ScheduleSourceRule:
    """Build a rule for a source that is display/audit only."""
    return ScheduleSourceRule(role=ScheduleSourceRole.OBSERVE, name=name)
