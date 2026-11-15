"""Offline correlation of ETW activities.

Groups events by ``ActivityId``, links activities through the
``RelatedActivityId`` extended data item and uses the ``ProcessStartKey``
extended data item to tell process instances apart when a PID is reused.

The correlator only connects events that carry actual evidence (a non-zero
GUID or a process start key). Relations that cannot be resolved from the
trace alone (missing parent activity, ambiguous process attribution) are
reported separately, and cycles or multiple parents in the activity graph
are surfaced as anomalies instead of being forced into a tree.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.etl.exceptions import NoMoreEventsError
from dissect.etl.headers.event import ExtType

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from datetime import datetime

    from dissect.etl.etl import ETL
    from dissect.etl.headers.headers import Header

ZERO_GUID = UUID(int=0)

KIND_RELATED_ACTIVITY = "related_activity"
KIND_ACTIVITY_FLOW = "activity_flow"

REASON_MISSING_PARENT = "missing_parent_activity"
REASON_AMBIGUOUS_PROCESS = "ambiguous_process"


@dataclass(frozen=True)
class RecordLocation:
    """Location of a raw event record inside an ETL file."""

    buffer_index: int
    record_offset: int
    file_offset: int

    def __str__(self) -> str:
        return f"buffer {self.buffer_index} offset 0x{self.record_offset:x} (file 0x{self.file_offset:x})"


@dataclass
class ActivityEvent:
    """Correlation-relevant view of a single event record."""

    location: RecordLocation
    timestamp: datetime | None
    provider_id: UUID | None
    process_id: int | None
    thread_id: int | None
    activity_id: UUID | None
    related_activity_id: UUID | None
    process_start_key: int | None

    @property
    def has_activity(self) -> bool:
        """Whether this event carries a usable (non-zero) activity id."""
        return self.activity_id is not None and self.activity_id != ZERO_GUID


@dataclass
class ActivityEdge:
    """A connection between two event records, backed by ETW evidence."""

    kind: str
    source: ActivityEvent
    target: ActivityEvent
    evidence: dict[str, str]


@dataclass
class UnresolvedRelation:
    """A relation that could not be connected from the trace alone."""

    kind: str
    event: ActivityEvent
    detail: str


@dataclass
class ProcessInstance:
    """A distinct process instance, disambiguated by its start key."""

    process_id: int
    start_key: int | None
    events: list[ActivityEvent] = field(default_factory=list)


@dataclass
class CorrelationResult:
    """Outcome of an offline activity correlation run."""

    events: list[ActivityEvent]
    activities: dict[UUID, list[ActivityEvent]]
    process_instances: list[ProcessInstance]
    edges: list[ActivityEdge]
    unresolved: list[UnresolvedRelation]
    cycles: list[list[UUID]]
    multiple_parents: dict[UUID, list[UUID]]

    def render(self) -> str:
        """Render a human-readable report for manual review."""
        lines = ["Activity correlation report", "===========================", ""]

        lines.append(f"Connected edges ({len(self.edges)}):")
        for edge in self.edges:
            if edge.kind == KIND_RELATED_ACTIVITY:
                related = edge.evidence["related_activity_id"]
                lines.append(f"  [related] activity {related} -> activity {edge.target.activity_id}")
            else:
                lines.append(f"  [flow] activity {edge.evidence['activity_id']}")
            lines.append(f"    from {edge.source.location} pid={edge.source.process_id} tid={edge.source.thread_id}")
            lines.append(f"    to   {edge.target.location} pid={edge.target.process_id} tid={edge.target.thread_id}")
        lines.append("")

        lines.append(f"Unresolved relations ({len(self.unresolved)}):")
        for relation in self.unresolved:
            lines.append(f"  [{relation.kind}] {relation.detail} (record at {relation.event.location})")
        lines.append("")

        lines.append("Anomalies:")
        if not self.cycles and not self.multiple_parents:
            lines.append("  none")
        for cycle in self.cycles:
            lines.append(f"  [cycle] {' -> '.join(str(guid) for guid in [*cycle, cycle[0]])}")
        for child, parents in self.multiple_parents.items():
            lines.append(f"  [multiple-parents] activity {child} <- {', '.join(str(guid) for guid in parents)}")
        lines.append("")

        lines.append(f"Process instances ({len(self.process_instances)}):")
        for instance in self.process_instances:
            lines.append(
                f"  pid={instance.process_id} start_key={instance.start_key}: {len(instance.events)} record(s)"
            )
        return "\n".join(lines)


def activity_event_from_header(
    buffer_index: int, record_offset: int, file_offset: int, header: Header
) -> ActivityEvent:
    """Extract the correlation-relevant fields from a parsed event header."""
    related_activity_id = None
    process_start_key = None
    for item in getattr(header, "header_extensions", []):
        if item.ext_type == ExtType.RELATED_ACTIVITY_ID and item.Guid:
            related_activity_id = UUID(item.Guid)
        elif item.ext_type == ExtType.PROCESS_START_KEY:
            process_start_key = item.ProcessStartKey

    try:
        timestamp = header.timestamp
    except (TypeError, ValueError, AttributeError):
        timestamp = None

    return ActivityEvent(
        location=RecordLocation(buffer_index, record_offset, file_offset),
        timestamp=timestamp,
        provider_id=getattr(header, "provider_id", None),
        process_id=getattr(header, "process_id", None),
        thread_id=getattr(header, "thread_id", None),
        activity_id=getattr(header, "activity_id", None),
        related_activity_id=related_activity_id,
        process_start_key=process_start_key,
    )


def iter_activity_events(etl: ETL) -> Iterator[ActivityEvent]:
    """Walk an ETL file and yield an :class:`ActivityEvent` per record.

    Every yielded event keeps its raw record location (buffer index, offset
    inside the buffer and absolute file offset) for manual review.
    """
    for buffer_index, buffer in enumerate(etl.buffers()):
        offset = 0
        try:
            while offset < buffer.filled_bytes:
                record = buffer.read_record(offset)
                event = activity_event_from_header(buffer_index, offset, buffer.data_offset + offset, record.header)
                offset += record.aligned_size
                yield event
        except (EOFError, NoMoreEventsError):
            continue


def correlate_etl(etl: ETL) -> CorrelationResult:
    """Correlate all activities found in an ETL file."""
    return correlate(iter_activity_events(etl))


def correlate(events: Iterable[ActivityEvent]) -> CorrelationResult:
    """Correlate activity events offline.

    Events are grouped by their (non-zero) ``ActivityId``. Activities are
    linked through non-zero ``RelatedActivityId`` values, and events are
    attributed to process instances using the process start key so that a
    reused PID does not merge two different processes. Only events carrying
    actual evidence are connected; everything else ends up in
    :attr:`CorrelationResult.unresolved`.
    """
    events = list(events)

    activities: dict[UUID, list[ActivityEvent]] = defaultdict(list)
    for event in events:
        if event.has_activity:
            activities[event.activity_id].append(event)
    for members in activities.values():
        members.sort(key=_event_sort_key)

    process_instances, unattributed = _attribute_processes(events)

    edges: list[ActivityEdge] = []
    unresolved: list[UnresolvedRelation] = unattributed
    parent_map: dict[UUID, set[UUID]] = defaultdict(set)

    for event in events:
        related = event.related_activity_id
        if related is None or related == ZERO_GUID:
            continue

        parent_members = activities.get(related)
        if not parent_members:
            unresolved.append(
                UnresolvedRelation(
                    kind=REASON_MISSING_PARENT,
                    event=event,
                    detail=f"RelatedActivityId {related} not present in trace",
                )
            )
            continue

        edges.append(
            ActivityEdge(
                kind=KIND_RELATED_ACTIVITY,
                source=parent_members[0],
                target=event,
                evidence={"related_activity_id": str(related)},
            )
        )
        if event.has_activity:
            parent_map[event.activity_id].add(related)

    for activity_id, members in activities.items():
        for source, target in zip(members, members[1:]):
            edges.append(
                ActivityEdge(
                    kind=KIND_ACTIVITY_FLOW,
                    source=source,
                    target=target,
                    evidence={"activity_id": str(activity_id)},
                )
            )

    multiple_parents = {child: sorted(parents, key=str) for child, parents in parent_map.items() if len(parents) > 1}
    cycles = _find_cycles(parent_map)

    return CorrelationResult(
        events=events,
        activities=dict(activities),
        process_instances=process_instances,
        edges=edges,
        unresolved=unresolved,
        cycles=cycles,
        multiple_parents=multiple_parents,
    )


def _event_sort_key(event: ActivityEvent) -> tuple[float, int, int]:
    timestamp = event.timestamp.timestamp() if event.timestamp is not None else float("inf")
    return (timestamp, event.location.buffer_index, event.location.record_offset)


def _attribute_processes(events: list[ActivityEvent]) -> tuple[list[ProcessInstance], list[UnresolvedRelation]]:
    """Attribute events to process instances, tolerating PID reuse.

    Events carrying a process start key define the instances. Events without
    a key are attributed only when exactly one instance exists for their
    PID; otherwise they are reported as unresolved.
    """
    instances: dict[tuple[int, int | None], ProcessInstance] = {}
    pids_with_keys: dict[int, set[int]] = defaultdict(set)
    unattributed_events: list[ActivityEvent] = []

    for event in events:
        if event.process_id is None:
            continue
        if event.process_start_key is not None:
            key = (event.process_id, event.process_start_key)
            instance = instances.setdefault(
                key, ProcessInstance(process_id=event.process_id, start_key=event.process_start_key)
            )
            instance.events.append(event)
            pids_with_keys[event.process_id].add(event.process_start_key)
        else:
            unattributed_events.append(event)

    unresolved: list[UnresolvedRelation] = []
    for event in unattributed_events:
        known_keys = pids_with_keys.get(event.process_id, set())
        if len(known_keys) == 1:
            start_key = next(iter(known_keys))
            instances[(event.process_id, start_key)].events.append(event)
        elif not known_keys:
            key = (event.process_id, None)
            instance = instances.setdefault(key, ProcessInstance(process_id=event.process_id, start_key=None))
            instance.events.append(event)
        else:
            unresolved.append(
                UnresolvedRelation(
                    kind=REASON_AMBIGUOUS_PROCESS,
                    event=event,
                    detail=(
                        f"pid {event.process_id} has no ProcessStartKey and matches "
                        f"{len(known_keys)} process instances (PID reuse)"
                    ),
                )
            )

    return list(instances.values()), unresolved


def _find_cycles(parent_map: dict[UUID, set[UUID]]) -> list[list[UUID]]:
    """Return the activity-id cycles in the parent relation.

    Uses Tarjan's strongly connected components algorithm; any component
    with more than one member, or a single member that is its own parent,
    is a cycle and is reported as-is instead of being flattened into a tree.
    """
    indices: dict[UUID, int] = {}
    lowlinks: dict[UUID, int] = {}
    stack: list[UUID] = []
    on_stack: set[UUID] = set()
    cycles: list[list[UUID]] = []
    counter = 0

    def strongconnect(node: UUID) -> None:
        nonlocal counter
        indices[node] = lowlinks[node] = counter
        counter += 1
        stack.append(node)
        on_stack.add(node)

        for parent in parent_map.get(node, ()):
            if parent not in indices:
                strongconnect(parent)
                lowlinks[node] = min(lowlinks[node], lowlinks[parent])
            elif parent in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[parent])

        if lowlinks[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            if len(component) > 1 or node in parent_map.get(node, ()):
                cycles.append(sorted(component, key=str))

    for node in list(parent_map):
        if node not in indices:
            strongconnect(node)

    return cycles
