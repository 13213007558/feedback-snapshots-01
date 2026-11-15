from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import UUID

from dissect.etl.activity import (
    KIND_ACTIVITY_FLOW,
    KIND_RELATED_ACTIVITY,
    REASON_AMBIGUOUS_PROCESS,
    REASON_MISSING_PARENT,
    ActivityEvent,
    RecordLocation,
    activity_event_from_header,
    correlate,
    iter_activity_events,
)
from dissect.etl.c_etl import c_etl
from dissect.etl.exceptions import NoMoreEventsError
from dissect.etl.headers.event import EventHeader
from dissect.etl.headers.headers import Marker

EPOCH = datetime(2026, 11, 15, tzinfo=timezone.utc)

PROVIDER_1 = UUID("11111111-1111-1111-1111-111111111111")
PROVIDER_2 = UUID("22222222-2222-2222-2222-222222222222")
PROVIDER_3 = UUID("33333333-3333-3333-3333-333333333333")

ACT_PARENT = UUID("aaaaaaaa-0000-0000-0000-000000000001")
ACT_CHILD = UUID("bbbbbbbb-0000-0000-0000-000000000002")
ACT_REUSED = UUID("cccccccc-0000-0000-0000-000000000003")
ACT_ORPHAN = UUID("dddddddd-0000-0000-0000-000000000004")
ACT_MISSING = UUID("eeeeeeee-0000-0000-0000-000000000005")
ZERO_GUID = UUID(int=0)


def make_record_bytes(
    *,
    thread_id: int,
    process_id: int,
    time_delta: int,
    provider_id: UUID,
    activity_id: UUID = ZERO_GUID,
    related_activity_id: UUID | None = None,
    process_start_key: int | None = None,
) -> bytes:
    extensions = b""
    if related_activity_id is not None:
        extensions += c_etl.EventHeaderExtendedDataItemHeader(
            Size=24, ExtType=0x1, Reserved1=0, DataSize=16, Data=related_activity_id.bytes_le
        ).dumps()
    if process_start_key is not None:
        extensions += c_etl.EventHeaderExtendedDataItemHeader(
            Size=16, ExtType=0xD, Reserved1=0, DataSize=8, Data=process_start_key.to_bytes(8, "little")
        ).dumps()

    header = c_etl.EventHeader(
        Size=0x50 + len(extensions),
        Marker=0xC013,
        Flags=0,
        EventProperty=0,
        ThreadId=thread_id,
        ProcessId=process_id,
        TimeDelta=time_delta,
        ProviderId=provider_id.bytes,
        Id=1,
        Version=0,
        Channel=0,
        Level=0,
        OpCode=0,
        Task=0,
        Keywords=0,
        ProcessorTime=0,
        ActivityId=activity_id.bytes_le,
    ).dumps()
    return header + extensions


def make_activity_event(buffer_index: int, record_offset: int, **kwargs) -> ActivityEvent:
    record = make_record_bytes(**kwargs)
    etl = Mock()
    etl.calculate_timestamp.side_effect = lambda time_delta: EPOCH + timedelta(microseconds=time_delta)
    marker = Marker(0xC0130000 | len(record))
    header = EventHeader(marker, memoryview(record), etl)
    return activity_event_from_header(buffer_index, record_offset, 0x48 + record_offset, header)


def test_activity_event_extraction() -> None:
    event = make_activity_event(
        0,
        0,
        thread_id=100,
        process_id=500,
        time_delta=10,
        provider_id=PROVIDER_1,
        activity_id=ACT_PARENT,
        related_activity_id=ACT_CHILD,
        process_start_key=1111,
    )

    assert event.location == RecordLocation(0, 0, 0x48)
    assert event.timestamp == EPOCH + timedelta(microseconds=10)
    assert event.provider_id == PROVIDER_1
    assert event.process_id == 500
    assert event.thread_id == 100
    assert event.activity_id == ACT_PARENT
    assert event.related_activity_id == ACT_CHILD
    assert event.process_start_key == 1111
    assert event.has_activity


def test_zero_guids_are_not_evidence() -> None:
    event = make_activity_event(
        0,
        0,
        thread_id=100,
        process_id=500,
        time_delta=10,
        provider_id=PROVIDER_1,
        activity_id=ZERO_GUID,
        related_activity_id=ZERO_GUID,
    )

    result = correlate([event])

    assert not event.has_activity
    assert result.activities == {}
    assert result.edges == []
    assert result.unresolved == []


def test_sample_cross_thread_activity_and_pid_reuse() -> None:
    """A small sample with one real cross-thread activity and one new process on a reused PID.

    The child event is listed before the parent event on purpose: offline
    correlation must still connect them. Only events carrying evidence
    (non-zero GUIDs, process start keys) may end up in edges.
    """
    child_1 = make_activity_event(
        0,
        0x000,
        thread_id=200,
        process_id=500,
        time_delta=20,
        provider_id=PROVIDER_2,
        activity_id=ACT_CHILD,
        related_activity_id=ACT_PARENT,
        process_start_key=1111,
    )
    parent = make_activity_event(
        0,
        0x100,
        thread_id=100,
        process_id=500,
        time_delta=10,
        provider_id=PROVIDER_1,
        activity_id=ACT_PARENT,
        process_start_key=1111,
    )
    child_2 = make_activity_event(
        0,
        0x200,
        thread_id=300,
        process_id=600,
        time_delta=30,
        provider_id=PROVIDER_3,
        activity_id=ACT_CHILD,
        process_start_key=2222,
    )
    reused_pid = make_activity_event(
        0,
        0x300,
        thread_id=400,
        process_id=500,
        time_delta=40,
        provider_id=PROVIDER_1,
        activity_id=ACT_REUSED,
        process_start_key=9999,
    )
    orphan = make_activity_event(
        0,
        0x400,
        thread_id=500,
        process_id=500,
        time_delta=50,
        provider_id=PROVIDER_1,
    )
    missing_parent = make_activity_event(
        0,
        0x500,
        thread_id=600,
        process_id=700,
        time_delta=60,
        provider_id=PROVIDER_2,
        activity_id=ACT_ORPHAN,
        related_activity_id=ACT_MISSING,
        process_start_key=3333,
    )
    zero_guid = make_activity_event(
        0,
        0x600,
        thread_id=700,
        process_id=800,
        time_delta=70,
        provider_id=PROVIDER_3,
    )

    result = correlate([child_1, parent, child_2, reused_pid, orphan, missing_parent, zero_guid])

    # The cross-thread, cross-provider activity is connected: parent -> child_1
    # (child seen before parent in the trace) and child_1 -> child_2 across
    # threads 200/300, providers 2/3 and processes 500/600.
    related_edges = [edge for edge in result.edges if edge.kind == KIND_RELATED_ACTIVITY]
    assert len(related_edges) == 1
    assert related_edges[0].source is parent
    assert related_edges[0].target is child_1
    assert related_edges[0].evidence == {"related_activity_id": str(ACT_PARENT)}

    flow_edges = [edge for edge in result.edges if edge.kind == KIND_ACTIVITY_FLOW]
    assert len(flow_edges) == 1
    assert flow_edges[0].source is child_1
    assert flow_edges[0].target is child_2
    assert flow_edges[0].evidence == {"activity_id": str(ACT_CHILD)}

    # Events without evidence (reused PID process, zero GUIDs) are not connected.
    connected = {id(edge.source) for edge in result.edges} | {id(edge.target) for edge in result.edges}
    assert id(reused_pid) not in connected
    assert id(orphan) not in connected
    assert id(zero_guid) not in connected
    assert id(missing_parent) not in connected

    # PID 500 was reused: two distinct process instances must exist.
    instances = {(instance.process_id, instance.start_key): instance for instance in result.process_instances}
    assert set(instances) == {(500, 1111), (500, 9999), (600, 2222), (700, 3333), (800, None)}
    assert sorted(instances[(500, 1111)].events, key=lambda event: event.timestamp) == [parent, child_1]
    assert instances[(500, 9999)].events == [reused_pid]

    # The orphan event sits on a reused PID without a start key: ambiguous.
    # The missing parent activity is reported, not silently dropped.
    unresolved_kinds = {relation.kind: relation for relation in result.unresolved}
    assert set(unresolved_kinds) == {REASON_AMBIGUOUS_PROCESS, REASON_MISSING_PARENT}
    assert unresolved_kinds[REASON_AMBIGUOUS_PROCESS].event is orphan
    assert unresolved_kinds[REASON_MISSING_PARENT].event is missing_parent
    assert str(ACT_MISSING) in unresolved_kinds[REASON_MISSING_PARENT].detail

    assert result.cycles == []
    assert result.multiple_parents == {}

    # The report carries edges, unresolved relations and raw record locations.
    report = result.render()
    assert "[related]" in report
    assert "[flow]" in report
    assert REASON_MISSING_PARENT in report
    assert REASON_AMBIGUOUS_PROCESS in report
    assert "buffer 0 offset 0x100 (file 0x148)" in report


def test_cycles_and_multiple_parents_are_explicit() -> None:
    act_x = UUID("f0000000-0000-0000-0000-00000000000a")
    act_y = UUID("f0000000-0000-0000-0000-00000000000b")
    act_m = UUID("f0000000-0000-0000-0000-00000000000c")
    act_p1 = UUID("f0000000-0000-0000-0000-00000000000d")
    act_p2 = UUID("f0000000-0000-0000-0000-00000000000e")

    events = [
        make_activity_event(
            0,
            0x000,
            thread_id=1,
            process_id=1,
            time_delta=1,
            provider_id=PROVIDER_1,
            activity_id=act_x,
            related_activity_id=act_y,
        ),
        make_activity_event(
            0,
            0x100,
            thread_id=1,
            process_id=1,
            time_delta=2,
            provider_id=PROVIDER_1,
            activity_id=act_y,
            related_activity_id=act_x,
        ),
        make_activity_event(
            0,
            0x200,
            thread_id=1,
            process_id=1,
            time_delta=3,
            provider_id=PROVIDER_1,
            activity_id=act_m,
            related_activity_id=act_p1,
        ),
        make_activity_event(
            0,
            0x300,
            thread_id=2,
            process_id=1,
            time_delta=4,
            provider_id=PROVIDER_1,
            activity_id=act_m,
            related_activity_id=act_p2,
        ),
        make_activity_event(
            0, 0x400, thread_id=1, process_id=1, time_delta=5, provider_id=PROVIDER_1, activity_id=act_p1
        ),
        make_activity_event(
            0, 0x500, thread_id=1, process_id=1, time_delta=6, provider_id=PROVIDER_1, activity_id=act_p2
        ),
    ]

    result = correlate(events)

    assert result.cycles == [sorted([act_x, act_y], key=str)]
    assert result.multiple_parents == {act_m: sorted([act_p1, act_p2], key=str)}

    # The underlying edges are still there; the graph is just not flattened.
    related_edges = [edge for edge in result.edges if edge.kind == KIND_RELATED_ACTIVITY]
    assert len(related_edges) == 4

    report = result.render()
    assert "[cycle]" in report
    assert "[multiple-parents]" in report


def test_iter_activity_events_keeps_record_locations() -> None:
    record = make_record_bytes(
        thread_id=100, process_id=500, time_delta=10, provider_id=PROVIDER_1, activity_id=ACT_PARENT
    )
    etl_mock = Mock()
    etl_mock.calculate_timestamp.side_effect = lambda time_delta: EPOCH + timedelta(microseconds=time_delta)
    header = EventHeader(Marker(0xC0130000 | len(record)), memoryview(record), etl_mock)

    event_record = Mock()
    event_record.header = header
    event_record.aligned_size = len(record)

    buffer = Mock()
    buffer.filled_bytes = len(record)
    buffer.data_offset = 0x48
    buffer.read_record.side_effect = [event_record, NoMoreEventsError]

    etl = Mock()
    etl.buffers.return_value = [buffer]

    events = list(iter_activity_events(etl))

    assert len(events) == 1
    assert events[0].location == RecordLocation(buffer_index=0, record_offset=0, file_offset=0x48)
    assert events[0].activity_id == ACT_PARENT
