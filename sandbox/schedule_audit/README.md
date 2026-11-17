# Offline BACnet Schedule Control-Path Audit

Limited offline analysis that explains **why a BACnet point is commanded the
way it is at a specified instant**, instead of only displaying the current
`weeklySchedule`. It is built directly on the BACpypes3 object structure
(`bacpypes3.object.ScheduleObject`, `CalendarObject`, the types in
`bacpypes3.basetypes`) and reuses the pure date-matching functions from
`bacpypes3.local.schedule`, so its schedule semantics match a running
BACpypes3 device without instantiating one.

## What is combined

For a given Schedule object the evaluation joins every configuration layer
that can change the commanded value:

1. `effectivePeriod` — a date outside the range short-circuits everything
   (BACpypes3 `eval()` returns no value; reported as
   `outside-effective-period`).
2. `exceptionSchedule` — each `SpecialEvent` is matched either through an
   inline `calendarEntry` or through a `calendarReference` resolved against
   Calendar objects in the snapshot. Matching events take precedence over the
   weekly schedule, ordered by `eventPriority` exactly as BACpypes3 does.
3. `weeklySchedule` — the day-of-week selects one of the seven
   `DailySchedule` entries; the last `TimeValue` not later than the
   evaluation time wins.
4. `scheduleDefault` — used when no time value is active, or after a Null
   ("relinquish") time value.
5. `listOfObjectPropertyReferences` + `priorityForWriting` — identify the
   target point/property and the BACnet priority the schedule writes at.
6. The target point's observed `priorityArray` — the highest-priority
   non-Null slot determines what the device has actually applied. A write at
   a more urgent priority (smaller number) shadows the schedule even while
   the schedule's own slot stays occupied.

## Pending, never guessed

Offline analysis only knows what is in the snapshot. When a referenced
object is missing the relevant conclusion is retained as **pending**:

- a `calendarReference` whose Calendar object is absent →
  `missing-calendar-object`; the weekly/default fallback is still reported,
  but whether the exception applies stays open;
- a referenced target point absent from the snapshot →
  `missing-referenced-point`;
- a point present without a `priorityArray` →
  `missing-point-priority-array`.

## Time is caller-supplied

The evaluation instant is an explicit timezone-aware ISO 8601 string
(e.g. `2026-12-25T10:30:00+08:00`) and is interpreted as the **device-local
wall clock**. Naive datetimes are rejected. The package never reads the
analysis machine's clock, timezone or local calendar as a device fact
(verified: no `datetime.now`/`time.time`/`Date.now`/`Time.now` calls).

## Declarations vs. executed state

Every piece of evidence is tagged:

- `declared` — what the device configuration says the schedule should
  command (effective period, calendar entries, time values, write priority,
  object property references);
- `executed` — what the observed point state shows the device has applied
  (`priorityArray` slots, active command priority, `outOfService`).

The headline conclusion is only `schedule-in-command` when the schedule's
write-priority slot is itself the active slot; a more urgent slot yields
`higher-priority-override`.

## Sample: weekly plan overridden by exception day, then by a manual write

`sample_snapshot.json` contains:

- Calendar `calendar,1` marking 2026-12-25 (Friday) as a holiday;
- Schedule `schedule,1`: Mon–Fri 08:00→1 / 17:00→0, an exception referencing
  the holiday calendar that forces 0 all day, `priorityForWriting = 10`,
  targeting `binaryValue,1 presentValue`;
- the point snapshot with a priority-8 manual write `active` and the
  schedule's priority-10 slot holding `inactive`.

At `2026-12-25T10:30:00+08:00` the weekly Friday schedule would command
`1`, but:

1. the exception schedule (via the calendar reference) overrides it and
   declares `0`;
2. the point's priority-8 slot outranks the schedule's priority-10 write, so
   the effective point value is `active` — the schedule declaration is
   shadowed.

Run it:

```bash
python -m sandbox.schedule_audit.cli sandbox/schedule_audit/sample_snapshot.json
python -m sandbox.schedule_audit.cli sandbox/schedule_audit/sample_snapshot.json --json
```

Changing `evaluation-instant` to an ordinary Wednesday (e.g.
`2026-12-23T10:30:00+08:00`) makes the weekly schedule the declaration; the
priority-8 override conclusion is unchanged, which demonstrates the
declaration/execution split.

## Snapshot format

```json
{
  "evaluation-instant": "2026-12-25T10:30:00+08:00",
  "objects": [
    { "object-identifier": "calendar,1", "date-list": [ ... ], ... },
    { "object-identifier": "schedule,1",
      "effective-period": { "start-date": "...", "end-date": "..." },
      "weekly-schedule": [ ... 7 daily schedules ... ],
      "exception-schedule": [ ... ],
      "schedule-default": 0,
      "list-of-object-property-references": [ ... ],
      "priority-for-writing": 10, ... }
  ],
  "points": [
    { "object-identifier": "binary-value,1",
      "priority-array": [ 16 slots, null or {"enumerated": "active"} ],
      "out-of-service": false, ... }
  ]
}
```

Property names follow BACpypes3's kebab-case JSON convention. Atomic values
in schedule slots accept plain JSON literals; `priorityArray` slots use a
single-key tagged object (`{"real": 21.5}`, `{"enumerated": "active"}`) or
`null` for a relinquished slot.

## Tests

```bash
python -m pytest sandbox/schedule_audit/tests/ -q
```

The suite cross-checks the weekly/default/exception/effective-period
declarations against the native `ScheduleObject.eval()` and covers the
missing-calendar and missing-point pending paths, priority overrides,
relinquished arrays, out-of-service handling and timezone handling.
