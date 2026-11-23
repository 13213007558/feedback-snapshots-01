# Query Permits

A reporting task that runs after approval should only be able to run the
exact, parameterized statements that were granted — nothing else. A
**query permit** packages that approval as a one-time manifest bound to the
task that requested it and to the database connections it may use.

Ordinary calls made outside a permit keep their existing connection and
transaction conventions; enforcement only runs while a permit is active.

## Granting a permit

Build a manifest of approved statements. Each entry gives the SQL text, an
inclusive range for every bound parameter, and optionally how many times the
statement may run (`max_calls`, defaults to one):

```python
manifest = [
    {
        "sql": "INSERT INTO notes (text, completed) VALUES (:text, :completed)",
        "parameters": {"text": ("a", "z"), "completed": (0, 1)},
        "max_calls": 2,
    },
    {
        "sql": "SELECT id, text FROM notes WHERE id = :id",
        "parameters": {"id": (1, 1000)},
    },
]
```

Activate the permit as an async context manager. It opens a transaction, and
every `execute`, `execute_many`, `fetch_*` or `iterate` call inside it is
checked against the manifest before reaching the driver:

```python
permit = database.permit("report-task-42", manifest)
async with permit:
    await database.execute(
        "INSERT INTO notes (text, completed) VALUES (:text, :completed)",
        {"text": "ok", "completed": True},
    )
```

A statement that is not in the manifest, a parameter outside its approved
range, an extra or missing parameter, or exceeding `max_calls` raises
`PermitViolation` or `PermitExpired` and leaves the permit's transaction to
roll back.

## Connection and task binding

The permit is bound to the connection scope it may touch. Pass
`connections=[...]` to restrict it explicitly; by default it is scoped to the
database that created it:

```python
permit = database.permit(
    "report-task-42", manifest, connections=[str(database.url)]
)
```

The permit is also bound to the `asyncio.Task` that created it. A subtask
copies the parent context, but it cannot run statements under a permit it did
not request — doing so raises `PermitExpired`. Cancelling the owning task
rolls the protected transaction back rather than reusing the parent's
approval.

## Permit states

A permit exposes three states through `permit.status` (`PermitStatus`):

- `NOT_STARTED` — granted but not yet settled; no effect is confirmed.
- `EFFECTIVE` — the protected transaction committed; the approval is spent.
- `ROLLED_BACK` — the library rolled the transaction back, including on
  cancellation; the approval is spent.

A settled permit can never be reused. After a rollback the same work may only
run again under a freshly granted permit:

```python
permit = database.permit("retry", manifest)
try:
    async with permit:
        ...
except RuntimeError:
    assert permit.status == PermitStatus.ROLLED_BACK

retry = database.permit("retry-2", manifest)  # a new approval is required
async with retry:
    ...
```

## Audit trail and attribution

Each authorized statement is appended to `permit.audit_trail` as an
`ExecutionRecord` carrying the permit id, owning task, SQL text, bound values
and a sequence number.

On SQLite you can additionally pass an `ExecutionRecorder` to the `Database`
to capture every statement handed to the underlying driver — including
`BEGIN`, `COMMIT` and `ROLLBACK` — together with the permit that was active
when it was scheduled:

```python
from databases.backends.sqlite import ExecutionRecorder

recorder = ExecutionRecorder()
database = Database(DATABASE_URL, execution_recorder=recorder)
...
recorder.for_permit("report-task-42")  # driver-level statements for one permit
```
