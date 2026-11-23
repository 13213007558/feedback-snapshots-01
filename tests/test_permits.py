import asyncio
import typing

import pytest
import pytest_asyncio
import sqlalchemy

from databases import (
    Database,
    ExecutionRecord,
    PermitError,
    PermitExpired,
    PermitStatus,
    PermitViolation,
)
from databases.backends.sqlite import ExecutionRecorder



INSERT_SQL = "INSERT INTO notes (text, completed) VALUES (:text, :completed)"
SELECT_SQL = "SELECT id, text FROM notes WHERE id = :id"


def make_manifest() -> typing.List[dict]:
    return [
        {
            "sql": INSERT_SQL,
            "parameters": {"text": ("a", "z"), "completed": (0, 1)},
            "max_calls": 4,
        },
        {"sql": SELECT_SQL, "parameters": {"id": (1, 1000)}},
    ]


@pytest_asyncio.fixture
async def database(tmp_path):
    recorder = ExecutionRecorder()
    db = Database(
        f"sqlite:///{tmp_path / 'permit.db'}", execution_recorder=recorder
    )
    await db.connect()
    await db.execute(
        "CREATE TABLE notes ("
        "id INTEGER PRIMARY KEY, text VARCHAR(100), completed BOOLEAN)"
    )
    yield db, recorder
    await db.disconnect()


@pytest.mark.asyncio
async def test_ordinary_calls_keep_existing_conventions(database):
    db, recorder = database
    await db.execute(INSERT_SQL, {"text": "plain", "completed": False})
    rows = await db.fetch_all("SELECT text FROM notes")
    assert [row["text"] for row in rows] == ["plain"]
    # Unpermitted statements are recorded at the driver with no permit owner.
    assert all(owner is None for _, owner in recorder.statements)


@pytest.mark.asyncio
async def test_manifest_must_cover_every_parameter(database):
    db, _ = database
    with pytest.raises(PermitViolation, match="range for every parameter"):
        db.permit("bad", [{"sql": INSERT_SQL, "parameters": {"text": ("a", "z")}}])
    with pytest.raises(PermitViolation, match="at least one query"):
        db.permit("empty", [])


@pytest.mark.asyncio
async def test_connection_scope_is_bound_to_the_database(database, tmp_path):
    db, _ = database
    with pytest.raises(PermitViolation, match="connection scope"):
        db.permit(
            "scoped",
            make_manifest(),
            connections=[f"sqlite:///{tmp_path / 'some_other.db'}"],
        )
    permit = db.permit("scoped", make_manifest(), connections=[str(db.url)])
    assert str(db.url) in permit.connections


@pytest.mark.asyncio
async def test_three_states_and_audit_trail(database):
    db, _ = database
    permit = db.permit("states", make_manifest())
    assert permit.status is PermitStatus.NOT_STARTED
    assert permit.is_valid

    async with permit:
        await db.execute(INSERT_SQL, {"text": "first", "completed": True})
        await db.fetch_one(SELECT_SQL, {"id": 1})

    assert permit.status is PermitStatus.EFFECTIVE
    assert not permit.is_valid
    assert [record.sequence for record in permit.audit_trail] == [1, 2]
    assert all(isinstance(record, ExecutionRecord) for record in permit.audit_trail)
    assert all(record.permit_id == "states" for record in permit.audit_trail)
    assert all(
        record.task_name == permit._owner_name for record in permit.audit_trail
    )


@pytest.mark.asyncio
async def test_unapproved_sql_and_out_of_range_parameters_are_rejected(database):
    db, _ = database
    async with db.permit("strict", make_manifest()):
        with pytest.raises(PermitViolation, match="not part of permit"):
            await db.execute("DELETE FROM notes", {})
        with pytest.raises(PermitViolation, match="outside the approved range"):
            await db.execute(INSERT_SQL, {"text": "0-BAD", "completed": True})
        with pytest.raises(PermitViolation, match="not part of permit"):
            await db.fetch_val("SELECT count(*) FROM notes")

    assert await db.fetch_all("SELECT text FROM notes") == []


@pytest.mark.asyncio
async def test_execute_many_is_checked_per_value_set(database):
    db, _ = database
    manifest = [
        {
            "sql": INSERT_SQL,
            "parameters": {"text": ("a", "z"), "completed": (0, 1)},
            "max_calls": 2,
        }
    ]
    async with db.permit("batch", manifest):
        await db.execute_many(
            INSERT_SQL,
            [
                {"text": "one", "completed": 0},
                {"text": "two", "completed": 1},
            ],
        )
        with pytest.raises(PermitExpired, match="at most 2 time"):
            await db.execute_many(
                INSERT_SQL, [{"text": "three", "completed": 1}]
            )
        with pytest.raises(PermitViolation, match="outside the approved range"):
            await db.execute_many(
                INSERT_SQL, [{"text": "zzz-bad", "completed": 1}]
            )

    texts = [row["text"] for row in await db.fetch_all("SELECT text FROM notes")]
    assert texts == ["one", "two"]


@pytest.mark.asyncio
async def test_non_text_clause_is_rejected(database):
    db, _ = database
    table = sqlalchemy.table(
        "notes",
        sqlalchemy.column("text"),
        sqlalchemy.column("completed"),
    )
    async with db.permit("clause", make_manifest()):
        with pytest.raises(PermitViolation, match="explicit parameterized text"):
            await db.execute(table.insert().values(text="x", completed=True))


@pytest.mark.asyncio
async def test_subtask_cannot_borrow_the_parent_permit(database):
    db, _ = database
    entered = asyncio.Event()

    async with db.permit("parent", make_manifest()):

        async def child():
            entered.set()
            with pytest.raises(PermitExpired, match="cannot be used from"):
                await db.execute(INSERT_SQL, {"text": "child", "completed": 1})

        child_task = asyncio.create_task(child(), name="child-task")
        await child_task
        assert entered.is_set()
        # The parent permit still works in its own task.
        await db.execute(INSERT_SQL, {"text": "parent", "completed": 1})

    texts = [row["text"] for row in await db.fetch_all("SELECT text FROM notes")]
    assert texts == ["parent"]


@pytest.mark.asyncio
async def test_cancelled_task_rolls_back_and_invalidates_its_permit(database):
    db, recorder = database
    gate = asyncio.Event()
    cancelled_permit: typing.Optional[object] = None

    async def cancelled_report():
        nonlocal cancelled_permit
        cancelled_permit = db.permit("report-cancel", make_manifest())
        async with cancelled_permit:
            await db.execute(
                INSERT_SQL, {"text": "will-rollback", "completed": 1}
            )
            gate.set()
            await asyncio.Event().wait()  # cancellation lands here

    task = asyncio.create_task(cancelled_report(), name="report-cancel-task")
    await gate.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert cancelled_permit is not None
    assert cancelled_permit.status is PermitStatus.ROLLED_BACK
    assert not cancelled_permit.is_valid

    cancelled_statements = recorder.for_permit("report-cancel")
    assert any("INSERT INTO notes" in sql for sql in cancelled_statements)
    assert "BEGIN" in cancelled_statements
    assert "ROLLBACK" in cancelled_statements
    assert "COMMIT" not in cancelled_statements

    assert await db.fetch_all("SELECT text FROM notes") == []

    # The spent approval cannot be reused: it is both settled and owned by the
    # cancelled task, so re-entry from the parent task is rejected either way.
    with pytest.raises(PermitExpired):
        async with cancelled_permit:  # pragma: no branch
            await db.execute(INSERT_SQL, {"text": "retry", "completed": 1})

    # Settle-state is checked first whenever the owning task itself retries.
    settled_in_owner = db.permit("settled-owner", make_manifest())
    settled_in_owner.status = PermitStatus.ROLLED_BACK
    with pytest.raises(PermitExpired, match="already settled"):
        async with settled_in_owner:  # pragma: no branch
            pass


@pytest.mark.asyncio
async def test_second_task_commits_its_own_permitted_transaction(database):
    db, recorder = database

    async def successful_report():
        permit = db.permit("report-commit", make_manifest())
        async with permit:
            await db.execute(INSERT_SQL, {"text": "committed", "completed": 1})
            await db.execute(INSERT_SQL, {"text": "second", "completed": 0})
        return permit

    permit = await asyncio.create_task(
        successful_report(), name="report-commit-task"
    )

    assert permit.status is PermitStatus.EFFECTIVE
    committed = recorder.for_permit("report-commit")
    assert committed[0] == "BEGIN"
    assert committed.count("COMMIT") == 1
    assert committed.count("ROLLBACK") == 0
    assert sum("INSERT INTO notes" in sql for sql in committed) == 2

    texts = [row["text"] for row in await db.fetch_all("SELECT text FROM notes")]
    assert texts == ["committed", "second"]


@pytest.mark.asyncio
async def test_rollback_retry_requires_a_fresh_approval(database):
    db, recorder = database
    manifest = make_manifest()

    permit = db.permit("retry", manifest)
    with pytest.raises(RuntimeError, match="boom"):
        async with permit:
            await db.execute(INSERT_SQL, {"text": "rolled", "completed": 1})
            raise RuntimeError("boom")

    assert permit.status is PermitStatus.ROLLED_BACK
    rolled = recorder.for_permit("retry")
    assert "BEGIN" in rolled and "ROLLBACK" in rolled and "COMMIT" not in rolled
    assert await db.fetch_all("SELECT text FROM notes") == []

    # The spent approval cannot authorize a retry, even with an in-range query.
    with pytest.raises(PermitExpired, match="already settled"):
        async with permit:  # pragma: no branch
            await db.execute(INSERT_SQL, {"text": "retry", "completed": 1})

    # A freshly granted approval retries the same work successfully.
    retry_permit = db.permit("retry-2", manifest)
    async with retry_permit:
        await db.execute(INSERT_SQL, {"text": "retry-ok", "completed": 1})
    assert retry_permit.status is PermitStatus.EFFECTIVE
    texts = [row["text"] for row in await db.fetch_all("SELECT text FROM notes")]
    assert texts == ["retry-ok"]


@pytest.mark.asyncio
async def test_driver_records_attribute_every_statement_to_a_permit(database):
    db, recorder = database
    async with db.permit("attr", make_manifest()) as permit:
        await db.execute(INSERT_SQL, {"text": "attr", "completed": 1})

    attributed = recorder.for_permit("attr")
    assert attributed == [
        "BEGIN",
        "INSERT INTO notes (text, completed) VALUES (?, ?)",
        "COMMIT",
    ]
    assert permit.audit_trail[0].sql == INSERT_SQL
    assert dict(permit.audit_trail[0].values) == {
        "completed": 1,
        "text": "attr",
    }
    # Setup DDL ran without any active permit and stays unattributed.
    assert any(owner is None for _, owner in recorder.statements)


def test_permit_creation_outside_a_task_is_rejected():
    import threading

    from databases.permits import QueryPermit

    class DummyURL:
        def __str__(self) -> str:
            return "sqlite:///dummy"

    class DummyDatabase:
        url = DummyURL()

    errors: typing.List[BaseException] = []

    def create_without_task() -> None:
        try:
            QueryPermit(
                DummyDatabase(), [{"sql": "SELECT 1", "parameters": {}}], "x"
            )
        except PermitError as exc:
            errors.append(exc)

    thread = threading.Thread(target=create_without_task)
    thread.start()
    thread.join()
    assert len(errors) == 1
    assert "within a task" in str(errors[0])
