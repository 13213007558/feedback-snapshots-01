import asyncio
import logging
import os
import sqlite3
import typing
from contextlib import aclosing

import pytest

from databases import Database, IterationOutcome, LoggingAuditRecorder, QueryAudit

pytestmark = pytest.mark.asyncio


SECRET_PARAMETER = "SECRET-PARAMETER-91c1"
SECRET_RESULTS = [
    "SECRET-RESULT-alpha",
    "SECRET-RESULT-bravo",
    "SECRET-RESULT-charlie",
    "SECRET-RESULT-delta",
    "SECRET-RESULT-echo",
]
FAILURE_MESSAGE = "SECRET-FAILURE-mid-stream"


def sqlite_path(tmp_path) -> str:
    return os.path.join(str(tmp_path), "audit.sqlite3")


async def prepare(database_url: str, *, chunk_size: int = 1) -> Database:
    database = Database(database_url, iter_chunk_size=chunk_size)
    await database.connect()
    await database.execute(
        "CREATE TABLE rows (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)"
    )
    await database.execute_many(
        "INSERT INTO rows (id, payload) VALUES (:id, :payload)",
        [{"id": i, "payload": value} for i, value in enumerate(SECRET_RESULTS, 1)],
    )
    return database


async def mark_evaluated(connection) -> typing.List[int]:
    """Install a UDF that records which rows SQLite actually evaluates.

    Reading this list after iteration shows whether the audit path fetched
    (or drained) any rows beyond the ones delivered to the caller.  The
    function must be registered on the connection that runs the query, so
    callers hold a connection open around the iteration.
    """

    evaluated: typing.List[int] = []

    def record(row_id: int) -> int:
        evaluated.append(row_id)
        return row_id

    await connection.raw_connection.create_function("audit_mark", 1, record)
    return evaluated


def assert_value_free(event: QueryAudit) -> None:
    dump = repr(event_attrs(event))
    assert SECRET_PARAMETER not in dump
    for value in SECRET_RESULTS:
        assert value not in dump
    assert FAILURE_MESSAGE not in dump


def event_attrs(event: QueryAudit) -> typing.Dict[str, typing.Any]:
    return {
        "query": event.query,
        "duration": event.duration,
        "row_count": event.row_count,
        "outcome": event.outcome.value,
    }


async def test_full_read_is_completed(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        rows = []

        query = (
            "SELECT id, audit_mark(id) AS marked FROM rows "
            "WHERE payload != :secret ORDER BY id"
        )
        async with database.connection() as connection:
            evaluated = await mark_evaluated(connection)
            async with aclosing(
                database.iterate(
                    query,
                    {"secret": SECRET_PARAMETER},
                    audit=events.append,
                )
            ) as iterator:
                async for row in iterator:
                    rows.append(row["marked"])

        assert rows == [1, 2, 3, 4, 5]
        assert len(events) == 1
        event = events[0]
        assert event.outcome is IterationOutcome.COMPLETED
        assert event.row_count == 5
        assert event.duration >= 0
        assert ":secret" in event.query
        assert_value_free(event)
        # The audit must not have caused any extra reads.
        assert evaluated == [1, 2, 3, 4, 5]
    finally:
        await database.disconnect()


async def test_partial_read_then_close_is_closed_and_does_not_drain(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        rows = []

        query = "SELECT id, audit_mark(id) AS marked FROM rows ORDER BY id"
        async with database.connection() as connection:
            evaluated = await mark_evaluated(connection)
            async with aclosing(
                database.iterate(query, audit=events.append)
            ) as iterator:
                async for row in iterator:
                    rows.append(row["marked"])
                    if len(rows) == 2:
                        break

        assert rows == [1, 2]
        assert len(events) == 1
        event = events[0]
        assert event.outcome is IterationOutcome.CLOSED
        assert event.row_count == 2
        assert event.closed_early is True
        assert_value_free(event)
        # Closing must not drain the rest of the cursor.  SQLite itself may
        # evaluate one row ahead while producing the last delivered row.
        assert 5 not in evaluated
        assert len(evaluated) <= len(rows) + 1
    finally:
        await database.disconnect()


async def test_plain_break_is_closed_without_explicit_close(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        rows = []

        # Keep a reference to the stream to prove classification does not
        # depend on the stream object itself being garbage collected.
        stream = database.iterate(
            "SELECT id FROM rows ORDER BY id", audit=events.append
        )
        async for row in stream:
            rows.append(row["id"])
            if len(rows) == 2:
                break

        assert rows == [1, 2]
        assert len(events) == 1
        assert events[0].outcome is IterationOutcome.CLOSED
        assert events[0].row_count == 2

        # Closing afterwards must not emit a second record.
        await stream.aclose()
        assert len(events) == 1
    finally:
        await database.disconnect()


async def test_async_context_partial_read_is_closed(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        rows = []

        async with database.iterate(
            "SELECT id FROM rows ORDER BY id", audit=events.append
        ) as stream:
            async for row in stream:
                rows.append(row["id"])
                break

        assert rows == [1]
        assert len(events) == 1
        assert events[0].outcome is IterationOutcome.CLOSED
        assert events[0].row_count == 1
    finally:
        await database.disconnect()


async def test_manual_iterator_partial_read_then_aclose_is_closed(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        iterator = database.iterate(
            "SELECT id FROM rows ORDER BY id", audit=events.append
        )

        first = await iterator.__anext__()
        assert first["id"] == 1
        assert events == []

        await iterator.aclose()

        assert len(events) == 1
        assert events[0].outcome is IterationOutcome.CLOSED
        assert events[0].row_count == 1
    finally:
        await database.disconnect()


async def test_mid_stream_failure_is_failed(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        rows = []

        query = (
            "SELECT id, CASE WHEN id = 3 THEN json_extract('not json', '$.x') "
            "ELSE id END AS value FROM rows ORDER BY id"
        )
        with pytest.raises(sqlite3.OperationalError):
            async with aclosing(
                database.iterate(query, audit=events.append)
            ) as iterator:
                async for row in iterator:
                    rows.append(row["id"])

        # The driver reports the failure while producing the row after the
        # last delivered one, so rows delivered is len(rows).
        assert len(rows) < len(SECRET_RESULTS)
        assert len(events) == 1
        event = events[0]
        assert event.outcome is IterationOutcome.FAILED
        assert event.row_count == len(rows)
        assert event.failed is True
        assert_value_free(event)
    finally:
        await database.disconnect()


async def test_failure_before_first_row_is_failed(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        with pytest.raises(sqlite3.OperationalError):
            async for _ in database.iterate(
                "SELECT * FROM does_not_exist", audit=events.append
            ):
                pass

        assert len(events) == 1
        assert events[0].outcome is IterationOutcome.FAILED
        assert events[0].row_count == 0
    finally:
        await database.disconnect()


async def test_cancellation_is_closed(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []

        async def consume() -> None:
            async for _ in database.iterate(
                "SELECT id FROM rows ORDER BY id", audit=events.append
            ):
                await asyncio.sleep(10)

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Async generator finalization is scheduled on the event loop.
        await asyncio.sleep(0.01)

        assert len(events) == 1
        assert events[0].outcome is IterationOutcome.CLOSED
        assert events[0].row_count == 1
    finally:
        await database.disconnect()


async def test_logging_recorder_is_value_free_and_does_not_read_ahead(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        records: typing.List[logging.LogRecord] = []

        class Collector(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = Collector()
        audit_logger = logging.getLogger("databases.audit")
        audit_logger.addHandler(handler)
        audit_logger.setLevel(logging.INFO)
        try:
            async with database.connection() as connection:
                evaluated = await mark_evaluated(connection)
                async with aclosing(
                    database.iterate(
                        "SELECT id, audit_mark(id) AS marked FROM rows ORDER BY id",
                        audit=LoggingAuditRecorder(),
                    )
                ) as iterator:
                    async for row in iterator:
                        if row["marked"] == 1:
                            break
        finally:
            audit_logger.removeHandler(handler)

        assert len(records) == 1
        message = records[0].getMessage()
        assert "rows=1" in message
        assert "outcome=closed" in message
        for value in SECRET_RESULTS:
            assert value not in message
        # Logging the audit did not drain the rest of the cursor.
        assert 5 not in evaluated
        assert len(evaluated) <= 2
    finally:
        await database.disconnect()


async def test_parameters_and_result_values_never_appear_in_audit(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []

        query = "SELECT id, payload FROM rows WHERE payload = :payload"
        async for row in database.iterate(
            query, {"payload": SECRET_RESULTS[0]}, audit=events.append
        ):
            assert row["payload"] == SECRET_RESULTS[0]

        assert len(events) == 1
        event = events[0]
        assert event.query == query
        assert ":payload" in event.query
        assert_value_free(event)
    finally:
        await database.disconnect()


async def test_recorder_errors_do_not_break_iteration(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        def broken(event: QueryAudit) -> None:
            raise RuntimeError(SECRET_PARAMETER)

        rows = [
            row["id"]
            async for row in database.iterate(
                "SELECT id FROM rows ORDER BY id", audit=broken
            )
        ]

        assert rows == [1, 2, 3, 4, 5]
    finally:
        await database.disconnect()


async def test_unused_stream_does_not_emit_audit(tmp_path):
    database = await prepare(f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}")
    try:
        events: typing.List[QueryAudit] = []
        stream = database.iterate("SELECT id FROM rows", audit=events.append)

        await stream.aclose()

        assert events == []
    finally:
        await database.disconnect()


async def test_database_level_default_audit(tmp_path):
    events: typing.List[QueryAudit] = []
    database = Database(
        f"sqlite+aiosqlite:///{sqlite_path(tmp_path)}",
        audit=events.append,
    )
    await database.connect()
    try:
        await database.execute("CREATE TABLE rows (id INTEGER PRIMARY KEY)")
        await database.execute_many(
            "INSERT INTO rows (id) VALUES (:id)", [{"id": i} for i in range(1, 4)]
        )

        rows = [row["id"] async for row in database.iterate("SELECT id FROM rows")]

        assert rows == [1, 2, 3]
        assert len(events) == 1
        assert events[0].row_count == 3
        assert events[0].outcome is IterationOutcome.COMPLETED
    finally:
        await database.disconnect()
