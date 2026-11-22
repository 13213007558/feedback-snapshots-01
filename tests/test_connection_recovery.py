"""
Tests for the connection-exit recovery flow.

When a task is cancelled (e.g. by a query timeout), the connection it
leaves behind must be recovered deterministically: leftover transactions
are rolled back first, the raw connection is released second, and the
`Connection` is detached so the next task either gets a clean connection
or sees an explicit failure.
"""

import asyncio
import functools
import typing

import pytest

from databases import Database
from databases.interfaces import ConnectionBackend, DatabaseBackend, TransactionBackend


def async_adapter(wrapped_func):
    """
    Decorator used to run async test cases.
    """

    @functools.wraps(wrapped_func)
    def run_sync(*args, **kwargs):
        loop = asyncio.new_event_loop()
        task = wrapped_func(*args, **kwargs)
        return loop.run_until_complete(task)

    return run_sync


class PausableRawConnection:
    """Stands in for a driver-level connection."""

    def __init__(self) -> None:
        self.in_transaction = False


class PausableBackend(DatabaseBackend):
    """
    A backend stand-in that records the order of operations, can pause any
    operation (so tests can cancel tasks deterministically mid-operation),
    and can be told to fail specific operations.

    Its pool reuses released raw connections, so a dirty connection leaked
    back into the pool is observable by the next task.
    """

    def __init__(self) -> None:
        self.events: typing.List[str] = []
        self.raw_connections: typing.List[PausableRawConnection] = []
        self.acquired_in_transaction: typing.List[bool] = []
        self._pool: typing.List[PausableRawConnection] = []
        self._pause_once: typing.Dict[
            str, typing.Tuple[asyncio.Event, asyncio.Event]
        ] = {}
        self._fail_on: typing.Dict[str, BaseException] = {}

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    def connection(self) -> "PausableConnection":
        return PausableConnection(self)

    def pause_once(self, operation: str) -> typing.Tuple[asyncio.Event, asyncio.Event]:
        """Pause the next call of `operation` until `resume` is set."""
        reached = asyncio.Event()
        resume = asyncio.Event()
        self._pause_once[operation] = (reached, resume)
        return reached, resume

    def fail_on(self, operation: str, exception: BaseException) -> None:
        self._fail_on[operation] = exception

    async def _gate(self, operation: str) -> None:
        self.events.append(operation)
        pause = self._pause_once.pop(operation, None)
        if pause is not None:
            reached, resume = pause
            reached.set()
            await resume.wait()
        exception = self._fail_on.get(operation)
        if exception is not None:
            raise exception

    def _acquire_raw(self) -> PausableRawConnection:
        if self._pool:
            raw = self._pool.pop()
        else:
            raw = PausableRawConnection()
            self.raw_connections.append(raw)
        self.acquired_in_transaction.append(raw.in_transaction)
        return raw

    def _release_raw(self, raw: PausableRawConnection) -> None:
        # The pool refuses connections with an unresolved transaction:
        # releasing one is exactly the bug these tests guard against.
        assert not raw.in_transaction, "released a connection mid-transaction"
        self._pool.append(raw)


class PausableConnection(ConnectionBackend):
    def __init__(self, backend: PausableBackend) -> None:
        self._backend = backend
        self.raw: typing.Optional[PausableRawConnection] = None

    async def acquire(self) -> None:
        assert self.raw is None
        await self._backend._gate("acquire")
        self.raw = self._backend._acquire_raw()

    async def release(self) -> None:
        assert self.raw is not None
        await self._backend._gate("release")
        self._backend._release_raw(self.raw)
        self.raw = None

    async def fetch_all(self, query: typing.Any) -> list:
        await self._backend._gate("fetch_all")
        return []

    async def fetch_one(self, query: typing.Any) -> typing.Any:
        await self._backend._gate("fetch_one")
        return None

    async def execute(self, query: typing.Any) -> typing.Any:
        await self._backend._gate("execute")
        return 0

    async def execute_many(self, queries: list) -> None:
        await self._backend._gate("execute_many")

    async def iterate(self, query: typing.Any) -> typing.AsyncGenerator:
        for index in range(3):
            await self._backend._gate("iterate")
            yield index

    def transaction(self) -> "PausableTransaction":
        return PausableTransaction(self._backend, self)

    @property
    def raw_connection(self) -> typing.Any:
        return self.raw


class PausableTransaction(TransactionBackend):
    def __init__(
        self, backend: PausableBackend, connection: PausableConnection
    ) -> None:
        self._backend = backend
        self._connection = connection

    async def start(self, is_root: bool, extra_options: dict) -> None:
        await self._backend._gate("begin")
        assert self._connection.raw is not None
        self._connection.raw.in_transaction = True

    async def commit(self) -> None:
        await self._backend._gate("commit")
        assert self._connection.raw is not None
        self._connection.raw.in_transaction = False

    async def rollback(self) -> None:
        await self._backend._gate("rollback")
        assert self._connection.raw is not None
        self._connection.raw.in_transaction = False


def pausable_database(backend: PausableBackend) -> Database:
    database = Database("sqlite:///pausable")
    database._backend = backend
    return database


@async_adapter
async def test_cancel_during_iterate_rolls_back_before_release():
    """
    Cancelling a task while it is reading a result stream must roll back
    the stream's transaction before the connection is released, and the
    next task must acquire a connection with no transaction state.
    """
    backend = PausableBackend()
    database = pausable_database(backend)
    await database.connect()

    stream_paused, _resume = backend.pause_once("iterate")

    async def reader():
        async for record in database.iterate("SELECT 1"):
            pass

    task = asyncio.create_task(reader())
    await stream_paused.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert backend.events == ["acquire", "begin", "iterate", "rollback", "release"]

    async def next_task():
        return await database.fetch_all("SELECT 1")

    assert await asyncio.create_task(next_task()) == []
    # The pooled raw connection was reused, in a clean state.
    assert len(backend.raw_connections) == 1
    assert backend.acquired_in_transaction == [False, False]


@async_adapter
async def test_cancel_inside_transaction_completes_cleanup_under_recancellation():
    """
    Cancelling a task inside a transaction must roll the transaction back
    before release, even if the task is cancelled again while the first
    rollback attempt is still in flight.
    """
    backend = PausableBackend()
    database = pausable_database(backend)
    await database.connect()

    execute_paused, _resume_execute = backend.pause_once("execute")
    rollback_paused, _resume_rollback = backend.pause_once("rollback")

    async def worker():
        async with database.transaction():
            await database.execute("INSERT INTO notes (text) VALUES ('x')")

    task = asyncio.create_task(worker())
    await execute_paused.wait()
    task.cancel()
    # The cancellation triggers a rollback; interrupt that rollback too.
    await rollback_paused.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The interrupted rollback was retried by the connection's recovery
    # flow, and the release only happened afterwards.
    assert backend.events == [
        "acquire",
        "begin",
        "execute",
        "rollback",
        "rollback",
        "release",
    ]
    assert backend.raw_connections[0].in_transaction is False

    async def next_task():
        return await database.fetch_all("SELECT 1")

    assert await asyncio.create_task(next_task()) == []
    assert backend.acquired_in_transaction == [False, False]


@async_adapter
async def test_cleanup_failure_is_explicit_and_connection_is_not_reused():
    """
    If the cleanup itself fails, the failure must surface explicitly and
    the tainted connection must not be released back into the pool, so the
    next task gets a fresh connection rather than one in an unknown
    transaction state.
    """
    backend = PausableBackend()
    database = pausable_database(backend)
    await database.connect()

    execute_paused, _resume = backend.pause_once("execute")
    backend.fail_on("rollback", RuntimeError("rollback failed"))

    async def worker():
        async with database.transaction():
            await database.execute("INSERT INTO notes (text) VALUES ('x')")

    task = asyncio.create_task(worker())
    await execute_paused.wait()
    task.cancel()
    with pytest.raises(RuntimeError, match="rollback failed"):
        await task

    # The rollback was attempted (and retried by the recovery flow), and
    # the tainted connection was never released back into the pool.
    assert backend.events == ["acquire", "begin", "execute", "rollback", "rollback"]
    assert backend.raw_connections[0].in_transaction is True

    async def next_task():
        return await database.fetch_all("SELECT 1")

    assert await asyncio.create_task(next_task()) == []
    # The next task got a brand-new raw connection in a clean state.
    assert len(backend.raw_connections) == 2
    assert backend.acquired_in_transaction == [False, False]


@async_adapter
async def test_cancel_during_iterate_aiosqlite(tmp_path):
    """
    End-to-end with aiosqlite: cancelling a reader mid-stream leaves the
    database usable for the next task.
    """
    database = Database(f"sqlite:///{tmp_path}/test.db")
    await database.connect()
    await database.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)")
    await database.execute_many(
        "INSERT INTO notes (text) VALUES (:text)",
        [{"text": f"note{index}"} for index in range(3)],
    )

    first_row = asyncio.Event()

    async def reader():
        async for record in database.iterate("SELECT * FROM notes"):
            first_row.set()
            await asyncio.sleep(60)

    task = asyncio.create_task(reader())
    await first_row.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    async def next_task():
        return await database.fetch_all("SELECT * FROM notes")

    rows = await asyncio.create_task(next_task())
    assert [row["text"] for row in rows] == ["note0", "note1", "note2"]
    await database.disconnect()


@async_adapter
async def test_cancel_inside_transaction_aiosqlite(tmp_path):
    """
    End-to-end with aiosqlite: cancelling a task inside a transaction
    rolls the transaction back, and the next task can transact normally.
    """
    database = Database(f"sqlite:///{tmp_path}/test.db")
    await database.connect()
    await database.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)")

    inside_transaction = asyncio.Event()

    async def writer():
        async with database.transaction():
            await database.execute("INSERT INTO notes (text) VALUES ('rolled back')")
            inside_transaction.set()
            await asyncio.sleep(60)

    task = asyncio.create_task(writer())
    await inside_transaction.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    async def next_task():
        # The cancelled transaction was rolled back...
        assert await database.fetch_all("SELECT * FROM notes") == []
        # ...and a fresh transaction commits cleanly.
        async with database.transaction():
            await database.execute("INSERT INTO notes (text) VALUES ('committed')")
        rows = await database.fetch_all("SELECT * FROM notes")
        return [row["text"] for row in rows]

    assert await asyncio.create_task(next_task()) == ["committed"]
    await database.disconnect()
