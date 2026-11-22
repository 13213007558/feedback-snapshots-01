"""
Tests for explicit transaction handoffs between asyncio tasks.

These use aiosqlite against a file-backed database so that each task's
connection is observable, and gated coroutines so the ordering of concurrent
work is deterministic.
"""

import asyncio
import contextlib
import functools
import os
import tempfile

import pytest

from databases import Database
from databases.core import (
    ConnectionNotAcquired,
    TransactionHandoffError,
    TransactionNotAuthorized,
)


def async_adapter(wrapped_func):
    """Run an async test case with its own event loop."""

    @functools.wraps(wrapped_func)
    def run_sync(*args, **kwargs):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(wrapped_func(*args, **kwargs))
        finally:
            loop.close()

    return run_sync


@contextlib.asynccontextmanager
async def sqlite_database():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = Database(f"sqlite+aiosqlite:///{path}")
    await database.connect()
    await database.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)")
    try:
        yield database
    finally:
        await database.disconnect()
        os.unlink(path)


async def _texts(database: Database) -> list:
    records = await database.fetch_all("SELECT text FROM notes ORDER BY id")
    return [record["text"] for record in records]


@async_adapter
async def test_parent_task_uses_transaction_directly():
    """
    The owning task keeps full access to its own transaction.
    """
    async with sqlite_database() as database:
        async with database.transaction():
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")

            # The owner sees its uncommitted write from the same task.
            assert await _texts(database) == ["parent"]

        # Commit belongs to the owning task.
        assert await _texts(database) == ["parent"]


@async_adapter
async def test_approved_delegate_shares_transaction():
    """
    A child task holding a handoff shares the parent's transaction.
    """
    async with sqlite_database() as database:
        started = asyncio.Event()
        released = asyncio.Event()

        async def delegated(handoff):
            async with handoff:
                # The delegate sees the parent's uncommitted write.
                assert await _texts(database) == ["parent"]

                await database.execute(
                    "INSERT INTO notes (id, text) VALUES (2, 'child')"
                )

                # Let the parent observe the delegate's write.
                started.set()
                await released.wait()

        async with database.transaction() as transaction:
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")

            task = asyncio.create_task(delegated(transaction.handoff()))
            await started.wait()
            assert await _texts(database) == ["parent", "child"]
            released.set()
            await task

        # The parent's commit covers both writes.
        assert await _texts(database) == ["parent", "child"]


@async_adapter
async def test_delegate_does_not_inherit_access_without_handoff():
    """
    Child tasks neither see nor use the parent's transaction by default.
    """
    async with sqlite_database() as database:
        checked = asyncio.Event()
        errors = []

        async def unauthorized(transaction, connection):
            # The transaction state is not inherited...
            assert transaction._transaction is None
            # ...and the parent's connection cannot be used.
            try:
                await connection.execute(
                    "INSERT INTO notes (id, text) VALUES (2, 'child')"
                )
            except TransactionNotAuthorized:
                errors.append("connection")
            checked.set()

        async with database.transaction() as transaction:
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")
            connection = database.connection()

            task = asyncio.create_task(unauthorized(transaction, connection))
            await checked.wait()
            await task

        assert errors == ["connection"]
        assert await _texts(database) == ["parent"]


@async_adapter
async def test_handoff_is_bound_to_one_task():
    """
    A single handoff authorizes exactly one task, not every sibling.
    """
    async with sqlite_database() as database:
        claimed = asyncio.Event()
        second_attempt = asyncio.Event()
        results = {}

        async def first(handoff):
            async with handoff:
                # The handoff records the task it was delegated to.
                assert handoff.task is asyncio.current_task()
                claimed.set()
                await second_attempt.wait()

        async def second(handoff):
            await claimed.wait()
            try:
                async with handoff:
                    pass
            except TransactionNotAuthorized:
                results["second"] = "denied"
            finally:
                second_attempt.set()

        async with database.transaction() as transaction:
            handoff = transaction.handoff()
            await asyncio.gather(
                asyncio.create_task(first(handoff)),
                asyncio.create_task(second(handoff)),
            )

        assert results == {"second": "denied"}


@async_adapter
async def test_handoff_cannot_commit_or_rollback():
    """
    Commit and rollback stay with the owning task.
    """
    async with sqlite_database() as database:
        attempts = []

        async def delegated(handoff, transaction):
            async with handoff:
                for operation in (transaction.commit, transaction.rollback):
                    try:
                        await operation()
                    except TransactionNotAuthorized:
                        attempts.append(operation.__name__)

        async with database.transaction() as transaction:
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")
            await asyncio.create_task(delegated(transaction.handoff(), transaction))

        assert attempts == ["commit", "rollback"]


@async_adapter
async def test_handoff_expires_when_transaction_closes():
    """
    Outstanding handoffs are revoked when the owner commits or rolls back.
    """
    async with sqlite_database() as database:
        async with database.transaction() as transaction:
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")
            handoff = transaction.handoff()

            async with handoff:
                await database.execute(
                    "INSERT INTO notes (id, text) VALUES (2, 'child')"
                )

            assert handoff.is_valid

        assert not handoff.is_valid

        with pytest.raises(TransactionHandoffError):
            async with handoff:
                pass


@async_adapter
async def test_connection_cannot_be_used_after_transaction_exit():
    """
    A connection handed to a child task is unusable once the transaction closes.
    """
    async with sqlite_database() as database:
        checked = asyncio.Event()
        errors = []

        async def late_use(connection):
            await checked.wait()
            try:
                await connection.fetch_all("SELECT text FROM notes")
            except ConnectionNotAcquired:
                errors.append("released")

        async with database.transaction():
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")
            connection = database.connection()
            task = asyncio.create_task(late_use(connection))

        checked.set()
        await task
        assert errors == ["released"]


@async_adapter
async def test_rollback_from_owner_discards_delegated_writes():
    """
    Writes performed under a handoff are only durable if the owner commits.
    """
    async with sqlite_database() as database:

        async def delegated(handoff):
            async with handoff:
                await database.execute(
                    "INSERT INTO notes (id, text) VALUES (2, 'child')"
                )

        with pytest.raises(RuntimeError):
            async with database.transaction() as transaction:
                await database.execute(
                    "INSERT INTO notes (id, text) VALUES (1, 'parent')"
                )
                await asyncio.create_task(delegated(transaction.handoff()))
                raise RuntimeError("abort")

        assert await _texts(database) == []


@async_adapter
async def test_unauthorized_reads_do_not_see_uncommitted_writes():
    """
    Unauthorized child tasks read through their own connection, so they never
    observe the parent's uncommitted transaction.
    """
    async with sqlite_database() as database:
        ready = asyncio.Event()
        release = asyncio.Event()

        async def reader():
            assert await _texts(database) == []
            ready.set()
            await release.wait()

        async with database.transaction():
            await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")
            task = asyncio.create_task(reader())
            await ready.wait()
            release.set()
            await task


@async_adapter
async def test_unauthorized_task_cannot_reach_raw_connection():
    """
    Holding the parent's connection is not enough to reach the driver or
    open a nested transaction without an authorized handoff.
    """
    async with sqlite_database() as database:
        errors = []

        async def unauthorized(connection):
            for attempt in (
                connection.__aenter__,
                connection.__aexit__,
                lambda: connection.transaction().__aenter__(),
                lambda: asyncio.sleep(0, connection.raw_connection),
            ):
                try:
                    await attempt()
                except TransactionNotAuthorized:
                    errors.append("denied")

        async with database.transaction():
            connection = database.connection()
            await asyncio.create_task(unauthorized(connection))

            # The owner's connection is unaffected by the rejected attempts.
            assert await _texts(database) == []

        assert errors == ["denied"] * 4


@async_adapter
async def test_released_connection_cannot_be_reacquired():
    """
    A connection released after its task finishes cannot be brought back to
    life by another task.
    """
    async with sqlite_database() as database:
        connection = database.connection()
        async with connection:
            pass

        with pytest.raises(ConnectionNotAcquired):
            async with connection:
                pass

        with pytest.raises(ConnectionNotAcquired):
            connection.raw_connection


@async_adapter
async def test_force_rollback_shared_transaction_survives_task_boundaries():
    """
    The force-rollback global transaction is deliberately shared, and may be
    started and stopped by different tasks.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        setup = Database(f"sqlite+aiosqlite:///{path}")
        async with setup:
            await setup.execute(
                "CREATE TABLE notes (id INTEGER PRIMARY KEY, text TEXT)"
            )

        database = Database(f"sqlite+aiosqlite:///{path}", force_rollback=True)
        await asyncio.create_task(database.connect())
        await database.execute("INSERT INTO notes (id, text) VALUES (1, 'parent')")

        async def child():
            return await _texts(database)

        assert await asyncio.create_task(child()) == ["parent"]

        # `disconnect` runs in a different task than `connect`.
        await asyncio.create_task(database.disconnect())

        # Everything was rolled back, so a fresh connection sees no rows.
        check = Database(f"sqlite+aiosqlite:///{path}")
        async with check:
            assert await _texts(check) == []
    finally:
        os.unlink(path)


@async_adapter
async def test_decorator_transactions_do_not_leak_between_tasks():
    """
    A decorator-based transaction shared by many tasks keeps independent
    per-task activations, and child tasks do not observe the owner's state.
    """
    async with sqlite_database() as database:

        transaction = database.transaction()

        @transaction
        async def insert(index):
            await database.execute(
                "INSERT INTO notes (id, text) VALUES (:id, :text)",
                {"id": index, "text": f"v{index}"},
            )
            await asyncio.sleep(0)

        await asyncio.gather(*(insert(index) for index in range(1, 6)))
        assert len(await _texts(database)) == 5

        observed = []

        async def child():
            observed.append(transaction._transaction)

        async with transaction:
            await asyncio.create_task(child())

        assert observed == [None]
