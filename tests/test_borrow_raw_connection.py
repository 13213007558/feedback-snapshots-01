"""
Unit tests for the explicitly scoped raw driver connection borrowing.

A fake driver/backend pair is used so the behaviour can be exercised without
requiring a real database.
"""
import asyncio
import typing

import pytest

from databases.core import (
    BorrowedConnection,
    BorrowedConnectionExpired,
    Connection,
    Database,
)
from databases.interfaces import (
    ConnectionBackend,
    DatabaseBackend,
    TransactionBackend,
)


class FakeRawConnection:
    """
    Stands in for the raw object exposed by a real driver (asyncpg
    connection, aiosqlite connection, ...).
    """

    def __init__(self, pool: "FakePool", identity: int) -> None:
        self.pool = pool
        self.identity = identity
        self.closed = False
        self.operations: typing.List[str] = []

    async def submit(self, operation: str) -> str:
        if self.closed:
            raise RuntimeError("Cannot submit on a closed raw connection")
        self.operations.append(operation)
        return f"{self.identity}:{operation}"


class FakePool:
    def __init__(self) -> None:
        self._next_identity = 0
        self.checked_out: typing.Dict[int, FakeRawConnection] = {}
        self.available: typing.List[FakeRawConnection] = []
        self.acquisitions = 0
        self.releases = 0

    async def acquire(self) -> FakeRawConnection:
        self.acquisitions += 1
        if self.available:
            raw_connection = self.available.pop()
        else:
            self._next_identity += 1
            raw_connection = FakeRawConnection(self, self._next_identity)
        self.checked_out[raw_connection.identity] = raw_connection
        return raw_connection

    async def release(self, raw_connection: FakeRawConnection) -> None:
        self.releases += 1
        self.checked_out.pop(raw_connection.identity, None)
        self.available.append(raw_connection)


class FakeConnectionBackend(ConnectionBackend):
    def __init__(self, pool: FakePool) -> None:
        self._pool = pool
        self._connection: typing.Optional[FakeRawConnection] = None

    async def acquire(self) -> None:
        assert self._connection is None, "Connection is already acquired"
        self._connection = await self._pool.acquire()

    async def release(self) -> None:
        assert self._connection is not None, "Connection is not acquired"
        await self._pool.release(self._connection)
        self._connection = None

    def transaction(self) -> TransactionBackend:
        raise NotImplementedError()

    @property
    def raw_connection(self) -> FakeRawConnection:
        assert self._connection is not None, "Connection is not acquired"
        return self._connection


class FakeBackend(DatabaseBackend):
    scheme = "fake"

    def __init__(self, url: typing.Any = None, **options: typing.Any) -> None:
        self.pool = FakePool()

    async def connect(self) -> None:
        ...

    async def disconnect(self) -> None:
        ...

    def connection(self) -> FakeConnectionBackend:
        return FakeConnectionBackend(self.pool)


@pytest.fixture
def fake_database(monkeypatch: pytest.MonkeyPatch) -> Database:
    monkeypatch.setitem(
        Database.SUPPORTED_BACKENDS,
        "fake",
        "tests.test_borrow_raw_connection:FakeBackend",
    )
    return Database("fake://localhost/testsuite")


@pytest.mark.asyncio
async def test_default_interfaces_are_unchanged(fake_database: Database) -> None:
    database = fake_database
    assert database.is_connected is False
    assert callable(database.connection)
    assert callable(database.transaction)
    assert isinstance(database.connection(), Connection)
    assert isinstance(database.borrow_raw_connection(), typing.AsyncContextManager)


@pytest.mark.asyncio
async def test_borrow_raw_connection_succeeds(fake_database: Database) -> None:
    database = fake_database
    connection = database.connection()

    async with connection.borrow_raw_connection() as borrowed:
        assert isinstance(borrowed, BorrowedConnection)
        assert borrowed.expired is False

        raw_connection = borrowed.raw_connection
        checked_out = database._backend.pool.checked_out
        assert checked_out[raw_connection.identity] is raw_connection

        # The raw driver object remains usable through the handle.
        assert await borrowed.submit("ping") == f"{raw_connection.identity}:ping"
        assert raw_connection.operations == ["ping"]

    # Exiting the scope returned the connection to the pool.
    assert database._backend.pool.checked_out == {}
    assert database._backend.pool.releases == 1


@pytest.mark.asyncio
async def test_borrowed_handle_expires_after_scope(fake_database: Database) -> None:
    database = fake_database
    connection = database.connection()

    async with connection.borrow_raw_connection() as borrowed:
        raw_connection = borrowed.raw_connection
        identity = raw_connection.identity

    assert borrowed.expired is True

    with pytest.raises(BorrowedConnectionExpired):
        borrowed.raw_connection

    with pytest.raises(BorrowedConnectionExpired):
        await borrowed.submit("ping")

    # The expired handle must not hold the driver object anymore.
    assert borrowed._raw_connection is None
    assert identity in [conn.identity for conn in database._backend.pool.available]


@pytest.mark.asyncio
async def test_borrowed_handle_expires_on_exception(fake_database: Database) -> None:
    database = fake_database
    connection = database.connection()
    borrowed: typing.Optional[BorrowedConnection] = None

    with pytest.raises(RuntimeError):
        async with connection.borrow_raw_connection() as borrowed:
            assert borrowed.expired is False
            raise RuntimeError("boom")

    assert borrowed is not None
    assert borrowed.expired is True
    with pytest.raises(BorrowedConnectionExpired):
        borrowed.raw_connection
    assert database._backend.pool.checked_out == {}


@pytest.mark.asyncio
async def test_nested_borrows_share_and_release_connection(
    fake_database: Database,
) -> None:
    database = fake_database
    connection = database.connection()

    async with connection.borrow_raw_connection() as outer:
        outer_raw = outer.raw_connection
        assert database._backend.pool.acquisitions == 1

        async with connection.borrow_raw_connection() as inner:
            # Same underlying connection, same acquisition, distinct handles.
            assert inner is not outer
            assert inner.raw_connection is outer_raw
            assert database._backend.pool.acquisitions == 1
            assert await inner.submit("inner") == f"{outer_raw.identity}:inner"

        # The inner handle is expired while the outer scope stays active.
        assert inner.expired is True
        with pytest.raises(BorrowedConnectionExpired):
            inner.raw_connection
        assert outer.expired is False
        assert outer.raw_connection is outer_raw

    # Only after the outer scope exits is the connection released.
    assert outer.expired is True
    assert database._backend.pool.acquisitions == 1
    assert database._backend.pool.releases == 1
    assert database._backend.pool.checked_out == {}


@pytest.mark.asyncio
async def test_borrow_is_cancelled_safely(fake_database: Database) -> None:
    database = fake_database
    connection = database.connection()
    captured: typing.Dict[str, typing.Any] = {}
    entered = asyncio.Event()

    async def borrow_scope() -> None:
        async with connection.borrow_raw_connection() as borrowed:
            captured["borrowed"] = borrowed
            entered.set()
            # Block until the task is cancelled.
            await asyncio.Event().wait()

    task = asyncio.create_task(borrow_scope())
    await entered.wait()

    borrowed = captured["borrowed"]
    assert borrowed.expired is False
    raw_connection = borrowed.raw_connection
    assert raw_connection.identity in database._backend.pool.checked_out

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Cancellation still closes the scope and releases the connection.
    assert borrowed.expired is True
    with pytest.raises(BorrowedConnectionExpired):
        borrowed.raw_connection
    assert database._backend.pool.checked_out == {}
    assert database._backend.pool.releases == 1


@pytest.mark.asyncio
async def test_next_borrow_reuses_its_own_connection(fake_database: Database) -> None:
    database = fake_database
    connection = database.connection()

    async with connection.borrow_raw_connection() as first:
        first_raw = first.raw_connection
        await first.submit("first")

    assert first.expired is True
    with pytest.raises(BorrowedConnectionExpired):
        await first.submit("stale")

    # The next normal borrow gets a working (recycled) connection again.
    async with connection.borrow_raw_connection() as second:
        second_raw = second.raw_connection
        assert second.expired is False
        assert second_raw.identity == first_raw.identity
        assert await second.submit("second") == f"{second_raw.identity}:second"
        assert second_raw.operations == ["first", "second"]

    assert second.expired is True
    with pytest.raises(BorrowedConnectionExpired):
        second.raw_connection
    assert database._backend.pool.checked_out == {}
    assert database._backend.pool.acquisitions == 2
    assert database._backend.pool.releases == 2


@pytest.mark.asyncio
async def test_database_level_borrow_scope(fake_database: Database) -> None:
    database = fake_database

    async with database.borrow_raw_connection() as borrowed:
        raw_connection = borrowed.raw_connection
        assert await borrowed.submit("ping") == f"{raw_connection.identity}:ping"

    assert borrowed.expired is True
    with pytest.raises(BorrowedConnectionExpired):
        borrowed.raw_connection
