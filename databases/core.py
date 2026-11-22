import asyncio
import contextlib
import functools
import logging
import typing
import weakref
from contextvars import ContextVar
from types import TracebackType
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit

from sqlalchemy import text
from sqlalchemy.sql import ClauseElement

from databases.importer import import_from_string
from databases.interfaces import DatabaseBackend, Record, TransactionBackend

try:  # pragma: no cover
    import click

    # Extra log info for optional coloured terminal outputs.
    LOG_EXTRA = {
        "color_message": "Query: " + click.style("%s", bold=True) + " Args: %s"
    }
    CONNECT_EXTRA = {
        "color_message": "Connected to database " + click.style("%s", bold=True)
    }
    DISCONNECT_EXTRA = {
        "color_message": "Disconnected from database " + click.style("%s", bold=True)
    }
except ImportError:  # pragma: no cover
    LOG_EXTRA = {}
    CONNECT_EXTRA = {}
    DISCONNECT_EXTRA = {}


logger = logging.getLogger("databases")


_ACTIVE_TRANSACTIONS: ContextVar[
    typing.Optional["weakref.WeakKeyDictionary['Transaction', 'TransactionBackend']"]
] = ContextVar("databases:active_transactions", default=None)

# Set while a task is running inside an authorized transaction handoff.
_CURRENT_HANDOFF: ContextVar[typing.Optional["TransactionHandoff"]] = ContextVar(
    "databases:current_handoff", default=None
)


class TransactionHandoffError(RuntimeError):
    """
    Raised when a transaction handoff is used incorrectly, or after the
    transaction that issued it has closed.
    """


class TransactionNotAuthorized(TransactionHandoffError):
    """
    Raised when a task uses a transaction, or a handoff for it, without having
    been authorized to do so.
    """


class ConnectionNotAcquired(RuntimeError):
    """
    Raised when a released connection is used again.
    """


class _TransactionMetadata:
    """
    The owner-scoped state for a single `Transaction` activation.

    This deliberately lives in task state instead of on the `Transaction`
    object: decorator-based transactions are shared by concurrent tasks, and
    each task has its own independent activation.
    """

    def __init__(
        self,
        owner: asyncio.Task,
        transaction: "Transaction",
        connection: "Connection",
        backend: TransactionBackend,
        shared: bool = False,
    ) -> None:
        self.owner = owner
        self.transaction = transaction
        self.connection = connection
        self.backend = backend
        # Force-rollback databases deliberately expose a single connection to
        # every task, so that connection's root transaction must stay shared.
        self.shared = shared
        self.closed = False
        self.handoffs: typing.Set["TransactionHandoff"] = set()

    def close(self) -> None:
        """
        Revoke outstanding handoffs and prevent any further use of the
        transaction's connection.

        This runs before the backend commit/rollback so that a delegated task
        cannot keep using the connection once the owner has decided the
        transaction's fate.
        """
        if self.closed:
            return
        self.closed = True
        for handoff in list(self.handoffs):
            handoff._invalidate()
        self.handoffs.clear()


class TransactionHandoff:
    """
    An authorization for one delegated task to use a transaction's connection.

    Handoffs are created by the owning task with `transaction.handoff()` and
    passed explicitly to a child task. They are intentionally not inherited
    through task context: using one from a task other than the delegate raises
    `TransactionNotAuthorized`, and using one after the owning transaction has
    closed raises `TransactionHandoffError`.

    The delegate can use the transaction's connection directly:

    ```python
    async def child(handoff):
        async with handoff:
            await handoff.connection.execute(...)

    async with database.transaction() as transaction:
        task = asyncio.create_task(child(transaction.handoff()))
        ...
    ```

    Or the regular `Database` helpers while the handoff is active:

    ```python
    async def child(handoff):
        async with handoff:
            await database.execute(...)

    async with database.transaction() as transaction:
        await asyncio.create_task(child(transaction.handoff()))
    ```

    The first task to use the handoff becomes its delegate. Commit and rollback
    always remain with the owning task. The handoff is revoked as soon as the
    owning transaction commits or rolls back.
    """

    def __init__(
        self,
        transaction: "Transaction",
        metadata: _TransactionMetadata,
        task: typing.Optional[asyncio.Task] = None,
    ):
        self._transaction = transaction
        self._metadata = metadata
        self._task: typing.Optional[asyncio.Task] = task
        self._tokens: typing.List[typing.Tuple[asyncio.Task, typing.Any]] = []
        self._invalidated = False

    @property
    def transaction(self) -> "Transaction":
        self._claim()
        return self._transaction

    @property
    def connection(self) -> "Connection":
        self._claim()
        return self._metadata.connection

    @property
    def task(self) -> typing.Optional[asyncio.Task]:
        return self._task

    @property
    def is_valid(self) -> bool:
        return not self._invalidated and not self._metadata.closed

    def _claim(self) -> asyncio.Task:
        self._validate()
        task = asyncio.current_task()
        if task is None:  # pragma: no cover
            raise TransactionHandoffError(
                "Transaction handoffs can only be used from an asyncio task"
            )
        if task is self._metadata.owner:
            # The owner does not need the handoff, but inspecting it must not
            # consume the delegation intended for a child task.
            return task
        if self._task is None:
            self._task = task
        elif self._task is not task:
            raise TransactionNotAuthorized(
                "This transaction handoff was issued to a different task"
            )
        return task

    def _validate(self) -> None:
        if self._invalidated or self._metadata.closed:
            raise TransactionHandoffError("This transaction handoff is no longer valid")

    def _ensure_usable(self) -> None:
        self._validate()
        task = asyncio.current_task()
        if task is self._metadata.owner:
            return
        if self._task is None or task is not self._task:
            raise TransactionNotAuthorized(
                "This transaction handoff was issued to a different task"
            )

    def _invalidate(self) -> None:
        self._invalidated = True

    async def __aenter__(self) -> "TransactionHandoff":
        task = self._claim()
        self._tokens.append((task, _CURRENT_HANDOFF.set(self)))
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        task = asyncio.current_task()
        for index in range(len(self._tokens) - 1, -1, -1):
            token_task, token = self._tokens[index]
            if token_task is task:
                del self._tokens[index]
                _CURRENT_HANDOFF.reset(token)
                return


class Database:
    SUPPORTED_BACKENDS = {
        "postgresql": "databases.backends.postgres:PostgresBackend",
        "postgresql+aiopg": "databases.backends.aiopg:AiopgBackend",
        "postgres": "databases.backends.postgres:PostgresBackend",
        "mysql": "databases.backends.mysql:MySQLBackend",
        "mysql+asyncmy": "databases.backends.asyncmy:AsyncMyBackend",
        "sqlite": "databases.backends.sqlite:SQLiteBackend",
    }

    _connection_map: "weakref.WeakKeyDictionary[asyncio.Task, 'Connection']"

    def __init__(
        self,
        url: typing.Union[str, "DatabaseURL"],
        *,
        force_rollback: bool = False,
        **options: typing.Any,
    ):
        self.url = DatabaseURL(url)
        self.options = options
        self.is_connected = False
        self._connection_map = weakref.WeakKeyDictionary()

        self._force_rollback = force_rollback

        backend_str = self._get_backend()
        backend_cls = import_from_string(backend_str)
        assert issubclass(backend_cls, DatabaseBackend)
        self._backend = backend_cls(self.url, **self.options)

        # When `force_rollback=True` is used, we use a single global
        # connection, within a transaction that always rolls back.
        self._global_connection: typing.Optional[Connection] = None
        self._global_transaction: typing.Optional[Transaction] = None

    @property
    def _current_task(self) -> asyncio.Task:
        task = asyncio.current_task()
        if not task:
            raise RuntimeError("No currently active asyncio.Task found")
        return task

    @property
    def _connection(self) -> typing.Optional["Connection"]:
        return self._connection_map.get(self._current_task)

    @_connection.setter
    def _connection(
        self, connection: typing.Optional["Connection"]
    ) -> typing.Optional["Connection"]:
        task = self._current_task

        if connection is None:
            self._connection_map.pop(task, None)
        else:
            self._connection_map[task] = connection

        return self._connection

    async def connect(self) -> None:
        """
        Establish the connection pool.
        """
        if self.is_connected:
            logger.debug("Already connected, skipping connection")
            return None

        await self._backend.connect()
        logger.info(
            "Connected to database %s", self.url.obscure_password, extra=CONNECT_EXTRA
        )
        self.is_connected = True

        if self._force_rollback:
            assert self._global_connection is None
            assert self._global_transaction is None

            self._global_connection = Connection(self, self._backend)
            self._global_transaction = self._global_connection.transaction(
                force_rollback=True, shared=True
            )

            await self._global_transaction.__aenter__()

    async def disconnect(self) -> None:
        """
        Close all connections in the connection pool.
        """
        if not self.is_connected:
            logger.debug("Already disconnected, skipping disconnection")
            return None

        if self._force_rollback:
            assert self._global_connection is not None
            assert self._global_transaction is not None

            await self._global_transaction.__aexit__()

            self._global_transaction = None
            self._global_connection = None
        else:
            self._connection = None

        await self._backend.disconnect()
        logger.info(
            "Disconnected from database %s",
            self.url.obscure_password,
            extra=DISCONNECT_EXTRA,
        )
        self.is_connected = False

    async def __aenter__(self) -> "Database":
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        await self.disconnect()

    async def fetch_all(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.List[Record]:
        async with self.connection() as connection:
            return await connection.fetch_all(query, values)

    async def fetch_one(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.Optional[Record]:
        async with self.connection() as connection:
            return await connection.fetch_one(query, values)

    async def fetch_val(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
        column: typing.Any = 0,
    ) -> typing.Any:
        async with self.connection() as connection:
            return await connection.fetch_val(query, values, column=column)

    async def execute(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.Any:
        async with self.connection() as connection:
            return await connection.execute(query, values)

    async def execute_many(
        self, query: typing.Union[ClauseElement, str], values: list
    ) -> None:
        async with self.connection() as connection:
            return await connection.execute_many(query, values)

    async def iterate(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.AsyncGenerator[typing.Mapping, None]:
        async with self.connection() as connection:
            async for record in connection.iterate(query, values):
                yield record

    def connection(self) -> "Connection":
        if self._global_connection is not None:
            return self._global_connection

        handoff = _CURRENT_HANDOFF.get()
        if handoff is not None and handoff._metadata.connection._database is self:
            # While a handoff is active, the regular database helpers operate
            # on the transaction's connection rather than a task-local one.
            handoff._ensure_usable()
            return handoff._metadata.connection

        if not self._connection:
            self._connection = Connection(self, self._backend)

        return self._connection

    def transaction(
        self, *, force_rollback: bool = False, **kwargs: typing.Any
    ) -> "Transaction":
        return Transaction(self.connection, force_rollback=force_rollback, **kwargs)

    @contextlib.contextmanager
    def force_rollback(self) -> typing.Iterator[None]:
        initial = self._force_rollback
        self._force_rollback = True
        try:
            yield
        finally:
            self._force_rollback = initial

    def _get_backend(self) -> str:
        return self.SUPPORTED_BACKENDS.get(
            self.url.scheme, self.SUPPORTED_BACKENDS[self.url.dialect]
        )


class Connection:
    def __init__(self, database: Database, backend: DatabaseBackend) -> None:
        self._database = database
        self._backend = backend

        self._connection_lock = asyncio.Lock()
        self._connection = self._backend.connection()
        self._connection_counter = 0
        self._released = False

        self._transaction_lock = asyncio.Lock()
        self._transaction_stack: typing.List[Transaction] = []
        # Metadata for the activations on `_transaction_stack`, in the same
        # order. This lets authorization checks work from any task, including
        # tasks that only hold a reference to this connection.
        self._transaction_metadata_stack: typing.List[_TransactionMetadata] = []

        self._query_lock = asyncio.Lock()

    def _ensure_acquired(self) -> None:
        if self._connection_counter == 0:
            raise ConnectionNotAcquired(
                "This connection has been released and can no longer be used"
            )

    def _ensure_authorized(self) -> None:
        """
        Refuse to run work on this connection from a task that does not own the
        active transaction, unless it holds an explicit handoff.
        """
        task = asyncio.current_task()
        handoff = _CURRENT_HANDOFF.get()

        for transaction, metadata in reversed(
            list(zip(self._transaction_stack, self._transaction_metadata_stack))
        ):
            if metadata.shared:
                continue
            if metadata.closed:
                raise TransactionHandoffError(
                    "The transaction that owns this connection has already closed"
                )
            if task is metadata.owner:
                return
            if handoff is not None and handoff._transaction is transaction:
                handoff._ensure_usable()
                return
            raise TransactionNotAuthorized(
                "This connection is part of a transaction owned by a different "
                "task. Use `transaction.handoff()` to delegate access explicitly."
            )

    async def __aenter__(self) -> "Connection":
        self._ensure_authorized()
        async with self._connection_lock:
            if self._released:
                raise ConnectionNotAcquired(
                    "This connection has been released and can no longer be used"
                )
            self._connection_counter += 1
            try:
                if self._connection_counter == 1:
                    await self._connection.acquire()
            except BaseException as e:
                self._connection_counter -= 1
                raise e
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        self._ensure_authorized()
        async with self._connection_lock:
            assert self._connection is not None
            self._connection_counter -= 1
            if self._connection_counter == 0:
                self._released = True
                await self._connection.release()
                if self._database._connection is self:
                    self._database._connection = None

    async def fetch_all(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.List[Record]:
        self._ensure_acquired()
        self._ensure_authorized()
        built_query = self._build_query(query, values)
        async with self._query_lock:
            return await self._connection.fetch_all(built_query)

    async def fetch_one(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.Optional[Record]:
        self._ensure_acquired()
        self._ensure_authorized()
        built_query = self._build_query(query, values)
        async with self._query_lock:
            return await self._connection.fetch_one(built_query)

    async def fetch_val(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
        column: typing.Any = 0,
    ) -> typing.Any:
        self._ensure_acquired()
        self._ensure_authorized()
        built_query = self._build_query(query, values)
        async with self._query_lock:
            return await self._connection.fetch_val(built_query, column)

    async def execute(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.Any:
        self._ensure_acquired()
        self._ensure_authorized()
        built_query = self._build_query(query, values)
        async with self._query_lock:
            return await self._connection.execute(built_query)

    async def execute_many(
        self, query: typing.Union[ClauseElement, str], values: list
    ) -> None:
        self._ensure_acquired()
        self._ensure_authorized()
        queries = [self._build_query(query, values_set) for values_set in values]
        async with self._query_lock:
            await self._connection.execute_many(queries)

    async def iterate(
        self,
        query: typing.Union[ClauseElement, str],
        values: typing.Optional[dict] = None,
    ) -> typing.AsyncGenerator[typing.Any, None]:
        self._ensure_acquired()
        self._ensure_authorized()
        built_query = self._build_query(query, values)
        async with self.transaction():
            async with self._query_lock:
                async for record in self._connection.iterate(built_query):
                    yield record

    def transaction(
        self, *, force_rollback: bool = False, **kwargs: typing.Any
    ) -> "Transaction":
        def connection_callable() -> Connection:
            return self

        return Transaction(connection_callable, force_rollback, **kwargs)

    @property
    def raw_connection(self) -> typing.Any:
        self._ensure_acquired()
        self._ensure_authorized()
        return self._connection.raw_connection

    @staticmethod
    def _build_query(
        query: typing.Union[ClauseElement, str], values: typing.Optional[dict] = None
    ) -> ClauseElement:
        if isinstance(query, str):
            query = text(query)

            return query.bindparams(**values) if values is not None else query
        elif values:
            return query.values(**values)  # type: ignore

        return query


_CallableType = typing.TypeVar("_CallableType", bound=typing.Callable)


class Transaction:
    def __init__(
        self,
        connection_callable: typing.Callable[[], Connection],
        force_rollback: bool,
        shared: bool = False,
        **kwargs: typing.Any,
    ) -> None:
        self._connection_callable = connection_callable
        self._force_rollback = force_rollback
        self._shared = shared
        self._extra_options = kwargs

        # Activations are keyed by the task that owns them. Decorator-based
        # transactions are shared across tasks, so activation state must not
        # be stored on this object directly. Each key holds a stack to support
        # recursive use of the same decorator within a single task.
        self._activations: (
            "weakref.WeakKeyDictionary[asyncio.Task, typing.List[_TransactionMetadata]]"
        ) = weakref.WeakKeyDictionary()

    def _activation_stack(self) -> typing.List["_TransactionMetadata"]:
        task = asyncio.current_task()
        if task is None:  # pragma: no cover
            return []
        return self._activations.get(task, [])

    def _transaction_metadata(self) -> typing.Optional["_TransactionMetadata"]:
        stack = self._activation_stack()
        return stack[-1] if stack else None

    def _push_transaction_metadata(self, metadata: "_TransactionMetadata") -> None:
        task = metadata.owner
        stack = list(self._activations.get(task, []))
        stack.append(metadata)
        self._activations[task] = stack

    def _pop_transaction_metadata(self, metadata: "_TransactionMetadata") -> None:
        task = metadata.owner
        stack = list(self._activations.get(task, []))
        if metadata in stack:
            stack.remove(metadata)
        if stack:
            self._activations[task] = stack
        else:
            self._activations.pop(task, None)

    @property
    def owner(self) -> typing.Optional[asyncio.Task]:
        """
        The task that started this transaction activation, if any.
        """
        metadata = self._transaction_metadata()
        return None if metadata is None else metadata.owner

    @property
    def _connection(self) -> "Connection":
        # Returns the same connection if called multiple times.
        handoff = _CURRENT_HANDOFF.get()
        if handoff is not None and handoff._transaction is self:
            handoff._ensure_usable()
            return handoff._metadata.connection

        metadata = self._transaction_metadata()
        if metadata is None:
            return self._connection_callable()

        if asyncio.current_task() is metadata.owner:
            return metadata.connection

        raise TransactionNotAuthorized(
            "This transaction is owned by a different task. "
            "Use `transaction.handoff()` to delegate access explicitly."
        )

    def handoff(self) -> "TransactionHandoff":
        """
        Create a single-use authorization for one other task to use this
        transaction.

        Only the task that owns the active transaction may issue a handoff.
        The handoff must be passed to the delegated task explicitly; it is not
        inherited by sibling or child tasks automatically.
        """
        metadata = self._transaction_metadata()
        if metadata is None or metadata.closed:
            raise TransactionHandoffError(
                "Cannot hand off a transaction that is not active"
            )

        if asyncio.current_task() is not metadata.owner:
            raise TransactionNotAuthorized(
                "Only the task that owns a transaction can hand it off"
            )

        handoff = TransactionHandoff(self, metadata)
        metadata.handoffs.add(handoff)
        return handoff

    @property
    def _transaction(self) -> typing.Optional["TransactionBackend"]:
        # Only the activation owned by the current task is visible. A child
        # task that merely inherited the contextvar sees no transaction state.
        metadata = self._transaction_metadata()
        return None if metadata is None else metadata.backend

    @_transaction.setter
    def _transaction(
        self, transaction: typing.Optional["TransactionBackend"]
    ) -> typing.Optional["TransactionBackend"]:
        # Kept in sync for backwards compatibility with code that inspects the
        # contextvar directly. Authorization decisions use the per-task
        # activation state instead, because contextvars are inherited by child
        # tasks and would otherwise leak access.
        transactions = _ACTIVE_TRANSACTIONS.get()
        if transactions is None:
            transactions = weakref.WeakKeyDictionary()
        else:
            transactions = transactions.copy()

        if transaction is None:
            transactions.pop(self, None)
        else:
            transactions[self] = transaction

        _ACTIVE_TRANSACTIONS.set(transactions)
        return transactions.get(self, None)

    async def __aenter__(self) -> "Transaction":
        """
        Called when entering `async with database.transaction()`
        """
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        """
        Called when exiting `async with database.transaction()`
        """
        if exc_type is not None or self._force_rollback:
            await self.rollback()
        else:
            await self.commit()

    def __await__(self) -> typing.Generator[None, None, "Transaction"]:
        """
        Called if using the low-level `transaction = await database.transaction()`
        """
        return self.start().__await__()

    def __call__(self, func: _CallableType) -> _CallableType:
        """
        Called if using `@database.transaction()` as a decorator.
        """

        @functools.wraps(func)
        async def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            async with self:
                return await func(*args, **kwargs)

        return wrapper  # type: ignore

    async def start(self) -> "Transaction":
        connection = self._connection
        backend = connection._connection.transaction()
        self._transaction = backend

        async with connection._transaction_lock:
            is_root = not connection._transaction_stack
            await connection.__aenter__()
            await backend.start(is_root=is_root, extra_options=self._extra_options)
            owner = asyncio.current_task()
            if owner is None:  # pragma: no cover
                raise RuntimeError("No currently active asyncio.Task found")
            metadata = _TransactionMetadata(
                owner=owner,
                transaction=self,
                connection=connection,
                backend=backend,
                shared=self._shared,
            )
            connection._transaction_stack.append(self)
            connection._transaction_metadata_stack.append(metadata)

        self._push_transaction_metadata(metadata)
        return self

    def _close_metadata(self, connection: "Connection") -> "_TransactionMetadata":
        if not connection._transaction_metadata_stack:
            raise TransactionHandoffError("Transaction is not active")

        metadata = connection._transaction_metadata_stack[-1]
        if metadata.transaction is not self:
            raise TransactionHandoffError("Transaction is not active")
        # The force-rollback global transaction may be started and stopped by
        # different tasks, so it is exempt from the owner-only rule.
        if not metadata.shared and asyncio.current_task() is not metadata.owner:
            raise TransactionNotAuthorized(
                "Only the task that owns a transaction can commit or roll it back"
            )
        metadata.close()
        return metadata

    async def commit(self) -> None:
        connection = self._connection
        async with connection._transaction_lock:
            assert connection._transaction_stack[-1] is self
            metadata = self._close_metadata(connection)
            connection._transaction_stack.pop()
            connection._transaction_metadata_stack.pop()
            await metadata.backend.commit()
            await connection.__aexit__()
            self._pop_transaction_metadata(metadata)
            self._transaction = None

    async def rollback(self) -> None:
        connection = self._connection
        async with connection._transaction_lock:
            assert connection._transaction_stack[-1] is self
            metadata = self._close_metadata(connection)
            connection._transaction_stack.pop()
            connection._transaction_metadata_stack.pop()
            await metadata.backend.rollback()
            await connection.__aexit__()
            self._pop_transaction_metadata(metadata)
            self._transaction = None


class _EmptyNetloc(str):
    def __bool__(self) -> bool:
        return True


class DatabaseURL:
    def __init__(self, url: typing.Union[str, "DatabaseURL"]):
        if isinstance(url, DatabaseURL):
            self._url: str = url._url
        elif isinstance(url, str):
            self._url = url
        else:
            raise TypeError(
                f"Invalid type for DatabaseURL. Expected str or DatabaseURL, got {type(url)}"
            )

    @property
    def components(self) -> SplitResult:
        if not hasattr(self, "_components"):
            self._components = urlsplit(self._url)
        return self._components

    @property
    def scheme(self) -> str:
        return self.components.scheme

    @property
    def dialect(self) -> str:
        return self.components.scheme.split("+")[0]

    @property
    def driver(self) -> str:
        if "+" not in self.components.scheme:
            return ""
        return self.components.scheme.split("+", 1)[1]

    @property
    def userinfo(self) -> typing.Optional[bytes]:
        if self.components.username:
            info = self.components.username
            if self.components.password:
                info += ":" + self.components.password
            return info.encode("utf-8")
        return None

    @property
    def username(self) -> typing.Optional[str]:
        if self.components.username is None:
            return None
        return unquote(self.components.username)

    @property
    def password(self) -> typing.Optional[str]:
        if self.components.password is None:
            return None
        return unquote(self.components.password)

    @property
    def hostname(self) -> typing.Optional[str]:
        return (
            self.components.hostname
            or self.options.get("host")
            or self.options.get("unix_sock")
        )

    @property
    def port(self) -> typing.Optional[int]:
        return self.components.port

    @property
    def netloc(self) -> typing.Optional[str]:
        return self.components.netloc

    @property
    def database(self) -> str:
        path = self.components.path
        if path.startswith("/"):
            path = path[1:]
        return unquote(path)

    @property
    def options(self) -> dict:
        if not hasattr(self, "_options"):
            self._options = dict(parse_qsl(self.components.query))
        return self._options

    def replace(self, **kwargs: typing.Any) -> "DatabaseURL":
        if (
            "username" in kwargs
            or "password" in kwargs
            or "hostname" in kwargs
            or "port" in kwargs
        ):
            hostname = kwargs.pop("hostname", self.hostname)
            port = kwargs.pop("port", self.port)
            username = kwargs.pop("username", self.components.username)
            password = kwargs.pop("password", self.components.password)

            netloc = hostname
            if port is not None:
                netloc += f":{port}"
            if username is not None:
                userpass = username
                if password is not None:
                    userpass += f":{password}"
                netloc = f"{userpass}@{netloc}"

            kwargs["netloc"] = netloc

        if "database" in kwargs:
            kwargs["path"] = "/" + kwargs.pop("database")

        if "dialect" in kwargs or "driver" in kwargs:
            dialect = kwargs.pop("dialect", self.dialect)
            driver = kwargs.pop("driver", self.driver)
            kwargs["scheme"] = f"{dialect}+{driver}" if driver else dialect

        if not kwargs.get("netloc", self.netloc):
            # Using an empty string that evaluates as True means we end up
            # with URLs like `sqlite:///database` instead of `sqlite:/database`
            kwargs["netloc"] = _EmptyNetloc()

        components = self.components._replace(**kwargs)
        return self.__class__(components.geturl())

    @property
    def obscure_password(self) -> str:
        if self.password:
            return self.replace(password="********")._url
        return self._url

    def __str__(self) -> str:
        return self._url

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self.obscure_password)})"

    def __eq__(self, other: typing.Any) -> bool:
        return str(self) == str(other)
