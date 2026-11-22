"""Optional, value-free auditing for streamed query iteration.

An audit event deliberately contains only:

* the query template (never bound parameters or result values),
* the elapsed wall-clock time, and
* the number of rows actually delivered to the caller.

Nothing in this module reads ahead from a cursor.  Emitting or logging an
audit event therefore never fetches rows that the caller did not consume.
"""

import asyncio
import dataclasses
import enum
import inspect
import logging
import time
import typing

from sqlalchemy.sql import ClauseElement


logger = logging.getLogger("databases.audit")


class IterationOutcome(str, enum.Enum):
    """How a streamed query finished."""

    COMPLETED = "completed"
    CLOSED = "closed"
    FAILED = "failed"



@dataclasses.dataclass(frozen=True)
class QueryAudit:
    """A value-free audit record for one streamed query iteration.

    ``query`` is the statement template.  Bound parameter values are not
    included.  ``duration`` is measured in seconds, from the first row request
    until iteration completes, is closed, or fails.  ``row_count`` is the
    number of records handed to the caller, not the number fetched by the
    driver.
    """

    query: str
    duration: float
    row_count: int
    outcome: IterationOutcome = IterationOutcome.COMPLETED

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, IterationOutcome):
            object.__setattr__(self, "outcome", IterationOutcome(self.outcome))
        object.__setattr__(self, "duration", float(self.duration))
        object.__setattr__(self, "row_count", int(self.row_count))

    @property
    def query_template(self) -> str:
        """Alias for :attr:`query`."""

        return self.query

    @property
    def duration_ms(self) -> float:
        """The duration expressed in milliseconds."""

        return self.duration * 1000.0

    @property
    def closed_early(self) -> bool:
        """Whether the caller stopped consuming early."""

        return self.outcome is IterationOutcome.CLOSED

    @property
    def failed(self) -> bool:
        """Whether starting or advancing the query raised an error."""

        return self.outcome is IterationOutcome.FAILED

    def as_dict(self) -> typing.Dict[str, typing.Any]:
        """Return the record as a plain dictionary."""

        return {
            "query": self.query,
            "duration": self.duration,
            "row_count": self.row_count,
            "outcome": self.outcome.value,
        }

    def __getitem__(self, key: str) -> typing.Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc


class AuditRecorder(typing.Protocol):
    """A synchronous or asynchronous sink for :class:`QueryAudit` objects."""

    def record(self, event: QueryAudit) -> typing.Any:
        ...


AuditHook = typing.Union[
    AuditRecorder,
    typing.Callable[[QueryAudit], typing.Any],
    typing.List[QueryAudit],
    logging.Logger,
    bool,
    None,
]


class LoggingAuditRecorder:
    """Write value-free audit records through the standard logging module.

    Emitted records contain the query template, duration, delivered row count,
    and outcome.  They never contain bound parameters or result values, and
    logging an event never reads from the associated cursor.
    """

    def __init__(
        self,
        target: typing.Optional[logging.Logger] = None,
        level: int = logging.INFO,
    ) -> None:
        self._logger = target or logger
        self._level = level

    def record(self, event: QueryAudit) -> None:
        self._logger.log(
            self._level,
            "query iteration template=%s duration=%.6fs rows=%d outcome=%s",
            event.query,
            event.duration,
            event.row_count,
            event.outcome.value,
            extra={
                "query_template": event.query,
                "duration_seconds": event.duration,
                "row_count": event.row_count,
                "outcome": event.outcome.value,
            },
        )


def query_template(query: typing.Any) -> str:
    """Return a statement template without bound parameter values.

    Raw strings are returned unchanged.  SQLAlchemy expressions render bound
    values as placeholders with ``str()``, so they are safe.  Unknown objects
    are represented by their type name rather than a possibly value-bearing
    ``repr``.
    """

    if isinstance(query, str):
        return query
    if isinstance(query, ClauseElement):
        return str(query)
    return "<%s>" % type(query).__name__


def _deliver(audit: AuditHook, event: QueryAudit) -> typing.Any:
    """Pass an event to the configured sink and return its result."""

    target: typing.Any = audit
    if target is True:
        target = LoggingAuditRecorder()

    if isinstance(target, logging.Logger):
        LoggingAuditRecorder(target).record(event)
        return None

    record = getattr(target, "record", None)
    if record is not None:
        return record(event)

    append = getattr(target, "append", None)
    if append is not None:
        return append(event)

    if callable(target):
        return target(event)

    raise TypeError("audit must be a recorder, callable, logger, or list")


async def emit_audit(audit: AuditHook, event: QueryAudit) -> None:
    """Deliver an audit event without affecting the query result.

    Recorder failures are reported by type only and swallowed.  Auditing is
    observational and must never change the behaviour of the audited query.
    """

    if audit is None or audit is False:
        return

    try:
        result = _deliver(audit, event)
        if inspect.isawaitable(result):
            await result
    except Exception as exc:  # pragma: no cover - defensive
        # Never include the exception message or a traceback here: a recorder
        # might put sensitive values in either.
        logger.warning("Failed to record query iteration audit: %s", type(exc).__name__)


def _spawn(awaitable: typing.Awaitable[typing.Any]) -> None:
    """Run an awaitable in the background, retrieving any exception."""

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    try:
        task = loop.create_task(awaitable)
    except RuntimeError:
        return

    def _consume(task: "asyncio.Task[typing.Any]") -> None:
        if not task.cancelled():
            task.exception()

    task.add_done_callback(_consume)


def emit_audit_now(audit: AuditHook, event: QueryAudit) -> None:
    """Synchronous audit delivery, used when a stream is abandoned.

    ``break`` out of an ``async for`` loop does not await cleanup.  The record
    is emitted synchronously so the outcome is still accurate; an asynchronous
    sink is scheduled on the running loop instead.
    """

    if audit is None or audit is False:
        return

    try:
        result = _deliver(audit, event)
        if inspect.isawaitable(result):
            _spawn(result)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to record query iteration audit: %s", type(exc).__name__)


async def close_async_iterator(iterator: typing.Any) -> None:
    """Close an async iterator without consuming any remaining items.

    Closing is idempotent.  If the iterator is already being finalized -
    for example by the event loop's async-generator shutdown hook - this is a
    no-op rather than an error.
    """

    if iterator is None:
        return
    aclose = getattr(iterator, "aclose", None)
    if aclose is None:
        return
    try:
        await aclose()
    except RuntimeError as exc:
        if "already running" not in str(exc):
            raise


class QueryIteration:
    """An async iterator that records one value-free audit event.

    Use it directly with ``async for``, or close it deterministically with
    ``await stream.aclose()`` / ``async with database.iterate(...) as rows``.

    The wrapper reads exactly as far as the caller does.  It increments the
    delivered row count only after a record has been handed out, and closing
    it never drains the remaining rows.
    """

    __slots__ = (
        "_iterator",
        "_query",
        "_audit",
        "_row_count",
        "_outcome",
        "_finished",
        "_created_at",
        "_started_at",
    )

    def __init__(
        self,
        iterator: typing.AsyncIterator[typing.Any],
        query: str,
        audit: AuditHook = None,
    ) -> None:
        self._iterator = iterator
        self._query = query
        self._audit = audit
        self._row_count = 0
        self._outcome: typing.Optional[IterationOutcome] = None
        self._finished = False
        self._created_at = time.perf_counter()
        self._started_at: typing.Optional[float] = None

    def __aiter__(self) -> "_IterationSession":
        # Returning a per-loop session lets an ordinary ``break`` finalize the
        # audit, because the session is released as soon as the loop ends even
        # if the caller still holds a reference to the stream object itself.
        return _IterationSession(self)

    async def __anext__(self) -> typing.Any:
        if self._finished:
            raise StopAsyncIteration

        if self._started_at is None:
            self._started_at = time.perf_counter()

        try:
            record = await self._iterator.__anext__()
        except StopAsyncIteration:
            await self._finish(IterationOutcome.COMPLETED)
            raise
        except (asyncio.CancelledError, KeyboardInterrupt):
            # The consumer abandoned the iteration.
            await self._finish(IterationOutcome.CLOSED)
            raise
        except BaseException:
            await self._finish(IterationOutcome.FAILED)
            raise

        self._row_count += 1
        return record

    async def aclose(self) -> None:
        """Stop the stream without reading any remaining rows."""

        if self._started_at is None and not self._finished:
            # The query was never executed, so there is nothing to audit.
            self._finished = True
            return

        if self._finished:
            # The loop already finalized the audit (for example after a
            # ``break``); make sure the underlying iterator is still closed.
            await close_async_iterator(self._iterator)
            return

        try:
            await close_async_iterator(self._iterator)
        except BaseException:
            await self._finish(IterationOutcome.FAILED)
            raise
        else:
            await self._finish(IterationOutcome.CLOSED)

    async def __aenter__(self) -> "QueryIteration":
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Any = None,
    ) -> None:
        await self.aclose()

    def __del__(self) -> None:
        # A plain ``break`` out of ``async for`` does not await ``aclose``.
        # Emit the record synchronously here so the early close is still
        # classified even when the caller never closes the stream themselves.
        self._finalize_closed_now()

    def _finalize_closed_now(self) -> None:
        # This may run from ``__del__`` at interpreter shutdown, so every
        # step is defensive: module globals may already be torn down.
        try:
            if getattr(self, "_finished", True) or self._started_at is None:
                self._finished = True
                return
            self._finished = True
            self._outcome = IterationOutcome.CLOSED
            emit_audit_now(self._audit, self._event())
        except Exception:  # pragma: no cover - defensive
            pass
        # Keep the underlying iterator so a later ``aclose()`` can still close
        # it deterministically.  If the stream itself is collected, the event
        # loop's async-generator finalizer closes it without reading ahead.

    @property
    def row_count(self) -> int:
        """Rows delivered to the caller so far."""

        return self._row_count

    @property
    def outcome(self) -> typing.Optional[IterationOutcome]:
        """The final outcome, or ``None`` while the stream is still open."""

        return self._outcome

    def _elapsed(self) -> float:
        start = self._started_at if self._started_at is not None else self._created_at
        return time.perf_counter() - start

    def _event(self) -> QueryAudit:
        return QueryAudit(
            query=self._query,
            duration=self._elapsed(),
            row_count=self._row_count,
            outcome=self._outcome or IterationOutcome.COMPLETED,
        )

    async def _finish(self, outcome: IterationOutcome) -> None:
        if self._finished:
            return
        self._finished = True
        self._outcome = outcome
        await emit_audit(self._audit, self._event())


class _IterationSession:
    """The object ``async for`` actually iterates.

    It is deliberately tiny and per-loop: when the loop exits - including via
    ``break`` or an exception - the session is released, which finalizes the
    parent stream exactly once.
    """

    __slots__ = ("_stream", "_released")

    def __init__(self, stream: QueryIteration) -> None:
        self._stream = stream
        self._released = False

    def __aiter__(self) -> "_IterationSession":
        return self

    async def __anext__(self) -> typing.Any:
        return await self._stream.__anext__()

    def __del__(self) -> None:
        try:
            if getattr(self, "_released", True):
                return
            self._released = True
            stream = getattr(self, "_stream", None)
            if stream is not None:
                stream._finalize_closed_now()
        except Exception:  # pragma: no cover - defensive
            pass
