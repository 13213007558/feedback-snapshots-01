import enum
import re
import typing
from contextvars import ContextVar
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.sql.elements import TextClause

if typing.TYPE_CHECKING:
    from databases.core import Database


class PermitStatus(str, enum.Enum):
    """Lifecycle states of an approved query permit.

    NOT_STARTED: the permit has been granted but never entered, or is currently
        in flight. No effect has been confirmed.
    EFFECTIVE: the protected transaction committed; the approved statements
        have taken effect and the permit is spent.
    ROLLED_BACK: the protected transaction was rolled back by the library
        (including cancellation). The permit is spent and may not be reused.
    """

    NOT_STARTED = "not_started"
    EFFECTIVE = "effective"
    ROLLED_BACK = "rolled_back"


class PermitError(RuntimeError):
    """Base class for query-permit failures."""


class PermitViolation(PermitError):
    """Raised when a statement or parameter falls outside the approved manifest."""


class PermitExpired(PermitError):
    """Raised when a settled permit is used again, or used from the wrong task."""


class QueryClaim(typing.NamedTuple):
    """One approved parameterized statement plus its parameter ranges."""

    sql: str
    parameters: typing.FrozenSet[str]
    ranges: typing.Mapping[str, typing.Tuple[typing.Any, typing.Any]]
    max_calls: int

    def matches(self, sql: str) -> bool:
        return normalize_sql(sql) == normalize_sql(self.sql)

    def check_parameters(self, values: typing.Mapping[str, typing.Any]) -> None:
        unknown = set(values) - set(self.parameters)
        if unknown:
            raise PermitViolation(
                f"Query carries parameters that are not part of the approval: "
                f"{sorted(unknown)}"
            )
        missing = set(self.parameters) - set(values)
        if missing:
            raise PermitViolation(
                f"Query does not bind every approved parameter: {sorted(missing)}"
            )
        for name, value in values.items():
            low, high = self.ranges[name]
            if value < low or value > high:
                raise PermitViolation(
                    f"Parameter {name!r}={value!r} is outside the approved "
                    f"range [{low!r}, {high!r}]"
                )


@dataclass(frozen=True)
class ExecutionRecord:
    """An auditable record of one statement authorized under a permit."""

    permit_id: str
    task_name: str
    sql: str
    values: typing.Tuple[typing.Tuple[str, typing.Any], ...]
    sequence: int


_ACTIVE_PERMIT: ContextVar[typing.Optional["QueryPermit"]] = ContextVar(
    "databases:active_query_permit", default=None
)


def get_active_permit() -> typing.Optional["QueryPermit"]:
    """Return the permit governing the current task, if any.

    The value follows ``contextvars`` semantics: an asyncio subtask copies the
    parent's context at creation time, but each permit is additionally bound to
    the task that activated it, so a copied permit cannot authorize a subtask.
    """

    return _ACTIVE_PERMIT.get()


def normalize_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip().lower()


class QueryPermit:
    """A one-time, explicit manifest of approved parameterized queries.

    A permit is bound to the reporting task that requested it and to the
    database connections it may use. Every statement executed while the permit
    is active must match an entry of the manifest, both in SQL text and in
    parameter range. Ordinary, unpermitted calls keep their existing behaviour
    because checks only run while a permit is active.
    """

    def __init__(
        self,
        database: "Database",
        manifest: typing.Sequence[typing.Mapping[str, typing.Any]],
        permit_id: str,
        *,
        connections: typing.Optional[typing.Sequence[str]] = None,
    ) -> None:
        import asyncio

        try:
            owner = asyncio.current_task()
        except RuntimeError:
            owner = None
        if owner is None:
            raise PermitError("A query permit must be created from within a task")

        self.permit_id = permit_id
        self._database = database
        self._owner = owner
        self._owner_name = owner.get_name()
        self.status = PermitStatus.NOT_STARTED
        self.audit_trail: typing.List[ExecutionRecord] = []
        self._sequence = 0
        self._token: typing.Optional[typing.Any] = None
        self._transaction: typing.Optional[typing.Any] = None

        url = str(database.url)
        if connections is not None and url not in list(connections):
            raise PermitViolation(
                f"Connection {url!r} is outside the callable connection scope "
                f"{list(connections)!r}"
            )
        self.connections: typing.Tuple[str, ...] = (
            tuple(connections) if connections is not None else (url,)
        )

        claims: typing.List[QueryClaim] = []
        for entry in manifest:
            sql_text = entry["sql"]
            parameter_ranges = entry.get("parameters", {})
            max_calls = int(entry.get("max_calls", 1))
            if max_calls < 1:
                raise PermitViolation("max_calls must be at least 1")
            compiled = text(sql_text)
            approved = frozenset(parameter_ranges)
            declared = frozenset(compiled._bindparams)
            if declared != approved:
                raise PermitViolation(
                    f"Approval for {sql_text!r} must declare a range for every "
                    f"parameter {sorted(declared)}, got {sorted(approved)}"
                )
            claims.append(
                QueryClaim(
                    sql=sql_text,
                    parameters=approved,
                    ranges=dict(parameter_ranges),
                    max_calls=max_calls,
                )
            )
        if not claims:
            raise PermitViolation("A permit manifest must contain at least one query")
        self._claims = tuple(claims)
        self._call_counts: typing.Dict[int, int] = {
            index: 0 for index in range(len(claims))
        }

    @property
    def is_valid(self) -> bool:
        return self.status is PermitStatus.NOT_STARTED

    def authorize(self, query: typing.Any) -> None:
        """Validate a compiled statement against the manifest and record it."""

        import asyncio

        current = asyncio.current_task()
        if current is not self._owner:
            raise PermitExpired(
                f"Permit {self.permit_id!r} belongs to task "
                f"{self._owner_name!r} and cannot be used from "
                f"{None if current is None else current.get_name()!r}"
            )
        if self.status is not PermitStatus.NOT_STARTED:
            raise PermitExpired(
                f"Permit {self.permit_id!r} has already settled "
                f"({self.status.value}); the same approval cannot be reused"
            )
        if not isinstance(query, TextClause):
            raise PermitViolation(
                "Only explicit parameterized text() queries can be approved; "
                f"got {type(query).__name__}"
            )

        values = {name: bind.value for name, bind in query._bindparams.items()}
        try:
            claim = next(
                candidate for candidate in self._claims if candidate.matches(str(query))
            )
        except StopIteration:
            raise PermitViolation(
                f"Statement {normalize_sql(str(query))!r} is not part of permit "
                f"{self.permit_id!r}"
            )

        claim.check_parameters(values)
        index = self._claims.index(claim)
        if self._call_counts[index] >= claim.max_calls:
            raise PermitExpired(
                f"Approved statement {normalize_sql(claim.sql)!r} may run at most "
                f"{claim.max_calls} time(s) under permit {self.permit_id!r}"
            )
        self._call_counts[index] += 1

        self._sequence += 1
        self.audit_trail.append(
            ExecutionRecord(
                permit_id=self.permit_id,
                task_name=self._owner_name,
                sql=str(query),
                values=tuple(sorted(values.items())),
                sequence=self._sequence,
            )
        )

    async def __aenter__(self) -> "QueryPermit":
        import asyncio

        if asyncio.current_task() is not self._owner:
            raise PermitExpired(
                "A permit may only be activated by the task that requested it"
            )
        if self.status is not PermitStatus.NOT_STARTED:
            raise PermitExpired(
                f"Permit {self.permit_id!r} has already settled and cannot restart"
            )
        if self._token is not None:
            raise PermitError(f"Permit {self.permit_id!r} is already active")

        self._transaction = self._database.transaction()
        self._token = _ACTIVE_PERMIT.set(self)
        try:
            await self._transaction.__aenter__()
        except BaseException:
            _ACTIVE_PERMIT.reset(self._token)
            self._token = None
            raise
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[typing.Any] = None,
    ) -> None:
        token = self._token
        transaction = self._transaction
        self._token = None
        self._transaction = None
        assert transaction is not None
        try:
            # The contextvar stays active until commit/rollback finishes so the
            # driver attributes BEGIN/COMMIT/ROLLBACK to this permit as well.
            if exc_type is None:
                await transaction.commit()
                self.status = PermitStatus.EFFECTIVE
            else:
                await transaction.rollback()
                self.status = PermitStatus.ROLLED_BACK
        finally:
            if token is not None:
                _ACTIVE_PERMIT.reset(token)

    def __repr__(self) -> str:
        return (
            f"QueryPermit(permit_id={self.permit_id!r}, "
            f"status={self.status.value!r}, claims={len(self._claims)})"
        )
