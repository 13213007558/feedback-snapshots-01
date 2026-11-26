from __future__ import annotations

import asyncio
import copy
import itertools
import uuid

from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from openfga_sdk.client.client import OpenFgaClient
from openfga_sdk.client.configuration import ClientConfiguration
from openfga_sdk.configuration import RetryParams
from openfga_sdk.credentials import Credentials
from openfga_sdk.exceptions import RateLimitExceededError, ServiceException


class QueryRetryPolicy(str, Enum):
    """Contract for an idempotent read that has already started."""

    PIN_TO_APPROVED_GENERATION = "pin_to_approved_generation"
    FAIL_IF_GENERATION_SUPERSEDED = "fail_if_generation_superseded"


class PendingWritePolicy(str, Enum):
    """Contract for a write that had not reached the endpoint at cutover."""

    FENCE_IF_SUPERSEDED = "fence_if_superseded"
    PIN_TO_APPROVED_GENERATION = "pin_to_approved_generation"
    REBASE_TO_CURRENT_GENERATION = "rebase_to_current_generation"


QueryPolicy = QueryRetryPolicy
WritePolicy = PendingWritePolicy

_QUERY_POLICY_ALIASES = {
    "pin": QueryRetryPolicy.PIN_TO_APPROVED_GENERATION,
    "pinned": QueryRetryPolicy.PIN_TO_APPROVED_GENERATION,
    "sticky": QueryRetryPolicy.PIN_TO_APPROVED_GENERATION,
    "pin_to_approval": QueryRetryPolicy.PIN_TO_APPROVED_GENERATION,
    "fail": QueryRetryPolicy.FAIL_IF_GENERATION_SUPERSEDED,
    "abort": QueryRetryPolicy.FAIL_IF_GENERATION_SUPERSEDED,
    "fence": QueryRetryPolicy.FAIL_IF_GENERATION_SUPERSEDED,
    "fail_on_change": QueryRetryPolicy.FAIL_IF_GENERATION_SUPERSEDED,
}

_WRITE_POLICY_ALIASES = {
    "fence": PendingWritePolicy.FENCE_IF_SUPERSEDED,
    "abort": PendingWritePolicy.FENCE_IF_SUPERSEDED,
    "cancel": PendingWritePolicy.FENCE_IF_SUPERSEDED,
    "reject": PendingWritePolicy.FENCE_IF_SUPERSEDED,
    "pin": PendingWritePolicy.PIN_TO_APPROVED_GENERATION,
    "pinned": PendingWritePolicy.PIN_TO_APPROVED_GENERATION,
    "sticky": PendingWritePolicy.PIN_TO_APPROVED_GENERATION,
    "rebase": PendingWritePolicy.REBASE_TO_CURRENT_GENERATION,
    "current": PendingWritePolicy.REBASE_TO_CURRENT_GENERATION,
    "follow_current": PendingWritePolicy.REBASE_TO_CURRENT_GENERATION,
    "use_new": PendingWritePolicy.REBASE_TO_CURRENT_GENERATION,
}


def _coerce_query_policy(value: QueryPolicy | str) -> QueryRetryPolicy:
    if isinstance(value, QueryRetryPolicy):
        return value
    normalized = str(value).strip().lower().replace("-", "_")
    try:
        return _QUERY_POLICY_ALIASES[normalized]
    except KeyError:
        return QueryRetryPolicy(normalized)


def _coerce_write_policy(value: WritePolicy | str) -> PendingWritePolicy:
    if isinstance(value, PendingWritePolicy):
        return value
    normalized = str(value).strip().lower().replace("-", "_")
    try:
        return _WRITE_POLICY_ALIASES[normalized]
    except KeyError:
        return PendingWritePolicy(normalized)


class StoreRotationError(RuntimeError):
    """Base error for an unsafe store generation transition."""


class NoActiveStoreGenerationError(StoreRotationError):
    """Raised when work is started before a store profile is approved."""


class StaleWriteGenerationError(StoreRotationError):
    """Raised when a queued write is fenced after its approval was superseded."""

    def __init__(self, ticket: WriteTicket, decision: RotationDecision):
        self.ticket = ticket
        self.decision = decision
        super().__init__(
            f"write {ticket.ticket_id} is bound to store generation "
            f"{ticket.generation.number}, but generation "
            f"{decision.current_generation} is active; write was not sent"
        )


class QueryGenerationSupersededError(StoreRotationError):
    """Raised when a read retry is refused after approval changed."""

    def __init__(self, decision: RotationDecision, original: BaseException):
        self.decision = decision
        self.original = original
        super().__init__(
            f"query generation {decision.generation} was superseded by "
            f"{decision.current_generation}; retry was not sent"
        )


@dataclass(frozen=True)
class StoreProfile:
    """One jointly approved OpenFGA store, authorization model, and auth profile."""

    store_id: str
    authorization_model_id: str | None = None
    credentials: Credentials | None = None
    api_url: str = "http://api.fga.example"
    name: str | None = None
    headers: dict[str, str] | None = None
    retry_params: RetryParams | None = None
    timeout_millisec: int | None = None
    auth_label: str | None = None

    def __post_init__(self) -> None:
        if self.credentials is not None:
            object.__setattr__(self, "credentials", copy.deepcopy(self.credentials))
        if self.headers is not None:
            object.__setattr__(self, "headers", dict(self.headers))
        if self.retry_params is not None:
            object.__setattr__(self, "retry_params", copy.deepcopy(self.retry_params))

    @property
    def label(self) -> str:
        return self.name or self.auth_label or self.store_id

    @property
    def credential_method(self) -> str:
        return self.credentials.method if self.credentials is not None else "none"


@dataclass(frozen=True)
class StoreGeneration:
    """An immutable approved profile and its isolated SDK client."""

    number: int
    profile: StoreProfile
    client: Any = field(compare=False, repr=False)

    @property
    def store_id(self) -> str:
        return self.profile.store_id

    @property
    def authorization_model_id(self) -> str | None:
        return self.profile.authorization_model_id

    @property
    def credentials(self) -> Credentials | None:
        return self.profile.credentials


StoreConfig = StoreProfile
ApprovedStore = StoreGeneration


@dataclass(frozen=True)
class RotationDecision:
    """An auditable policy choice made at a concurrency boundary."""

    sequence: int
    kind: str
    policy: str
    action: str
    allowed: bool
    generation: int | None
    current_generation: int | None
    store_id: str | None
    authorization_model_id: str | None
    auth_method: str
    ticket_id: str | None = None
    detail: str | None = None


@dataclass
class WriteTicket:
    """A queued write bound to the approval that existed when it was enqueued."""

    body: Any
    generation: StoreGeneration
    options: dict[str, Any] | None = None
    policy: PendingWritePolicy = PendingWritePolicy.FENCE_IF_SUPERSEDED
    ticket_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: str = "queued"
    result: Any = None
    error: BaseException | None = None

    @property
    def generation_number(self) -> int:
        return self.generation.number


@dataclass
class QueryLease:
    """An in-flight idempotent query pinned to one approved generation."""

    lease_id: str
    generation: int
    operation: str
    status: str = "in_flight"


BeforeRetryHook = Callable[[RotationDecision], Awaitable[None] | None]
BeforeSendHook = Callable[[WriteTicket], Awaitable[None] | None]
ClientFactory = Callable[[StoreProfile], Any]


def default_client_factory(profile: StoreProfile) -> OpenFgaClient:
    """Build the isolated async SDK client used by one approved generation."""

    configuration = ClientConfiguration(
        api_url=profile.api_url,
        store_id=profile.store_id,
        authorization_model_id=profile.authorization_model_id,
        credentials=profile.credentials,
        retry_params=profile.retry_params
        or RetryParams(max_retry=0, min_wait_in_ms=0),
        headers=profile.headers,
        timeout_millisec=profile.timeout_millisec,
    )
    return OpenFgaClient(configuration)


class StoreRotationCoordinator:
    """Coordinate atomic store/model/auth cutover with explicit request contracts."""

    def __init__(
        self,
        profiles: list[StoreProfile] | tuple[StoreProfile, ...] | None = None,
        *,
        client_factory: ClientFactory = default_client_factory,
        query_policy: QueryPolicy = QueryRetryPolicy.PIN_TO_APPROVED_GENERATION,
        write_policy: WritePolicy = PendingWritePolicy.FENCE_IF_SUPERSEDED,
        max_query_retries: int = 1,
        retryable_exceptions: tuple[type[BaseException], ...] = (
            RateLimitExceededError,
            ServiceException,
        ),
    ) -> None:
        self._client_factory = client_factory
        self.query_policy = _coerce_query_policy(query_policy)
        self.write_policy = _coerce_write_policy(write_policy)
        self.max_query_retries = max_query_retries
        self.retryable_exceptions = retryable_exceptions
        self._numbers = itertools.count(1)
        self._current: StoreGeneration | None = None
        self._generations: dict[int, StoreGeneration] = {}
        self._active_queries: dict[str, QueryLease] = {}
        self._write_queue: deque[WriteTicket] = deque()
        self._decisions: list[RotationDecision] = []
        self._decision_numbers = itertools.count(1)
        self._write_lock = asyncio.Lock()

        for profile in profiles or ():
            self.approve(profile)

    @property
    def current(self) -> StoreGeneration:
        if self._current is None:
            raise NoActiveStoreGenerationError(
                "approve a StoreProfile before issuing requests"
            )
        return self._current

    @property
    def current_or_none(self) -> StoreGeneration | None:
        return self._current

    @property
    def decisions(self) -> tuple[RotationDecision, ...]:
        return tuple(self._decisions)

    @property
    def pending_writes(self) -> tuple[WriteTicket, ...]:
        return tuple(self._write_queue)

    @property
    def active_queries(self) -> tuple[QueryLease, ...]:
        return tuple(self._active_queries.values())

    @property
    def in_flight_query_count(self) -> int:
        return len(self._active_queries)

    def approve(
        self,
        profile: StoreProfile,
        *,
        client: Any | None = None,
        fence_queued_writes: bool = False,
    ) -> StoreGeneration:
        """Atomically approve a new store/model/auth generation and make it current."""

        generation = StoreGeneration(
            number=next(self._numbers),
            profile=profile,
            client=client if client is not None else self._client_factory(profile),
        )
        self._generations[generation.number] = generation
        previous = self._current.number if self._current is not None else None
        self._current = generation
        self._record(
            kind="rotation",
            policy="atomic_profile_switch",
            action="approve",
            allowed=True,
            generation=generation.number,
            current_generation=generation.number,
            store_id=profile.store_id,
            authorization_model_id=profile.authorization_model_id,
            auth_method=profile.credential_method,
            detail=f"previous_generation={previous}",
        )
        if fence_queued_writes:
            self.fence_pending_writes()
        return generation

    switch_to = approve
    activate = approve

    def generation(self, number: int) -> StoreGeneration:
        return self._generations[number]

    def client_for(self, number: int | StoreGeneration) -> Any:
        if isinstance(number, StoreGeneration):
            return number.client
        return self.generation(number).client

    def _record(self, **kwargs: Any) -> RotationDecision:
        kwargs.setdefault(
            "current_generation",
            self._current.number if self._current is not None else None,
        )
        decision = RotationDecision(sequence=next(self._decision_numbers), **kwargs)
        self._decisions.append(decision)
        return decision

    async def check(
        self,
        body: Any,
        options: dict[str, Any] | None = None,
        *,
        policy: QueryPolicy | str | None = None,
        max_retries: int | None = None,
        before_retry: BeforeRetryHook | None = None,
    ) -> Any:
        """Run a check with all retries bound to one approved generation."""

        return await self.execute_query(
            "check",
            body,
            options,
            policy=policy,
            max_retries=max_retries,
            before_retry=before_retry,
        )

    async def execute_query(
        self,
        operation: str | Callable[[Any], Awaitable[Any]],
        *args: Any,
        policy: QueryPolicy | str | None = None,
        max_retries: int | None = None,
        before_retry: BeforeRetryHook | None = None,
        **kwargs: Any,
    ) -> Any:
        """Execute an idempotent query and apply the explicit retry contract."""

        generation = self.current
        retry_policy = _coerce_query_policy(policy or self.query_policy)
        retry_limit = self.max_query_retries if max_retries is None else max_retries
        operation_name = (
            operation
            if isinstance(operation, str)
            else getattr(operation, "__name__", "query")
        )
        lease = QueryLease(
            lease_id=uuid.uuid4().hex,
            generation=generation.number,
            operation=operation_name,
        )
        self._active_queries[lease.lease_id] = lease
        attempt = 0

        try:
            while True:
                try:
                    if callable(operation):
                        return await operation(generation.client, *args, **kwargs)
                    method = getattr(generation.client, operation)
                    return await method(*args, **kwargs)
                except self.retryable_exceptions as exc:
                    if attempt >= retry_limit:
                        lease.status = "failed"
                        self._record_query_decision(
                            generation,
                            retry_policy,
                            "retry_exhausted",
                            allowed=False,
                            detail=str(exc),
                        )
                        raise

                    attempt += 1
                    lease.status = "retry_waiting"
                    superseded = self.current_or_none != generation
                    decision = self._record_query_decision(
                        generation,
                        retry_policy,
                        "retry_ready",
                        allowed=True,
                        detail=(
                            "generation_superseded"
                            if superseded
                            else "generation_unchanged"
                        ),
                    )
                    if before_retry is not None:
                        result = before_retry(decision)
                        if asyncio.iscoroutine(result):
                            await result

                    if (
                        self.current_or_none != generation
                        and retry_policy
                        is QueryRetryPolicy.FAIL_IF_GENERATION_SUPERSEDED
                    ):
                        lease.status = "superseded"
                        refused = self._record_query_decision(
                            generation,
                            retry_policy,
                            "fail_superseded",
                            allowed=False,
                            detail="retry refused to mix old request with new approval",
                        )
                        raise QueryGenerationSupersededError(refused, exc) from exc

                    lease.status = "in_flight"
                    self._record_query_decision(
                        generation,
                        retry_policy,
                        "retry_pinned",
                        allowed=True,
                        detail="retry uses original store, model, and credentials",
                    )
        finally:
            self._active_queries.pop(lease.lease_id, None)

    query = check

    def _record_query_decision(
        self,
        generation: StoreGeneration,
        policy: QueryRetryPolicy,
        action: str,
        *,
        allowed: bool,
        detail: str | None = None,
    ) -> RotationDecision:
        return self._record(
            kind="query_retry",
            policy=policy.value,
            action=action,
            allowed=allowed,
            generation=generation.number,
            current_generation=(
                self._current.number if self._current is not None else None
            ),
            store_id=generation.store_id,
            authorization_model_id=generation.authorization_model_id,
            auth_method=generation.profile.credential_method,
            detail=detail,
        )

    def enqueue_write(
        self,
        body: Any,
        options: dict[str, Any] | None = None,
        *,
        policy: WritePolicy | str | None = None,
        ticket_id: str | None = None,
    ) -> WriteTicket:
        """Queue a write, binding it to the currently approved generation."""

        generation = self.current
        write_policy = _coerce_write_policy(policy or self.write_policy)
        ticket = WriteTicket(
            body=body,
            generation=generation,
            options=dict(options) if options is not None else None,
            policy=write_policy,
            ticket_id=ticket_id or uuid.uuid4().hex,
        )
        self._write_queue.append(ticket)
        self._record_write_decision(
            ticket,
            "enqueue",
            allowed=True,
            detail="write bound to approval at enqueue time",
        )
        return ticket

    queue_write = enqueue_write

    def fence_pending_writes(self) -> tuple[WriteTicket, ...]:
        """Fence all writes still sitting in the queue before the send edge."""

        tickets = tuple(self._write_queue)
        self._write_queue.clear()
        for ticket in tickets:
            ticket.status = "fenced"
            decision = self._record_write_decision(
                ticket,
                "fence_queued",
                allowed=False,
                detail="write was not sent and requires explicit re-approval",
            )
            ticket.error = StaleWriteGenerationError(ticket, decision)
        return tickets

    cancel_pending_writes = fence_pending_writes

    async def send_next_write(
        self, *, before_send: BeforeSendHook | None = None
    ) -> Any:
        """Pop the next queued write and apply its cutover contract."""

        async with self._write_lock:
            if not self._write_queue:
                raise IndexError("write queue is empty")
            ticket = self._write_queue.popleft()
            return await self.send_write(ticket, before_send=before_send)

    async def send_write(
        self,
        ticket: WriteTicket,
        *,
        before_send: BeforeSendHook | None = None,
    ) -> Any:
        """Send a specific ticket after evaluating generation at the send edge."""

        if ticket.status not in {"queued", "ready"}:
            raise StoreRotationError(
                f"write {ticket.ticket_id} already has status {ticket.status}"
            )

        ticket.status = "ready"
        if before_send is not None:
            result = before_send(ticket)
            if asyncio.iscoroutine(result):
                await result

        current = self.current
        superseded = current != ticket.generation

        if superseded and ticket.policy is PendingWritePolicy.FENCE_IF_SUPERSEDED:
            ticket.status = "fenced"
            decision = self._record_write_decision(
                ticket,
                "fence_superseded",
                allowed=False,
                detail="queued write must be explicitly re-approved before sending",
            )
            error = StaleWriteGenerationError(ticket, decision)
            ticket.error = error
            raise error

        generation = ticket.generation
        options = dict(ticket.options or {})
        action = "send_pinned"

        if (
            superseded
            and ticket.policy
            is PendingWritePolicy.REBASE_TO_CURRENT_GENERATION
        ):
            generation = current
            options["authorization_model_id"] = current.authorization_model_id
            action = "send_rebased"
        elif not superseded:
            action = "send_current"

        self._record_write_decision(
            ticket,
            action,
            allowed=True,
            detail=(
                "write uses the ticket's original approved profile"
                if action == "send_pinned"
                else "write uses the current approved profile"
            ),
        )
        ticket.status = "sending"
        try:
            ticket.result = await generation.client.write(ticket.body, options or None)
        except BaseException as exc:
            ticket.status = "failed"
            ticket.error = exc
            raise
        ticket.status = "sent"
        self._record_write_decision(ticket, "sent", allowed=True)
        return ticket.result

    async def drain_writes(
        self, *, before_send: BeforeSendHook | None = None
    ) -> list[Any]:
        """Send all queued writes in FIFO order."""

        results = []
        while self._write_queue:
            results.append(await self.send_next_write(before_send=before_send))
        return results

    def _record_write_decision(
        self,
        ticket: WriteTicket,
        action: str,
        *,
        allowed: bool,
        detail: str | None = None,
    ) -> RotationDecision:
        return self._record(
            kind="write_dispatch",
            policy=ticket.policy.value,
            action=action,
            allowed=allowed,
            generation=ticket.generation.number,
            current_generation=(
                self._current.number if self._current is not None else None
            ),
            store_id=ticket.generation.store_id,
            authorization_model_id=ticket.generation.authorization_model_id,
            auth_method=ticket.generation.profile.credential_method,
            ticket_id=ticket.ticket_id,
            detail=detail,
        )

    async def aclose(self) -> None:
        """Close every SDK client created for approved generations."""

        for generation in list(self._generations.values()):
            close = getattr(generation.client, "close", None)
            if close is not None:
                result = close()
                if asyncio.iscoroutine(result):
                    await result

    async def __aenter__(self) -> StoreRotationCoordinator:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()


StoreSwitchCoordinator = StoreRotationCoordinator
StoreRotationManager = StoreRotationCoordinator
StoreSwitchManager = StoreRotationCoordinator
RotationCoordinator = StoreRotationCoordinator
StoreRotationService = StoreRotationCoordinator
StoreSwitchService = StoreRotationCoordinator
DualStoreManager = StoreRotationCoordinator
