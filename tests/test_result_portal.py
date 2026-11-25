from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack
from datetime import timedelta
from logging import Logger

import anyio
import pytest
from anyio import create_task_group

from apscheduler import (
    Job,
    JobOutcome,
    JobResult,
    JobResultClaim,
    JobResultPortal,
    JobResultState,
    JobResultStatus,
    Task,
)
from apscheduler.abc import DataStore, EventBroker
from apscheduler.datastores.memory import MemoryDataStore

pytestmark = pytest.mark.anyio


@pytest.fixture(
    params=[
        pytest.param("memory", id="memory"),
        pytest.param("sqlite", id="sqlite"),
    ]
)
def store_kind(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
async def datastore(
    store_kind: str,
    tmp_path,
    local_broker: EventBroker,
    logger: Logger,
) -> AsyncGenerator[DataStore, None]:
    async with AsyncExitStack() as exit_stack:
        await local_broker.start(exit_stack, logger)
        if store_kind == "memory":
            data_store: DataStore = MemoryDataStore()
        else:
            pytest.importorskip("sqlalchemy", reason="sqlalchemy is not installed")
            from apscheduler.datastores.sqlalchemy import SQLAlchemyDataStore
            from sqlalchemy.ext.asyncio import create_async_engine

            engine = create_async_engine(
                f"sqlite+aiosqlite:///{tmp_path}/result-portal.db"
            )
            exit_stack.push_async_callback(engine.dispose)
            data_store = SQLAlchemyDataStore(engine)

        await data_store.start(exit_stack, local_broker, logger)
        yield data_store


async def run_job(
    data_store: DataStore,
    *,
    result_expiration_time: timedelta,
    return_value: str = "payload",
) -> tuple[Job, JobResult]:
    await data_store.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            owner="business",
        )
    )
    job = Job(
        task_id="task1",
        executor="async",
        owner="business",
        result_expiration_time=result_expiration_time,
    )
    await data_store.add_job(job)
    acquired = await data_store.acquire_jobs("worker", timedelta(seconds=30), 1)
    assert len(acquired) == 1
    result = JobResult.from_job(
        acquired[0], JobOutcome.success, return_value=return_value
    )
    await data_store.release_job("worker", acquired[0], result)
    return job, result


async def test_auditor_observation_does_not_consume_result(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.05)
    job, _ = await run_job(datastore, result_expiration_time=timedelta(minutes=1))

    # Repeated auditor observations must not consume the result
    for _ in range(3):
        status = await portal.observe(job.id)
        assert status.state is JobResultState.ready
        assert status.finished_at is not None
        assert status.expires_at is not None

    # A party that does not own the job gets no payload, and does not consume it
    foreign_claim = await portal.claim(job.id, owner="auditor")
    assert foreign_claim.status.state is JobResultState.ready
    assert not foreign_claim.claimed

    # The owning business party can now claim the result exactly once
    claim = await portal.claim(job.id, owner="business")
    assert claim.claimed
    assert claim.status.state is JobResultState.claimed
    assert claim.result is not None
    assert claim.result.return_value == "payload"

    # Subsequent claims see an explicit "already claimed" state
    second_claim = await portal.claim(job.id, owner="business")
    assert not second_claim.claimed
    assert second_claim.status.state is JobResultState.claimed
    assert (await portal.observe(job.id)).state is JobResultState.claimed


async def test_unclaimed_result_expires(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.05)
    job, _ = await run_job(datastore, result_expiration_time=timedelta(seconds=0.2))
    assert (await portal.observe(job.id)).state is JobResultState.ready

    await anyio.sleep(0.3)

    # Both the auditor and the business party see an explicit expired state
    audit_status = await portal.observe(job.id)
    assert audit_status.state is JobResultState.expired
    assert audit_status.expires_at is not None

    audit_claim = await portal.claim(job.id, owner="auditor")
    assert audit_claim.status.state is JobResultState.expired
    assert not audit_claim.claimed

    business_claim = await portal.claim(job.id, owner="business")
    assert business_claim.status.state is JobResultState.expired
    assert not business_claim.claimed

    # Expiry tombstones survive a cleanup pass
    await datastore.cleanup()
    assert (await portal.observe(job.id)).state is JobResultState.expired


async def test_claimed_result_stays_claimed_after_expiry(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.05)
    job, _ = await run_job(datastore, result_expiration_time=timedelta(seconds=0.2))
    claim = await portal.claim(job.id, owner="business")
    assert claim.claimed

    await anyio.sleep(0.3)
    await datastore.cleanup()
    assert (await portal.observe(job.id)).state is JobResultState.claimed


async def test_two_waiters_interleaved_wakeups(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    """
    Interleave an auditor waiter (observation only) with a business watcher that waits
    until shortly before the result expires, then claims it.
    """
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.02)

    await datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            owner="business",
        )
    )
    job = Job(
        task_id="task1",
        executor="async",
        owner="business",
        result_expiration_time=timedelta(seconds=1),
    )
    await datastore.add_job(job)

    publish = anyio.Event()
    observed_states: list[JobResultState] = []

    async def auditor() -> None:
        assert (await portal.observe(job.id)).state is JobResultState.pending

        async def observe_when_published() -> None:
            await publish.wait()
            observed_states.append((await portal.observe(job.id)).state)

        async with create_task_group() as tg:
            tg.start_soon(observe_when_published)
            status = await portal.wait_for_terminal_state(job.id, timeout=5)
            observed_states.append(status.state)

    async def business() -> None:
        claim = await portal.wait_and_claim(job.id, owner="business", timeout=5)
        assert claim.claimed
        assert claim.result is not None
        assert claim.result.return_value == "payload"

        # A second claim by the same party cannot get the payload again
        second = await portal.claim(job.id, owner="business")
        assert not second.claimed
        assert second.status.state is JobResultState.claimed

    async with create_task_group() as tg:
        tg.start_soon(auditor)
        tg.start_soon(business)
        await anyio.sleep(0.05)

        # Wake both waiters by publishing the result
        acquired = await datastore.acquire_jobs("worker", timedelta(seconds=30), 1)
        assert len(acquired) == 1
        await datastore.release_job(
            "worker",
            acquired[0],
            JobResult.from_job(
                acquired[0], JobOutcome.success, return_value="payload"
            ),
        )
        publish.set()

    # The auditor's observation got the "ready" state without consuming the result,
    # and the business party was still able to claim it afterwards
    assert JobResultState.ready in observed_states
    assert (await portal.observe(job.id)).state is JobResultState.claimed


async def test_business_waiter_claims_before_expiry(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    """
    Two waiters wake on the same short-lived result: the auditor observes it as ready
    without consuming it, and the business waiter claims it before it expires.
    """
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.02)
    job, _ = await run_job(datastore, result_expiration_time=timedelta(seconds=30))

    async with anyio.create_task_group() as tg:
        results: dict[str, object] = {}

        async def audit() -> None:
            results["audit"] = await portal.wait_for_terminal_state(
                job.id, timeout=3
            )

        async def business() -> None:
            results["claim"] = await portal.wait_and_claim(
                job.id, owner="business", timeout=3
            )

        tg.start_soon(audit)
        tg.start_soon(business)

    audit_status = results["audit"]
    assert isinstance(audit_status, JobResultStatus)
    assert audit_status.state is JobResultState.ready

    claim = results["claim"]
    assert isinstance(claim, JobResultClaim)
    assert claim.claimed
    assert claim.result is not None
    assert claim.result.return_value == "payload"

    # The second claim cannot get the payload again
    second_claim = await portal.claim(job.id, owner="business")
    assert not second_claim.claimed
    assert second_claim.status.state is JobResultState.claimed


async def test_waiter_observes_expiry_before_claim(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    """
    A short-lived result expires while both parties wait: the auditor's wait ends in
    the "expired" state without consuming anything, and a business party that arrives
    after the deadline also gets "expired" rather than a payload.
    """
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.02)
    await datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            owner="business",
        )
    )
    job = Job(
        task_id="task1",
        executor="async",
        owner="business",
        result_expiration_time=timedelta(seconds=0.1),
    )
    await datastore.add_job(job)
    acquired = await datastore.acquire_jobs("worker", timedelta(seconds=30), 1)
    await datastore.release_job(
        "worker",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success, return_value="payload"),
    )

    # Let the result pass its expiration time before either party proceeds. The
    # store is deliberately not cleaned up: the portal must derive "expired" on its
    # own, not rely on a tombstone being written by a cleanup pass.
    await anyio.sleep(0.2)

    async with anyio.create_task_group() as tg:
        results: dict[str, JobResultStatus | JobResultClaim] = {}

        async def audit() -> None:
            results["audit"] = await portal.wait_for_terminal_state(
                job.id, timeout=3
            )

        async def business() -> None:
            results["claim"] = await portal.claim(job.id, owner="business")

        tg.start_soon(audit)
        tg.start_soon(business)

    audit_status = results["audit"]
    assert isinstance(audit_status, JobResultStatus)
    assert audit_status.state is JobResultState.expired

    business_claim = results["claim"]
    assert isinstance(business_claim, JobResultClaim)
    assert business_claim.status.state is JobResultState.expired
    assert not business_claim.claimed
    assert (await portal.observe(job.id)).state is JobResultState.expired


async def test_interleaved_wakeup_auditor_then_business(
    datastore: DataStore, local_broker: EventBroker
) -> None:
    """
    Both waiters are woken by the same release event, but the auditor is allowed to
    observe first. Its observation must not consume the result, so the business party
    still gets the payload exactly once.
    """
    portal = JobResultPortal(datastore, local_broker, poll_interval=0.02)
    await datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            owner="business",
        )
    )
    job = Job(
        task_id="task1",
        executor="async",
        owner="business",
        result_expiration_time=timedelta(seconds=30),
    )
    await datastore.add_job(job)
    acquired = await datastore.acquire_jobs("worker", timedelta(seconds=30), 1)

    audit_observed = anyio.Event()
    audit_status: JobResultStatus | None = None
    business_claim: JobResultClaim | None = None

    async def audit() -> None:
        nonlocal audit_status
        audit_status = await portal.wait_for_terminal_state(job.id, timeout=3)
        audit_observed.set()

    async def business() -> None:
        nonlocal business_claim
        # Give the auditor a head start so its observation definitely happens first
        await audit_observed.wait()
        business_claim = await portal.claim(job.id, owner="business")

    async with anyio.create_task_group() as tg:
        tg.start_soon(audit)
        tg.start_soon(business)
        await anyio.sleep(0.05)
        await datastore.release_job(
            "worker",
            acquired[0],
            JobResult.from_job(acquired[0], JobOutcome.success, return_value="payload"),
        )

    assert audit_status is not None
    assert audit_status.state is JobResultState.ready
    assert business_claim is not None
    assert business_claim.claimed
    assert business_claim.result is not None
    assert business_claim.result.return_value == "payload"
    assert (await portal.observe(job.id)).state is JobResultState.claimed
