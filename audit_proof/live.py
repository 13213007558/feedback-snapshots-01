"""
Corroborate the simulation against real APScheduler code paths.

Two real integrations are exercised:

* :class:`apscheduler.AsyncScheduler` with the memory data store runs a task
  returning a secret result body; subscribers receive the real
  :class:`apscheduler.JobReleased`, which is converted into a redacted
  :class:`apscheduler.JobCompletionProof` and round-tripped through the stock
  external-broker framing/reconstitution.
* :class:`apscheduler.datastores.sqlalchemy.SQLAlchemyDataStore.release_job`
  (the exact transaction/publish boundary cited in the audit) is driven
  against a real temporary SQLite database to reproduce:
  commit-ok/publish-fails and save-rollback.

Requires the dependencies in ``.feedback/requirements.txt``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import timedelta

from .model import (
    PublicCompletionEvent,
    canonical_result_digest,
    result_reference,
    stable_event_id,
)

LIVE_SECRET = "LIVE-RESULT-BODY-SECRET-7558"


def live_secret_task(value: int) -> dict:
    """Module level task (APScheduler references tasks by qualified name)."""
    return {"value": value, "token": LIVE_SECRET}


@dataclass
class LiveReport:
    available: bool
    lines: list[str] = field(default_factory=list)
    checks: list[tuple[str, bool, str]] = field(default_factory=list)
    unavailable_reason: str | None = None


def run_live_corroboration() -> LiveReport:
    try:
        import aiosqlite  # noqa: F401
        import sqlalchemy  # noqa: F401

        import apscheduler  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment dependent
        return LiveReport(
            available=False,
            unavailable_reason=f"{type(exc).__name__}: {exc}",
        )

    report = LiveReport(available=True)
    for section in (_scheduler_section, _sqlalchemy_section):
        try:
            asyncio.run(section(report))
        except Exception as exc:  # pragma: no cover - surfaced to caller
            report.checks.append(
                (
                    f"live 佐证段落 {section.__name__} 执行",
                    False,
                    f"{type(exc).__name__}: {exc}",
                )
            )
    return report


async def _scheduler_section(report: LiveReport) -> None:
    from apscheduler import AsyncScheduler, JobReleased

    released_events: list[JobReleased] = []
    async with AsyncScheduler() as scheduler:
        await scheduler.start_in_background()
        scheduler.subscribe(lambda event: released_events.append(event), {JobReleased})
        return_value = await asyncio.wait_for(
            scheduler.run_job(live_secret_task, args=[7]), timeout=20
        )
        await scheduler.stop()

    released = released_events[0]
    job_id = str(released.job_id)
    secret_in_released_repr = LIVE_SECRET in repr(released)

    digest = canonical_result_digest(return_value)
    envelope = PublicCompletionEvent(
        event_id=stable_event_id(f"live|{job_id}|{released.outcome}"),
        job_id=job_id,
        task_id=released.task_id,
        outcome=getattr(released.outcome, "name", str(released.outcome)),
        producer_id=released.scheduler_id,
        seq=1,
        idempotency_key=f"live|{job_id}",
        outbox_id=f"live-outbox-{job_id[:8]}",
        result_ref=result_reference(job_id),
        result_digest=digest,
        schedule_id=released.schedule_id,
        finished_at=released.timestamp.isoformat(),
        committed_at=released.timestamp.isoformat(),
    )

    from .aps_bridge import stock_broker_roundtrip, to_native

    proof = to_native(envelope)
    restored = stock_broker_roundtrip(proof)
    secret_in_proof_frame = LIVE_SECRET.encode("utf-8") in _frame(proof)

    report.lines.append(
        f"real AsyncScheduler: job={job_id[:8]} outcome={envelope.outcome} "
        f"subscriber_events={len(released_events)}"
    )
    report.lines.append(
        f"authorized caller retrieved result body with token={return_value['token'][:12]}..."
    )
    report.lines.append(
        f"JobReleased leaks result body in repr? {secret_in_released_repr}; "
        f"proof frame leaks secret? {secret_in_proof_frame}; "
        f"reconstituted={type(restored).__name__} event_id_match="
        f"{str(restored.event_id) == envelope.event_id}"
    )
    report.checks.append(
        (
            "真实调度器：订阅者收到 JobReleased，且结果体不出现在事件/证明帧中",
            len(released_events) == 1
            and not secret_in_released_repr
            and not secret_in_proof_frame
            and str(restored.event_id) == envelope.event_id,
            "JobReleased + native JobCompletionProof reconstituted via stock broker",
        )
    )


def _frame(proof) -> bytes:
    from apscheduler.serializers.json import JSONSerializer

    from .aps_bridge import _ReconstitutionProbe

    broker = _ReconstitutionProbe(serializer=JSONSerializer())
    return broker.generate_notification(proof)


async def _sqlalchemy_section(report: LiveReport) -> None:
    import sqlalchemy as sa

    from apscheduler._enums import JobOutcome
    from apscheduler._structures import Job, JobResult
    from apscheduler.datastores.sqlalchemy import SQLAlchemyDataStore
    from apscheduler.eventbrokers.local import LocalEventBroker

    class RecordingBroker(LocalEventBroker):
        def __init__(self) -> None:
            super().__init__()
            self.publish_calls: list[str] = []
            self.delivered_types: list[str] = []
            self.fail_next = False

        async def publish(self, event) -> None:
            event_type = type(event).__name__
            self.publish_calls.append(event_type)
            if self.fail_next:
                self.fail_next = False
                raise RuntimeError("live: simulated broker publish outage")
            await self.publish_local(event)
            self.delivered_types.append(event_type)

    db_dir = tempfile.mkdtemp(prefix="audit-proof-", dir=os.environ.get("TMPDIR"))
    db_path = os.path.join(db_dir, "live.db")
    datastore = SQLAlchemyDataStore(engine_or_url=f"sqlite+aiosqlite:///{db_path}")
    broker = RecordingBroker()
    logger = logging.getLogger("audit-proof-live")

    async with AsyncExitStack() as exit_stack:
        await broker.start(exit_stack, logger)
        await datastore.start(exit_stack, broker, logger)

        # ---- Case A against the real release_job code path
        job_a = Job(
            task_id="live.audit_task_a",
            executor="async",
            result_expiration_time=timedelta(minutes=5),
        )
        await datastore.add_job(job_a)
        result_a = JobResult.from_job(
            job_a, JobOutcome.success, return_value={"token": LIVE_SECRET}
        )
        broker.fail_next = True
        publish_raised = False
        try:
            await datastore.release_job("live-scheduler", job_a, result_a)
        except RuntimeError:
            publish_raised = True

        async with datastore._engine.connect() as conn:
            result_rows_a = (
                await conn.execute(
                    sa.select(sa.func.count())
                    .select_from(datastore._t_job_results)
                    .where(datastore._t_job_results.c.job_id == job_a.id)
                )
            ).scalar_one()
            job_rows_a = (
                await conn.execute(
                    sa.select(sa.func.count())
                    .select_from(datastore._t_jobs)
                    .where(datastore._t_jobs.c.id == job_a.id)
                )
            ).scalar_one()

        report.lines.append(
            f"real release_job A: publish_raised={publish_raised} "
            f"committed result rows for job A={result_rows_a} "
            f"remaining job A rows={job_rows_a} "
            f"broker_calls={broker.publish_calls} delivered={broker.delivered_types}"
        )
        report.checks.append(
            (
                "真实 SQLAlchemyDataStore：保存已提交后发布失败 => 结果行仍在、订阅者无 JobReleased",
                publish_raised
                and result_rows_a == 1
                and job_rows_a == 0
                and "JobReleased" not in broker.delivered_types,
                "release_job commits before event_broker.publish()",
            )
        )

        # ---- Case B: failure inside the transaction => rollback
        job_b = Job(
            task_id="live.audit_task_b",
            executor="async",
            result_expiration_time=timedelta(minutes=5),
        )
        await datastore.add_job(job_b)
        delivered_before_b = list(broker.delivered_types)

        original_execute = datastore._execute

        async def failing_execute(conn, statement, *args, **kwargs):
            table_name = getattr(getattr(statement, "table", None), "name", "")
            if isinstance(statement, sa.sql.dml.Insert) and table_name == "job_results":
                raise RuntimeError("live: simulated result save failure")
            return await original_execute(conn, statement, *args, **kwargs)

        datastore._execute = failing_execute
        save_raised = False
        result_b = JobResult.from_job(job_b, JobOutcome.success, return_value={"x": 1})
        try:
            await datastore.release_job("live-scheduler", job_b, result_b)
        except RuntimeError:
            save_raised = True
        finally:
            datastore._execute = original_execute

        async with datastore._engine.connect() as conn:
            result_rows_b = (
                await conn.execute(
                    sa.select(sa.func.count())
                    .select_from(datastore._t_job_results)
                    .where(datastore._t_job_results.c.job_id == job_b.id)
                )
            ).scalar_one()
            job_rows_b = (
                await conn.execute(
                    sa.select(sa.func.count())
                    .select_from(datastore._t_jobs)
                    .where(datastore._t_jobs.c.id == job_b.id)
                )
            ).scalar_one()

        released_after_b = broker.delivered_types[len(delivered_before_b) :]
        report.lines.append(
            f"real release_job B: save_raised={save_raised} "
            f"result rows for job B={result_rows_b} remaining job B rows={job_rows_b} "
            f"new_delivered_events={released_after_b}"
        )
        report.checks.append(
            (
                "真实 SQLAlchemyDataStore：保存失败回滚 => 无结果行、job 仍在、无 JobReleased",
                save_raised
                and result_rows_b == 0
                and job_rows_b == 1
                and "JobReleased" not in released_after_b,
                "transaction rolls back; stock code publishes only after commit",
            )
        )

    await datastore._engine.dispose()
