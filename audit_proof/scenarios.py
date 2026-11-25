"""
Run the two required failure simulations plus redelivery/loss/gap handling.

Cases
-----
A. save commits, then publish fails
   The completion fact + outbox row commit; the broker publish raises. The
   subscriber initially sees nothing, but reconciliation proves the job ended
   and classifies the event as missing-with-publish-failure. A later relay
   resends the *same* event id; one redelivery is duplicated and the verifying
   consumer applies the business effect exactly once.

B. save rollback
   B1 (correct outbox ordering): staged fact/event are discarded; nothing is
       published; reconciliation reports a silent rollback.
   B2 (unsafe publish-before-commit): an event reaches the subscriber first,
       then the save rolls back; the consumer quarantines it and
       reconciliation flags a phantom/early event.

C. loss after publish + sequence gap
   Three committed events use consecutive producer sequences; the middle one
   is dropped in transport. Sequence tracking exposes seq=2 and the outbox
   identifies exactly which committed job/event is missing; replay closes it.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from .delivery import (
    ControllableBroker,
    Inbox,
    LossyForwarder,
    OutboxRelay,
    VerifyingConsumer,
)
from .model import canonical_result_digest, result_reference
from .reconcile import Reconciler, ReconciliationReport, Verdict
from .unit_of_work import (
    AuditUnitOfWork,
    CommittedState,
    SaveRolledBack,
    make_unbound_early_event,
)

JOB_A = "job-A-committed-publish-failed"
JOB_L = "job-L-published-then-lost"
JOB_R1 = "job-R1-rollback-silent"
JOB_R2 = "job-R2-rollback-with-early-event"
JOB_G1 = "job-G1-gap-seq1"
JOB_G2 = "job-G2-gap-seq2-missing"
JOB_G3 = "job-G3-gap-seq3"

RESULT_A: dict[str, Any] = {
    "report": "business-only payload",
    "decision_id": "AUTHZ-7558-result",
    "secret": "result-body-must-not-reach-the-public-bus",
}
RESULT_L = {"ledger_entry": "L-secret-body"}


@dataclasses.dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclasses.dataclass
class SimulationResult:
    state: CommittedState
    inbox: Inbox
    consumer: VerifyingConsumer
    broker: ControllableBroker
    relay: OutboxRelay
    reports: dict[str, ReconciliationReport]
    checks: list[Check]
    job_ids: dict[str, str]

    @property
    def all_passed(self) -> bool:
        return all(check.passed for check in self.checks)


def _check(checks: list[Check], name: str, condition: bool, detail: str) -> None:
    checks.append(Check(name=name, passed=bool(condition), detail=detail))


def run_simulation() -> SimulationResult:
    state = CommittedState()
    inbox = Inbox("forensic-subscriber")
    consumer = VerifyingConsumer(inbox, state)
    broker = ControllableBroker("audit-broker")
    forwarder = LossyForwarder(consumer.handle)
    broker.subscribe(forwarder)
    relay = OutboxRelay(state, broker)
    reconciler = Reconciler()
    checks: list[Check] = []
    reports: dict[str, ReconciliationReport] = {}

    # ------------------------------------------------------------------ A
    digest_a = canonical_result_digest(RESULT_A)
    with AuditUnitOfWork(
        state, producer_id="scheduler-A", label=f"completion:{JOB_A}"
    ) as uow:
        event_a = uow.stage_completion(
            job_id=JOB_A,
            task_id="business.generate_report",
            outcome="success",
            result_ref=result_reference(JOB_A),
            result_digest=digest_a,
        )

    _check(
        checks,
        "A 保存已原子提交（fact + outbox 可见）",
        JOB_A in state.facts and event_a.outbox_id in state.outbox,
        f"fact/outbox committed, event_id={event_a.event_id[:8]}",
    )
    _check(
        checks,
        "A 公开事件不含结果体/密钥",
        "secret" not in event_a.to_json()
        and RESULT_A["secret"] not in event_a.to_json()
        and digest_a in event_a.to_json(),
        "only result_ref + sha256 digest are public",
    )

    broker.fail_next_publishes = 1
    relay.publish_pending()
    message_a = state.outbox[event_a.outbox_id]
    report_a_failed = reconciler.reconcile(state, inbox, attempted_job_ids=[JOB_A])
    reports["A_after_publish_failure"] = report_a_failed
    audit_a = report_a_failed.get(JOB_A)

    _check(
        checks,
        "A 发布失败后：真实状态=已结束，订阅者=0 事件",
        state.facts[JOB_A] is not None
        and len(inbox.events_for_job(JOB_A)) == 0
        and message_a.status == "pending"
        and message_a.attempts == 1,
        f"verdict={audit_a.verdict.value}, attempts={message_a.attempts}",
    )
    _check(
        checks,
        "A 核对结论=ENDED_EVENT_MISSING_PUBLISH_FAILED（可辨别为缺失而非未结束）",
        audit_a.verdict is Verdict.ended_event_missing_publish_failed,
        audit_a.title_zh,
    )

    # Recovery: relay resends; this attempt fans out twice (at-least-once).
    broker.duplicate_next_deliveries = 1
    relay.publish_pending()
    report_a_resent = reconciler.reconcile(state, inbox, attempted_job_ids=[JOB_A])
    reports["A_after_redelivery"] = report_a_resent
    audit_a2 = report_a_resent.get(JOB_A)
    effects_a = [k for k in consumer.applied_effects if k == event_a.idempotency_key]

    _check(
        checks,
        "A 重发使用同一 event_id，订阅者收到 2 份但业务副作用仅 1 次",
        inbox.delivery_count_by_event[event_a.event_id] == 2
        and audit_a2.duplicate_copies == 1
        and len(effects_a) == 1,
        f"copies={audit_a2.received_copies}, duplicates={audit_a2.duplicate_copies}, "
        f"applied_once={len(effects_a) == 1}",
    )
    _check(
        checks,
        "A 重发后核对结论=VERIFIED_ENDED",
        audit_a2.verdict is Verdict.verified_ended and audit_a2.accepted_once,
        audit_a2.title_zh,
    )

    # ------------------------------------------------------------------ L
    digest_l = canonical_result_digest(RESULT_L)
    with AuditUnitOfWork(
        state, producer_id="scheduler-L", label=f"completion:{JOB_L}"
    ) as uow:
        event_l = uow.stage_completion(
            job_id=JOB_L,
            task_id="business.export",
            outcome="success",
            result_ref=result_reference(JOB_L),
            result_digest=digest_l,
        )

    # Broker accepts the publish, but the forwarder silently loses this one.
    forwarder.drop_event_ids.add(event_l.event_id)
    relay.publish_pending()
    report_l_lost = reconciler.reconcile(state, inbox, attempted_job_ids=[JOB_L])
    reports["L_after_loss"] = report_l_lost
    audit_l = report_l_lost.get(JOB_L)

    _check(
        checks,
        "L broker 已接受(outbox=published)，但订阅者缺失 => LOST_AFTER_PUBLISH",
        state.outbox[event_l.outbox_id].status == "published"
        and event_l.event_id in broker.accepted_event_ids
        and len(inbox.events_for_job(JOB_L)) == 0
        and audit_l.verdict is Verdict.ended_event_lost_after_publish,
        audit_l.title_zh,
    )

    decision_l = relay.replay(event_l.outbox_id, consumer)
    report_l_replayed = reconciler.reconcile(state, inbox, attempted_job_ids=[JOB_L])
    reports["L_after_replay"] = report_l_replayed
    _check(
        checks,
        "L 凭 outbox 用同一 event_id 重放 => applied，结论=VERIFIED_ENDED",
        decision_l == "applied"
        and report_l_replayed.get(JOB_L).verdict is Verdict.verified_ended,
        "manual outbox replay closes the loss",
    )

    # ----------------------------------------------------------------- B1
    try:
        with AuditUnitOfWork(
            state, producer_id="scheduler-B1", label=f"rollback:{JOB_R1}"
        ) as uow:
            uow.stage_completion(
                job_id=JOB_R1, task_id="business.rollback_case", outcome="success"
            )
            raise SaveRolledBack("injected save failure before commit")
    except SaveRolledBack:
        pass

    report_b1 = reconciler.reconcile(state, inbox, attempted_job_ids=[JOB_R1])
    reports["B1_rollback_silent"] = report_b1
    audit_b1 = report_b1.get(JOB_R1)

    _check(
        checks,
        "B1 回滚后无 fact/outbox，订阅者无事件 => ROLLED_BACK_SILENT",
        JOB_R1 not in state.facts
        and state.outbox_for_job(JOB_R1) == []
        and inbox.events_for_job(JOB_R1) == []
        and audit_b1.verdict is Verdict.rolled_back_silent,
        audit_b1.title_zh,
    )

    # ----------------------------------------------------------------- B2
    early_event = make_unbound_early_event(
        job_id=JOB_R2,
        task_id="business.unsafe_early_publish",
        outcome="success",
        producer_id="scheduler-B2",
        seq=1,
    )
    early_decision = consumer.handle(early_event)

    try:
        with AuditUnitOfWork(
            state, producer_id="scheduler-B2", label=f"rollback:{JOB_R2}"
        ) as uow:
            uow.stage_completion(
                job_id=JOB_R2,
                task_id="business.unsafe_early_publish",
                outcome="success",
            )
            raise SaveRolledBack("injected save failure after early publish")
    except SaveRolledBack:
        pass

    report_b2 = reconciler.reconcile(state, inbox, attempted_job_ids=[JOB_R2])
    reports["B2_early_phantom"] = report_b2
    audit_b2 = report_b2.get(JOB_R2)

    _check(
        checks,
        "B2 提前事件被消费者隔离(quarantined)，未产生业务副作用",
        early_decision == "quarantined_unbound"
        and early_event.event_id in consumer.quarantined
        and all(early_event.idempotency_key != k for k in consumer.applied_effects),
        "dedup is not enough; commit binding blocks the phantom effect",
    )
    _check(
        checks,
        "B2 订阅者先收到事件，但保存回滚、无提交事实 => PHANTOM_EARLY_EVENT",
        len(inbox.events_for_job(JOB_R2)) == 1
        and JOB_R2 not in state.facts
        and audit_b2.verdict is Verdict.phantom_early_event
        and any("ROLLBACK_CONFIRMED" in f for f in audit_b2.findings),
        audit_b2.title_zh,
    )

    # ------------------------------------------------------------------ C
    gap_events: dict[str, Any] = {}
    for index, job_id in enumerate((JOB_G1, JOB_G2, JOB_G3), start=1):
        with AuditUnitOfWork(
            state, producer_id="scheduler-gap", label=f"gap-commit:{job_id}"
        ) as uow:
            gap_events[job_id] = uow.stage_completion(
                job_id=job_id, task_id=f"business.gap_{index}", outcome="success"
            )

    consumer.handle(gap_events[JOB_G1])
    state.outbox[gap_events[JOB_G1].outbox_id].mark_attempt(None)
    consumer.handle(gap_events[JOB_G3])  # seq=2 never arrives
    state.outbox[gap_events[JOB_G3].outbox_id].mark_attempt(None)

    report_gap = reconciler.reconcile(
        state, inbox, attempted_job_ids=[JOB_G1, JOB_G2, JOB_G3]
    )
    reports["C_gap_open"] = report_gap
    gap_audit = next((g for g in report_gap.gaps if g.missing_seq == 2), None)

    _check(
        checks,
        "C 序列检测到缺口 seq=2，并由 outbox 定位到具体缺失作业",
        gap_audit is not None
        and gap_audit.job_id == JOB_G2
        and gap_audit.committed is True
        and gap_audit.received is False,
        gap_audit.explanation if gap_audit else "no gap detected",
    )

    consumer.handle(gap_events[JOB_G2])  # delayed redelivery / replay
    state.outbox[gap_events[JOB_G2].outbox_id].mark_attempt(None)
    report_gap_closed = reconciler.reconcile(
        state, inbox, attempted_job_ids=[JOB_G1, JOB_G2, JOB_G3]
    )
    reports["C_gap_closed"] = report_gap_closed

    _check(
        checks,
        "C 补齐 seq=2 后缺口消失，三个作业均 VERIFIED_ENDED",
        not report_gap_closed.gaps
        and all(
            report_gap_closed.get(job_id).verdict is Verdict.verified_ended
            for job_id in (JOB_G1, JOB_G2, JOB_G3)
        ),
        "gap closed by same-event-id redelivery",
    )

    all_job_ids = [JOB_A, JOB_L, JOB_R1, JOB_R2, JOB_G1, JOB_G2, JOB_G3]
    reports["final"] = reconciler.reconcile(state, inbox, attempted_job_ids=all_job_ids)

    return SimulationResult(
        state=state,
        inbox=inbox,
        consumer=consumer,
        broker=broker,
        relay=relay,
        reports=reports,
        checks=checks,
        job_ids={
            "A": JOB_A,
            "L": JOB_L,
            "R1": JOB_R1,
            "R2": JOB_R2,
            "G1": JOB_G1,
            "G2": JOB_G2,
            "G3": JOB_G3,
        },
    )
