"""
Reconcile subscriber events against the truly committed state.

The reconciler joins three evidence sources:

1. ``CommittedState.facts``  - the single source of truth (committed saves);
2. ``CommittedState.outbox`` - provenance and publish state of public events;
3. ``Inbox``                - what the subscriber actually received.

It answers the investigator's question per job: did it really end, did the
notification arrive early/without a commit, was it lost, or was it repeated?
"""

from __future__ import annotations

import dataclasses
from enum import Enum

from .delivery import Inbox
from .unit_of_work import CommittedState


class Verdict(str, Enum):
    verified_ended = "verified_ended"
    ended_event_missing_publish_failed = "ended_event_missing_publish_failed"
    ended_event_lost_after_publish = "ended_event_lost_after_publish"
    ended_event_missing = "ended_event_missing"
    phantom_early_event = "phantom_early_event"
    rolled_back_silent = "rolled_back_silent"
    unresolved_gap = "unresolved_gap"


VERDICT_TITLE_ZH = {
    Verdict.verified_ended: "已证实结束，公开事件与已提交事实一致",
    Verdict.ended_event_missing_publish_failed: "作业确已结束，但事件缺失：保存已提交、发布失败（可重发）",
    Verdict.ended_event_lost_after_publish: "作业确已结束，但事件在发布后/投递途中丢失（可凭 outbox 重放）",
    Verdict.ended_event_missing: "作业确已结束，但订阅者未收到任何事件（缺失）",
    Verdict.phantom_early_event: "收到完成事件，但没有任何已提交事实与之绑定（提前到达或回滚后的空头事件）",
    Verdict.rolled_back_silent: "保存已回滚、无提交事实，也没有公开完成事件（正确表现）",
    Verdict.unresolved_gap: "事件序列存在尚未补齐的缺口",
}


@dataclasses.dataclass
class JobAudit:
    job_id: str
    verdict: Verdict
    committed: bool
    received_copies: int
    unique_event_ids: int
    duplicate_copies: int
    accepted_once: bool
    outbox_status: str | None
    producer_id: str | None
    seq: int | None
    findings: list[str] = dataclasses.field(default_factory=list)
    received_kinds: list[str] = dataclasses.field(default_factory=list)
    digest_ok: bool | None = None

    @property
    def title_zh(self) -> str:
        return VERDICT_TITLE_ZH[self.verdict]


@dataclasses.dataclass
class GapAudit:
    producer_id: str
    missing_seq: int
    job_id: str | None
    outbox_id: str | None
    committed: bool
    received: bool
    explanation: str


@dataclasses.dataclass
class ReconciliationReport:
    jobs: dict[str, JobAudit]
    gaps: list[GapAudit]
    known_attempts: list[str]

    def get(self, job_id: str) -> JobAudit:
        return self.jobs[job_id]

    @property
    def committed_jobs_verified(self) -> bool:
        """Every job with a committed fact was delivered and accepted once."""
        return all(
            job.verdict is Verdict.verified_ended
            for job in self.jobs.values()
            if job.committed
        )

    @property
    def has_unresolved_gap(self) -> bool:
        return bool(self.gaps)


class Reconciler:
    """Bind public events to committed facts and expose dup/gap/phantom."""

    def reconcile(
        self,
        state: CommittedState,
        inbox: Inbox,
        *,
        attempted_job_ids: list[str] | None = None,
    ) -> ReconciliationReport:
        job_ids: list[str] = []
        for collection in (
            state.facts.keys(),
            [m.job_id for m in state.outbox.values()],
            [e.job_id for e in inbox.raw_deliveries],
            attempted_job_ids or [],
        ):
            for job_id in collection:
                if job_id not in job_ids:
                    job_ids.append(job_id)

        jobs: dict[str, JobAudit] = {}
        for job_id in job_ids:
            jobs[job_id] = self._reconcile_job(job_id, state, inbox)

        gaps = self._reconcile_gaps(state, inbox)
        return ReconciliationReport(
            jobs=jobs,
            gaps=gaps,
            known_attempts=list(attempted_job_ids or []),
        )

    def _reconcile_job(
        self, job_id: str, state: CommittedState, inbox: Inbox
    ) -> JobAudit:
        fact = state.facts.get(job_id)
        messages = state.outbox_for_job(job_id)
        events = inbox.events_for_job(job_id)

        copies = len(events)
        unique_ids = {e.event_id for e in events}
        duplicate_copies = max(0, copies - len(unique_ids))
        matching = [
            e for e in events if fact is not None and e.event_id == fact.event_id
        ]
        accepted_once = any(e.event_id in inbox.accepted_event_ids for e in matching)

        outbox_status = None
        producer_id = None
        seq = None
        if messages:
            message = messages[0]
            outbox_status = message.status
            producer_id = message.producer_id
            seq = message.seq
        elif events:
            producer_id = events[0].producer_id
            seq = events[0].seq
        elif fact is not None:
            producer_id = fact.producer_id
            seq = fact.seq

        findings: list[str] = []
        digest_ok: bool | None = None

        if duplicate_copies:
            dup_ids = inbox.duplicate_event_ids()
            detail = ", ".join(
                f"{event_id[:8]}×{count}" for event_id, count in dup_ids.items()
            )
            findings.append(
                f"DUPLICATE_EVENT: 重复投递 {duplicate_copies} 份 ({detail})"
            )

        if fact is not None:
            for event in events:
                if event.result_digest and fact.result_digest:
                    digest_ok = event.result_digest == fact.result_digest
                    if not digest_ok:
                        findings.append(
                            "DIGEST_MISMATCH: 事件结果摘要与已提交事实不一致（篡改或错绑）"
                        )

            if accepted_once:
                verdict = Verdict.verified_ended
                findings.append(
                    "BOUND_TO_COMMIT: event_id/outbox_id 与已提交事实匹配，业务副作用仅一次"
                )
            elif events:
                verdict = Verdict.ended_event_missing
                findings.append(
                    "EVENT_PRESENT_BUT_NOT_ACCEPTED: 有原始投递但未形成受理记录"
                )
            elif outbox_status == "published":
                verdict = Verdict.ended_event_lost_after_publish
                findings.append(
                    "OUTBOX_PUBLISHED_BUT_INBOX_EMPTY: broker 已接受，订阅者未收到"
                )
            elif messages and messages[0].attempts:
                verdict = Verdict.ended_event_missing_publish_failed
                findings.append(
                    "OUTBOX_PENDING_AFTER_PUBLISH_ERROR: "
                    f"attempts={messages[0].attempts}, last_error={messages[0].last_error}"
                )
            else:
                verdict = Verdict.ended_event_missing
                findings.append("NO_PUBLIC_EVENT: 已提交但无任何公开事件")
        else:
            if events:
                verdict = Verdict.phantom_early_event
                rollback_confirmed = any(job_id in entry for entry in state.rollbacks)
                if rollback_confirmed:
                    findings.append(
                        "ROLLBACK_CONFIRMED: 状态库存在该作业的回滚记录，"
                        "此事件为提交前提前发出的无效完成通知"
                    )
                for event in events:
                    if event.outbox_id:
                        findings.append(
                            "DANGLING_REFERENCE: 事件携带 outbox_id="
                            f"{event.outbox_id}，但已提交 outbox/账本中不存在（回滚或伪造）"
                        )
                    else:
                        findings.append(
                            "UNBOUND_EARLY_EVENT: 事件缺少 outbox_id/committed_at，"
                            "且无已提交事实（典型的提交前通知）"
                        )
            else:
                verdict = Verdict.rolled_back_silent
                findings.append(
                    "NO_COMMITTED_FACT: 账本无记录；保存已回滚，且未产生公开完成事件"
                )

        return JobAudit(
            job_id=job_id,
            verdict=verdict,
            committed=fact is not None,
            received_copies=copies,
            unique_event_ids=len(unique_ids),
            duplicate_copies=duplicate_copies,
            accepted_once=accepted_once,
            outbox_status=outbox_status,
            producer_id=producer_id,
            seq=seq,
            findings=findings,
            received_kinds=[e.kind for e in events],
            digest_ok=digest_ok,
        )

    def _reconcile_gaps(self, state: CommittedState, inbox: Inbox) -> list[GapAudit]:
        audits: list[GapAudit] = []
        for gap in inbox.gaps:
            message = state.outbox_by_seq(gap.producer_id, gap.missing_seq)
            job_id = message.job_id if message else None
            committed = bool(job_id and job_id in state.facts)
            received = False
            if message is not None:
                received = message.event_id in inbox.delivery_count_by_event
            explanation = f"{gap.producer_id} 序列缺口 seq={gap.missing_seq}；" + (
                f"outbox 可定位到 job={job_id}，committed={committed}，"
                f"subscriber_received={received}"
                if message
                else "outbox 中也无该序号（可能是回滚消耗或来源不明事件）"
            )
            audits.append(
                GapAudit(
                    producer_id=gap.producer_id,
                    missing_seq=gap.missing_seq,
                    job_id=job_id,
                    outbox_id=message.outbox_id if message else None,
                    committed=committed,
                    received=received,
                    explanation=explanation,
                )
            )
        return audits
