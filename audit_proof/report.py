"""Plain text rendering of events, committed state and reconciliation."""

from __future__ import annotations

from .reconcile import ReconciliationReport
from .scenarios import SimulationResult


def _line(char: str = "-", width: int = 104) -> str:
    return char * width


def render_job_table(
    report: ReconciliationReport, job_ids: list[str] | None = None
) -> str:
    ids = job_ids or list(report.jobs.keys())
    rows = [
        f"{'job_id':<34} {'committed':<9} {'recv':<4} {'dup':<3} {'outbox':<10} verdict"
    ]
    rows.append(_line())
    for job_id in ids:
        audit = report.jobs[job_id]
        short_id = job_id if len(job_id) <= 34 else job_id[:31] + "..."
        rows.append(
            f"{short_id:<34} {str(audit.committed):<9} {audit.received_copies:<4} "
            f"{audit.duplicate_copies:<3} {str(audit.outbox_status):<10} "
            f"{audit.verdict.value}"
        )
    return "\n".join(rows)


def render_findings(report: ReconciliationReport) -> str:
    lines: list[str] = []
    for job_id, audit in report.jobs.items():
        if not audit.findings:
            continue
        lines.append(f"* {job_id} -> {audit.verdict.value}")
        lines.append(f"    {audit.title_zh}")
        lines.extend(f"    - {finding}" for finding in audit.findings)
    lines.extend(
        f"* GAP {gap.producer_id}#{gap.missing_seq}: {gap.explanation}"
        for gap in report.gaps
    )
    return "\n".join(lines) if lines else "(no findings)"


def render_inbox(result: SimulationResult) -> str:
    lines = [
        f"subscriber={result.inbox.name!r} raw_deliveries={len(result.inbox.raw_deliveries)} "
        f"accepted_unique={len(result.inbox.accepted_event_ids)} "
        f"duplicate_copies={result.inbox.duplicate_copy_count}",
        f"verifying_consumer: applied_effects={len(result.consumer.applied_effects)} "
        f"quarantined_unbound={len(result.consumer.quarantined)}",
        _line(),
    ]
    for index, event in enumerate(result.inbox.raw_deliveries, start=1):
        lines.append(
            f"{index:>2}. {event.kind:<22} job={event.job_id:<26} "
            f"producer={event.producer_id:<15} seq={event.seq} "
            f"event_id={event.event_id[:8]} outbox={event.outbox_id or '-'}"
        )
    return "\n".join(lines)


def render_committed_state(result: SimulationResult) -> str:
    lines = [
        f"commits={len(result.state.commits)} rollbacks={len(result.state.rollbacks)} "
        f"facts={len(result.state.facts)} outbox_rows={len(result.state.outbox)}",
        _line(),
    ]
    for job_id, fact in result.state.facts.items():
        lines.append(
            f"FACT  job={job_id:<26} outcome={fact.outcome:<7} "
            f"outbox={fact.outbox_id:<22} event_id={fact.event_id[:8]} "
            f"digest={(fact.result_digest or '-')[:24]}"
        )
    lines.extend(f"ROLLBACK {label}" for label in result.state.rollbacks)
    return "\n".join(lines)


def render_checks(result: SimulationResult) -> str:
    lines = []
    for check in result.checks:
        mark = "PASS" if check.passed else "FAIL"
        lines.append(f"[{mark}] {check.name}\n         {check.detail}")
    passed = sum(check.passed for check in result.checks)
    lines.append(_line("="))
    lines.append(f"simulation assertions: {passed}/{len(result.checks)} passed")
    return "\n".join(lines)


def render_full_report(result: SimulationResult) -> str:
    final = result.reports["final"]
    sections = [
        "=" * 104,
        "APScheduler 作业生命周期事件 · 证明边界模拟（保存成功/发布失败 · 保存回滚 · 重发 · 缺失/重复）",
        "=" * 104,
        "",
        "[1] 订阅者实际收到的公开事件（含重复投递；事件体不含业务结果）",
        _line("="),
        render_inbox(result),
        "",
        "[2] 真实已提交状态（账本 fact + 事务发件箱 outbox；回滚不留痕）",
        _line("="),
        render_committed_state(result),
        "",
        "[3] 关键检查点：A 发布失败后的核对（缺失）",
        _line("="),
        render_job_table(
            result.reports["A_after_publish_failure"], [result.job_ids["A"]]
        ),
        "",
        "[4] 关键检查点：B2 提前发布后回滚（空头/提前事件）",
        _line("="),
        render_job_table(result.reports["B2_early_phantom"], [result.job_ids["R2"]]),
        "",
        "[5] 关键检查点：C 序列缺口（缺失可定位）",
        _line("="),
        render_job_table(
            result.reports["C_gap_open"],
            [result.job_ids["G1"], result.job_ids["G2"], result.job_ids["G3"]],
        ),
        render_findings(result.reports["C_gap_open"]),
        "",
        "[6] 最终全量核对表（重发/补齐之后）",
        _line("="),
        render_job_table(final),
        "",
        "[7] 核对发现与判定依据",
        _line("="),
        render_findings(final),
        "",
        "[8] 验收断言",
        _line("="),
        render_checks(result),
        "",
    ]
    return "\n".join(sections)
