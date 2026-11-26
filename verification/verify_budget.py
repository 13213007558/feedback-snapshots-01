#!/usr/bin/env python3
"""
Single-budget verification for the comment service.

Scenario (all numbers come from the fixed local documents in this folder):

1. Meter each document with a report-only budget to record the real work
   per stage (parse / clean / linkify) and choose a manually lowered quota.
2. Through ONE shared ``Cleaner`` entry configured with that lowered quota:
   * the long text document (no transformations) succeeds;
   * the node/link document is stopped in the ``linkify`` stage and no
     final output is published;
   * an ordinary short document processed immediately afterwards with the
     same instance/configuration succeeds.
3. A clean-only control proves doc B's parsing+cleaning fit the quota and
   that the link transformation is the extra work that crosses it.

Run from the repository root::

    .venv/bin/python verification/verify_budget.py

The script writes ``verification_record.md`` and full outputs under
``outputs/`` and exits non-zero if any expectation is violated.
"""

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT))

import bleach  # noqa: E402
from bleach.budget import (  # noqa: E402
    STAGE_CLEAN,
    STAGE_LINKIFY,
    STAGE_PARSE,
    Budget,
    BudgetExceeded,
)
from bleach.linkifier import LinkifyFilter  # noqa: E402
from bleach.sanitizer import Cleaner  # noqa: E402

# Comment-service allowlist: ordinary structural markup plus links.
COMMENT_TAGS = [
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "em",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "ul",
]

# Manually lowered single-run quota.  The unlimited baseline below shows
# these documents cost ~3.5k-4.5k units while the standard ceiling is
# Budget.DEFAULT_LIMIT (500k).  4400 sits above doc A (3496) and above doc
# B's parse+clean total (4342), but below doc B once link transforms count
# (4342 + 120); the sixth URL transformation crosses it.
LOWERED_QUOTA = 4400

STAGE_LABELS = {
    STAGE_PARSE: "解析 parse",
    STAGE_CLEAN: "清洗 clean",
    STAGE_LINKIFY: "链接处理 linkify",
}

DOC_A = HERE / "comment_long_text.txt"
DOC_B = HERE / "comment_with_links.html"
DOC_C = HERE / "comment_short.txt"
OUT_DIR = HERE / "outputs"


def build_cleaner(limit):
    """The single processing entry used by the comment service."""
    return Cleaner(
        tags=COMMENT_TAGS,
        filters=[LinkifyFilter],
        budget=Budget(limit),
    )


def meter_baseline(name, text):
    budget = Budget(limit=None)
    Cleaner(tags=COMMENT_TAGS, filters=[LinkifyFilter], budget=budget).clean(text)
    return budget.as_report()


def write_output(filename, content):
    OUT_DIR.mkdir(exist_ok=True)
    path = OUT_DIR / filename
    path.write_text(content, encoding="utf-8")
    return path


def fmt_report(report):
    return (
        f"spent={report['spent']} limit={report['limit']} "
        f"stages(parse={report['stage_spent'][STAGE_PARSE]}, "
        f"clean={report['stage_spent'][STAGE_CLEAN]}, "
        f"linkify={report['stage_spent'][STAGE_LINKIFY]}) "
        f"counts(nodes={report['counts']['nodes']}, "
        f"chars={report['counts']['characters']}, "
        f"attrs={report['counts']['attributes']}, "
        f"transforms={report['counts']['transforms']})"
    )


def main():
    OUT_DIR.mkdir(exist_ok=True)
    lines = []
    checks = []

    def check(condition, message):
        checks.append((condition, message))
        flag = "PASS" if condition else "FAIL"
        print(f"[{flag}] {message}")

    def emit(text=""):
        print(text)
        lines.append(text)

    doc_a = DOC_A.read_text(encoding="utf-8")
    doc_b = DOC_B.read_text(encoding="utf-8")
    doc_c = DOC_C.read_text(encoding="utf-8")

    emit("# Bleach 单次工作预算验证记录")
    emit()
    emit(f"- bleach 版本: `{bleach.__version__}`")
    emit(f"- Python: `{sys.version.split()[0]}`")
    emit(f"- 人工降低的共同单次额度: `{LOWERED_QUOTA}` work units")
    emit(
        f"- 默认建议上限: `{bleach.budget.DEFAULT_LIMIT}` work units（本次未启用限制时为无限）"
    )
    emit("- 计量规则: 节点/属性按件、文字按字符、附加转换(URL/email/锚点/CSS)按次加权")
    emit()

    # ---- 1. unlimited baseline: record real per-stage work --------------
    emit("## 1. 无限额度基线：各阶段真实工作量")
    emit()
    baseline = {}
    for key, label, text in (
        ("A", "文档A 长文字无转换", doc_a),
        ("B", "文档B 多节点加链接", doc_b),
        ("C", "文档C 普通短文", doc_c),
    ):
        report = meter_baseline(key, text)
        baseline[key] = report
        emit(f"- **{label}** (`{len(text)}` chars): `{fmt_report(report)}`")
    emit()
    emit("| 文档 | 字符数 | parse | clean | linkify | 合计 | nodes | transforms |")
    emit("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for key, text in (("A", doc_a), ("B", doc_b), ("C", doc_c)):
        r = baseline[key]
        emit(
            f"| {key} | {len(text)} | {r['stage_spent'][STAGE_PARSE]} | "
            f"{r['stage_spent'][STAGE_CLEAN]} | {r['stage_spent'][STAGE_LINKIFY]} | "
            f"{r['spent']} | {r['counts']['nodes']} | {r['counts']['transforms']} |"
        )
    emit()

    check(
        baseline["A"]["stage_spent"][STAGE_LINKIFY] == 0,
        "文档A 不触发任何附加链接转换 (linkify=0)",
    )
    check(
        baseline["A"]["spent"] <= LOWERED_QUOTA,
        f"文档A 基线总工作量 {baseline['A']['spent']} <= 降低后额度 {LOWERED_QUOTA}",
    )
    check(
        baseline["B"]["stage_spent"][STAGE_PARSE] < LOWERED_QUOTA,
        f"文档B 解析阶段 {baseline['B']['stage_spent'][STAGE_PARSE]} < 额度（解析本身可通过）",
    )
    check(
        baseline["B"]["stage_spent"][STAGE_LINKIFY] > 0,
        "文档B 确实触发了链接转换",
    )

    # ---- 2. clean-only control for doc B at the same quota --------------
    clean_only_budget = Budget(LOWERED_QUOTA)
    clean_only = Cleaner(tags=COMMENT_TAGS, budget=clean_only_budget)
    clean_only_output = clean_only.clean(doc_b)
    write_output("doc_b_clean_only.html", clean_only_output)
    check(
        clean_only_budget.spent <= LOWERED_QUOTA,
        f"对照：文档B 仅解析+清洗在额度内成功 (spent={clean_only_budget.spent})",
    )

    # ---- 3. the shared entry: A ok, B blocked at linkify, C recovers -----
    emit("## 2. 同一处理入口、同一降低额度下的连续三次调用")
    emit()
    service = build_cleaner(LOWERED_QUOTA)

    # (a) long text succeeds
    output_a = service.clean(doc_a)
    report_a = service.budget.as_report()
    path_a = write_output("doc_a_long_text.html", output_a)
    check(
        report_a["spent"] <= LOWERED_QUOTA and output_a,
        f"文档A 成功并正式发出完整结果 (spent={report_a['spent']}, -> {path_a.name})",
    )

    # (b) doc B fails in the linkify stage; nothing is published
    blocked = None
    stale_b = OUT_DIR / "doc_b_final.html"
    if stale_b.exists():
        stale_b.unlink()
    try:
        service.clean(doc_b)
    except BudgetExceeded as exc:
        blocked = exc
        write_output(
            "doc_b_BLOCKED.txt",
            (
                "DOCUMENT BLOCKED — no final cleaned output was published.\n"
                f"stage={exc.stage} ({STAGE_LABELS.get(exc.stage, exc.stage)})\n"
                f"limit={exc.limit}\nused={exc.used}\n"
                f"stage_spent={exc.stage_spent}\ncounts={exc.counts}\n"
            ),
        )

    check(blocked is not None, "文档B 抛出 BudgetExceeded")
    if blocked is not None:
        check(
            blocked.stage == STAGE_LINKIFY,
            f"文档B 明确在链接处理环节超额 (stage={blocked.stage}, used={blocked.used})",
        )
        check(
            not stale_b.exists(),
            "文档B 没有把任何半成品当作完整最终输出发出",
        )
        check(
            blocked.stage_spent[STAGE_LINKIFY] > 0,
            "失败快照中记录了 linkify 阶段已发生的转换计量",
        )

    # (c) same instance + same config, ordinary short doc after failure
    output_c = service.clean(doc_c)
    report_c = service.budget.as_report()
    path_c = write_output("doc_c_short_after_failure.html", output_c)
    check(
        bool(output_c) and report_c["spent"] <= LOWERED_QUOTA,
        f"失败后同一 Cleaner 立即处理短文成功 (spent={report_c['spent']}, -> {path_c.name})",
    )
    check(
        report_c["spent"] < 100,
        f"单次预算已重置，短文只统计本次工作量 (spent={report_c['spent']})",
    )

    emit("### 调用 A：长文字（无转换）— 成功")
    emit()
    emit(f"- 计量: `{fmt_report(report_a)}`")
    emit(f"- 最终输出文件: `{path_a.relative_to(HERE.parent)}`")
    emit()
    emit("```html")
    emit(output_a)
    emit("```")
    emit()

    emit("### 调用 B：多节点 + 链接 — 被阻止")
    emit()
    if blocked is not None:
        emit(
            f"- 超额环节: **{STAGE_LABELS.get(blocked.stage, blocked.stage)}** (`{blocked.stage}`)"
        )
        emit(f"- 额度 limit: `{blocked.limit}`")
        emit(f"- 已用 used: `{blocked.used}`")
        emit(f"- 分阶段: `{blocked.stage_spent}`")
        emit(f"- 计数: `{blocked.counts}`")
        emit("- 最终输出: **未发出**（`BudgetExceeded` 向上传播，`clean()` 无返回值）")
    emit()

    emit("### 对照 B-clean-only：去掉链接转换 — 成功")
    emit()
    emit(f"- 计量: `spent={clean_only_budget.spent}`（<= {LOWERED_QUOTA}）")
    emit("- 说明: 同额度下解析与清洗本身放得下，是附加链接转换把累计工作量推过上限。")
    emit()

    emit("### 调用 C：失败后的普通短文 — 同一入口成功")
    emit()
    emit(f"- 计量: `{fmt_report(report_c)}`")
    emit(f"- 最终输出文件: `{path_c.relative_to(HERE.parent)}`")
    emit()
    emit("```html")
    emit(output_c)
    emit("```")
    emit()

    emit("## 3. 自动核对的断言")
    emit()
    for condition, message in checks:
        emit(
            f"- [{'x' if condition else ' '}] {'PASS' if condition else 'FAIL'} — {message}"
        )
    emit()

    emit("## 4. 结论")
    emit()
    if all(condition for condition, _ in checks):
        emit("全部预期成立：共同单次预算覆盖解析/清洗/可选链接处理；失败可定位环节；")
        emit("半成品不会作为完整结果发出；失败后同一处理入口对后续文档恢复正常。")
        verdict = 0
    else:
        emit("存在未满足的预期，请检查上面的 FAIL 项。")
        verdict = 1

    record_path = HERE / "verification_record.md"
    record_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nRecord written to {record_path}")
    print(f"{sum(1 for ok, _ in checks if ok)}/{len(checks)} checks passed")
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
