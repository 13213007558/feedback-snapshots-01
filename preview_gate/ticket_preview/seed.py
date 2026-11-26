"""Create the canonical ticket and the three local preview caches.

The three required caches are:

1. ``cache_1_old_with_original.json`` -- legacy v1 *finished* Bleach artifact
   that still carries its attested raw original.
2. ``cache_2_old_missing_original.json`` -- legacy v1 finished artifact with
   no original/provenance.
3. ``cache_3_current_rules.json`` -- artifact already produced by the current
   v2 rules.

A fourth probe, ``probe_current_hit_withdrawn.json``, is an extra regression
fixture: a valid v2 cache that contains a field withdrawn after caching.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from . import gate, policy

TICKET_ID = "WO-2026-224"
SEEDED_AT = "2026-11-20T08:00:00+00:00"

# Distinctive canary tokens used by the end-to-end checks.
CANARY_BID = "SECRET-BID-9001"
CANARY_RISK = "RISK-SECRET-5566"
CANARY_CUSTOM = "INTERNAL-CUSTOM-3133"
CANARY_HOTLINE = "WITHDRAWN-HOTLINE-4242"
CANARY_TRIAGE = "INTERNAL-TRIAGE-6677"
CANARY_XSS = "XSSCANARY7731"
PUBLIC_LINK = "https://support.example.com/report-demo"

SUMMARY_RAW = '''<p>客户在导出 <strong>季度报表</strong> 为 PDF 后，发现<em>表头与数据错位</em>。</p>
<p>可参考 <a href="https://support.example.com/report-demo">示例报表</a>，复现步骤如下：</p>
<ul><li>打开报表页</li><li>点击“导出 PDF”</li><li>查看第 2 页</li></ul>
<blockquote>客户原话：导出后“合计”行跑到了下一页。</blockquote>
<p><img src="x" alt="broken" onerror="alert('XSSCANARY7731')"></p>
<p><a href="javascript:alert(1)">恶意协议链接</a></p>'''

DETAILS_RAW = '''<h3>处理进展</h3>
<p>研发已定位为分页样式问题，预计本周内修复。</p>
<p><span class="internal-tag">内部标签：VIP 客户 / 底价 SECRET-BID-9001</span></p>
<div data-internal="risk">风控内部备注：RISK-SECRET-5566 暂不外露。</div>
<internal-note>自定义内部节点 INTERNAL-CUSTOM-3133</internal-note>
<p>对外结论：问题可在 6.4.x 版本规避。</p>'''

AGENT_LINE_RAW = '''<p>值班直线（该字段已撤回）：<strong>WITHDRAWN-HOTLINE-4242</strong> / 分机 8899。</p>'''

INTERNAL_TRIAGE_RAW = '''<p>内部定级 P0，仅限值班同学查看：INTERNAL-TRIAGE-6677。</p>'''


def build_ticket() -> dict:
    return {
        "id": TICKET_ID,
        "title": "导出报表 PDF 排版错乱，客户催办",
        "requester": "华东大客户成功组",
        "status": "处理中",
        "updated_at": "2026-11-25T14:30:00+00:00",
        # Current external field scope. agent_direct_line was removed after the
        # legacy caches were written; internal_triage is staff-only.
        "public_field_order": ["summary", "details"],
        "internal_fields": ["internal_triage"],
        "withdrawn_fields": {
            "agent_direct_line": {
                "withdrawn_at": "2026-11-24T10:00:00+00:00",
                "reason": "值班号码迁移，旧直线停用并撤回对外展示",
            }
        },
        "raw": {
            "summary": SUMMARY_RAW,
            "details": DETAILS_RAW,
            "agent_direct_line": AGENT_LINE_RAW,
            "internal_triage": INTERNAL_TRIAGE_RAW,
        },
    }


def _write_json(path: Path, payload) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return path


def seed_all(data_dir) -> dict:
    data_dir = Path(data_dir)
    fixtures_dir = data_dir / "fixtures"
    live_dir = data_dir / "live"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    live_dir.mkdir(parents=True, exist_ok=True)

    ticket = build_ticket()
    tickets_path = _write_json(data_dir / "tickets.json", {"tickets": [ticket]})

    # The original as captured by the old preview system (note: at that time
    # agent_direct_line was still an externally visible field).
    old_original_parts = {
        "summary": SUMMARY_RAW,
        "details": DETAILS_RAW,
        "agent_direct_line": AGENT_LINE_RAW,
    }
    old_combined = "\n".join(old_original_parts.values())
    old_finished_html = policy.legacy_clean(old_combined)

    base_legacy = {
        "ticket_id": TICKET_ID,
        "rule_version": policy.LEGACY_POLICY_VERSION,
        "cached_at": "2026-11-10T09:00:00+00:00",
        "bleach_version": policy.bleach_version(),
        "policy": "v1-internal-class-labels-allowed",
        "html": old_finished_html,
    }

    cache1 = copy.deepcopy(base_legacy)
    cache1["cache_label"] = "old-with-original"
    cache1["original"] = {
        "digest": policy.digest_parts(old_original_parts),
        "parts": old_original_parts,
    }
    path1 = _write_json(fixtures_dir / "cache_1_old_with_original.json", cache1)

    cache2 = copy.deepcopy(base_legacy)
    cache2["cache_label"] = "old-missing-original"
    cache2["cached_at"] = "2026-11-12T16:20:00+00:00"
    # Deliberately no "original" key.
    path2 = _write_json(
        fixtures_dir / "cache_2_old_missing_original.json", cache2
    )

    current_envelope, _ = gate.build_current_envelope(
        ticket, reason="seed-current-rules"
    )
    current_envelope["cached_at"] = SEEDED_AT
    current_envelope["cache_label"] = "current-rules"
    path3 = _write_json(
        fixtures_dir / "cache_3_current_rules.json", current_envelope
    )

    # Extra regression probe: a perfectly valid v2 cache that happens to hold a
    # part for a field withdrawn *after* caching.
    probe = copy.deepcopy(current_envelope)
    probe["cache_label"] = "probe-current-hit-withdrawn-field"
    probe["parts"]["agent_direct_line"] = policy.clean_public(AGENT_LINE_RAW)
    probe["html"] = probe["html"] + "\n" + probe["parts"]["agent_direct_line"]
    probe["cached_at"] = "2026-11-23T09:30:00+00:00"
    probe_path = _write_json(
        fixtures_dir / "probe_current_hit_withdrawn.json", probe
    )

    # Start the live cache off as the genuine old cache #1.
    live_path = live_dir / f"{TICKET_ID}.json"
    live_path.write_text(path1.read_text(encoding="utf-8"), encoding="utf-8")

    return {
        "data_dir": data_dir,
        "tickets": tickets_path,
        "fixture1": path1,
        "fixture2": path2,
        "fixture3": path3,
        "probe": probe_path,
        "live": live_path,
        "ticket_id": TICKET_ID,
    }


if __name__ == "__main__":
    here = Path(__file__).resolve().parents[1]
    paths = seed_all(here / "data")
    print("Seeded preview_gate data:")
    for key, value in paths.items():
        print(f"  {key}: {value}")
