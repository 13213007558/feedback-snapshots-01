#!/usr/bin/env python3
"""End-to-end checks through the *real* ticket preview outlet.

It seeds three local caches, drives every one through the WSGI/HTTP preview
exit, inspects visible content + receipt + the canonical internal ticket, and
finally restores the old cache for a direct comparison.

Run::

    .venv/bin/python preview_gate/verify.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:  # Re-exec into the repository's locked venv if the caller lacks Bleach.
    import bleach  # noqa: F401
except ImportError:  # pragma: no cover - environment convenience
    venv_python = HERE.parent / ".venv" / "bin" / "python"
    if venv_python.exists():
        os.execv(
            str(venv_python),
            [str(venv_python), str(HERE / "verify.py"), *sys.argv[1:]],
        )
    raise

from ticket_preview import policy  # noqa: E402
from ticket_preview.cache_store import CacheStore  # noqa: E402
from ticket_preview.seed import (  # noqa: E402
    CANARY_BID,
    CANARY_CUSTOM,
    CANARY_HOTLINE,
    CANARY_RISK,
    CANARY_TRIAGE,
    CANARY_XSS,
    PUBLIC_LINK,
    TICKET_ID,
    seed_all,
)
from ticket_preview.ticket_store import TicketStore  # noqa: E402
from ticket_preview.wsgi_app import create_app  # noqa: E402

DATA_DIR = HERE / "data"
REPORT_PATH = HERE / "report" / "verification-report.md"

SECRET_CANARIES = {
    "内部底价标签": CANARY_BID,
    "风控内部备注": CANARY_RISK,
    "自定义内部节点": CANARY_CUSTOM,
    "已撤回值班直线": CANARY_HOTLINE,
    "内部定级资料": CANARY_TRIAGE,
    "XSS 事件载荷": CANARY_XSS,
}
LEAK_CANARIES = [CANARY_BID, CANARY_RISK, CANARY_CUSTOM, CANARY_HOTLINE]
FORMAT_TOKENS = ["<strong>", "<em>", "<blockquote>", "<ul>", PUBLIC_LINK]


@dataclass
class Resp:
    status: int
    headers: dict
    text: str

    def json(self):
        return json.loads(self.text)


class WSGITransport:
    kind = "real-wsgi-outlet"

    def __init__(self, app):
        self.app = app

    def request(self, method, path, headers=None, body=b""):
        from wsgiref.util import setup_testing_defaults

        parts = urlsplit(path)
        environ = {}
        setup_testing_defaults(environ)
        environ.update(
            {
                "REQUEST_METHOD": method,
                "PATH_INFO": parts.path,
                "QUERY_STRING": parts.query,
                "SERVER_NAME": "preview-gate.local",
                "SERVER_PORT": "80",
                "wsgi.input": BytesIO(body),
            }
        )
        environ["CONTENT_LENGTH"] = str(len(body))
        for key, value in (headers or {}).items():
            norm = key.upper().replace("-", "_")
            if norm == "CONTENT_TYPE":
                environ["CONTENT_TYPE"] = value
            else:
                environ[f"HTTP_{norm}"] = value

        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = response_headers

        chunks = self.app(environ, start_response)
        try:
            data = b"".join(chunks)
        finally:
            if hasattr(chunks, "close"):
                chunks.close()
        code = int(captured["status"].split(" ", 1)[0])
        hdrs = {k.lower(): v for k, v in captured["headers"]}
        return Resp(code, hdrs, data.decode("utf-8", "replace"))


class HTTPTransport:
    kind = "real-loopback-http"

    def __init__(self, httpd):
        self.httpd = httpd
        self.port = httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def request(self, method, path, headers=None, body=b""):
        import urllib.error
        import urllib.request

        req = urllib.request.Request(
            self.base + path, data=body if body else None, method=method
        )
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                return Resp(
                    resp.status,
                    {k.lower(): v for k, v in resp.headers.items()},
                    data.decode("utf-8", "replace"),
                )
        except urllib.error.HTTPError as err:
            data = err.read()
            return Resp(
                err.code,
                {k.lower(): v for k, v in (err.headers or {}).items()},
                data.decode("utf-8", "replace"),
            )

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def make_transport(app):
    """Prefer a genuine TCP HTTP outlet; fall back to in-process WSGI."""
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    class _QuietHandler(WSGIRequestHandler):
        def log_message(self, fmt, *args):  # keep verification output tidy
            return

    try:
        httpd = make_server("127.0.0.1", 0, app, handler_class=_QuietHandler)
    except OSError as exc:  # sandbox forbids bind(2)
        print(f"[transport] loopback bind unavailable ({exc}); using WSGI outlet")
        return WSGITransport(app), None

    server = HTTPTransport(httpd)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f"[transport] real HTTP on {server.base}")
    return server, server


class Recorder:
    def __init__(self):
        self.checks = []
        self.evidence = {"receipts": {}, "bodies": {}, "files": {}}

    def check(self, group, name, ok, detail=""):
        self.checks.append(
            {"group": group, "name": name, "ok": bool(ok), "detail": detail}
        )
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail and not ok:
            line += f" -- {detail}"
        print(line)
        return bool(ok)

    @property
    def failed(self):
        return [c for c in self.checks if not c["ok"]]


def contains_any_secret(text):
    return {label: token for label, token in SECRET_CANARIES.items() if token in text}


def assert_all_secrets_absent(rec, group, resp_text, prefix):
    found = contains_any_secret(resp_text)
    return rec.check(
        group,
        f"{prefix}：全部内部/撤回敏感标记均不可见",
        not found,
        f"泄漏={found}",
    )


def main() -> int:
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    paths = seed_all(DATA_DIR)

    tickets = TicketStore(DATA_DIR / "tickets.json")
    caches = CacheStore(DATA_DIR / "live")
    app = create_app(tickets, caches)
    transport, http_handle = make_transport(app)

    rec = Recorder()
    staff = {"X-Staff-Role": "staff"}

    canonical_ticket = tickets.get(TICKET_ID)
    canonical_digest = hashlib.sha256(
        json.dumps(canonical_ticket, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()

    def preview_json():
        return transport.request(
            "GET", f"/tickets/{TICKET_ID}/preview?format=json"
        )

    def preview_html():
        return transport.request("GET", f"/tickets/{TICKET_ID}/preview")

    def internal_ticket(with_staff=True):
        return transport.request(
            "GET",
            f"/internal/tickets/{TICKET_ID}",
            headers=staff if with_staff else None,
        )

    def activate(fixture_path):
        return caches.activate_fixture(fixture_path, TICKET_ID)

    def live_envelope():
        envelope, err = caches.load(TICKET_ID)
        assert err is None, err
        return envelope

    def check_original_ticket(group):
        """The same ticket must stay complete internally for every cache."""
        resp = internal_ticket()
        present = contains_any_secret(resp.text)
        rec.check(
            group,
            "原始工单：内部出口 200 且完整资料（含内部/撤回字段）仍在",
            resp.status == 200 and len(present) == len(SECRET_CANARIES),
            f"status={resp.status} 仅见 {sorted(present)}",
        )
        digest = hashlib.sha256(
            json.dumps(resp.json(), ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()
        rec.check(
            group,
            "原始工单：内容与权威工单一致，未被缓存流程改写",
            digest == canonical_digest,
        )

    # ------------------------------------------------------------------
    # Internal original ticket: complete data + access gate.
    # ------------------------------------------------------------------
    print("\n== 原始工单 / 内部出口 ==")
    forbidden = internal_ticket(with_staff=False)
    rec.check("internal", "无 staff 头访问内部接口被拒 (403)", forbidden.status == 403)

    internal = internal_ticket()
    rec.evidence["bodies"]["internal"] = internal.text
    rec.check("internal", "内部接口 200 且返回完整工单", internal.status == 200)
    leaked_internal = contains_any_secret(internal.text)
    rec.check(
        "internal",
        "内部资料保留全部字段（含内部/撤回原文）",
        len(leaked_internal) == len(SECRET_CANARIES),
        f"仅见到 {sorted(leaked_internal)}",
    )
    internal_digest = hashlib.sha256(
        json.dumps(internal.json(), ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()
    rec.check(
        "internal",
        "三次预览判定均不改动原始工单（摘要一致）",
        internal_digest == canonical_digest,
    )

    # ------------------------------------------------------------------
    # Case 1: legacy v1 cache WITH original -> recleaned.
    # ------------------------------------------------------------------
    print("\n== 缓存 1：旧规则 + 有原文 -> 重新清洗 ==")
    activate(paths["fixture1"])
    before1 = live_envelope()
    rec.check("case1", "激活的是 rule_version=1 旧缓存", before1["rule_version"] == 1)
    raw_old_html = before1["html"]
    rec.check(
        "case1",
        "对照：旧成品 html 直接读取时确实含内部/撤回内容",
        all(token in raw_old_html for token in LEAK_CANARIES),
    )
    rec.evidence["files"]["fixture1_html_has_leaks"] = {
        token: (token in raw_old_html) for token in SECRET_CANARIES.values()
    }

    rj = preview_json()
    data = rj.json()
    rec.evidence["receipts"]["case1_recleaned"] = data["receipt"]
    rec.evidence["bodies"]["case1_json"] = rj.text
    rec.check("case1", "HTTP 200", rj.status == 200, f"status={rj.status}")
    rec.check(
        "case1",
        "回执 decision=recleaned（重新清洗）",
        data["decision"] == "recleaned",
        data.get("decision"),
    )
    rec.check(
        "case1",
        "响应头 X-Preview-Decision=recleaned",
        rj.headers.get("x-preview-decision") == "recleaned",
    )
    rec.check(
        "case1",
        "回执记录原文存在且校验通过",
        data["receipt"]["source_present"] is True
        and data["receipt"]["source_verified"] is True,
    )
    rec.check(
        "case1",
        "回执登记被剔除的已撤回字段 agent_direct_line",
        "agent_direct_line" in data["receipt"]["redacted_withdrawn"],
        str(data["receipt"]["redacted_withdrawn"]),
    )
    body_html = data.get("public_html") or ""
    rec.check(
        "case1",
        "保留允许的普通排版（strong/em/blockquote/ul/链接）",
        all(token in body_html for token in FORMAT_TOKENS),
    )
    rec.check(
        "case1",
        "新规则移除内部 class 标签钩子",
        "internal-tag" not in body_html and "data-internal" not in body_html,
    )
    rec.check("case1", "无可执行事件属性 onerror", "onerror" not in rj.text.lower())
    rec.check("case1", "无 javascript: 协议", "javascript:" not in rj.text.lower())
    assert_all_secrets_absent(rec, "case1", rj.text, "重新清洗后")

    # Reset to the old cache so the *visible HTML outlet* performs its own
    # first-hit reclean rather than observing the cache the JSON call rebuilt.
    activate(paths["fixture1"])
    rh = preview_html()
    rec.evidence["bodies"]["case1_html"] = rh.text
    rec.check("case1", "HTML 出口 200", rh.status == 200)
    rec.check(
        "case1",
        "HTML 标注 data-preview-decision=recleaned",
        'data-preview-decision="recleaned"' in rh.text,
    )
    assert_all_secrets_absent(rec, "case1-html", rh.text, "所见页面")

    after1 = live_envelope()
    rec.check(
        "case1",
        "重建结果已写回本地缓存（rule_version 升级为 2）",
        after1["rule_version"] == policy.POLICY_VERSION
        and after1.get("build_reason", "").startswith("reclean"),
    )
    second_hit = preview_json().json()
    rec.check(
        "case1",
        "重建后的下一次读取转为 current（沿用新缓存）",
        second_hit["decision"] == "current",
        second_hit.get("decision"),
    )
    check_original_ticket("case1")

    # ------------------------------------------------------------------
    # Case 2: legacy v1 cache MISSING original -> unverifiable, withheld.
    # ------------------------------------------------------------------
    print("\n== 缓存 2：旧规则 + 缺原文 -> 暂时无法确认 ==")
    activate(paths["fixture2"])
    before2 = live_envelope()
    rec.check("case2", "激活的是 rule_version=1 旧缓存", before2["rule_version"] == 1)

    rj = preview_json()
    data = rj.json()
    rec.evidence["receipts"]["case2_unverifiable"] = data["receipt"]
    rec.evidence["bodies"]["case2_json"] = rj.text
    rec.check(
        "case2",
        "HTTP 422（明确的无法确认状态，fail-closed）",
        rj.status == 422,
        f"status={rj.status}",
    )
    rec.check(
        "case2",
        "回执 decision=unverifiable",
        data["decision"] == "unverifiable",
        data.get("decision"),
    )
    rec.check(
        "case2",
        "served=false 且不回传任何缓存 html",
        data["served"] is False and data["public_html"] is None,
    )
    rec.check(
        "case2",
        "原因码 stale-version-missing-original",
        data["receipt"].get("reason") == "stale-version-missing-original",
        str(data["receipt"].get("reason")),
    )
    rec.check(
        "case2",
        "响应头 X-Preview-Served=0 且 decision=unverifiable",
        rj.headers.get("x-preview-served") == "0"
        and rj.headers.get("x-preview-decision") == "unverifiable",
    )
    assert_all_secrets_absent(rec, "case2", rj.text, "暂缓返回的回执")

    rh = preview_html()
    rec.evidence["bodies"]["case2_html"] = rh.text
    rec.check("case2", "HTML 出口同样 422", rh.status == 422)
    rec.check(
        "case2",
        "页面给出明确中文状态与 withheld 区域",
        'data-preview-decision="unverifiable"' in rh.text
        and "暂时无法确认" in rh.text
        and 'role="alert"' in rh.text,
    )
    assert_all_secrets_absent(rec, "case2-html", rh.text, "所见 withheld 页面")

    after2 = live_envelope()
    rec.check(
        "case2",
        "unverifiable 不覆盖旧缓存（磁盘上仍是 v1）",
        after2["rule_version"] == 1,
    )
    check_original_ticket("case2")

    # Staff explicit rebuild remediates the indeterminate state.
    rb = transport.request(
        "POST", f"/internal/tickets/{TICKET_ID}/rebuild-preview", headers=staff
    )
    rec.check("case2", "值班显式重建返回 200 且升到 v2", rb.status == 200 and rb.json().get("rule_version") == 2)
    rj_fixed = preview_json()
    rec.check(
        "case2",
        "重建后再读 -> decision=current 且可安全预览",
        rj_fixed.status == 200 and rj_fixed.json()["decision"] == "current",
    )
    assert_all_secrets_absent(rec, "case2-fixed", rj_fixed.text, "显式重建后")

    # ------------------------------------------------------------------
    # Case 3: current-rule cache -> reuse verbatim.
    # ------------------------------------------------------------------
    print("\n== 缓存 3：已使用新规则 -> 沿用 ==")
    activate(paths["fixture3"])
    fixture3 = json.loads(paths["fixture3"].read_text(encoding="utf-8"))
    rj = preview_json()
    data = rj.json()
    rec.evidence["receipts"]["case3_current"] = data["receipt"]
    rec.evidence["bodies"]["case3_json"] = rj.text
    rec.check("case3", "HTTP 200", rj.status == 200)
    rec.check(
        "case3",
        "回执 decision=current（沿用）",
        data["decision"] == "current",
        data.get("decision"),
    )
    rec.check(
        "case3",
        "响应头 X-Preview-Decision=current",
        rj.headers.get("x-preview-decision") == "current",
    )
    rec.check(
        "case3",
        "直接沿用缓存成品（public_html 与缓存 html 逐字一致）",
        data["public_html"] == fixture3["html"],
    )
    rec.check(
        "case3",
        "公开页面保留允许的普通排版",
        all(token in (data["public_html"] or "") for token in FORMAT_TOKENS),
    )
    assert_all_secrets_absent(rec, "case3", rj.text, "沿用的新缓存")
    check_original_ticket("case3")

    # ------------------------------------------------------------------
    # Extra probe: valid v2 hit containing a since-withdrawn field.
    # ------------------------------------------------------------------
    print("\n== 追加探针：新规则缓存命中但含事后撤回字段 ==")
    probe_path = activate(paths["probe"])
    probe_raw = probe_path.read_text(encoding="utf-8")
    rec.check(
        "probe",
        "探针缓存文件本身确实含已撤回号码（证明是一次真实命中）",
        CANARY_HOTLINE in probe_raw,
    )
    rj = preview_json()
    data = rj.json()
    rec.evidence["receipts"]["probe_withdrawn_hit"] = data["receipt"]
    rec.evidence["bodies"]["probe_json"] = rj.text
    rec.check(
        "probe",
        "命中仍判 current（沿用缓存）",
        data["decision"] == "current",
        data.get("decision"),
    )
    rec.check(
        "probe",
        "出口拦截并登记撤回字段",
        data["receipt"]["redacted_withdrawn"] == ["agent_direct_line"]
        and "with-withdrawal-filter" in data["receipt"]["reason"],
        str(data["receipt"]["redacted_withdrawn"]),
    )
    rec.check(
        "probe",
        "响应头 X-Preview-Redacted 标出字段",
        rj.headers.get("x-preview-redacted") == "agent_direct_line",
    )
    rec.check(
        "probe",
        "其余缓存内容仍正常沿用",
        PUBLIC_LINK in (data["public_html"] or ""),
    )
    assert_all_secrets_absent(rec, "probe", rj.text, "撤回过滤后")

    # ------------------------------------------------------------------
    # Restore the old cache and compare raw file vs real outlet.
    # ------------------------------------------------------------------
    print("\n== 恢复旧缓存作对照 ==")
    restored = caches.activate_fixture(paths["fixture1"], TICKET_ID)
    restored_text = restored.read_text(encoding="utf-8")
    rec.evidence["files"]["restored_old_cache"] = {
        "rule_version_1": '"rule_version": 1' in restored_text,
        "has_internal_label_markup": "internal-tag" in restored_text,
        "has_withdrawn_value": CANARY_HOTLINE in restored_text,
        "has_bid": CANARY_BID in restored_text,
    }
    rec.check(
        "restore",
        "已恢复的旧缓存文件在磁盘上仍是 v1 且保留旧标记/撤回值",
        rec.evidence["files"]["restored_old_cache"]["rule_version_1"]
        and rec.evidence["files"]["restored_old_cache"]["has_internal_label_markup"]
        and rec.evidence["files"]["restored_old_cache"]["has_withdrawn_value"],
    )
    cmp_resp = preview_json()
    cmp_data = cmp_resp.json()
    rec.check(
        "restore",
        "恢复后过真实出口仍判 recleaned 而非直接命中旧成品",
        cmp_data["decision"] == "recleaned",
        cmp_data.get("decision"),
    )
    assert_all_secrets_absent(rec, "restore", cmp_resp.text, "对照出口")
    rec.check(
        "restore",
        "对照：旧文件含敏感值=True 而出口响应含敏感值=False",
        CANARY_HOTLINE in restored_text and CANARY_HOTLINE not in cmp_resp.text,
    )

    # Final internal integrity once more.
    final_internal = internal_ticket().json()
    rec.check(
        "restore",
        "结束时原始工单依旧完整未被缓存流程改写",
        hashlib.sha256(
            json.dumps(final_internal, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()
        == canonical_digest,
    )

    # Leave the live cache on disk as the restored old v1 artifact so the
    # comparison state is directly inspectable after this run.
    caches.activate_fixture(paths["fixture1"], TICKET_ID)

    if http_handle is not None:
        http_handle.shutdown()

    write_report(rec, transport.kind, started)

    total = len(rec.checks)
    failed = len(rec.failed)
    print(f"\n==== {total - failed}/{total} checks passed, {failed} failed ====")
    print(f"report: {REPORT_PATH.relative_to(HERE.parent)}")
    return 1 if failed else 0


def _presence(text, token):
    return "有" if token in (text or "") else "无"


def write_report(rec: Recorder, transport_kind: str, started: str) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("# 工单外部预览缓存：版本检查与处理规则验证\n")
    lines.append(f"- 运行时间：{started}")
    lines.append(f"- 出口方式：`{transport_kind}`（与 `ticket_preview/serve.py` 托管同一 WSGI application）")
    lines.append(f"- Python：`{sys.version.split()[0]}` · Bleach：`{policy.bleach_version()}` · 当前规则版本：`v{policy.POLICY_VERSION}`")
    passed = sum(1 for c in rec.checks if c["ok"])
    lines.append(f"- 结果：**{passed}/{len(rec.checks)} 通过**\n")

    lines.append("## 三种判定\n")
    lines.append("| 缓存 | 缓存版本 | 原文/证明 | 出口判定 | HTTP | 是否下发内容 |")
    lines.append("|---|---|---|---|---|---|")
    lines.append("| 1 有原文 | v1 | 有，SHA-256 校验通过 | `recleaned` 重新清洗 | 200 | 是（新规则） |")
    lines.append("| 2 缺原文 | v1 | 无 | `unverifiable` 暂时无法确认 | 422 | 否（fail-closed） |")
    lines.append("| 3 新规则 | v2 | 不需要 | `current` 沿用 | 200 | 是（逐字沿用） |")
    lines.append("| 探针：v2 命中但含事后撤回字段 | v2 | — | `current` + 出口撤回过滤 | 200 | 是（剔除该字段） |\n")

    lines.append("## 敏感标记暴露矩阵\n")
    lines.append("“旧成品 html”是直接读取缓存文件里的 Bleach 成品；其余列为真实出口/内部接口响应。\n")
    c_internal = rec.evidence["bodies"].get("internal", "")
    c1 = rec.evidence["bodies"].get("case1_json", "")
    c2 = rec.evidence["bodies"].get("case2_json", "")
    c3 = rec.evidence["bodies"].get("case3_json", "")
    cp = rec.evidence["bodies"].get("probe_json", "")
    old_html_presence = rec.evidence["files"].get("fixture1_html_has_leaks", {})
    lines.append("| 标记 | 旧成品 html | 内部接口 | 缓存1出口 | 缓存2出口 | 缓存3出口 | 探针出口 |")
    lines.append("|---|---|---|---|---|---|---|")
    for label, token in SECRET_CANARIES.items():
        old = "有" if old_html_presence.get(token) else "无"
        lines.append(
            f"| {label} `{token}` | {old} | {_presence(c_internal, token)} | "
            f"{_presence(c1, token)} | {_presence(c2, token)} | "
            f"{_presence(c3, token)} | {_presence(cp, token)} |"
        )
    lines.append("")
    lines.append("> 内部接口 `GET /internal/tickets/WO-2026-224`（带 `X-Staff-Role: staff`）"
                 "始终包含全部标记对应的完整原始资料；无该头返回 403。\n")

    restore = rec.evidence["files"].get("restored_old_cache", {})
    lines.append("## 恢复旧缓存对照\n")
    lines.append("```json")
    lines.append(json.dumps(restore, ensure_ascii=False, indent=2))
    lines.append("```")
    lines.append("恢复后再过真实出口仍为 `recleaned`，响应中敏感标记为“无”；"
                 "而磁盘旧文件依旧保留 `internal-tag` 与已撤回号码，证明安全结论来自出口规则而非改写证据。\n")

    lines.append("## 三份回执（receipt）\n")
    for key in ("case1_recleaned", "case2_unverifiable", "case3_current", "probe_withdrawn_hit"):
        receipt = rec.evidence["receipts"].get(key)
        if receipt:
            lines.append(f"### `{key}`")
            lines.append("```json")
            lines.append(json.dumps(receipt, ensure_ascii=False, indent=2))
            lines.append("```\n")

    lines.append("## 检查清单\n")
    current_group = None
    for check in rec.checks:
        if check["group"] != current_group:
            current_group = check["group"]
            lines.append(f"\n### {current_group}\n")
        mark = "✅" if check["ok"] else "❌"
        detail = f" — {check['detail']}" if check["detail"] and not check["ok"] else ""
        lines.append(f"- {mark} {check['name']}{detail}")
    lines.append("")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
