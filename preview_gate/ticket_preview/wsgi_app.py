"""WSGI application: the single real outlet for ticket previews.

Run a genuine HTTP server with ``python -m ticket_preview.serve`` (see
``serve.py``).  Tests/driver invoke this same callable through a WSGI transport
when the sandbox forbids binding a TCP port.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from urllib.parse import parse_qs

from . import gate
from .cache_store import CacheStore
from .ticket_store import TicketStore

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[1] / "data"

ID_PATTERN = r"(?P<tid>[A-Za-z0-9_-]+)"
PREVIEW_RE = re.compile(rf"^/tickets/{ID_PATTERN}/preview/?$")
INTERNAL_TICKET_RE = re.compile(rf"^/internal/tickets/{ID_PATTERN}/?$")
REBUILD_RE = re.compile(
    rf"^/internal/tickets/{ID_PATTERN}/rebuild-preview/?$"
)

DECISION_HELP = {
    gate.DECISION_CURRENT: (
        "该缓存由当前规则（v2，已收紧内部标签可见范围）生成，直接沿用；"
        "已撤回字段仍会在出口处被剔除。"
    ),
    gate.DECISION_RECLEANED: (
        "发现旧版（v1）清洗成品，但缓存内附有可验证原文；已按当前许可与 "
        "Bleach 规则重新清洗，并把结果写回缓存。"
    ),
    gate.DECISION_UNVERIFIABLE: (
        "这是缺少原文/许可证明的旧版成品，无法证明它满足当前收紧后的可见"
        "范围。为避免内部标签或已撤回字段借旧缓存重现，本次不对外展示该"
        "成品，状态为明确的 unverifiable。"
    ),
    gate.DECISION_BUILT: "缓存不存在，已直接依据权威工单按当前规则生成。",
}


def create_app(ticket_store: TicketStore, cache_store: CacheStore):
    def app(environ, start_response):
        return _dispatch(environ, start_response, ticket_store, cache_store)

    return app


def create_default_app(data_dir=None):
    data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    return create_app(
        TicketStore(data_dir / "tickets.json"),
        CacheStore(data_dir / "live"),
    )


def _respond(start_response, status, body: bytes, content_type, extra=None):
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
    ]
    if extra:
        headers.extend(extra)
    start_response(status, headers)
    return [body]


def _json(start_response, status, payload, extra=None):
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return _respond(
        start_response,
        status,
        body,
        "application/json; charset=utf-8",
        extra,
    )


def _html_response(start_response, status, text, extra=None):
    body = text.encode("utf-8")
    base_headers = [
        (
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
        )
    ]
    return _respond(
        start_response,
        status,
        body,
        "text/html; charset=utf-8",
        (extra or []) + base_headers,
    )


def _is_staff(environ) -> bool:
    # Deliberately simple gate for the exercise; a real deployment would sit
    # behind the organisation's identity/AuthN middleware.
    return environ.get("HTTP_X_STAFF_ROLE") == "staff"


def _dispatch(environ, start_response, tickets: TicketStore, caches: CacheStore):
    path = environ.get("PATH_INFO", "/") or "/"
    method = environ.get("REQUEST_METHOD", "GET").upper()
    query = parse_qs(environ.get("QUERY_STRING", "") or "")
    accept = environ.get("HTTP_ACCEPT", "") or ""
    want_json = query.get("format", [""])[0] == "json" or (
        "application/json" in accept and "text/html" not in accept
    )

    if path == "/healthz":
        return _json(start_response, "200 OK", {"ok": True})

    if path == "/" and method == "GET":
        ids = tickets.all_ids()
        items = "".join(
            f'<li><a href="/tickets/{tid}/preview">{tid} 外部预览</a>'
            f' · <a href="/tickets/{tid}/preview?format=json">JSON 回执</a></li>'
            for tid in ids
        )
        page = (
            "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<title>工单预览网关</title></head><body>"
            "<h1>工单预览网关</h1><ul>" + items + "</ul>"
            "<p>内部完整资料接口需请求头 <code>X-Staff-Role: staff</code>："
            "<code>GET /internal/tickets/&lt;id&gt;</code></p>"
            "</body></html>"
        )
        return _html_response(start_response, "200 OK", page)

    match = PREVIEW_RE.match(path)
    if match and method == "GET":
        return _handle_preview(
            start_response, match.group("tid"), tickets, caches, want_json
        )

    match = REBUILD_RE.match(path)
    if match and method == "POST":
        if not _is_staff(environ):
            return _json(
                start_response,
                "403 Forbidden",
                {"error": "staff role required (X-Staff-Role: staff)"},
            )
        return _handle_rebuild(
            start_response, match.group("tid"), tickets, caches
        )

    match = INTERNAL_TICKET_RE.match(path)
    if match and method == "GET":
        if not _is_staff(environ):
            return _json(
                start_response,
                "403 Forbidden",
                {"error": "staff role required (X-Staff-Role: staff)"},
            )
        ticket = tickets.get(match.group("tid"))
        if ticket is None:
            return _json(start_response, "404 Not Found", {"error": "not found"})
        return _json(
            start_response,
            "200 OK",
            ticket,
            extra=[("Cache-Control", "no-store")],
        )

    if want_json:
        return _json(start_response, "404 Not Found", {"error": "not found", "path": path})
    return _html_response(
        start_response,
        "404 Not Found",
        "<h1>404</h1><p>没有这个预览地址。</p>",
    )


def _preview_headers(result):
    receipt = result["receipt"]
    headers = [
        ("X-Preview-Decision", result["decision"]),
        ("X-Preview-Served", "1" if result["served"] else "0"),
        ("X-Preview-Rule-Version", str(receipt["rule_version_current"])),
    ]
    redacted = receipt.get("redacted_withdrawn") or []
    if redacted:
        headers.append(("X-Preview-Redacted", ",".join(redacted)))
    return headers


def _handle_preview(start_response, tid, tickets, caches, want_json):
    ticket = tickets.get(tid)
    if ticket is None:
        payload = {"error": "ticket not found", "ticket_id": tid}
        if want_json:
            return _json(start_response, "404 Not Found", payload)
        return _html_response(
            start_response, "404 Not Found", "<h1>404 工单不存在</h1>"
        )

    envelope, load_error = caches.load(tid)
    result = gate.evaluate_preview(ticket, envelope, load_error)
    if result.get("persist_envelope") is not None:
        caches.save(tid, result["persist_envelope"])

    status = (
        "200 OK"
        if result["http_status"] == gate.HTTP_STATUS_SERVED
        else "422 Unprocessable Content"
    )
    headers = _preview_headers(result)

    if want_json:
        payload = {
            "ticket_id": tid,
            "decision": result["decision"],
            "decision_zh": result["decision_zh"],
            "served": result["served"],
            "public_html": result["html"],
            "receipt": result["receipt"],
        }
        return _json(start_response, status, payload, extra=headers)

    page = render_preview_page(ticket, result)
    return _html_response(start_response, status, page, extra=headers)


def _handle_rebuild(start_response, tid, tickets, caches):
    ticket = tickets.get(tid)
    if ticket is None:
        return _json(start_response, "404 Not Found", {"error": "not found"})
    envelope, redacted = gate.build_current_envelope(
        ticket, reason="staff-explicit-rebuild"
    )
    caches.save(tid, envelope)
    return _json(
        start_response,
        "200 OK",
        {
            "ok": True,
            "decision": gate.DECISION_CURRENT,
            "rule_version": envelope["rule_version"],
            "redacted_withdrawn": redacted,
            "cache_file": str(caches.path_for(tid)),
        },
        extra=[("Cache-Control", "no-store")],
    )


def render_preview_page(ticket, result) -> str:
    esc = html.escape
    receipt = result["receipt"]
    decision = result["decision"]

    if result["served"]:
        stage = (
            '<article class="preview-body" data-sanitized="bleach-v'
            + str(receipt["rule_version_current"])
            + '">'
            + (result["html"] or "")
            + "</article>"
        )
    else:
        stage = (
            '<section class="withheld" role="alert" data-preview-status="'
            + decision
            + '">'
            "<h2>外部预览暂时无法确认，已暂缓展示</h2>"
            "<p>网关无法证明这份旧 Bleach 成品满足当前许可范围，因此不直接"
            "返回缓存内容。可由值班同学凭内部接口依据权威工单显式重建。</p>"
            '<p class="status-line">status = <code>unverifiable</code> · reason = '
            "<code>" + esc(str(receipt.get("reason"))) + "</code></p>"
            "</section>"
        )

    receipt_json = esc(json.dumps(receipt, ensure_ascii=False, indent=2))
    help_text = esc(DECISION_HELP.get(decision, ""))

    return PAGE_TEMPLATE.replace("__LANG__", "zh-CN").replace(
        "__TITLE__", esc(ticket.get("title", ticket.get("id", "")))
    ).replace("__TID__", esc(ticket.get("id", ""))).replace(
        "__DECISION__", esc(decision)
    ).replace("__DECISION_ZH__", esc(result["decision_zh"])).replace(
        "__HELP__", help_text
    ).replace(
        "__STAGE__", stage
    ).replace(
        "__RECEIPT_JSON__", receipt_json
    )


PAGE_TEMPLATE = """<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>外部预览 · __TITLE__</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
         margin: 0; background: #f5f6f8; color: #1f2329; }
  main { max-width: 820px; margin: 24px auto; padding: 0 16px; }
  .meta { color: #646a73; font-size: 13px; }
  .banner { border-radius: 8px; padding: 12px 16px; margin: 12px 0 18px;
            border: 1px solid #d0d3d6; background: #ffffff; }
  .banner .decision { font-weight: 700; }
  .banner.current { border-color: #34c724; background: #eafff5; }
  .banner.recleaned, .banner.built { border-color: #2b6cff; background: #eef3ff; }
  .banner.unverifiable { border-color: #f54a45; background: #fff0ef; }
  .paper { background: #fff; border: 1px solid #dee0e3; border-radius: 8px;
           padding: 20px 24px; }
  .preview-body blockquote { border-left: 4px solid #bbbfc4; margin: 8px 0;
           padding: 4px 14px; color: #555; background: #fafafa; }
  .preview-body img { max-width: 100%; }
  .withheld { border: 1px dashed #f54a45; background: #fff7f6; border-radius: 8px;
           padding: 18px 20px; }
  .status-line { color: #a8071a; }
  pre.receipt { background: #0f172a; color: #d7e3ff; padding: 14px; border-radius: 8px;
           overflow-x: auto; font-size: 12px; line-height: 1.5; }
  h2.receipt-title { font-size: 14px; color: #646a73; margin-top: 22px; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body data-preview-decision="__DECISION__">
<main>
  <p class="meta">工单 <code>__TID__</code> · 外部预览出口</p>
  <h1>__TITLE__</h1>
  <div class="banner __DECISION__" data-receipt-decision="__DECISION__">
    <span class="decision">__DECISION_ZH__</span>
    <div>__HELP__</div>
  </div>
  <div class="paper">
    __STAGE__
  </div>
  <h2 class="receipt-title">回执（receipt）</h2>
  <pre class="receipt" id="receipt-json">__RECEIPT_JSON__</pre>
</main>
</body>
</html>
"""
