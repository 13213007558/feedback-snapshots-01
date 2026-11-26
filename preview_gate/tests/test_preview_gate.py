"""Hermetic tests for the version-aware preview cache gate."""

from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path

import pytest

PREVIEW_GATE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PREVIEW_GATE))

from ticket_preview import gate, policy  # noqa: E402
from ticket_preview.cache_store import CacheStore  # noqa: E402
from ticket_preview.ticket_store import TicketStore  # noqa: E402
from ticket_preview.wsgi_app import create_app  # noqa: E402

TID = "WO-TEST-1"
HOTLINE = "HOTLINE-CANARY-1"
BID = "BID-CANARY-1"


def make_ticket():
    return {
        "id": TID,
        "title": "t",
        "public_field_order": ["summary", "details"],
        "withdrawn_fields": {"agent_line": {"reason": "withdrawn"}},
        "raw": {
            "summary": (
                "<p>Hello <strong>bold</strong> "
                "<a href=\"https://example.org/a\">link</a></p>"
                "<img src=x onerror=\"alert('X')\">"
                "<a href=\"javascript:alert(1)\">js</a>"
            ),
            "details": (
                "<p>visible</p>"
                f"<span class=\"internal-tag\">{BID}</span>"
                "<div data-internal=\"x\">RISK-TEXT</div>"
                "<internal-x>CUSTOM-TEXT</internal-x>"
                "<script>alert('SCRIPT-TEXT')</script>"
            ),
            "agent_line": f"<p>{HOTLINE}</p>",
        },
    }


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def test_public_typography_and_link_preserved():
    out = policy.clean_public(
        "<p>A <strong>b</strong> <em>i</em> "
        "<a href=\"https://e.org\">e</a></p>"
        "<ul><li>1</li></ul><blockquote>q</blockquote>"
    )
    assert "<strong>b</strong>" in out
    assert "<em>i</em>" in out
    assert 'href="https://e.org"' in out
    assert "<ul>" in out and "<blockquote>" in out


def test_internal_subtree_text_is_removed_not_just_escaped():
    out = policy.clean_public(
        "<p>keep</p>"
        "<span class=\"internal-tag\">SECRET-SPAN</span>"
        "<div data-internal=\"1\">SECRET-DIV</div>"
        "<internal-note>SECRET-CUSTOM</internal-note>"
    )
    assert "keep" in out
    assert "SECRET-SPAN" not in out
    assert "SECRET-DIV" not in out
    assert "SECRET-CUSTOM" not in out
    assert "internal-tag" not in out and "data-internal" not in out


def test_xss_handlers_and_protocols_neutralized():
    out = policy.clean_public(
        "<img src=x onerror=\"alert('XSS')\">"
        "<p onclick=\"x\">p</p>"
        "<a href=\"javascript:alert(1)\">js</a>"
    )
    assert "onerror" not in out.lower()
    assert "onclick" not in out.lower()
    assert "javascript:" not in out.lower()
    assert "<img" not in out


# ---------------------------------------------------------------------------
# Decision triad
# ---------------------------------------------------------------------------

def test_current_envelope_is_current():
    ticket = make_ticket()
    envelope, _ = gate.build_current_envelope(ticket)
    result = gate.evaluate_preview(ticket, envelope)
    assert result["decision"] == gate.DECISION_CURRENT
    assert result["served"] is True
    assert BID not in (result["html"] or "")
    assert HOTLINE not in (result["html"] or "")


def test_legacy_with_original_is_recleaned():
    ticket = make_ticket()
    parts = {
        "summary": ticket["raw"]["summary"],
        "details": ticket["raw"]["details"],
        "agent_line": ticket["raw"]["agent_line"],
    }
    envelope = {
        "rule_version": 1,
        "html": policy.legacy_clean("\n".join(parts.values())),
        "original": {"digest": policy.digest_parts(parts), "parts": parts},
    }
    result = gate.evaluate_preview(ticket, envelope)
    assert result["decision"] == gate.DECISION_RECLEANED
    assert result["persist_envelope"]["rule_version"] == 2
    assert "agent_line" in result["receipt"]["redacted_withdrawn"]
    html = result["html"]
    assert BID not in html and "RISK-TEXT" not in html
    assert "CUSTOM-TEXT" not in html and "SCRIPT-TEXT" not in html
    assert HOTLINE not in html
    assert "<strong>bold</strong>" in html


def test_legacy_missing_original_is_unverifiable():
    ticket = make_ticket()
    envelope = {"rule_version": 1, "html": "<p>old finished product</p>"}
    result = gate.evaluate_preview(ticket, envelope)
    assert result["decision"] == gate.DECISION_UNVERIFIABLE
    assert result["served"] is False
    assert result["http_status"] == 422
    assert result["html"] is None
    assert result["persist_envelope"] is None


def test_legacy_broken_digest_is_unverifiable():
    ticket = make_ticket()
    parts = {"summary": "<p>x</p>"}
    envelope = {
        "rule_version": 1,
        "original": {"digest": "sha256:deadbeef", "parts": parts},
    }
    result = gate.evaluate_preview(ticket, envelope)
    assert result["decision"] == gate.DECISION_UNVERIFIABLE
    assert result["receipt"]["reason"] == "original-digest-mismatch"


def test_current_hit_with_withdrawn_part_is_filtered():
    ticket = make_ticket()
    envelope, _ = gate.build_current_envelope(ticket)
    # Simulate a field withdrawn after this v2 cache was written.
    envelope["parts"]["agent_line"] = policy.clean_public(ticket["raw"]["agent_line"])
    envelope["html"] = envelope["html"] + envelope["parts"]["agent_line"]
    result = gate.evaluate_preview(ticket, envelope)
    assert result["decision"] == gate.DECISION_CURRENT
    assert result["receipt"]["redacted_withdrawn"] == ["agent_line"]
    assert HOTLINE not in result["html"]
    assert "Hello" in result["html"]


def test_unreadable_cache_fails_closed():
    ticket = make_ticket()
    result = gate.evaluate_preview(ticket, None, load_error="cache-unreadable")
    assert result["decision"] == gate.DECISION_UNVERIFIABLE


# ---------------------------------------------------------------------------
# WSGI outlet
# ---------------------------------------------------------------------------

class WSGIClient:
    def __init__(self, app):
        self.app = app

    def get(self, path, headers=None):
        return self._call("GET", path, headers)

    def post(self, path, headers=None):
        return self._call("POST", path, headers)

    def _call(self, method, path, headers):
        from urllib.parse import urlsplit

        parts = urlsplit(path)
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": parts.path,
            "QUERY_STRING": parts.query,
            "wsgi.input": BytesIO(b""),
            "CONTENT_LENGTH": "0",
            "SERVER_NAME": "test",
            "SERVER_PORT": "80",
            "wsgi.url_scheme": "http",
        }
        for key, value in (headers or {}).items():
            environ["HTTP_" + key.upper().replace("-", "_")] = value
        captured = {}

        def start_response(status, resp_headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = resp_headers

        chunks = self.app(environ, start_response)
        text = b"".join(chunks).decode("utf-8")
        code = int(captured["status"].split()[0])
        hdrs = {k.lower(): v for k, v in captured["headers"]}
        return code, hdrs, text


@pytest.fixture()
def client(tmp_path):
    ticket_file = tmp_path / "tickets.json"
    ticket_file.write_text(
        json.dumps({"tickets": [make_ticket()]}), encoding="utf-8"
    )
    tickets = TicketStore(ticket_file)
    caches = CacheStore(tmp_path / "live")
    app = create_app(tickets, caches)
    return WSGIClient(app), caches


def _store(caches, envelope):
    caches.save(TID, envelope)


def test_outlet_triad_over_wsgi(client):
    wsgi, caches = client

    # legacy without original -> 422 unverifiable
    _store(caches, {"rule_version": 1, "html": f"<p>{BID}</p>"})
    code, hdrs, text = wsgi.get(f"/tickets/{TID}/preview?format=json")
    payload = json.loads(text)
    assert code == 422
    assert payload["decision"] == "unverifiable"
    assert hdrs["x-preview-decision"] == "unverifiable"
    assert BID not in text

    # legacy with original -> 200 recleaned
    ticket = make_ticket()
    parts = {
        "summary": ticket["raw"]["summary"],
        "details": ticket["raw"]["details"],
    }
    _store(
        caches,
        {
            "rule_version": 1,
            "original": {"digest": policy.digest_parts(parts), "parts": parts},
        },
    )
    code, hdrs, text = wsgi.get(f"/tickets/{TID}/preview?format=json")
    payload = json.loads(text)
    assert code == 200
    assert payload["decision"] == "recleaned"
    assert BID not in text and "RISK-TEXT" not in text
    assert hdrs["x-preview-decision"] == "recleaned"

    # subsequent hit -> current
    code, _, text = wsgi.get(f"/tickets/{TID}/preview?format=json")
    assert code == 200
    assert json.loads(text)["decision"] == "current"


def test_internal_endpoint_full_data_and_auth(client):
    wsgi, _ = client
    code, _, _ = wsgi.get(f"/internal/tickets/{TID}")
    assert code == 403
    code, hdrs, text = wsgi.get(
        f"/internal/tickets/{TID}", {"X-Staff-Role": "staff"}
    )
    assert code == 200
    assert "no-store" in hdrs.get("cache-control", "")
    assert HOTLINE in text and BID in text


def test_html_outlet_marks_unverifiable(client):
    wsgi, caches = client
    _store(caches, {"rule_version": 1, "html": "<p>x</p>"})
    code, _, text = wsgi.get(f"/tickets/{TID}/preview")
    assert code == 422
    assert 'data-preview-decision="unverifiable"' in text
    assert "暂时无法确认" in text


def test_unknown_or_unsafe_id_is_clean_404(client):
    wsgi, _ = client
    code, _, _ = wsgi.get("/tickets/NOPE/preview?format=json")
    assert code == 404
    # Dots / traversal-ish ids must not reach the filesystem path guard as 500.
    code, _, _ = wsgi.get("/tickets/bad.id/preview?format=json")
    assert code == 404
    code, _, _ = wsgi.get("/tickets/..%2Fetc/preview?format=json")
    assert code == 404
