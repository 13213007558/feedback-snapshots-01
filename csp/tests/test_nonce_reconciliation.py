from __future__ import annotations

import os
from typing import TYPE_CHECKING

from django.conf import settings
from django.http import HttpResponse, StreamingHttpResponse
from django.template import engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
from csp.decorators import csp, csp_update
from csp.exceptions import CSPNonceConflictError
from csp.middleware import CSPMiddleware
from csp.tests.utils import response
from csp.utils import get_nonces_from_body, get_nonces_from_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

rf = RequestFactory()
mw = CSPMiddleware(response())

UPSTREAM_HEADER = "X-Upstream-CSP-Nonce"
UPSTREAM_NONCE = "trusted-upstream-nonce-value"
ENFORCED_POLICY = {"DIRECTIVES": {"default-src": [SELF, NONCE]}}

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _templates_setting() -> list[dict]:
    # Add the local templates directory to the Django template backend's DIRS.
    configured = []
    for backend in settings.TEMPLATES:
        entry = dict(backend)
        if entry["BACKEND"].endswith("django.template.backends.django.DjangoTemplates"):
            entry["DIRS"] = list(entry.get("DIRS", [])) + [_TEMPLATE_DIR]
        configured.append(entry)
    return configured


@pytest.fixture(autouse=True)
def _template_dirs() -> object:
    with override_settings(TEMPLATES=_templates_setting()):
        # Force the engine handler to rebuild backends from the overridden setting.
        from django.template import engines as _engines

        _engines._engines = {}
        yield
        _engines._engines = {}


def _render(template_name: str, request: HttpRequest, **extra: object) -> str:
    template = engines["django"].get_template(template_name)
    return template.render({"request": request, **extra}, request)


def _rendered_response(template_name: str, request: HttpRequest, **extra: object) -> HttpResponse:
    return HttpResponse(_render(template_name, request, **extra))


# ---------------------------------------------------------------------------
# Path 1: Django owns the nonce
# ---------------------------------------------------------------------------


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_django_owned_nonce_matches_enforced_policy() -> None:
    request = rf.get("/")
    mw.process_request(request)

    body = _render("csp/nonced_page.html", request)
    rendered_nonce = next(iter(get_nonces_from_body(body)))

    resp = _rendered_response("csp/nonced_page.html", request)
    result = mw.process_response(request, resp)

    assert result.status_code == 200
    assert rendered_nonce in result[HEADER]
    assert get_nonces_from_policy(result[HEADER]) == {rendered_nonce}
    assert get_nonces_from_body(result.content) == get_nonces_from_policy(result[HEADER])
    assert getattr(request, "_csp_nonce_upstream", False) is False
    reconciliation = getattr(result, "_csp_nonce_reconciled")
    assert reconciliation["status"] == "released"
    assert reconciliation["owner"] == "Django"
    assert reconciliation["body_nonces"] == {rendered_nonce}
    assert reconciliation["enforced_nonces"] == {rendered_nonce}


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_django_owned_nonce_manual_template_tag() -> None:
    request = rf.get("/")
    mw.process_request(request)

    resp = _rendered_response("csp/manual_nonce_page.html", request)
    result = mw.process_response(request, resp)

    body_nonces = get_nonces_from_body(result.content)
    assert body_nonces == get_nonces_from_policy(result[HEADER])
    assert result.status_code == 200


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_django_owned_nonce_with_decorator_response() -> None:
    request = rf.get("/")
    mw.process_request(request)

    @csp_update({"script-src": [NONCE]})
    def decorated_view(req: HttpRequest) -> HttpResponseBase:
        return _rendered_response("csp/nonced_page.html", req)

    resp = decorated_view(request)
    result = mw.process_response(request, resp)

    body_nonces = get_nonces_from_body(result.content)
    assert body_nonces == get_nonces_from_policy(result[HEADER])
    assert result[HEADER].startswith("default-src 'self' 'nonce-")
    assert "script-src 'nonce-" in result[HEADER]


# ---------------------------------------------------------------------------
# Path 2: a trusted upstream proxy owns the nonce
# ---------------------------------------------------------------------------


@override_settings(CONTENT_SECURITY_POLICY={**ENFORCED_POLICY, "UPSTREAM_NONCE_HEADER": UPSTREAM_HEADER})
def test_upstream_owned_nonce_is_used_by_template_and_policy() -> None:
    request = rf.get("/", HTTP_X_UPSTREAM_CSP_NONCE=UPSTREAM_NONCE)
    mw.process_request(request)

    assert str(getattr(request, "csp_nonce")) == UPSTREAM_NONCE
    assert getattr(request, "_csp_nonce_upstream") is True

    body = _render("csp/nonced_page.html", request)
    assert get_nonces_from_body(body) == {UPSTREAM_NONCE}

    resp = _rendered_response("csp/nonced_page.html", request)
    result = mw.process_response(request, resp)

    assert result.status_code == 200
    assert get_nonces_from_policy(result[HEADER]) == {UPSTREAM_NONCE}
    assert get_nonces_from_body(result.content) == get_nonces_from_policy(result[HEADER])
    reconciliation = getattr(result, "_csp_nonce_reconciled")
    assert reconciliation["status"] == "released"
    assert reconciliation["owner"] == "upstream proxy"
    assert reconciliation["body_nonces"] == {UPSTREAM_NONCE}


@override_settings(CONTENT_SECURITY_POLICY={**ENFORCED_POLICY, "UPSTREAM_NONCE_HEADER": UPSTREAM_HEADER})
def test_upstream_nonce_not_guessed_from_untrusted_request_field() -> None:
    # An untrusted header that is not configured must never become the nonce.
    request = rf.get("/", HTTP_X_FORWARDED_NONCE="spoofed")
    mw.process_request(request)

    assert getattr(request, "_csp_nonce_upstream", False) is False
    generated = str(getattr(request, "csp_nonce"))
    assert generated != "spoofed"


@override_settings(CONTENT_SECURITY_POLICY={**ENFORCED_POLICY, "UPSTREAM_NONCE_HEADER": UPSTREAM_HEADER})
def test_upstream_nonce_with_decorator_response() -> None:
    request = rf.get("/", HTTP_X_UPSTREAM_CSP_NONCE=UPSTREAM_NONCE)
    mw.process_request(request)

    @csp({"default-src": [SELF, NONCE]})
    def decorated_view(req: HttpRequest) -> HttpResponseBase:
        return _rendered_response("csp/nonced_page.html", req)

    result = mw.process_response(request, decorated_view(request))

    assert result.status_code == 200
    assert get_nonces_from_body(result.content) == {UPSTREAM_NONCE}
    assert get_nonces_from_policy(result[HEADER]) == {UPSTREAM_NONCE}


# ---------------------------------------------------------------------------
# Path 3: conflicting configuration between the two parties
# ---------------------------------------------------------------------------


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_conflicting_nonce_fails_closed_and_does_not_release_page() -> None:
    request = rf.get("/")
    mw.process_request(request)

    # The template is given a placeholder nonce that differs from the value the
    # middleware will place in the enforced policy.
    resp = _rendered_response("csp/nonce_mismatch.html", request, placeholder_nonce="a-different-placeholder-nonce")

    with pytest.raises(CSPNonceConflictError):
        mw.process_response(request, resp)

    # The unresolved conflict is recorded so the page is never mistaken for approved.
    assert getattr(resp, "_csp_nonce_reconciled") == "conflict"


@override_settings(CONTENT_SECURITY_POLICY={**ENFORCED_POLICY, "UPSTREAM_NONCE_HEADER": UPSTREAM_HEADER})
def test_upstream_nonce_conflicting_with_body_fails_closed() -> None:
    request = rf.get("/", HTTP_X_UPSTREAM_CSP_NONCE=UPSTREAM_NONCE)
    mw.process_request(request)

    # Body renders a placeholder nonce that is not the trusted upstream value.
    resp = _rendered_response("csp/nonce_mismatch.html", request, placeholder_nonce="untrusted-placeholder")

    with pytest.raises(CSPNonceConflictError):
        mw.process_response(request, resp)


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_body_nonce_without_policy_nonce_is_a_conflict() -> None:
    request = rf.get("/")
    mw.process_request(request)

    # A policy that does not advertise any nonce cannot authorize a nonced body.
    @csp({"default-src": [SELF]})
    def decorated_view(req: HttpRequest) -> HttpResponseBase:
        return _rendered_response("csp/nonced_page.html", req)

    with pytest.raises(CSPNonceConflictError):
        mw.process_response(request, decorated_view(request))


# ---------------------------------------------------------------------------
# Streaming / lazy responses are never consumed to inspect their nonces
# ---------------------------------------------------------------------------


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_exempt_response_without_policy_header_is_not_reconciled() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))

    resp = HttpResponse(f'<script nonce="{nonce}"></script>')
    setattr(resp, "_csp_exempt", True)

    result = mw.process_response(request, resp)
    assert HEADER not in result
    assert getattr(result, "_csp_nonce_reconciled") == "no-policy-header"


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_body_without_nonce_attribute_is_left_alone() -> None:
    request = rf.get("/")
    mw.process_request(request)

    resp = HttpResponse("<script>var plain = 1;</script>")
    result = mw.process_response(request, resp)

    assert getattr(result, "_csp_nonce_reconciled") == "no-nonce-in-body"
    assert "nonce-" not in result[HEADER]


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_streaming_response_is_not_consumed_for_reconciliation() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))

    chunks = [f'<script nonce="{nonce}">', 'var hello="world";', "</script>"]
    streamed = StreamingHttpResponse(iter(chunks))

    result = mw.process_response(request, streamed)
    assert isinstance(result, StreamingHttpResponse)
    # Reconciliation is skipped rather than consuming the iterator.
    assert getattr(result, "_csp_nonce_reconciled") == "skipped-streaming"
    # The iterator is still intact and untouched (Django re-encodes chunks to bytes).
    assert b"".join(result.streaming_content) == "".join(chunks).encode("utf-8")
    assert nonce in result[HEADER]


@override_settings(CONTENT_SECURITY_POLICY=ENFORCED_POLICY)
def test_streaming_response_with_mismatched_placeholder_is_not_read() -> None:
    request = rf.get("/")
    mw.process_request(request)

    chunks = ['<script nonce="totally-different-placeholder">', "var x=1;", "</script>"]
    streamed = StreamingHttpResponse(iter(chunks))

    # No conflict is raised because the streaming body is never materialised.
    result = mw.process_response(request, streamed)
    assert isinstance(result, StreamingHttpResponse)
    assert b"".join(result.streaming_content) == "".join(chunks).encode("utf-8")


# ---------------------------------------------------------------------------
# Report-only header is reconciled independently and never blocks delivery
# ---------------------------------------------------------------------------


@override_settings(
    CONTENT_SECURITY_POLICY=ENFORCED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only_mismatch_does_not_block_enforced_response(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = rf.get("/")
    mw.process_request(request)

    resp = _rendered_response("csp/nonced_page.html", request)
    result = mw.process_response(request, resp)

    # Enforced policy matches, so the page is released...
    assert result.status_code == 200
    assert get_nonces_from_body(result.content) == get_nonces_from_policy(result[HEADER])
    # ...while the report-only header carries no nonce and only logs a warning.
    assert HEADER_REPORT_ONLY in result
    assert get_nonces_from_policy(result[HEADER_REPORT_ONLY]) == set()
    assert any("report-only nonce mismatch" in record.getMessage() for record in caplog.records)


@override_settings(
    CONTENT_SECURITY_POLICY=None,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
)
def test_report_only_matching_nonce_is_released() -> None:
    request = rf.get("/")
    mw.process_request(request)

    resp = _rendered_response("csp/nonced_page.html", request)
    result = mw.process_response(request, resp)

    assert result.status_code == 200
    assert HEADER not in result
    assert get_nonces_from_body(result.content) == get_nonces_from_policy(result[HEADER_REPORT_ONLY])
