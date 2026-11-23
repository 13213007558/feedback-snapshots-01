from __future__ import annotations

from django.http import HttpResponse
from django.test import Client, RequestFactory, override_settings

from csp.constants import (
    HEADER,
    HEADER_REPORT_ONLY,
    MEDIA_TYPE_POLICIES,
    NONCE,
    UNKNOWN_MEDIA_TYPE,
    UNKNOWN_MEDIA_TYPE_SKIP,
)
from csp.middleware import CSPMiddleware
from csp.tests import views
from csp.tests.utils import response
from csp.utils import get_response_media_type, resolve_config

mw = CSPMiddleware(response())
rf = RequestFactory()

ROUTED_POLICY = {
    "DIRECTIVES": {"default-src": ["'default.example'"]},
    MEDIA_TYPE_POLICIES: {
        "text/html": {"DIRECTIVES": {"default-src": ["'html.example'"]}},
        "application/json": {"DIRECTIVES": {"default-src": ["'api.example'"]}},
        "application/octet-stream": None,
    },
}

ROUTED_RO_POLICY = {
    "DIRECTIVES": {"default-src": ["'ro-default.example'"]},
    MEDIA_TYPE_POLICIES: {
        "text/html": {"DIRECTIVES": {"default-src": ["'ro-html.example'"]}},
        "application/json": {"DIRECTIVES": {"default-src": ["'ro-api.example'"]}},
        "application/octet-stream": None,
    },
}


# --- Unit tests for the pure selection helpers (no body is ever touched). ---


def test_get_response_media_type_strips_parameters() -> None:
    assert get_response_media_type(HttpResponse(content_type="text/html; charset=utf-8")) == "text/html"


def test_get_response_media_type_normalises_case() -> None:
    resp = HttpResponse(content_type="Application/JSON; charset=utf-8")
    assert get_response_media_type(resp) == "application/json"


def test_get_response_media_type_none_without_header() -> None:
    resp = HttpResponse()
    del resp["Content-Type"]
    assert get_response_media_type(resp) is None


def test_resolve_config_routes_by_media_type() -> None:
    html = HttpResponse(content_type="text/html")
    config, skip = resolve_config(html, ROUTED_POLICY)
    assert config == {"default-src": ["'html.example'"]}
    assert skip is False

    api = HttpResponse(content_type="application/json")
    config, skip = resolve_config(api, ROUTED_POLICY)
    assert config == {"default-src": ["'api.example'"]}
    assert skip is False


def test_resolve_config_disabled_media_type_skips() -> None:
    download = HttpResponse(content_type="application/octet-stream")
    config, skip = resolve_config(download, ROUTED_POLICY)
    assert config is None
    assert skip is True


def test_resolve_config_unknown_media_falls_back_to_default() -> None:
    resp = HttpResponse(content_type="image/png")
    config, skip = resolve_config(resp, ROUTED_POLICY)
    assert config == {"default-src": ["'default.example'"]}
    assert skip is False


def test_resolve_config_missing_media_uses_default_by_default() -> None:
    resp = HttpResponse()
    del resp["Content-Type"]
    config, skip = resolve_config(resp, ROUTED_POLICY)
    assert config == {"default-src": ["'default.example'"]}
    assert skip is False


def test_resolve_config_missing_media_can_skip() -> None:
    policy = {**ROUTED_POLICY, UNKNOWN_MEDIA_TYPE: UNKNOWN_MEDIA_TYPE_SKIP}
    resp = HttpResponse()
    del resp["Content-Type"]
    config, skip = resolve_config(resp, policy)
    assert config is None
    assert skip is True


def test_resolve_config_without_routes_keeps_legacy_behaviour() -> None:
    legacy = {"DIRECTIVES": {"default-src": ["'legacy.example'"]}}
    resp = HttpResponse(content_type="application/octet-stream")
    config, skip = resolve_config(resp, legacy)
    assert config == {"default-src": ["'legacy.example'"]}
    assert skip is False


def test_resolve_config_does_not_consume_stream() -> None:
    def chunks():
        raise AssertionError("streaming body must not be consumed during policy selection")
        yield b"never"  # pragma: no cover

    from django.http import StreamingHttpResponse

    stream = StreamingHttpResponse(chunks(), content_type="application/octet-stream")
    config, skip = resolve_config(stream, ROUTED_POLICY)
    assert skip is True


# --- Integration tests going through the full Django request/response stack. ---


@override_settings(
    ROOT_URLCONF="csp.tests.urls",
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=ROUTED_RO_POLICY,
)
def test_normal_html_gets_html_policy() -> None:
    client = Client()
    resp = client.get("/html/")
    assert resp.headers["Content-Type"].startswith("text/html")
    assert resp.headers[HEADER] == "default-src 'html.example'"
    assert resp.headers[HEADER_REPORT_ONLY] == "default-src 'ro-html.example'"


@override_settings(
    ROOT_URLCONF="csp.tests.urls",
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=ROUTED_RO_POLICY,
)
def test_api_view_rendering_exception_html_uses_html_policy() -> None:
    # The view is an API view (it would normally return JSON), but Django renders the raised
    # exception as an HTML 500 response. The *final* media type, not the view's annotation,
    # decides the policy.
    client = Client(raise_request_exception=False)
    resp = client.get("/api/error/")
    assert resp.status_code == 500
    assert resp.headers["Content-Type"].startswith("text/html")
    assert resp.headers[HEADER] == "default-src 'html.example'"
    assert resp.headers[HEADER_REPORT_ONLY] == "default-src 'ro-html.example'"


@override_settings(
    ROOT_URLCONF="csp.tests.urls",
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=ROUTED_RO_POLICY,
)
def test_successful_api_json_uses_api_policy() -> None:
    client = Client()
    resp = client.get("/api/json/")
    assert resp.headers["Content-Type"].startswith("application/json")
    assert resp.headers[HEADER] == "default-src 'api.example'"
    assert resp.headers[HEADER_REPORT_ONLY] == "default-src 'ro-api.example'"


@override_settings(
    ROOT_URLCONF="csp.tests.urls",
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=ROUTED_RO_POLICY,
)
def test_streaming_download_does_not_iterate_body_and_skips_both_headers() -> None:
    client = Client()
    resp = client.get("/download/")
    assert resp.streaming is True
    assert resp.headers["Content-Type"] == "application/octet-stream"
    # The download media type is explicitly disabled, so neither header is sent.
    assert HEADER not in resp
    assert HEADER_REPORT_ONLY not in resp
    # The middleware must not have consumed the stream while choosing the policy.
    assert views.streaming_download_view.iterations == 0

    # Consuming the response later iterates the underlying stream exactly once.
    content = b"".join(resp.streaming_content)
    assert content == b"chunk-1chunk-2"
    assert views.streaming_download_view.iterations == 1


@override_settings(
    ROOT_URLCONF="csp.tests.urls",
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=ROUTED_RO_POLICY,
)
def test_report_only_view_declaration_and_preexisting_header() -> None:
    client = Client()
    resp = client.get("/report-only/")
    # The view already set the enforced header; the middleware must leave it untouched.
    assert resp.headers[HEADER] == "default-src 'preexisting.example'"
    # The view's report-only declaration is applied on top of the routed report-only base.
    assert resp.headers[HEADER_REPORT_ONLY] == "default-src 'report-only.example'"


@override_settings(
    ROOT_URLCONF="csp.tests.urls",
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'legacy.example'"]}},
)
def test_legacy_config_applies_to_every_media_type() -> None:
    client = Client()
    resp = client.get("/download/")
    assert HEADER in resp
    assert resp.headers[HEADER] == "default-src 'legacy.example'"
    # Drain the stream so the test client does not leave a resource open.
    list(resp.streaming_content)


@override_settings(
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
)
def test_view_update_layers_on_routed_media_type_config() -> None:
    from csp.decorators import csp_update

    @csp_update({"img-src": ["'img.example'"]})
    def view(request):
        return HttpResponse(content_type="text/html")

    request = rf.get("/")
    mw.process_request(request)
    resp = view(request)
    mw.process_response(request, resp)
    directives = sorted(resp[HEADER].split("; "))
    assert directives == ["default-src 'html.example'", "img-src 'img.example'"]


@override_settings(
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
)
def test_view_csp_replace_overrides_routed_config() -> None:
    from csp.decorators import csp

    @csp({"default-src": ["'view.example'"]})
    def view(request):
        # Even on a JSON response, the explicit view declaration wins over media-type routing.
        return HttpResponse(content_type="application/json")

    request = rf.get("/")
    resp = view(request)
    mw.process_response(request, resp)
    assert resp[HEADER] == "default-src 'view.example'"


@override_settings(
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": ["'self'", NONCE]},
        MEDIA_TYPE_POLICIES: {
            "text/html": {"DIRECTIVES": {"default-src": ["'html.example'", NONCE]}},
        },
    },
)
def test_nonce_added_to_routed_html_policy() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    resp = HttpResponse(content_type="text/html")
    mw.process_response(request, resp)
    assert resp[HEADER] == f"default-src 'html.example' 'nonce-{nonce}'"


@override_settings(
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_disabled_media_type_does_not_add_header_without_report_only() -> None:
    request = rf.get("/")
    resp = HttpResponse(content_type="application/octet-stream")
    mw.process_response(request, resp)
    assert HEADER not in resp
    assert HEADER_REPORT_ONLY not in resp


@override_settings(
    MIDDLEWARE=["csp.middleware.CSPMiddleware"],
    CONTENT_SECURITY_POLICY=ROUTED_POLICY,
)
def test_view_exempt_suppresses_routed_header() -> None:
    from csp.decorators import csp_exempt

    @csp_exempt()
    def view(request):
        return HttpResponse(content_type="text/html")

    request = rf.get("/")
    resp = view(request)
    mw.process_response(request, resp)
    assert HEADER not in resp
