from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
)
from django.template import Context, Template, engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, SELF
from csp.exceptions import CSPNonceError
from csp.middleware import (
    DECISION_DEBUG_EXEMPT,
    DECISION_EXCLUDED,
    DECISION_EXEMPT,
    DECISION_GENERATED,
    DECISION_NOT_CONFIGURED,
    DECISION_PRESET,
    CheckableLazyObject,
    CSPMiddleware,
    PolicyDecision,
)
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()


class DiagnosticsMiddleware(CSPMiddleware):
    """A middleware that collects policy decisions in memory."""

    def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self.decisions: list[PolicyDecision] = []
        self.diagnostics_callback = self.decisions.append


def test_checkable_lazy_object() -> None:
    def generate_value() -> str:
        return "generated"

    lazy = CheckableLazyObject(generate_value)

    # Before wrapped object is initiated, lazy is falsy
    assert bool(lazy) is False

    # After str(lazy) calls generate_value, lazy is truthy
    assert str(lazy) == "generated"
    assert bool(lazy) is True


def test_add_header() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["example.com"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_both_headers() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": {"example.com"}}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": {SELF}}},
)
def test_directives_configured_as_sets() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


def test_exempt() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_exempt", True)
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": ["/inlines-r-us"]})
def test_exclude() -> None:
    request = rf.get("/inlines-r-us/foo")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(
    CONTENT_SECURITY_POLICY=None,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response
    assert HEADER_REPORT_ONLY in response
    assert response[HEADER_REPORT_ONLY] == "default-src 'self'"


def test_dont_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    response[HEADER] = "default-src example.com"
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_config() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_config", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_update() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_update", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self' example.com"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_use_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_replace", {"img-src": ["bar.com"]})
    mw.process_response(request, response)
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


@override_settings(DEBUG=True)
def test_debug_errors_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseServerError()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(DEBUG=True)
def test_debug_notfound_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseNotFound()
    mw.process_response(request, response)
    assert HEADER not in response


def test_nonce_created_when_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    mw.process_response(request, response)
    assert nonce in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


def test_nonce_is_false_before_access_and_true_after() -> None:
    request = rf.get("/")
    mw.process_request(request)
    assert bool(getattr(request, "csp_nonce")) is False
    nonce = str(getattr(request, "csp_nonce"))
    assert bool(getattr(request, "csp_nonce")) is True

    response = HttpResponse()
    mw.process_response(request, response)
    assert bool(getattr(request, "csp_nonce")) is True
    assert getattr(request, "csp_nonce") == nonce


def test_nonce_conditional_in_django_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = Template(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_django_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = Template("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_nonce_conditional_in_jinja2_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = engines["jinja2"].from_string(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_jinja2_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = engines["jinja2"].from_string("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_no_nonce_when_not_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = HttpResponse()
    mw.process_response(request, response)
    assert "nonce-" not in response[HEADER]
    assert response[HEADER] == "default-src 'self'"


def test_nonce_regenerated_on_new_request() -> None:
    request1 = rf.get("/")
    request2 = rf.get("/")
    mw.process_request(request1)
    mw.process_request(request2)
    nonce1 = str(getattr(request1, "csp_nonce"))
    nonce2 = str(getattr(request2, "csp_nonce"))
    assert nonce1 != nonce2

    response1 = HttpResponse()
    response2 = HttpResponse()
    mw.process_response(request1, response1)
    mw.process_response(request2, response2)
    assert nonce1 not in response2[HEADER]
    assert nonce2 not in response1[HEADER]


def test_no_nonce_access_after_middleware_is_attribute_error() -> None:
    # Test `CSPNonceError` is raised when accessing an unset nonce after the response has been processed.
    request = rf.get("/")
    mw.process_request(request)
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", True)) is False
    with pytest.raises(CSPNonceError):
        str(getattr(request, "csp_nonce"))


def test_set_nonce_access_after_middleware_is_ok() -> None:
    # Test accessing a set nonce after the response has been processed is OK.
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", False)) is True
    assert str(getattr(request, "csp_nonce")) == nonce


def test_diagnostics_generated_and_not_configured() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/some/path/")
    diag_mw.process_response(request, HttpResponse())
    assert diag_mw.decisions == [
        PolicyDecision(header=HEADER, report_only=False, decision=DECISION_GENERATED, path="/some/path/"),
        PolicyDecision(header=HEADER_REPORT_ONLY, report_only=True, decision=DECISION_NOT_CONFIGURED, path="/some/path/"),
    ]


@override_settings(CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}})
def test_diagnostics_report_only_generated() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    diag_mw.process_response(request, HttpResponse())
    assert [d.decision for d in diag_mw.decisions] == [DECISION_GENERATED, DECISION_GENERATED]


def test_diagnostics_preset_by_view() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    resp = HttpResponse()
    resp[HEADER] = "default-src example.com"
    diag_mw.process_response(request, resp)
    assert resp[HEADER] == "default-src example.com"
    assert diag_mw.decisions[0] == PolicyDecision(
        header=HEADER, report_only=False, decision=DECISION_PRESET, path="/"
    )


def test_diagnostics_exempt() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    resp = HttpResponse()
    setattr(resp, "_csp_exempt", True)
    diag_mw.process_response(request, resp)
    assert HEADER not in resp
    assert diag_mw.decisions[0].decision == DECISION_EXEMPT


@override_settings(CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}})
def test_diagnostics_report_only_exempt() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    resp = HttpResponse()
    setattr(resp, "_csp_exempt_ro", True)
    diag_mw.process_response(request, resp)
    assert [d.decision for d in diag_mw.decisions] == [DECISION_GENERATED, DECISION_EXEMPT]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}, "EXCLUDE_URL_PREFIXES": ["/excluded"]})
def test_diagnostics_excluded_url_prefix() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/excluded/page")
    resp = HttpResponse()
    diag_mw.process_response(request, resp)
    assert HEADER not in resp
    assert diag_mw.decisions[0] == PolicyDecision(
        header=HEADER, report_only=False, decision=DECISION_EXCLUDED, path="/excluded/page"
    )


@override_settings(CONTENT_SECURITY_POLICY=None, CONTENT_SECURITY_POLICY_REPORT_ONLY=None)
def test_diagnostics_not_configured() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    resp = HttpResponse()
    diag_mw.process_response(request, resp)
    assert HEADER not in resp
    assert HEADER_REPORT_ONLY not in resp
    assert [d.decision for d in diag_mw.decisions] == [DECISION_NOT_CONFIGURED, DECISION_NOT_CONFIGURED]


@override_settings(DEBUG=True)
def test_diagnostics_debug_exempt() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    diag_mw.process_response(request, HttpResponseServerError())
    assert [d.decision for d in diag_mw.decisions] == [DECISION_DEBUG_EXEMPT, DECISION_DEBUG_EXEMPT]


def test_diagnostics_contain_no_nonce_or_header_values() -> None:
    diag_mw = DiagnosticsMiddleware(response())
    request = rf.get("/")
    diag_mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    resp = HttpResponse()
    diag_mw.process_response(request, resp)
    # The nonce and policy made it into the real header...
    assert nonce in resp[HEADER]
    # ...but neither appears anywhere in the diagnostics records.
    recorded = repr(diag_mw.decisions)
    assert nonce not in recorded
    assert resp[HEADER] not in recorded
    assert "default-src" not in recorded
