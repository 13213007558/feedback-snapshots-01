import copy
from unittest import mock

from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.contrib.rate_limiting import RateLimitedCSPMiddleware
from csp.constants import HEADER, HEADER_REPORT_ONLY, SELF
from csp.decorators import csp_replace
from csp.tests.utils import response

mw = RateLimitedCSPMiddleware(response())
rf = RequestFactory()


@override_settings(CONTENT_SECURITY_POLICY={"REPORT_PERCENTAGE": 10, "DIRECTIVES": {"report-uri": "x"}})
def test_report_percentage() -> None:
    times_seen = 0
    for _ in range(5000):
        request = rf.get("/")
        response = HttpResponse()
        mw.process_response(request, response)
        if "report-uri" in response[HEADER]:
            times_seen += 1
        if "report-to" in response[HEADER]:
            times_seen += 1
    # Roughly 10%
    assert 400 <= times_seen <= 600


@override_settings(CONTENT_SECURITY_POLICY={"REPORT_PERCENTAGE": 9.9, "DIRECTIVES": {"report-uri": "x"}})
def test_report_percentage_float() -> None:
    times_seen = 0
    for _ in range(5000):
        request = rf.get("/")
        response = HttpResponse()
        mw.process_response(request, response)
        if "report-uri" in response[HEADER]:
            times_seen += 1
        if "report-to" in response[HEADER]:
            times_seen += 1
    # Roughly 10%
    assert 400 <= times_seen <= 600


@override_settings(CONTENT_SECURITY_POLICY={"REPORT_PERCENTAGE": 100, "DIRECTIVES": {"report-uri": "x"}})
def test_report_percentage_100() -> None:
    times_seen = 0
    for _ in range(1000):
        request = rf.get("/")
        response = HttpResponse()
        mw.process_response(request, response)
        if "report-uri" in response[HEADER]:
            times_seen += 1
        if "report-to" in response[HEADER]:
            times_seen += 1
    assert times_seen == 1000


@override_settings(CONTENT_SECURITY_POLICY_REPORT_ONLY={"REPORT_PERCENTAGE": 10, "DIRECTIVES": {"report-uri": "x"}})
def test_report_percentage_report_only() -> None:
    times_seen = 0
    for _ in range(5000):
        request = rf.get("/")
        response = HttpResponse()
        mw.process_response(request, response)
        if "report-uri" in response[HEADER_REPORT_ONLY]:
            times_seen += 1
    # Roughly 10%
    assert 400 <= times_seen <= 600


@override_settings(CONTENT_SECURITY_POLICY=None)
def test_no_csp() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(CONTENT_SECURITY_POLICY_REPORT_ONLY=None)
def test_no_csp_ro() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response


@override_settings(
    CONTENT_SECURITY_POLICY={"REPORT_PERCENTAGE": 50, "DIRECTIVES": {"report-uri": "/report/", "report-to": "csp"}},
)
def test_shared_replace_config_not_mutated() -> None:
    shared_config: dict = {"default-src": [SELF], "report-to": "csp-endpoint"}
    snapshot = copy.deepcopy(shared_config)

    @csp_replace(shared_config)
    def view_one(request: HttpRequest) -> HttpResponse:
        return HttpResponse()

    @csp_replace(shared_config)
    def view_two(request: HttpRequest) -> HttpResponse:
        return HttpResponse()

    # First request is not sampled: reporting directives are omitted for this response only.
    with mock.patch("csp.contrib.rate_limiting.random.random", return_value=0.9):
        request = rf.get("/")
        response = view_one(request)
        mw.process_response(request, response)
    assert "report-uri" not in response[HEADER]
    assert "report-to" not in response[HEADER]
    assert f"default-src {SELF}" in response[HEADER]

    # Second request is sampled: the full reporting directives come from the original policy.
    with mock.patch("csp.contrib.rate_limiting.random.random", return_value=0.1):
        request = rf.get("/")
        response = view_two(request)
        mw.process_response(request, response)
    assert "report-uri /report/" in response[HEADER]
    assert "report-to csp-endpoint" in response[HEADER]

    # The decorator config shared by both views is unchanged.
    assert shared_config == snapshot


@override_settings(
    CONTENT_SECURITY_POLICY={"REPORT_PERCENTAGE": 50, "DIRECTIVES": {"report-uri": "/enforce/"}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"REPORT_PERCENTAGE": 50, "DIRECTIVES": {"report-uri": "/report-only/"}},
)
def test_report_percentage_independent_per_policy() -> None:
    # The enforced policy is not sampled while the report-only policy is.
    with mock.patch("csp.contrib.rate_limiting.random.random", side_effect=[0.9, 0.1]):
        request = rf.get("/")
        response = HttpResponse()
        mw.process_response(request, response)
    assert "report-uri" not in response[HEADER]
    assert "report-uri /report-only/" in response[HEADER_REPORT_ONLY]
