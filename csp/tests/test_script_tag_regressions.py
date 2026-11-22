from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from django.http import HttpResponse
from django.template import Context, Template, engines
from django.test import RequestFactory

from csp.constants import HEADER
from csp.middleware import CSPMiddleware
from csp.tests.utils import response

if TYPE_CHECKING:
    from django.http import HttpRequest

mw = CSPMiddleware(response())
rf = RequestFactory()

SCRIPT_BODY = "var hello='world';"
NONCE_RE = re.compile(r'nonce="([^"]+)"')
PLAIN_BODY = "plain body, no protected script tag"


def expected_script(element_id: str) -> str:
    # The literal `{nonce}` is filled in once the rendered nonce has been extracted from the body.
    return f'<script nonce="{{nonce}}" id="{element_id}" type="application/javascript" defer>{SCRIPT_BODY}</script>'


class ScriptTagRegressionBase(ABC):
    """End-to-end regressions shared by the Django template tag and the Jinja2 extension.

    Every scenario renders through the middleware so the CSP header and the response
    body are observed together, rather than only checking that a nonce was fetched.
    """

    include_template_name = ""
    direct_template = ""
    include_parent_template = ""

    @abstractmethod
    def render_string(self, template_string: str, request: HttpRequest) -> str: ...

    def render_response(self, template_string: str) -> tuple[HttpRequest, HttpResponse]:
        request = rf.get("/")
        mw.process_request(request)
        body = self.render_string(template_string, request)
        http_response = HttpResponse(body)
        mw.process_response(request, http_response)
        return request, http_response

    def assert_protected_script_response(self, template_string: str, element_id: str) -> None:
        request, http_response = self.render_response(template_string)

        body = http_response.content.decode()
        match = NONCE_RE.search(body)
        assert match is not None
        nonce = match.group(1)

        # The full tag, including its attributes and body, is observable in the response.
        assert expected_script(element_id).format(nonce=nonce) in body
        # The nonce rendered in the body is the one attached to the request.
        assert nonce == str(request.csp_nonce)
        # The same nonce must be present in the actual CSP header.
        assert http_response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"

    def test_direct_render_injects_nonce_into_body_and_header(self) -> None:
        self.assert_protected_script_response(self.direct_template, "jeff")

    def test_rendered_through_include_injects_nonce_into_body_and_header(self) -> None:
        self.assert_protected_script_response(self.include_parent_template, "included")

    def test_response_without_protected_tag_has_no_nonce(self) -> None:
        request, http_response = self.render_response(PLAIN_BODY)

        assert http_response.content.decode() == PLAIN_BODY
        assert "nonce-" not in http_response[HEADER]
        assert http_response[HEADER] == "default-src 'self'"
        assert bool(request.csp_nonce) is False


class TestDjangoScriptTagRegression(ScriptTagRegressionBase):
    include_template_name = "csp/_included_script.html"

    direct_template = """
        {% load csp %}
        {% script type="application/javascript" id="jeff" defer=True %}
            var hello='world';
        {% endscript %}
    """
    include_parent_template = f'{{% include "{include_template_name}" %}}'

    def render_string(self, template_string: str, request: HttpRequest) -> str:
        return Template(template_string).render(Context({"request": request}))


class TestJinjaScriptTagRegression(ScriptTagRegressionBase):
    include_template_name = "csp/_included_script.jinja"

    direct_template = """
        {% script type="application/javascript" id="jeff" defer=True %}
            var hello='world';
        {% endscript %}
    """
    include_parent_template = f'{{% include "{include_template_name}" %}}'

    def render_string(self, template_string: str, request: HttpRequest) -> str:
        template = engines["jinja2"].from_string(template_string)
        return template.render({"request": request})
