"""
End-to-end examples of the ``{% script %}`` and ``{% style %}`` template tags
working together with ``CSPMiddleware``.

These tests verify that:
- both tags share a single, consistent nonce value within one response,
- that value matches the ``'nonce-...'`` source in the relevant CSP directives,
- a new nonce is generated for the next request.
"""

import re

from django.http import HttpResponse
from django.template import Context, Template
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import HEADER, NONCE, SELF
from csp.middleware import CSPMiddleware
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()

POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF],
        "script-src": [SELF, NONCE],
        "style-src": [SELF, NONCE],
    }
}

TEMPLATE = """
{% load csp %}
{% script %}var hello='world';{% endscript %}
{% style %}.hello { color: red; }{% endstyle %}
"""

NONCE_RE = re.compile(r'nonce="([^"]+)"')


def render_page() -> tuple[str, str]:
    """Render the mixed template through the middleware, return (html, header)."""
    request = rf.get("/")
    mw.process_request(request)
    html = Template(TEMPLATE).render(Context({"request": request}))
    resp = mw.process_response(request, HttpResponse(html))
    return html, resp[HEADER]


@override_settings(CONTENT_SECURITY_POLICY=POLICY)
def test_script_and_style_tags_share_nonce_matching_header() -> None:
    html, header = render_page()

    script_nonce = NONCE_RE.search(html.split("<script", 1)[1]).group(1)  # type: ignore[union-attr]
    style_nonce = NONCE_RE.search(html.split("<style", 1)[1]).group(1)  # type: ignore[union-attr]

    # Both tags in the same response use the same nonce value.
    assert script_nonce == style_nonce

    # The nonce matches the value emitted in each relevant directive.
    assert f"script-src 'self' 'nonce-{script_nonce}'" in header
    assert f"style-src 'self' 'nonce-{style_nonce}'" in header


@override_settings(CONTENT_SECURITY_POLICY=POLICY)
def test_each_request_generates_a_new_nonce() -> None:
    _, first_header = render_page()
    _, second_header = render_page()

    first_nonce = re.search(r"'nonce-([^']+)'", first_header).group(1)  # type: ignore[union-attr]
    second_nonce = re.search(r"'nonce-([^']+)'", second_header).group(1)  # type: ignore[union-attr]

    assert first_nonce != second_nonce
