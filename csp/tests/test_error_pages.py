"""End-to-end checks for CSP headers on error pages, redirects and preset headers.

These tests drive the full Django stack through the test client, mirroring the
verification matrix in ``docs/error-pages.rst``. The CSP policy under test is
the one configured in ``csp.tests.settings``:

    default-src 'self' 'nonce-<value>'   (only when request.csp_nonce is read)
"""

from __future__ import annotations

from django.http import HttpResponse, HttpResponseRedirect
from django.template import engines
from django.test import Client, RequestFactory, SimpleTestCase, override_settings

from csp.constants import HEADER, SELF
from csp.exceptions import CSPNonceError
from csp.middleware import CSPMiddleware

MIDDLEWARE = [
    "django.middleware.common.BrokenLinkEmailsMiddleware",
    "csp.middleware.CSPMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "csp.tests.error_urls"

django_engine = engines["django"]
_NONCED_500_TEMPLATE = django_engine.from_string(
    "<html><body><script nonce='{{ request.csp_nonce }}'></script></body></html>"
)


def _nonced_server_error(request):
    # A custom handler500 that renders with the request, so reading
    # request.csp_nonce happens before CSPMiddleware.process_response().
    return HttpResponse(_NONCED_500_TEMPLATE.render({"request": request}, request), status=500)


def boom(request):
    raise RuntimeError("kaboom")


def redirect_view(request):
    return HttpResponseRedirect("/somewhere/")


def preset_header_view(request):
    response = HttpResponseRedirect("/somewhere/")
    response[HEADER] = "default-src preset.example"
    return response


def nonced_view(request):
    template = django_engine.from_string("<script nonce='{{ request.csp_nonce }}'></script>")
    return HttpResponse(template.render({"request": request}, request))


urlpatterns = []


handler500 = "csp.tests.test_error_pages._nonced_server_error"


@override_settings(DEBUG=False, MIDDLEWARE=MIDDLEWARE, ROOT_URLCONF=ROOT_URLCONF)
class ProductionResponseHeaderTests(SimpleTestCase):
    def setUp(self) -> None:
        # Do not let the test client re-raise the view exception; we want the
        # converted 500 response that a real WSGI handler would produce.
        self.client = Client(raise_request_exception=False)

    def test_404_gets_enforced_header_without_nonce(self) -> None:
        response = self.client.get("/does-not-exist/")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers[HEADER], f"default-src {SELF}")
        self.assertNotIn("nonce-", response.headers[HEADER])

    def test_exception_becomes_500_with_header(self) -> None:
        response = self.client.get("/boom/")
        self.assertEqual(response.status_code, 500)
        self.assertTrue(response.headers[HEADER].startswith(f"default-src {SELF}"))

    def test_redirect_gets_header(self) -> None:
        response = self.client.get("/redirect/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers[HEADER], f"default-src {SELF}")

    def test_view_preset_header_is_not_overwritten(self) -> None:
        response = self.client.get("/preset/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers[HEADER], "default-src preset.example")

    def test_nonce_in_header_when_error_template_reads_it(self) -> None:
        response = self.client.get("/boom/")
        self.assertEqual(response.status_code, 500)
        self.assertIn("nonce-", response.headers[HEADER])
        nonce = response.headers[HEADER].split("'nonce-", 1)[1].rstrip("'")
        self.assertIn(f"nonce='{nonce}'", response.content.decode())

    def test_nonce_in_header_for_normal_view(self) -> None:
        response = self.client.get("/nonced/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("nonce-", response.headers[HEADER])


@override_settings(DEBUG=True, MIDDLEWARE=MIDDLEWARE, ROOT_URLCONF=ROOT_URLCONF)
class DebugResponseHeaderTests(SimpleTestCase):
    def setUp(self) -> None:
        self.client = Client(raise_request_exception=False)

    def test_technical_500_is_exempt(self) -> None:
        response = self.client.get("/boom/")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(HEADER, response)

    def test_technical_404_is_exempt(self) -> None:
        response = self.client.get("/does-not-exist/")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(HEADER, response)

    def test_redirect_still_gets_header_in_debug(self) -> None:
        response = self.client.get("/redirect/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers[HEADER], f"default-src {SELF}")


class NonceTimingTests(SimpleTestCase):
    def test_nonce_access_after_header_raises(self) -> None:
        request = RequestFactory().get("/")
        middleware = CSPMiddleware(lambda request: HttpResponse())
        middleware.process_request(request)
        middleware.process_response(request, HttpResponse())
        with self.assertRaises(CSPNonceError):
            str(request.csp_nonce)

    def test_unused_nonce_sentinel_is_stripped(self) -> None:
        request = RequestFactory().get("/")
        middleware = CSPMiddleware(lambda request: HttpResponse())
        middleware.process_request(request)
        response = HttpResponse()
        middleware.process_response(request, response)
        self.assertEqual(response.headers[HEADER], f"default-src {SELF}")
        self.assertNotIn("nonce-", response.headers[HEADER])
