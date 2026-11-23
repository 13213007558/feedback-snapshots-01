from __future__ import annotations

from typing import Any

from django.http import HttpRequest, HttpResponseBase
from django.shortcuts import render
from django.template.response import TemplateResponse

from csp.constants import NONCE
from csp.decorators import csp_update

TEMPLATES = {
    "django": "django/page.html",
    "jinja": "jinja/page.html",
}


def _context(show_scripts: bool) -> dict[str, Any]:
    return {"show_scripts": show_scripts}


def django_direct(request: HttpRequest, show_scripts: bool) -> HttpResponseBase:
    return render(request, TEMPLATES["django"], _context(show_scripts), using="django")


def django_deferred(request: HttpRequest, show_scripts: bool) -> TemplateResponse:
    return TemplateResponse(request, TEMPLATES["django"], _context(show_scripts), using="django")


def jinja_direct(request: HttpRequest, show_scripts: bool) -> HttpResponseBase:
    return render(request, TEMPLATES["jinja"], _context(show_scripts), using="jinja2")


def jinja_deferred(request: HttpRequest, show_scripts: bool) -> TemplateResponse:
    return TemplateResponse(request, TEMPLATES["jinja"], _context(show_scripts), using="jinja2")


@csp_update({"script-src": ["https://report.example.com", NONCE]}, REPORT_ONLY=True)
def django_report_tweak(request: HttpRequest, show_scripts: bool) -> HttpResponseBase:
    return render(request, TEMPLATES["django"], _context(show_scripts), using="django")
