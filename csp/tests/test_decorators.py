from __future__ import annotations

import asyncio
import inspect
from typing import TYPE_CHECKING

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest
from asgiref.sync import iscoroutinefunction

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE
from csp.decorators import csp, csp_exempt, csp_replace, csp_update
from csp.middleware import CSPMiddleware
from csp.tests.utils import response

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

mw = CSPMiddleware(response())


def test_csp_exempt() -> None:
    @csp_exempt()
    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view(RequestFactory().get("/"))
    assert getattr(response, "_csp_exempt") is True
    assert not hasattr(response, "_csp_exempt_ro")


def test_csp_exempt_ro() -> None:
    @csp_exempt(REPORT_ONLY=True)
    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view(RequestFactory().get("/"))
    assert not hasattr(response, "_csp_exempt")
    assert getattr(response, "_csp_exempt_ro") is True


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_update() -> None:
    request = RequestFactory().get("/")

    def view_without_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]

    @csp_update({"img-src": ["bar.com", NONCE]})
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_update") == {"img-src": ["bar.com", NONCE]}
    mw.process_request(request)
    csp_nonce = str(getattr(request, "csp_nonce"))  # This also triggers the nonce creation.
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", f"img-src foo.com bar.com 'nonce-{csp_nonce}'"]

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]


@override_settings(CONTENT_SECURITY_POLICY=None, CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_update_ro() -> None:
    request = RequestFactory().get("/")

    def view_without_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]

    @csp_update({"img-src": ["bar.com", NONCE]}, REPORT_ONLY=True)
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_update_ro") == {"img-src": ["bar.com", NONCE]}
    mw.process_request(request)
    csp_nonce = str(getattr(request, "csp_nonce"))  # This also triggers the nonce creation.
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", f"img-src foo.com bar.com 'nonce-{csp_nonce}'"]

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_replace() -> None:
    request = RequestFactory().get("/")

    def view_without_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]

    @csp_replace({"img-src": ["bar.com"]})
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_replace") == {"img-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]

    @csp_replace({"img-src": None})
    def view_removing_directive(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_removing_directive(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'"]


@override_settings(CONTENT_SECURITY_POLICY=None, CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_replace_ro() -> None:
    request = RequestFactory().get("/")

    def view_without_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]

    @csp_replace({"img-src": ["bar.com"]}, REPORT_ONLY=True)
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_replace_ro") == {"img-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com"]

    @csp_replace({"img-src": None}, REPORT_ONLY=True)
    def view_removing_directive(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_removing_directive(request)
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'"]


def test_csp() -> None:
    request = RequestFactory().get("/")

    def view_without_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'"]

    @csp({"img-src": ["foo.com"], "font-src": ["bar.com"]})
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_config") == {"img-src": ["foo.com"], "font-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["font-src bar.com", "img-src foo.com"]

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'"]


def test_csp_ro() -> None:
    request = RequestFactory().get("/")

    def view_without_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'"]

    @csp({"img-src": ["foo.com"], "font-src": ["bar.com"]}, REPORT_ONLY=True)
    @csp({})  # CSP with no directives effectively removes the header.
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_config_ro") == {"img-src": ["foo.com"], "font-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["font-src bar.com", "img-src foo.com"]

    response = view_without_decorator(request)
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'"]


def test_csp_string_values() -> None:
    # Test backwards compatibility where values were strings
    request = RequestFactory().get("/")

    @csp({"img-src": "foo.com", "font-src": "bar.com"})
    def view_with_decorator(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = view_with_decorator(request)
    assert getattr(response, "_csp_config") == {"img-src": ["foo.com"], "font-src": ["bar.com"]}
    mw.process_response(request, response)
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["font-src bar.com", "img-src foo.com"]


# Deprecation tests


def test_csp_exempt_error() -> None:
    with pytest.raises(RuntimeError) as excinfo:
        # Ignore type error since we're checking for the exception raised for 3.x syntax
        @csp_exempt  # type: ignore
        def view(request: HttpRequest) -> HttpResponseBase:
            return HttpResponse()

    assert "Incompatible `csp_exempt` decorator usage" in str(excinfo.value)


def test_csp_update_error() -> None:
    with pytest.raises(RuntimeError) as excinfo:

        @csp_update(IMG_SRC="bar.com")
        def view(request: HttpRequest) -> HttpResponseBase:
            return HttpResponse()

    assert "Incompatible `csp_update` decorator arguments" in str(excinfo.value)


def test_csp_replace_error() -> None:
    with pytest.raises(RuntimeError) as excinfo:

        @csp_replace(IMG_SRC="bar.com")
        def view(request: HttpRequest) -> HttpResponseBase:
            return HttpResponse()

    assert "Incompatible `csp_replace` decorator arguments" in str(excinfo.value)


def test_csp_error() -> None:
    with pytest.raises(RuntimeError) as excinfo:

        @csp(IMG_SRC=["bar.com"])
        def view(request: HttpRequest) -> HttpResponseBase:
            return HttpResponse()

    assert "Incompatible `csp` decorator arguments" in str(excinfo.value)


# Async view tests


def test_csp_exempt_async() -> None:
    @csp_exempt()
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(RequestFactory().get("/")))
    assert getattr(response, "_csp_exempt") is True
    assert not hasattr(response, "_csp_exempt_ro")


def test_csp_exempt_ro_async() -> None:
    @csp_exempt(REPORT_ONLY=True)
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(RequestFactory().get("/")))
    assert not hasattr(response, "_csp_exempt")
    assert getattr(response, "_csp_exempt_ro") is True


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_update_async() -> None:
    request = RequestFactory().get("/")

    @csp_update({"img-src": ["bar.com"]})
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(request))
    assert getattr(response, "_csp_update") == {"img-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com bar.com"]


@override_settings(CONTENT_SECURITY_POLICY=None, CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_update_ro_async() -> None:
    request = RequestFactory().get("/")

    @csp_update({"img-src": ["bar.com"]}, REPORT_ONLY=True)
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(request))
    assert getattr(response, "_csp_update_ro") == {"img-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src foo.com bar.com"]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_replace_async() -> None:
    request = RequestFactory().get("/")

    @csp_replace({"img-src": ["bar.com"]})
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(request))
    assert getattr(response, "_csp_replace") == {"img-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


@override_settings(CONTENT_SECURITY_POLICY=None, CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_csp_replace_ro_async() -> None:
    request = RequestFactory().get("/")

    @csp_replace({"img-src": ["bar.com"]}, REPORT_ONLY=True)
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(request))
    assert getattr(response, "_csp_replace_ro") == {"img-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


def test_csp_async() -> None:
    request = RequestFactory().get("/")

    @csp({"img-src": ["foo.com"], "font-src": ["bar.com"]})
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(request))
    assert getattr(response, "_csp_config") == {"img-src": ["foo.com"], "font-src": ["bar.com"]}
    mw.process_response(request, response)
    assert HEADER_REPORT_ONLY not in response.headers
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["font-src bar.com", "img-src foo.com"]


def test_csp_ro_async() -> None:
    request = RequestFactory().get("/")

    @csp({"img-src": ["foo.com"]}, REPORT_ONLY=True)
    @csp({})  # CSP with no directives effectively removes the header.
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    response = asyncio.run(view(request))
    assert getattr(response, "_csp_config_ro") == {"img-src": ["foo.com"]}
    mw.process_response(request, response)
    assert HEADER not in response.headers
    policy_list = sorted(response[HEADER_REPORT_ONLY].split("; "))
    assert policy_list == ["img-src foo.com"]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_async_interleaved_responses_keep_own_overrides() -> None:
    async def main() -> None:
        entered_a = asyncio.Event()
        release_a = asyncio.Event()

        @csp_replace({"img-src": ["a.com"]})
        async def view_a(request: HttpRequest) -> HttpResponseBase:
            entered_a.set()
            await release_a.wait()
            return HttpResponse()

        @csp_update({"img-src": ["b.com"]})
        async def view_b(request: HttpRequest) -> HttpResponseBase:
            return HttpResponse()

        @csp_replace({"img-src": ["sync.com"]})
        def view_sync(request: HttpRequest) -> HttpResponseBase:
            return HttpResponse()

        request_a = RequestFactory().get("/")
        request_b = RequestFactory().get("/")
        request_sync = RequestFactory().get("/")

        # Interleave: view_a suspends mid-request, view_b and the sync view
        # run to completion, then view_a resumes.
        task_a = asyncio.ensure_future(view_a(request_a))
        await entered_a.wait()
        response_b = await view_b(request_b)
        response_sync = view_sync(request_sync)
        release_a.set()
        response_a = await task_a

        mw.process_response(request_a, response_a)
        mw.process_response(request_b, response_b)
        mw.process_response(request_sync, response_sync)

        assert getattr(response_a, "_csp_replace") == {"img-src": ["a.com"]}
        assert getattr(response_b, "_csp_update") == {"img-src": ["b.com"]}
        assert getattr(response_sync, "_csp_replace") == {"img-src": ["sync.com"]}
        assert "img-src a.com" in response_a[HEADER]
        assert "img-src foo.com b.com" in response_b[HEADER]
        assert "img-src sync.com" in response_sync[HEADER]

    asyncio.run(main())


def test_async_view_still_coroutine_function() -> None:
    @csp_exempt()
    async def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    # Same check Django's request handler uses (django.core.handlers.base).
    assert iscoroutinefunction(view)
    assert inspect.iscoroutinefunction(view)


def test_sync_view_not_coroutine_function() -> None:
    @csp_replace({"img-src": ["bar.com"]})
    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    assert not iscoroutinefunction(view)
    assert not inspect.iscoroutinefunction(view)


def test_async_view_exception_propagates() -> None:
    @csp_update({"img-src": ["bar.com"]})
    async def view(request: HttpRequest) -> HttpResponseBase:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        asyncio.run(view(RequestFactory().get("/")))


def test_sync_view_exception_propagates() -> None:
    @csp_update({"img-src": ["bar.com"]})
    def view(request: HttpRequest) -> HttpResponseBase:
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        view(RequestFactory().get("/"))
