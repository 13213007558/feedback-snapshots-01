from __future__ import annotations

from collections.abc import Iterator

from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse

from csp.constants import HEADER
from csp.decorators import csp


def html_view(request: HttpRequest) -> HttpResponse:
    return HttpResponse("<html><body>html</body></html>")


def api_view(request: HttpRequest) -> JsonResponse:
    # A view that normally returns JSON, but Django may render its exceptions as HTML.
    raise RuntimeError("boom")


def api_json_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


def streaming_download_view(request: HttpRequest) -> StreamingHttpResponse:
    def chunks() -> Iterator[bytes]:
        # Count every time the underlying stream is iterated (consumed).
        streaming_download_view.iterations += 1
        yield b"chunk-1"
        yield b"chunk-2"

    streaming_download_view.iterations = 0
    return StreamingHttpResponse(
        chunks(),
        content_type="application/octet-stream",
    )


@csp({"default-src": ["'report-only.example'"]}, REPORT_ONLY=True)
def report_only_view(request: HttpRequest) -> HttpResponse:
    response = HttpResponse("<html><body>report only</body></html>")
    # An already-present enforced header must be preserved by the middleware.
    response[HEADER] = "default-src 'preexisting.example'"
    return response
