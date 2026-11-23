from __future__ import annotations

from django.urls import path

from csp.tests import views

urlpatterns = [
    path("html/", views.html_view),
    path("api/error/", views.api_view),
    path("api/json/", views.api_json_view),
    path("download/", views.streaming_download_view),
    path("report-only/", views.report_only_view),
]
