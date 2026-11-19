from django.urls import path

from csp.tests.test_error_pages import (
    boom,
    nonced_view,
    preset_header_view,
    redirect_view,
)

urlpatterns = [
    path("boom/", boom),
    path("redirect/", redirect_view),
    path("preset/", preset_header_view),
    path("nonced/", nonced_view),
]

handler500 = "csp.tests.test_error_pages._nonced_server_error"
