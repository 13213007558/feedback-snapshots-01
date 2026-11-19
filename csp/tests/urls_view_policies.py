from __future__ import annotations

from django.http import HttpRequest, HttpResponse
from django.urls import include, path

from csp.decorators import csp_update


def profile(request: HttpRequest) -> HttpResponse:
    return HttpResponse("profile")


@csp_update({"script-src": ["local.example.com"]})
def decorated_profile(request: HttpRequest) -> HttpResponse:
    return HttpResponse("decorated profile")


def other(request: HttpRequest) -> HttpResponse:
    return HttpResponse("other")


# One decorated view function mounted under two namespaces.
shared_view = csp_update({"script-src": ["local.example.com"]})(profile)

employees_patterns = [path("profile/", profile, name="profile")]
help_center_patterns = [path("profile/", profile, name="profile")]
staff_patterns = [path("profile/", shared_view, name="profile")]
support_patterns = [path("profile/", shared_view, name="profile")]

urlpatterns = [
    path("employees/", include((employees_patterns, "employees"), namespace="employees")),
    path("help/", include((help_center_patterns, "help"), namespace="help")),
    path("staff/", include((staff_patterns, "staff"), namespace="staff")),
    path("support/", include((support_patterns, "support"), namespace="support")),
    path("local/", decorated_profile, name="local.profile"),
    path("other/", other, name="other"),
]
