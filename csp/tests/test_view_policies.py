from __future__ import annotations

from django.http import HttpResponse
from django.test import Client, override_settings

from csp.constants import HEADER, HEADER_REPORT_ONLY, SELF
from csp.tests.urls_view_policies import profile

SITE_POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF],
        "script-src": ["cdn.example.com"],
        "form-action": [SELF],
    },
    "VIEW_POLICIES": {
        "employees:profile": {
            "script-src": ["scripts.employee.example.com"],
            "form-action": ["forms.employee.example.com"],
        },
        "help:profile": {
            "script-src": ["scripts.help.example.com"],
        },
        "local.profile": {
            "form-action": ["forms.local.example.com"],
        },
        "staff:profile": {
            "script-src": ["scripts.staff.example.com"],
        },
        # This name never matches a resolved view name, so it must not be used.
        "profile": {
            "script-src": ["wrong.example.com"],
        },
    },
}

SITE_POLICY_RO = {
    "DIRECTIVES": {
        "default-src": [SELF],
        "script-src": ["report.cdn.example.com"],
    },
    "VIEW_POLICIES": {
        "employees:profile": {
            "script-src": ["report.employees.example.com"],
            "form-action": ["report.forms.employee.example.com"],
        },
    },
}

URL_SETTINGS = {
    "ROOT_URLCONF": "csp.tests.urls_view_policies",
    "MIDDLEWARE": ["csp.middleware.CSPMiddleware"],
    "ALLOWED_HOSTS": ["testserver"],
    "CONTENT_SECURITY_POLICY": SITE_POLICY,
    "CONTENT_SECURITY_POLICY_REPORT_ONLY": SITE_POLICY_RO,
}

PATH_EMPLOYEES = "/employees/profile/"
PATH_HELP = "/help/profile/"
PATH_STAFF = "/staff/profile/"
PATH_SUPPORT = "/support/profile/"
PATH_LOCAL = "/local/"
PATH_OTHER = "/other/"


def directives(response: HttpResponse, header: str = HEADER) -> list[str]:
    return sorted(response[header].split("; "))


@override_settings(**URL_SETTINGS)
def test_same_view_gets_a_policy_per_mount_point() -> None:
    client = Client()

    employees = client.get(PATH_EMPLOYEES)
    help_center = client.get(PATH_HELP)

    # Both requests were served by the same view function, but Django resolved
    # different names for them and the configured route policies differ.
    assert employees.wsgi_request.resolver_match.view_name == "employees:profile"
    assert help_center.wsgi_request.resolver_match.view_name == "help:profile"
    assert employees.wsgi_request.resolver_match.func is help_center.wsgi_request.resolver_match.func

    assert directives(employees) == [
        "default-src 'self'",
        "form-action forms.employee.example.com",
        "script-src scripts.employee.example.com",
    ]
    assert directives(help_center) == [
        "default-src 'self'",
        "form-action 'self'",
        "script-src scripts.help.example.com",
    ]


@override_settings(**URL_SETTINGS)
def test_acceptance_shows_three_effective_policies() -> None:
    client = Client()

    employees = client.get(PATH_EMPLOYEES)
    help_center = client.get(PATH_HELP)
    local = client.get(PATH_LOCAL)

    policies = {
        "employees": dict(part.split(" ", 1) for part in employees[HEADER].split("; ")),
        "help": dict(part.split(" ", 1) for part in help_center[HEADER].split("; ")),
        "local": dict(part.split(" ", 1) for part in local[HEADER].split("; ")),
    }

    assert policies["employees"]["script-src"] == "scripts.employee.example.com"
    assert policies["employees"]["form-action"] == "forms.employee.example.com"
    assert policies["help"]["script-src"] == "scripts.help.example.com"
    assert policies["help"]["form-action"] == "'self'"
    assert policies["local"]["script-src"] == "cdn.example.com local.example.com"
    assert policies["local"]["form-action"] == "forms.local.example.com"

    # Three distinct effective enforced policies.
    assert len({employees[HEADER], help_center[HEADER], local[HEADER]}) == 3


@override_settings(**URL_SETTINGS)
def test_route_policy_combines_with_view_decorator() -> None:
    response = Client().get(PATH_LOCAL)

    assert response.wsgi_request.resolver_match.view_name == "local.profile"
    # The route policy sets form-action; the view decorator appends to the
    # site-wide script-src on top of the directives selected for the route.
    assert directives(response) == [
        "default-src 'self'",
        "form-action forms.local.example.com",
        "script-src cdn.example.com local.example.com",
    ]


@override_settings(**URL_SETTINGS)
def test_decorated_view_gets_route_policy_only_at_the_matching_mount() -> None:
    staff = Client().get(PATH_STAFF)
    support = Client().get(PATH_SUPPORT)

    assert staff.wsgi_request.resolver_match.view_name == "staff:profile"
    assert support.wsgi_request.resolver_match.view_name == "support:profile"
    assert staff.wsgi_request.resolver_match.func is support.wsgi_request.resolver_match.func

    # The route policy replaces the site-wide script-src, then the view
    # decorator appends its own source.
    assert directives(staff) == [
        "default-src 'self'",
        "form-action 'self'",
        "script-src scripts.staff.example.com local.example.com",
    ]
    # The other mount point has no entry, so the decorator appends to the
    # site-wide script-src.
    assert directives(support) == [
        "default-src 'self'",
        "form-action 'self'",
        "script-src cdn.example.com local.example.com",
    ]


@override_settings(**URL_SETTINGS)
def test_unmatched_route_keeps_site_policy() -> None:
    response = Client().get(PATH_OTHER)

    assert response.wsgi_request.resolver_match.view_name == "other"
    assert directives(response) == [
        "default-src 'self'",
        "form-action 'self'",
        "script-src cdn.example.com",
    ]


@override_settings(**URL_SETTINGS)
def test_enforced_and_report_only_route_policies_are_independent() -> None:
    response = Client().get(PATH_EMPLOYEES)

    assert directives(response, HEADER) == [
        "default-src 'self'",
        "form-action forms.employee.example.com",
        "script-src scripts.employee.example.com",
    ]
    assert directives(response, HEADER_REPORT_ONLY) == [
        "default-src 'self'",
        "form-action report.forms.employee.example.com",
        "script-src report.employees.example.com",
    ]

    # The help center has no report-only route policy, so its report-only
    # policy is the site policy even though its enforced policy is overridden.
    help_center = Client().get(PATH_HELP)
    assert directives(help_center, HEADER) == [
        "default-src 'self'",
        "form-action 'self'",
        "script-src scripts.help.example.com",
    ]
    assert directives(help_center, HEADER_REPORT_ONLY) == [
        "default-src 'self'",
        "script-src report.cdn.example.com",
    ]


@override_settings(**URL_SETTINGS)
def test_request_order_does_not_change_effective_policies() -> None:
    client = Client()
    paths = [PATH_EMPLOYEES, PATH_HELP, PATH_STAFF, PATH_SUPPORT, PATH_LOCAL, PATH_OTHER]

    def collect(order: list[str]) -> dict[str, tuple[str | None, str | None]]:
        result = {}
        for path in order:
            response = client.get(path)
            result[path] = (
                response.headers.get(HEADER),
                response.headers.get(HEADER_REPORT_ONLY),
            )
        return result

    forward = collect(paths)
    backward = collect(list(reversed(paths)))

    assert forward == backward
    assert len({value[0] for value in forward.values()}) == 6


@override_settings(**URL_SETTINGS)
def test_site_policy_is_not_mutated_between_requests() -> None:
    client = Client()
    client.get(PATH_EMPLOYEES)
    client.get(PATH_LOCAL)

    # The shared settings dictionaries are unchanged after requests that
    # overlay route policies and view decorators.
    assert SITE_POLICY["DIRECTIVES"]["script-src"] == ["cdn.example.com"]
    assert SITE_POLICY["DIRECTIVES"]["form-action"] == [SELF]
    assert SITE_POLICY["VIEW_POLICIES"]["employees:profile"]["script-src"] == ["scripts.employee.example.com"]
    assert SITE_POLICY["VIEW_POLICIES"]["local.profile"]["form-action"] == ["forms.local.example.com"]

    # The view function still carries only its own decorator configuration.
    assert getattr(profile, "__wrapped__", None) is None
