from __future__ import annotations

from typing import TYPE_CHECKING

from django.test import RequestFactory, override_settings

from csp.constants import SELF
from csp.utils import build_policy, invalid_view_policies, resolved_view_name, view_policy_config

if TYPE_CHECKING:
    from django.http import HttpRequest

rf = RequestFactory()


class _ResolverMatch:
    def __init__(self, view_name: str | None) -> None:
        self.view_name = view_name


def request_for(view_name: str | None) -> HttpRequest:
    request = rf.get("/ignored/")
    if view_name is not None:
        request.resolver_match = _ResolverMatch(view_name)
    return request


POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF],
        "script-src": ["site.example.com"],
        "form-action": [SELF],
    },
    "VIEW_POLICIES": {
        "employees:profile": {
            "script-src": ["employees.example.com"],
            "form-action": ["forms.employees.example.com"],
        },
        "help:profile": {"script-src": ["help.example.com"]},
        "removed:profile": {"form-action": None},
    },
}


def test_resolved_view_name_prefers_snapshot() -> None:
    request = request_for("resolver:name")
    setattr(request, "_csp_view_name", "snapshot:name")
    assert resolved_view_name(request) == "snapshot:name"


def test_resolved_view_name_without_resolver_match() -> None:
    assert resolved_view_name(rf.get("/")) is None
    assert resolved_view_name(None) is None


def test_view_policy_config_without_policy() -> None:
    assert view_policy_config(None, request_for("employees:profile")) is None


def test_view_policy_config_without_request() -> None:
    assert view_policy_config(POLICY) is POLICY


def test_view_policy_config_unmatched_route_keeps_site_policy() -> None:
    assert view_policy_config(POLICY, request_for("other:view")) is POLICY


def test_view_policy_config_matches_resolved_name_not_url_name() -> None:
    # A route policy can only be selected by the fully qualified name Django
    # resolves; the bare ``url_name`` is not a match.
    assert view_policy_config(POLICY, request_for("profile")) is POLICY


def test_view_policy_config_overrides_directive() -> None:
    effective = view_policy_config(POLICY, request_for("employees:profile"))
    assert effective is not None
    assert effective["DIRECTIVES"] == {
        "default-src": [SELF],
        "script-src": ["employees.example.com"],
        "form-action": ["forms.employees.example.com"],
    }
    # The original policy is not mutated.
    assert POLICY["DIRECTIVES"]["script-src"] == ["site.example.com"]


def test_view_policy_config_keeps_unmentioned_directives() -> None:
    effective = view_policy_config(POLICY, request_for("help:profile"))
    assert effective is not None
    assert effective["DIRECTIVES"]["default-src"] == [SELF]
    assert effective["DIRECTIVES"]["form-action"] == [SELF]
    assert effective["DIRECTIVES"]["script-src"] == ["help.example.com"]


def test_view_policy_config_none_removes_directive() -> None:
    effective = view_policy_config(POLICY, request_for("removed:profile"))
    assert effective is not None
    assert effective["DIRECTIVES"]["form-action"] is None
    assert effective["DIRECTIVES"]["script-src"] == ["site.example.com"]


def test_view_policy_config_accepts_full_policy_entry() -> None:
    policy = {
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["site.example.com"]},
        "VIEW_POLICIES": {"employees:profile": {"DIRECTIVES": {"script-src": ["employees.example.com"]}}},
    }
    effective = view_policy_config(policy, request_for("employees:profile"))
    assert effective is not None
    assert effective["DIRECTIVES"]["script-src"] == ["employees.example.com"]


def policy_eq(a: str, b: str) -> None:
    assert sorted(a.split("; ")) == sorted(b.split("; ")), f"{a!r} != {b!r}"


@override_settings(
    CONTENT_SECURITY_POLICY=POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["report.site.example.com"]},
        "VIEW_POLICIES": {"employees:profile": {"script-src": ["report.employees.example.com"]}},
    },
)
def test_build_policy_uses_route_policy() -> None:
    policy_eq(
        build_policy(request=request_for("employees:profile")),
        "default-src 'self'; script-src employees.example.com; form-action forms.employees.example.com",
    )
    policy_eq(
        build_policy(request=request_for("help:profile")),
        "default-src 'self'; script-src help.example.com; form-action 'self'",
    )
    policy_eq(
        build_policy(request=request_for("other:view")),
        "default-src 'self'; script-src site.example.com; form-action 'self'",
    )


@override_settings(
    CONTENT_SECURITY_POLICY=POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": [SELF], "script-src": ["report.site.example.com"]},
        "VIEW_POLICIES": {"employees:profile": {"script-src": ["report.employees.example.com"]}},
    },
)
def test_build_policy_report_only_route_is_independent() -> None:
    request = request_for("employees:profile")
    assert "script-src employees.example.com" in build_policy(request=request)
    assert "script-src report.employees.example.com" in build_policy(request=request, report_only=True)

    # No route entry for the help center in the report-only setting, so that
    # policy stays at the site value even though the enforced policy differs.
    help_center = request_for("help:profile")
    assert "script-src help.example.com" in build_policy(request=help_center)
    assert "script-src report.site.example.com" in build_policy(request=help_center, report_only=True)


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {"default-src": [SELF]},
        "VIEW_POLICIES": {"employees:profile": {"script-src": ["employees.example.com"]}},
    },
)
def test_build_policy_route_plus_decorator_update() -> None:
    request = request_for("employees:profile")
    policy_eq(
        build_policy(update={"script-src": ["local.example.com"]}, request=request),
        "default-src 'self'; script-src employees.example.com local.example.com",
    )


def test_invalid_view_policies_accepts_missing_and_valid() -> None:
    assert invalid_view_policies(None) == []
    assert invalid_view_policies({"DIRECTIVES": {}}) == []
    assert invalid_view_policies(POLICY) == []


def test_invalid_view_policies_reports_bad_shapes() -> None:
    errors = invalid_view_policies({"VIEW_POLICIES": ["employees:profile"]})
    assert len(errors) == 1

    errors = invalid_view_policies({"VIEW_POLICIES": {"employees:profile": ["script-src"]}})
    assert len(errors) == 1

    errors = invalid_view_policies({"VIEW_POLICIES": {"employees:profile": {"DIRECTIVES": ["script-src"]}}})
    assert len(errors) == 1


def test_invalid_view_policies_reports_unsupported_keys() -> None:
    errors = invalid_view_policies({"VIEW_POLICIES": {"employees:profile": {"DIRECTIVES": {"script-src": ["x"]}, "EXCLUDE_URL_PREFIXES": ["/x"]}}})
    assert len(errors) == 1
    assert "EXCLUDE_URL_PREFIXES" in errors[0]


@override_settings(CONTENT_SECURITY_POLICY={"VIEW_POLICIES": {"employees:profile": ["not", "a", "dict"]}})
def test_build_policy_ignores_malformed_entry() -> None:
    policy_eq(build_policy(request=request_for("employees:profile")), "default-src 'self'")
