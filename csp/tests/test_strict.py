from django.core.exceptions import ImproperlyConfigured
from django.test.utils import override_settings

import pytest

from csp.checks import check_strict_directives
from csp.constants import NONE, SELF
from csp.decorators import csp, csp_replace, csp_update
from csp.strict import summarize_directives, validate_directives, validate_directives_or_raise

ORIGIN = 'CONTENT_SECURITY_POLICY["DIRECTIVES"]'


def codes(issues):
    return [issue.code for issue in issues]


def test_explicit_removal_is_valid() -> None:
    assert validate_directives({"frame-ancestors": None}, origin=ORIGIN) == []


def test_flag_directive_bool_values_are_valid() -> None:
    assert validate_directives({"upgrade-insecure-requests": True}, origin=ORIGIN) == []
    assert validate_directives({"upgrade-insecure-requests": False}, origin=ORIGIN) == []


def test_flag_directive_empty_list_is_ambiguous() -> None:
    issues = validate_directives({"upgrade-insecure-requests": []}, origin=ORIGIN)
    assert codes(issues) == ["empty-flag-value"]
    assert issues[0].location == f"{ORIGIN}['upgrade-insecure-requests']"
    assert "silently enables" in issues[0].message


def test_flag_directive_empty_string_is_ambiguous() -> None:
    issues = validate_directives({"block-all-mixed-content": ""}, origin=ORIGIN)
    assert codes(issues) == ["empty-flag-value"]


def test_flag_directive_with_sources_is_invalid() -> None:
    issues = validate_directives({"upgrade-insecure-requests": [SELF]}, origin=ORIGIN)
    assert codes(issues) == ["invalid-flag-value"]


def test_source_directive_empty_list_is_ambiguous() -> None:
    issues = validate_directives({"script-src": []}, origin=ORIGIN)
    assert codes(issues) == ["empty-source-list"]
    assert "Use None to remove" in issues[0].message


def test_conflicting_none_and_sources() -> None:
    issues = validate_directives({"script-src": [NONE, "cdn.example.com"]}, origin=ORIGIN)
    assert codes(issues) == ["conflicting-none"]
    assert issues[0].location == f"{ORIGIN}['script-src']"


def test_none_alone_is_valid() -> None:
    assert validate_directives({"default-src": [NONE]}, origin=ORIGIN) == []


def test_unknown_directive_is_dropped() -> None:
    issues = validate_directives({"x-acme-tracking": ["https://tracker.example"]}, origin=ORIGIN)
    assert codes(issues) == ["unknown-directive"]
    assert "silently dropped" in issues[0].message


def test_registered_extension_directive_is_valid() -> None:
    directives = {"x-acme-tracking": ["https://tracker.example"]}
    assert validate_directives(directives, origin=ORIGIN, extra_directives=["x-acme-tracking"]) == []


def test_validate_directives_or_raise() -> None:
    with pytest.raises(ImproperlyConfigured) as exc_info:
        validate_directives_or_raise({"script-src": []}, origin=ORIGIN)
    assert f"{ORIGIN}['script-src']" in str(exc_info.value)


def test_summarize_directives() -> None:
    summary = summarize_directives({"default-src": [SELF], "frame-ancestors": None})
    assert summary.kept == {"default-src": [SELF]}
    assert summary.removed == ("frame-ancestors",)


@override_settings(
    CSP_STRICT=True,
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "upgrade-insecure-requests": [],
            "script-src": [NONE, "cdn.example.com"],
        }
    },
)
def test_check_strict_directives_reports_issues() -> None:
    errors = check_strict_directives(None)
    assert len(errors) == 2
    assert all(error.id == "csp.E003" for error in errors)
    assert "CONTENT_SECURITY_POLICY[\"DIRECTIVES\"]['upgrade-insecure-requests']" in errors[0].msg
    assert "CONTENT_SECURITY_POLICY[\"DIRECTIVES\"]['script-src']" in errors[1].msg


@override_settings(
    CSP_STRICT=True,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"img-src": []}},
)
def test_check_strict_directives_report_only() -> None:
    errors = check_strict_directives(None)
    assert len(errors) == 1
    assert "CONTENT_SECURITY_POLICY_REPORT_ONLY[\"DIRECTIVES\"]['img-src']" in errors[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"upgrade-insecure-requests": []}},
)
def test_check_strict_directives_disabled_by_default() -> None:
    assert check_strict_directives(None) == []


@override_settings(
    CSP_STRICT=True,
    CSP_EXTRA_DIRECTIVES=["x-acme-tracking"],
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"x-acme-tracking": ["https://tracker.example"]}},
)
def test_check_strict_directives_registered_extension() -> None:
    assert check_strict_directives(None) == []


@override_settings(
    CSP_STRICT=True,
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "frame-ancestors": None,
            "upgrade-insecure-requests": True,
        }
    },
)
def test_check_strict_directives_clean_config() -> None:
    assert check_strict_directives(None) == []


@override_settings(CSP_STRICT=True)
def test_csp_replace_decorator_strict_raises() -> None:
    with pytest.raises(ImproperlyConfigured) as exc_info:

        @csp_replace({"script-src": []})
        def my_view(request):
            pass

    assert "@csp_replace on view" in str(exc_info.value)
    assert "'script-src'" in str(exc_info.value)


@override_settings(CSP_STRICT=True)
def test_csp_update_decorator_strict_raises() -> None:
    with pytest.raises(ImproperlyConfigured):

        @csp_update({"img-src": [NONE, "cdn.example.com"]})
        def my_view(request):
            pass


@override_settings(CSP_STRICT=True)
def test_csp_decorator_strict_raises() -> None:
    with pytest.raises(ImproperlyConfigured):

        @csp({"upgrade-insecure-requests": []})
        def my_view(request):
            pass


@override_settings(CSP_STRICT=True)
def test_decorator_strict_accepts_unambiguous_config() -> None:
    @csp_replace({"frame-ancestors": None, "script-src": [SELF]})
    def my_view(request):
        pass

    assert my_view is not None


def test_decorator_lenient_by_default() -> None:
    @csp_replace({"script-src": []})
    def my_view(request):
        pass

    assert my_view is not None
