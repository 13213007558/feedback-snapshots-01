from django.test.utils import override_settings

from csp.checks import (
    check_django_csp_lt_4_0,
    check_exclude_url_lists_are_not_string,
    check_exclude_url_prefixes_deprecated,
    check_exclude_urls_patterns,
    migrate_settings,
)
from csp.constants import NONCE


@override_settings(
    CSP_REPORT_PERCENTAGE=0.25,
    CSP_EXCLUDE_URL_PREFIXES=["/admin/"],
    CSP_REPORT_ONLY=False,
    CSP_DEFAULT_SRC=["'self'", "example.com"],
)
def test_migrate_settings() -> None:
    config, report_only = migrate_settings()
    assert config == {
        "REPORT_PERCENTAGE": 25.0,
        "EXCLUDE_URL_PREFIXES": ["/admin/"],
        "DIRECTIVES": {"default-src": ["'self'", "example.com"]},
    }
    assert report_only is False


@override_settings(
    CSP_REPORT_ONLY=True,
    CSP_DEFAULT_SRC=["'self'", "example.com"],
    CSP_SCRIPT_SRC=["'self'", "example.com", "'unsafe-inline'"],
    CSP_INCLUDE_NONCE_IN=["script-src"],
)
def test_migrate_settings_report_only() -> None:
    config, report_only = migrate_settings()
    assert config == {
        "DIRECTIVES": {
            "default-src": ["'self'", "example.com"],
            "script-src": ["'self'", "example.com", "'unsafe-inline'", NONCE],
        }
    }
    assert report_only is True


@override_settings(
    CSP_DEFAULT_SRC=["'self'", "example.com"],
)
def test_check_django_csp_lt_4_0() -> None:
    errors = check_django_csp_lt_4_0(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E001"
    assert "update your settings to use the new format" in error.msg


def test_check_django_csp_lt_4_0_no_config() -> None:
    assert check_django_csp_lt_4_0(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_is_not_string() -> None:
    errors = check_exclude_url_lists_are_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY settings must be a list or tuple."


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_ro_is_not_string() -> None:
    errors = check_exclude_url_lists_are_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY_REPORT_ONLY settings must be a list or tuple."


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": "/admin"},
)
def test_check_exclude_urls_is_not_string() -> None:
    errors = check_exclude_url_lists_are_not_string(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E002"
    assert errors[0].msg == "EXCLUDE_URLS in CONTENT_SECURITY_POLICY settings must be a list or tuple."


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": ["/admin"]},
)
def test_check_exclude_url_prefixes_deprecated() -> None:
    warnings = check_exclude_url_prefixes_deprecated(None)
    assert len(warnings) == 1
    warning = warnings[0]
    assert warning.id == "csp.W003"
    assert "EXCLUDE_URLS" in warning.msg


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"EXCLUDE_URL_PREFIXES": ["/admin"]},
)
def test_check_exclude_url_prefixes_deprecated_ro() -> None:
    warnings = check_exclude_url_prefixes_deprecated(None)
    assert len(warnings) == 1
    assert warnings[0].id == "csp.W003"
    assert "CONTENT_SECURITY_POLICY_REPORT_ONLY" in warnings[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/admin"]},
)
def test_check_exclude_url_prefixes_deprecated_only_warns_for_legacy_setting() -> None:
    assert check_exclude_url_prefixes_deprecated(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["admin/"]},
)
def test_check_exclude_urls_pattern_must_start_with_slash() -> None:
    errors = check_exclude_urls_patterns(None)
    assert {error.id for error in errors} == {"csp.E004"}
    assert any("must start with '/'" in error.msg for error in errors)


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/admin/"]},
)
def test_check_exclude_urls_pattern_must_not_end_with_slash() -> None:
    errors = check_exclude_urls_patterns(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E004"
    assert "must not end with '/'" in errors[0].msg
    assert "'/admin'" in errors[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/admin/*"]},
)
def test_check_exclude_urls_pattern_rejects_glob() -> None:
    errors = check_exclude_urls_patterns(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E004"
    assert "literal path" in errors[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/admin", 42]},
)
def test_check_exclude_urls_pattern_must_be_string() -> None:
    errors = check_exclude_urls_patterns(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E004"
    assert "must be strings" in errors[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/"]},
)
def test_check_exclude_urls_root_pattern_is_valid() -> None:
    assert check_exclude_urls_patterns(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/admin", "/reports/assets"]},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"EXCLUDE_URLS": ["/reports-backup/"]},
)
def test_check_exclude_urls_patterns_reports_each_setting() -> None:
    errors = check_exclude_urls_patterns(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E004"
    assert "CONTENT_SECURITY_POLICY_REPORT_ONLY" in errors[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URLS": ["/admin"]},
)
def test_check_exclude_urls_valid_patterns_pass() -> None:
    assert check_exclude_urls_patterns(None) == []
