from typing import Any

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.checks import check_django_csp_lt_4_0, check_exclude_url_prefixes_is_not_string, migrate_settings
from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
from csp.middleware import CSPMiddleware
from csp.tests.utils import response

rf = RequestFactory()
mw = CSPMiddleware(response())


def parse_policy(header: str | None) -> dict[str, frozenset[str]]:
    """Parse a CSP header into ``{directive: frozenset(tokens)}``.

    Token sets make assertions independent of both directive serialization order and the order of
    sources inside a directive. Boolean directives (e.g. ``upgrade-insecure-requests``) parse to an
    empty token set, so the presence of the directive is still asserted.
    """
    if not header:
        return {}
    policy: dict[str, frozenset[str]] = {}
    for part in header.split("; "):
        directive, _, tokens = part.partition(" ")
        policy[directive] = frozenset(tokens.split()) if tokens else frozenset()
    return policy


def apply_migration_and_get_headers(**old_settings: Any) -> tuple[str | None, str | None]:
    """Turn the migration suggestion into real Django settings, then run a response through the middleware.

    The suggestion emitted by the ``csp.E001`` check (``migrate_settings``) is loaded under the
    appropriate new dict setting (enforced vs. report-only) while the inactive header is disabled,
    so the returned headers reflect exactly what the migrated config produces.
    """
    with override_settings(**old_settings):
        config, report_only = migrate_settings()
    new_setting = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
    inactive_setting = "CONTENT_SECURITY_POLICY" if report_only else "CONTENT_SECURITY_POLICY_REPORT_ONLY"
    with override_settings(**{new_setting: config, inactive_setting: None}):
        request = rf.get("/")
        http_response = HttpResponse()
        mw.process_response(request, http_response)
        return http_response.get(HEADER), http_response.get(HEADER_REPORT_ONLY)


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
    errors = check_exclude_url_prefixes_is_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY settings must be a list or tuple."


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_ro_is_not_string() -> None:
    errors = check_exclude_url_prefixes_is_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY_REPORT_ONLY settings must be a list or tuple."


# --- Contract tests: the migration suggestion must produce the intended on-the-wire policy. ---


def test_migration_contract_unset_directives_are_not_added() -> None:
    # Directives that were never configured must not appear; only the configured fetch directives do.
    enforced, report_only = apply_migration_and_get_headers(
        CSP_DEFAULT_SRC=[SELF, "*.example.com"],
        CSP_SCRIPT_SRC=[SELF, "js.cdn.com/example/"],
    )
    # Exact dict equality fails if the migration silently widens the policy (extra directive or source).
    assert parse_policy(enforced) == {
        "default-src": frozenset({SELF, "*.example.com"}),
        "script-src": frozenset({SELF, "js.cdn.com/example/"}),
    }
    assert report_only is None


def test_migration_contract_explicitly_disabled_directives_are_dropped() -> None:
    # Falsy values mean the directive is turned off and must be omitted from the suggestion/header.
    enforced, report_only = apply_migration_and_get_headers(
        CSP_DEFAULT_SRC=[SELF],
        CSP_OBJECT_SRC=None,
        CSP_UPGRADE_INSECURE_REQUESTS=False,
        CSP_BLOCK_ALL_MIXED_CONTENT=False,
        CSP_SCRIPT_SRC=[],
    )
    assert parse_policy(enforced) == {
        "default-src": frozenset({SELF}),
    }
    assert report_only is None


def test_migration_contract_reporting_targets_are_serialized() -> None:
    enforced, report_only = apply_migration_and_get_headers(
        CSP_DEFAULT_SRC=[SELF],
        CSP_REPORT_URI=["/csp-report/"],
        CSP_REPORT_TO="csp-endpoint",
    )
    assert parse_policy(enforced) == {
        "default-src": frozenset({SELF}),
        "report-uri": frozenset({"/csp-report/"}),
        "report-to": frozenset({"csp-endpoint"}),
    }
    assert report_only is None


def test_migration_contract_report_only_uses_report_only_header() -> None:
    enforced, report_only = apply_migration_and_get_headers(
        CSP_REPORT_ONLY=True,
        CSP_DEFAULT_SRC=[SELF],
        CSP_SCRIPT_SRC=[SELF],
        CSP_INCLUDE_NONCE_IN=["script-src"],
    )
    # A report-only restriction must never reach the enforcing header.
    assert enforced is None
    # The NONCE sentinel is stripped because the view never accessed a nonce for this response.
    assert parse_policy(report_only) == {
        "default-src": frozenset({SELF}),
        "script-src": frozenset({SELF}),
    }
