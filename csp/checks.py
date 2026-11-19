from __future__ import annotations

import pprint
from collections.abc import Sequence
from importlib.metadata import version
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core import checks
from django.core.checks import Error, Warning, register

from packaging.version import Version

from csp.constants import NONCE

if TYPE_CHECKING:
    from django.apps.config import AppConfig

# Characters that signal an attempt to write a glob or regex instead of a literal path.
_GLOB_CHARS = frozenset("*?[]")


OUTDATED_SETTINGS = [
    "CSP_CHILD_SRC",
    "CSP_CONNECT_SRC",
    "CSP_DEFAULT_SRC",
    "CSP_SCRIPT_SRC",
    "CSP_SCRIPT_SRC_ATTR",
    "CSP_SCRIPT_SRC_ELEM",
    "CSP_OBJECT_SRC",
    "CSP_STYLE_SRC",
    "CSP_STYLE_SRC_ATTR",
    "CSP_STYLE_SRC_ELEM",
    "CSP_FONT_SRC",
    "CSP_FRAME_SRC",
    "CSP_IMG_SRC",
    "CSP_MANIFEST_SRC",
    "CSP_MEDIA_SRC",
    "CSP_PREFETCH_SRC",
    "CSP_WORKER_SRC",
    "CSP_BASE_URI",
    "CSP_PLUGIN_TYPES",
    "CSP_SANDBOX",
    "CSP_FORM_ACTION",
    "CSP_FRAME_ANCESTORS",
    "CSP_NAVIGATE_TO",
    "CSP_REQUIRE_SRI_FOR",
    "CSP_REQUIRE_TRUSTED_TYPES_FOR",
    "CSP_TRUSTED_TYPES",
    "CSP_UPGRADE_INSECURE_REQUESTS",
    "CSP_BLOCK_ALL_MIXED_CONTENT",
    "CSP_REPORT_URI",
    "CSP_REPORT_TO",
]


def migrate_settings() -> tuple[dict[str, Any], bool]:
    # This function is used to migrate settings from the old format to the new format.
    config: dict[str, Any] = {
        "DIRECTIVES": {},
    }

    REPORT_ONLY = getattr(settings, "CSP_REPORT_ONLY", False)

    _EXCLUDE_URL_PREFIXES = getattr(settings, "CSP_EXCLUDE_URL_PREFIXES", None)
    if _EXCLUDE_URL_PREFIXES is not None:
        config["EXCLUDE_URL_PREFIXES"] = _EXCLUDE_URL_PREFIXES

    _REPORT_PERCENTAGE = getattr(settings, "CSP_REPORT_PERCENTAGE", None)
    if _REPORT_PERCENTAGE is not None:
        config["REPORT_PERCENTAGE"] = _REPORT_PERCENTAGE * 100

    include_nonce_in = getattr(settings, "CSP_INCLUDE_NONCE_IN", [])

    for setting in OUTDATED_SETTINGS:
        if hasattr(settings, setting):
            directive = setting[4:].replace("_", "-").lower()
            value = getattr(settings, setting)
            if value:
                config["DIRECTIVES"][directive] = value
            if directive in include_nonce_in:
                config["DIRECTIVES"][directive].append(NONCE)

    return config, REPORT_ONLY


@register(checks.Tags.security)
def check_django_csp_lt_4_0(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    check_settings = OUTDATED_SETTINGS + ["CSP_REPORT_ONLY", "CSP_EXCLUDE_URL_PREFIXES", "CSP_REPORT_PERCENTAGE"]
    if any(hasattr(settings, setting) for setting in check_settings):
        # Try to build the new config.
        config, REPORT_ONLY = migrate_settings()
        warning = (
            "You are using django-csp < 4.0 settings. Please update your settings to use the new format.\n"
            "See https://django-csp.readthedocs.io/en/latest/migration-guide.html for more information.\n\n"
            "We have attempted to build the new CSP config for you based on your current settings:\n\n"
            f"CONTENT_SECURITY_POLICY{'_REPORT_ONLY' if REPORT_ONLY else ''} = " + pprint.pformat(config, sort_dicts=True)
        )
        return [Error(warning, id="csp.E001")]

    return []


@register(checks.Tags.security)
def check_exclude_url_lists_are_not_string(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    """
    Check that the URL exclusion settings are not a string.

    If they are a string it can lead to a security issue where the string is treated as a list of
    characters, resulting in '/' matching all paths excluding the CSP header from all responses.
    """
    # Skip check for django-csp < 4.0.
    if Version(version("django-csp")) < Version("4.0a1"):
        return []

    errors = []
    keys = (
        "CONTENT_SECURITY_POLICY",
        "CONTENT_SECURITY_POLICY_REPORT_ONLY",
    )
    for key in keys:
        config = getattr(settings, key, {})
        if not isinstance(config, dict):
            continue
        for setting_name in ("EXCLUDE_URL_PREFIXES", "EXCLUDE_URLS"):
            if isinstance(config.get(setting_name), str):
                errors.append(
                    Error(
                        f"{setting_name} in {key} settings must be a list or tuple.",
                        id="csp.E002",
                    )
                )

    return errors


@register(checks.Tags.security)
def check_exclude_url_prefixes_deprecated(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Warning]:
    """
    Point users at the path-segment based EXCLUDE_URLS replacement.

    EXCLUDE_URL_PREFIXES matches character prefixes, so a prefix such as "/reports" also excludes
    sibling directories like "/reports-backup". The warning is intentionally advisory so existing
    configurations keep working while they are migrated.
    """
    if Version(version("django-csp")) < Version("4.0a1"):
        return []

    warnings = []
    keys = (
        "CONTENT_SECURITY_POLICY",
        "CONTENT_SECURITY_POLICY_REPORT_ONLY",
    )
    for key in keys:
        config = getattr(settings, key, {})
        if isinstance(config, dict) and config.get("EXCLUDE_URL_PREFIXES"):
            warnings.append(
                Warning(
                    f"EXCLUDE_URL_PREFIXES in {key} settings is deprecated in favor of EXCLUDE_URLS, "
                    "which matches whole URL path segments instead of character prefixes. "
                    "For example, EXCLUDE_URLS=['/reports'] excludes '/reports' and its sub-paths "
                    "without also excluding a sibling such as '/reports-backup'.",
                    id="csp.W003",
                )
            )

    return warnings


@register(checks.Tags.security)
def check_exclude_urls_patterns(app_configs: Sequence[AppConfig] | None, **kwargs: Any) -> list[Error]:
    """
    Validate that EXCLUDE_URLS entries are unambiguous literal path-segment patterns.

    Ambiguous entries are reported rather than silently interpreted as the new segment-based rule,
    which would change which URLs lose their CSP headers.
    """
    if Version(version("django-csp")) < Version("4.0a1"):
        return []

    errors = []
    keys = (
        "CONTENT_SECURITY_POLICY",
        "CONTENT_SECURITY_POLICY_REPORT_ONLY",
    )
    for key in keys:
        config = getattr(settings, key, {})
        if not isinstance(config, dict):
            continue
        patterns = config.get("EXCLUDE_URLS")
        if not patterns:
            continue
        for pattern in patterns:
            if not isinstance(pattern, str):
                errors.append(
                    Error(
                        f"EXCLUDE_URLS entries in {key} settings must be strings, got {pattern!r}.",
                        id="csp.E004",
                    )
                )
                continue
            if not pattern.startswith("/"):
                errors.append(
                    Error(
                        f"EXCLUDE_URLS pattern {pattern!r} in {key} settings must start with '/'. "
                        "Patterns are matched against the path Django hands to the view (request.path_info).",
                        id="csp.E004",
                    )
                )
            if pattern != "/" and pattern.endswith("/"):
                errors.append(
                    Error(
                        f"EXCLUDE_URLS pattern {pattern!r} in {key} settings must not end with '/'. "
                        f"Use {pattern.rstrip('/')!r} instead; a pattern matches the directory itself "
                        "and every sub-path beneath it.",
                        id="csp.E004",
                    )
                )
            if any(char in pattern for char in _GLOB_CHARS):
                errors.append(
                    Error(
                        f"EXCLUDE_URLS pattern {pattern!r} in {key} settings must be a literal path; " "glob or regex characters are not supported.",
                        id="csp.E004",
                    )
                )

    return errors
