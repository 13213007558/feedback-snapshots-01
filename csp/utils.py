from __future__ import annotations

import copy
import re
from itertools import chain
from typing import TYPE_CHECKING, Any, Callable

from django.conf import settings
from django.utils.encoding import force_str

from csp.constants import (
    DIRECTIVES,
    MEDIA_TYPE_POLICIES,
    NONCE,
    SELF,
    UNKNOWN_MEDIA_TYPE,
    UNKNOWN_MEDIA_TYPE_DEFAULT,
    UNKNOWN_MEDIA_TYPE_SKIP,
)

if TYPE_CHECKING:
    from django.http import HttpResponseBase

DEFAULT_DIRECTIVES = {
    # Fetch Directives
    "child-src": None,
    "connect-src": None,
    "default-src": [SELF],
    "script-src": None,
    "script-src-attr": None,
    "script-src-elem": None,
    "object-src": None,
    "style-src": None,
    "style-src-attr": None,
    "style-src-elem": None,
    "font-src": None,
    "frame-src": None,
    "img-src": None,
    "manifest-src": None,
    "media-src": None,
    "prefetch-src": None,  # Deprecated.
    # Document Directives
    "base-uri": None,
    "plugin-types": None,  # Deprecated.
    "sandbox": None,
    # Navigation Directives
    "form-action": None,
    "frame-ancestors": None,
    "navigate-to": None,
    # Reporting Directives
    "report-uri": None,
    "report-to": None,
    "require-sri-for": None,
    # Trusted Types Directives
    "require-trusted-types-for": None,
    "trusted-types": None,
    # Other Directives
    "webrtc": None,
    "worker-src": None,
    # Directives Defined in Other Documents
    "upgrade-insecure-requests": False,
    "block-all-mixed-content": False,  # Deprecated.
}

DIRECTIVES_T = dict[str, Any]


def default_config(csp: DIRECTIVES_T | None) -> DIRECTIVES_T | None:
    if csp is None:
        return None
    # Make a copy of the passed in config to avoid mutating it, and also to drop any unknown keys.
    config = {}
    for key, value in DEFAULT_DIRECTIVES.items():
        config[key] = csp.get(key, value)
    return config


def get_response_media_type(response: HttpResponseBase) -> str | None:
    """
    Return the final media type of a response without touching its body.

    The media type is derived solely from the ``Content-Type`` header, so streaming and
    file responses never have their content consumed or rendered early. Parameters such as
    ``charset`` are stripped and the type is normalised to lower case.

    Returns ``None`` when the response carries no usable media type.
    """
    content_type = response.headers.get("Content-Type")
    if not content_type:
        return None
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type or None


def resolve_config(
    response: HttpResponseBase,
    policy: DIRECTIVES_T | None,
) -> tuple[DIRECTIVES_T | None, bool]:
    """
    Pick the directive configuration that applies to a response.

    Selection is based on the response's *final* media type. The returned tuple is
    ``(config, skip)`` where ``config`` is the directives to use and ``skip`` indicates that
    no header should be written at all (an explicitly disabled media type, or an unknown
    media type configured to be skipped).

    A policy without ``MEDIA_TYPE_POLICIES`` keeps the historical response-level behaviour:
    the top-level ``DIRECTIVES`` apply to every response regardless of media type.
    """
    if policy is None:
        return None, False

    media_type_policies = policy.get(MEDIA_TYPE_POLICIES)
    if not media_type_policies:
        return policy.get(DIRECTIVES), False

    media_type = get_response_media_type(response)
    if media_type is None:
        unknown_behavior = policy.get(UNKNOWN_MEDIA_TYPE, UNKNOWN_MEDIA_TYPE_DEFAULT)
        if unknown_behavior == UNKNOWN_MEDIA_TYPE_SKIP:
            return None, True
        return policy.get(DIRECTIVES), False

    if media_type in media_type_policies:
        media_config = media_type_policies[media_type]
        # An explicit ``None`` disables the header for this media type.
        return (None, True) if media_config is None else (media_config.get(DIRECTIVES), False)

    # No route for this media type: fall back to the default policy.
    return policy.get(DIRECTIVES), False


def build_policy(
    config: DIRECTIVES_T | None = None,
    update: DIRECTIVES_T | None = None,
    replace: DIRECTIVES_T | None = None,
    nonce: str | None = None,
    report_only: bool = False,
) -> str:
    """Builds the policy as a string from the settings."""

    if config is None:
        if report_only:
            config = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None
        else:
            config = getattr(settings, "CONTENT_SECURITY_POLICY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None

    # If config is still `None`, return empty policy.
    if config is None:
        return ""

    update = update if update is not None else {}
    replace = replace if replace is not None else {}

    csp = {}

    for k in set(chain(config, replace)):
        if k in replace:
            v = replace[k]
        else:
            v = config[k]
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            csp[k] = v

    for k, v in update.items():
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            if csp.get(k) is None:
                csp[k] = v
            else:
                csp[k] += tuple(v)

    report_uri = csp.pop("report-uri", None)

    policy_parts = {}

    for key, value in csp.items():
        # Check for boolean directives.
        if len(value) == 1 and isinstance(value[0], bool):
            if value[0] is True:
                policy_parts[key] = ""
            continue
        if NONCE in value:
            if nonce:
                value = [f"'nonce-{nonce}'" if v == NONCE else v for v in value]
            else:
                # Strip the `NONCE` sentinel value if no nonce is provided.
                value = [v for v in value if v != NONCE]

        value = list(dict.fromkeys(value))  # Deduplicate
        policy_parts[key] = " ".join(value)

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts["report-uri"] = " ".join(report_uri)

    return "; ".join([f"{k} {val}".strip() for k, val in policy_parts.items()])


def _default_attr_mapper(attr_name: str, val: str) -> str:
    if val:
        return f' {attr_name}="{val}"'
    else:
        return ""


def _bool_attr_mapper(attr_name: str, val: bool) -> str:
    # Only return the bare word if the value is truthy
    # ie - defer=False should actually return an empty string
    if val:
        return f" {attr_name}"
    else:
        return ""


def _async_attr_mapper(attr_name: str, val: str | bool) -> str:
    """The `async` attribute works slightly different than the other bool
    attributes. It can be set explicitly to `false` with no surrounding quotes
    according to the spec."""
    if val in [False, "False"]:
        return f" {attr_name}=false"
    elif val:
        return f" {attr_name}"
    else:
        return ""


# Allow per-attribute customization of returned string template
SCRIPT_ATTRS: dict[str, Callable[[str, Any], str]] = {
    "nonce": _default_attr_mapper,
    "id": _default_attr_mapper,
    "src": _default_attr_mapper,
    "type": _default_attr_mapper,
    "async": _async_attr_mapper,
    "defer": _bool_attr_mapper,
    "integrity": _default_attr_mapper,
    "nomodule": _bool_attr_mapper,
}

# Generates an interpolatable string of valid attrs eg - '{nonce}{id}...'
ATTR_FORMAT_STR = "".join([f"{{{a}}}" for a in SCRIPT_ATTRS])


_script_tag_contents_re = re.compile(
    r"""<script        # match the opening script tag
            [\s|\S]*?> # minimally match attrs and spaces in opening script tag
    ([\s|\S]+)         # greedily capture the script tag contents
    </script>          # match the closing script tag
""",
    re.VERBOSE,
)


def _unwrap_script(text: str) -> str:
    """Extract content defined between script tags"""
    matches = re.search(_script_tag_contents_re, text)
    if matches and len(matches.groups()):
        return matches.group(1).strip()

    return text


def build_script_tag(content: str | None = None, **kwargs: Any) -> str:
    data = {}
    # Iterate all possible script attrs instead of kwargs to make
    # interpolation as easy as possible below
    for attr_name, mapper in SCRIPT_ATTRS.items():
        data[attr_name] = mapper(attr_name, kwargs.get(attr_name))

    # Don't render block contents if the script has a 'src' attribute
    c = _unwrap_script(content) if content and not kwargs.get("src") else ""
    attrs = ATTR_FORMAT_STR.format(**data).rstrip()
    return f"<script{attrs}>{c}</script>".strip()
