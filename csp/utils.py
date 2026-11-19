from __future__ import annotations

import copy
import re
from itertools import chain
from typing import TYPE_CHECKING, Any, Callable

from django.conf import settings
from django.utils.encoding import force_str

if TYPE_CHECKING:
    from django.http import HttpRequest

from csp.constants import NONCE, SELF

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


def resolved_view_name(request: HttpRequest | None) -> str | None:
    """
    Return the view name Django resolved for this request, if any.

    ``request.resolver_match`` is normally populated by Django before the view
    is called, which is early enough for ``process_response``. Middleware that
    builds a policy outside of that phase can pass the name explicitly, or set
    ``request._csp_view_name`` from its own ``process_view`` hook.
    """
    if request is None:
        return None
    view_name = getattr(request, "_csp_view_name", None)
    if isinstance(view_name, str):
        return view_name
    resolver_match = getattr(request, "resolver_match", None)
    view_name = getattr(resolver_match, "view_name", None)
    return view_name if isinstance(view_name, str) else None


def view_policy_config(
    policy: DIRECTIVES_T | None,
    request: HttpRequest | None = None,
) -> DIRECTIVES_T | None:
    """
    Return the policy that applies to the request's resolved view.

    ``VIEW_POLICIES`` is an optional dictionary inside the
    ``CONTENT_SECURITY_POLICY`` / ``CONTENT_SECURITY_POLICY_REPORT_ONLY``
    setting, keyed by the fully qualified view name Django resolves
    (``request.resolver_match.view_name``), e.g. ``"employees:profile"``.

    The entry for a matching route overrides individual directives on top of
    the site-wide ``DIRECTIVES``; directives the entry doesn't mention keep
    their site-wide value, and a value of ``None`` removes a directive. Routes
    without an entry keep the site-wide policy unchanged. An entry may also be
    a full policy dict with a ``DIRECTIVES`` key, which is useful when sharing
    fragments between the two settings.

    The enforced and report-only settings each carry their own
    ``VIEW_POLICIES``, so the two kinds of rule are configured independently.
    """
    if policy is None:
        return None

    view_name = resolved_view_name(request)
    if view_name is None:
        return policy

    view_policies = policy.get("VIEW_POLICIES")
    if not isinstance(view_policies, dict):
        return policy

    entry = view_policies.get(view_name)
    if not isinstance(entry, dict):
        return policy

    overrides = entry.get("DIRECTIVES", entry)
    if not isinstance(overrides, dict):
        return policy

    directives = policy.get("DIRECTIVES") or {}
    effective = dict(policy)
    effective["DIRECTIVES"] = {**directives, **overrides}
    effective.pop("VIEW_POLICIES", None)
    return effective


def invalid_view_policies(policy: Any) -> list[str]:
    """Return descriptions of malformed ``VIEW_POLICIES`` entries.

    Used by the system check so configuration mistakes are reported at startup
    rather than silently falling back to the site policy.
    """
    errors = []
    if not isinstance(policy, dict):
        return errors
    view_policies = policy.get("VIEW_POLICIES")
    if view_policies is None:
        return errors
    if not isinstance(view_policies, dict):
        return ["VIEW_POLICIES must be a dictionary keyed by resolved view name."]

    for view_name, entry in view_policies.items():
        if not isinstance(view_name, str):
            errors.append(f"VIEW_POLICIES keys must be resolved view names, got {view_name!r}.")
            continue
        if not isinstance(entry, dict):
            errors.append(f"VIEW_POLICIES[{view_name!r}] must be a dictionary of directives.")
            continue
        if "DIRECTIVES" in entry:
            unsupported = sorted(set(entry) - {"DIRECTIVES"})
            if unsupported:
                errors.append(f"VIEW_POLICIES[{view_name!r}] only supports a 'DIRECTIVES' key, got {unsupported!r}.")
            if not isinstance(entry["DIRECTIVES"], dict):
                errors.append(f"VIEW_POLICIES[{view_name!r}]['DIRECTIVES'] must be a dictionary of directives.")
    return errors


def default_config(csp: DIRECTIVES_T | None) -> DIRECTIVES_T | None:
    if csp is None:
        return None
    # Make a copy of the passed in config to avoid mutating it, and also to drop any unknown keys.
    config = {}
    for key, value in DEFAULT_DIRECTIVES.items():
        config[key] = csp.get(key, value)
    return config


def build_policy(
    config: DIRECTIVES_T | None = None,
    update: DIRECTIVES_T | None = None,
    replace: DIRECTIVES_T | None = None,
    nonce: str | None = None,
    report_only: bool = False,
    request: HttpRequest | None = None,
) -> str:
    """Builds the policy as a string from the settings."""

    if config is None:
        if report_only:
            policy = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {}
        else:
            policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
        policy = view_policy_config(policy, request)
        config = default_config(policy.get("DIRECTIVES", {})) if policy else None

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
