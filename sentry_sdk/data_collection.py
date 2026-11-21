"""
Data Collection configuration.

Implements the ``data_collection`` client option described in the Sentry SDK
"Data Collection" spec
(https://develop.sentry.dev/sdk/foundations/client/data-collection/).

``data_collection`` supersedes the single ``send_default_pii`` boolean with a
structured configuration that lets users enable or restrict automatically
collected data by category (user identity, cookies, HTTP headers, URL query params,
HTTP bodies, generative AI inputs/outputs, stack frame variables, source
context).

Resolution precedence (see :func:`_resolve_data_collection`):

* ``data_collection`` set, ``send_default_pii`` unset -> honour ``data_collection``
  using the spec defaults for any omitted field.
* ``send_default_pii`` set, ``data_collection`` unset -> derive a
  resolved ``DataCollection`` that mirrors what ``send_default_pii`` collects today.
* neither set -> treated as ``send_default_pii=False``.
* both set -> ``data_collection`` wins (it is the single source of truth); a
  ``DeprecationWarning`` is emitted for ``send_default_pii``.
"""

import os
import warnings
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Union, cast
from urllib.parse import parse_qs, urlencode

from sentry_sdk._types import SENSITIVE_DATA_SUBSTITUTE

if TYPE_CHECKING:
    from sentry_sdk._types import (
        DataCollection,
        GenAICollectionBehaviour,
        GraphQLCollectionBehaviour,
        HttpHeadersCollectionBehaviour,
        KeyValueCollectionBehaviour,
        StackFrameVariablesBehaviour,
    )

# ``http_bodies`` defaults to this (collect everything the
# platform supports); an empty list is the explicit opt-out.
# ``incoming_response`` is not included here because we don't
# currently capture incoming response bodies.
_ALL_HTTP_BODY_TYPES = [
    "incoming_request",
    "outgoing_request",
    "outgoing_response",
]

# Default number of source lines captured above and below a stack frame.
_DEFAULT_FRAME_CONTEXT_LINES = 5

# Collection modes for key-value data (cookies, headers, URL query params).
# snake_case (Python-only deviation from the spec's camelCase); never
# serialized to Sentry.
_VALID_KEY_VALUE_COLLECTION_BEHAVIOUR_MODES = ("off", "denylist", "allowlist")

# Values of keys that contain any of
# these terms (partial, case-insensitive) are always replaced with
# ``"[Filtered]"`` regardless of the configured collection mode.
_SENSITIVE_DENYLIST = [
    "auth",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "key",
    "jwt",
    "bearer",
    "sso",
    "saml",
    "csrf",
    "xsrf",
    "credentials",
    "session",
    "sid",
    "identity",
]


def _is_sensitive_key(key: str, extra_terms: "Optional[List[str]]" = None) -> bool:
    """
    Return whether ``key`` matches the sensitive denylist using a partial,
    case-insensitive substring match.

    :param extra_terms: additional deny terms (e.g. user-provided) to consider
        alongside the built-in `_SENSITIVE_DENYLIST`.
    """
    lowered = key.lower()
    for term in _SENSITIVE_DENYLIST:
        if term in lowered:
            return True
    if extra_terms:
        for term in extra_terms:
            if term and term.lower() in lowered:
                return True
    return False


def _apply_data_collection_filtering_to_query_string(
    query_string: str,
    behaviour: "KeyValueCollectionBehaviour",
) -> "Union[str, None]":
    parsed_qs = parse_qs(query_string, keep_blank_values=True)
    filtered_qs = _apply_key_value_collection_filtering(
        items=parsed_qs, behaviour=behaviour
    )

    if filtered_qs:
        return urlencode(filtered_qs, doseq=True)

    return None


def _apply_key_value_collection_filtering(
    items: "Mapping[str, Any]",
    behaviour: "KeyValueCollectionBehaviour",
    substitute: "Any" = SENSITIVE_DATA_SUBSTITUTE,
) -> "Dict[str, Any]":
    if behaviour["mode"] == "off":
        return {}

    result: "Dict[str, Any]" = {}

    if behaviour["mode"] == "allowlist":
        for key, value in items.items():
            is_allowed = False
            if isinstance(key, str):
                lowered = key.lower()
                is_allowed = any(
                    term and term.lower() in lowered
                    for term in behaviour.get("terms", [])
                )
            if is_allowed and not _is_sensitive_key(key):
                result[key] = value
            else:
                result[key] = substitute
        return result

    # denylist behaviour
    for key, value in items.items():
        if isinstance(key, str) and _is_sensitive_key(
            key=key, extra_terms=behaviour.get("terms", [])
        ):
            result[key] = substitute
        else:
            result[key] = value
    return result


def _map_from_send_default_pii(
    *,
    send_default_pii: bool,
    include_local_variables: bool,
    include_source_context: bool,
) -> "DataCollection":
    """
    Build a fully-resolved ``DataCollection`` dict that mirrors the data
    ``send_default_pii`` collects today. Used when ``data_collection`` is not
    provided explicitly.
    """
    terms = [] if send_default_pii else ["forwarded", "-ip", "remote-", "via", "-user"]

    return {
        "provided_by_user": False,
        "user_info": send_default_pii,
        "cookies": {"mode": "denylist", "terms": terms},
        # Headers are collected in both PII modes today (sensitive ones filtered
        # when PII is off), so this never maps to "off".
        "http_headers": {
            "request": {"mode": "denylist", "terms": terms},
        },
        # Bodies are collected regardless of PII today, bounded by
        # ``max_request_body_size``.
        "http_bodies": list(_ALL_HTTP_BODY_TYPES),
        "url_query_params": {"mode": "denylist", "terms": terms},
        "graphql": {"document": send_default_pii, "variables": send_default_pii},
        "gen_ai": {"inputs": send_default_pii, "outputs": send_default_pii},
        "database_query_data": send_default_pii,
        "queues": send_default_pii,
        "stack_frame_variables": include_local_variables,
        "frame_context_lines": (
            _DEFAULT_FRAME_CONTEXT_LINES if include_source_context else 0
        ),
    }


def _resolve_explicit(
    d: "dict[str, Any]",
) -> "DataCollection":
    """
    Build a fully-resolved ``DataCollection`` from a user-supplied
    ``data_collection`` dict, filling in spec defaults for any omitted or
    partially-specified field.
    """
    frame_context_lines = d.get("frame_context_lines")
    if frame_context_lines is None:
        frame_context_lines = _DEFAULT_FRAME_CONTEXT_LINES
    elif isinstance(frame_context_lines, bool):
        frame_context_lines = _DEFAULT_FRAME_CONTEXT_LINES if frame_context_lines else 0
    else:
        if not isinstance(frame_context_lines, int) or frame_context_lines < 0:
            raise ValueError(
                "Invalid `frame_context_lines` value: Must be 0 or greater."
            )

    raw_stack_frame_variables = d.get("stack_frame_variables", True)
    stack_frame_variables = _stack_frame_variables_from_value(raw_stack_frame_variables)

    # http_bodies: omitted means "all valid types"; [] is the explicit opt-out.
    http_bodies = d.get("http_bodies")
    http_bodies = (
        list(http_bodies) if http_bodies is not None else list(_ALL_HTTP_BODY_TYPES)
    )

    return {
        "provided_by_user": True,
        "user_info": d.get("user_info", True),
        "cookies": _kvcb_from_value(d.get("cookies") or {}),
        "http_headers": _http_headers_from_value(d.get("http_headers") or {}),
        "http_bodies": http_bodies,
        "url_query_params": _kvcb_from_value(d.get("url_query_params") or {}),
        "graphql": _graphql_from_value(d.get("graphql") or {}),
        "gen_ai": _gen_ai_from_value(d.get("gen_ai") or {}),
        "database_query_data": d.get("database_query_data", True),
        "queues": d.get("queues", True),
        "stack_frame_variables": stack_frame_variables,
        "frame_context_lines": frame_context_lines,
    }


def _kvcb_from_value(
    val: "dict[str, Any]",
) -> "KeyValueCollectionBehaviour":
    mode = val.get("mode", "denylist")
    terms = val.get("terms", None)

    if mode not in _VALID_KEY_VALUE_COLLECTION_BEHAVIOUR_MODES:
        raise ValueError(
            "Invalid collection mode {!r}. Must be one of {}.".format(
                mode, _VALID_KEY_VALUE_COLLECTION_BEHAVIOUR_MODES
            )
        )

    behaviour: "dict[str, Any]" = {"mode": mode}
    if terms is not None:
        behaviour["terms"] = list(terms)
    return cast("KeyValueCollectionBehaviour", behaviour)


def _stack_frame_variable_source_from_value(
    val: "Any",
    index: int,
) -> "dict[str, Any]":
    """
    Normalize a single ``stack_frame_variables.sources`` entry.

    A source rule selects frames by ``module`` (a dotted module name or prefix)
    or by ``path`` (an absolute file path or prefix). Exactly one of the two
    selectors is required.
    """
    prefix = "Invalid `stack_frame_variables.sources[{}]`".format(index)

    if not isinstance(val, dict):
        raise ValueError("{}: expected a dict.".format(prefix))

    module = val.get("module")
    path = val.get("path")
    if (module is None) == (path is None):
        raise ValueError(
            "{}: exactly one of `module` or `path` is required.".format(prefix)
        )
    if module is not None and (not isinstance(module, str) or not module):
        raise ValueError("{}: `module` must be a non-empty string.".format(prefix))
    if path is not None and (not isinstance(path, str) or not path):
        raise ValueError("{}: `path` must be a non-empty string.".format(prefix))

    rule: "dict[str, Any]" = dict(_kvcb_from_value(val))
    if module is not None:
        rule["module"] = module
    else:
        rule["path"] = path
    return rule


def _stack_frame_variables_from_value(
    val: "Any",
) -> "Union[bool, StackFrameVariablesBehaviour]":
    """
    Normalize the ``stack_frame_variables`` option.

    In addition to the global boolean/key-value form, this accepts a
    ``sources`` list that selects frames by module or path. Rules are evaluated
    in order and the first match wins.

    Frames that match no rule -- including frames without a module or path --
    use the fallback behaviour from the top-level ``mode``/``terms``. When
    ``sources`` is present and no top-level ``mode`` is given, the fallback is
    ``"off"`` so unknown sources never leak locals by default.
    """
    if not isinstance(val, dict):
        return bool(val)

    sources = val.get("sources")
    if sources is None:
        return _kvcb_from_value(val)

    if not isinstance(sources, list):
        raise ValueError("Invalid `stack_frame_variables.sources`: expected a list.")

    fallback_value: "dict[str, Any]" = {}
    if "mode" in val:
        fallback_value["mode"] = val["mode"]
    else:
        fallback_value["mode"] = "off"
    if "terms" in val:
        fallback_value["terms"] = val["terms"]
    fallback = _kvcb_from_value(fallback_value)

    rules = [
        _stack_frame_variable_source_from_value(rule, index)
        for index, rule in enumerate(sources)
    ]

    behaviour: "dict[str, Any]" = dict(fallback)
    behaviour["sources"] = rules
    return cast("StackFrameVariablesBehaviour", behaviour)


def _frame_matches_source_rule(
    rule: "Mapping[str, Any]",
    module: "Optional[str]",
    abs_path: "Optional[str]",
) -> bool:
    module_prefix = rule.get("module")
    if module_prefix is not None:
        return bool(
            module
            and (module == module_prefix or module.startswith(module_prefix + "."))
        )

    path_prefix = rule.get("path")
    if path_prefix is not None:
        if not abs_path:
            return False
        if abs_path.startswith(path_prefix):
            return True
        try:
            normalized_path_prefix = os.path.abspath(path_prefix)
        except Exception:
            return False
        return abs_path.startswith(normalized_path_prefix)

    return False


def _stack_frame_variables_behaviour_for_frame(
    behaviour: "Union[bool, StackFrameVariablesBehaviour]",
    module: "Optional[str]",
    abs_path: "Optional[str]",
) -> "Optional[Union[bool, KeyValueCollectionBehaviour]]":
    """
    Resolve the effective collection behaviour for one frame.

    Returns:

    * ``None`` -- do not collect local variables for this frame. Callers must
      not evaluate anything (including ``repr``/``custom_repr``) in that case.
    * ``True`` -- collect all locals without key filtering (the historical
      meaning of ``stack_frame_variables=True``).
    * a key-value behaviour -- collect locals with the given filtering.

    Frames that match no source rule, including frames without a module or
    absolute path, fall back to the top-level ``mode``/``terms``.
    """
    if isinstance(behaviour, bool):
        return True if behaviour else None

    sources = behaviour.get("sources")
    if not sources:
        resolved: "Optional[KeyValueCollectionBehaviour]" = cast(
            "KeyValueCollectionBehaviour", behaviour
        )
    else:
        resolved = None
        for rule in sources:
            if _frame_matches_source_rule(rule, module, abs_path):
                resolved = cast("KeyValueCollectionBehaviour", rule)
                break

        if resolved is None:
            resolved = cast(
                "KeyValueCollectionBehaviour",
                {
                    key: value
                    for key, value in behaviour.items()
                    if key in ("mode", "terms")
                },
            )

    if resolved.get("mode") == "off":
        return None

    return resolved


def _http_headers_from_value(
    val: "dict[str, Any]",
) -> "HttpHeadersCollectionBehaviour":
    return {
        "request": (
            _kvcb_from_value(val["request"])
            if "request" in val
            else _kvcb_from_value({"mode": "denylist"})
        ),
    }


def _gen_ai_from_value(val: "dict[str, Any]") -> "GenAICollectionBehaviour":
    return {
        "inputs": val.get("inputs", True),
        "outputs": val.get("outputs", True),
    }


def _graphql_from_value(
    val: "dict[str, Any]",
) -> "GraphQLCollectionBehaviour":
    return {
        "document": val.get("document", True),
        "variables": val.get("variables", True),
    }


def _resolve_data_collection(options: "Dict[str, Any]") -> "DataCollection":
    """
    Resolve the effective ``DataCollection`` dict from client ``options``.

    Reads ``data_collection``, ``send_default_pii``, ``include_local_variables``
    and ``include_source_context`` and returns a fully-resolved dict with
    concrete values for every field.

    ``data_collection`` must be a plain ``dict``.

    Must be called exactly once per options dict, before ``client._get_options``
    overwrites ``options["data_collection"]`` with the resolved result. Feeding an
    already-resolved dict back in would flip ``provided_by_user`` to ``True``.
    """
    user_dc = options.get("data_collection")
    if user_dc is None:
        user_dc = options.get("_experiments", {}).get("data_collection")

    send_default_pii = options.get("send_default_pii")

    include_local_variables = (
        bool(options.get("include_local_variables"))
        if options.get("include_local_variables") is not None
        else True
    )
    include_source_context = (
        bool(options.get("include_source_context"))
        if options.get("include_source_context") is not None
        else True
    )

    if user_dc is not None:
        if not isinstance(user_dc, dict):
            raise TypeError(
                "`data_collection` must be a dict, got {!r}.".format(
                    type(user_dc).__name__
                )
            )
        if send_default_pii is not None:
            warnings.warn(
                "`send_default_pii` is deprecated and ignored when "
                "`data_collection` is set.",
                DeprecationWarning,
                stacklevel=2,
            )
        return _resolve_explicit(
            user_dc,
        )

    return _map_from_send_default_pii(
        send_default_pii=bool(send_default_pii),
        include_local_variables=include_local_variables,
        include_source_context=include_source_context,
    )
