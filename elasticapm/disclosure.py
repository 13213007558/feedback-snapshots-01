#  BSD 3-Clause License
#
#  Copyright (c) 2019, Elasticsearch BV
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Local disclosure ceiling support.

Central configuration may adjust diagnostic collection settings, but it must
never exceed what the local deployment allows.  The local (first) configuration
is used as the ceiling for a small set of options that can disclose captured
payloads, headers, source excerpts or local variables.

For each option the ceiling is combined with the requested value using the most
restrictive result.  This means central configuration can still tighten a
setting (for example switch ``capture_body`` from ``all`` to ``off``) or select
any value inside the locally allowed range, but it cannot widen collection by
itself.
"""

import copy
import fnmatch
import itertools
import re
from datetime import timedelta

from elasticapm.conf.constants import ERROR, MASK, SPAN, TRANSACTION
from elasticapm.utils import starmatch_to_regex, varmap
from elasticapm.utils.logging import get_logger

logger = get_logger("elasticapm.disclosure")

# capture modes are modelled as sets of event types. ``off`` is the empty set.
_CAPTURE_MODES = {
    "off": frozenset(),
    "error": frozenset({ERROR}),
    "errors": frozenset({ERROR}),
    "transaction": frozenset({TRANSACTION}),
    "transactions": frozenset({TRANSACTION}),
    "all": frozenset({ERROR, TRANSACTION}),
}
_CAPTURE_MODE_NAMES = {
    frozenset(): "off",
    frozenset({ERROR}): "error",
    frozenset({TRANSACTION}): "transaction",
    frozenset({ERROR, TRANSACTION}): "all",
}

# local variable collection uses the same event-type sets but keeps the
# plural spelling used by the public configuration option.
_LOCAL_VARIABLE_MODE_NAMES = {
    frozenset(): "off",
    frozenset({ERROR}): "errors",
    frozenset({TRANSACTION}): "transactions",
    frozenset({ERROR, TRANSACTION}): "all",
}


def _capture_set(value):
    if value is None:
        return frozenset()
    return _CAPTURE_MODES.get(str(value).lower(), frozenset())


def _bool(value):
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)


def _min_number(ceiling, requested, unlimited_sentinel=None):
    if requested is None:
        return ceiling
    if ceiling is None:
        return requested
    if unlimited_sentinel is not None:
        ceiling = float("inf") if ceiling == unlimited_sentinel else ceiling
        requested = float("inf") if requested == unlimited_sentinel else requested
        result = min(ceiling, requested)
        return unlimited_sentinel if result == float("inf") else result
    return min(ceiling, requested)


def _span_stack_rank(value):
    if value is None:
        return 0.0
    seconds = value.total_seconds() if isinstance(value, timedelta) else float(value)
    # -1 disables stack trace collection entirely and is the strictest value.
    return float("inf") if seconds < 0 else seconds


def _span_stack_value(rank):
    return timedelta(seconds=-1) if rank == float("inf") else timedelta(seconds=rank)


def pattern_text(pattern):
    return getattr(pattern, "pattern", pattern)


def _sanitize_union(ceiling, requested):
    """More patterns means stricter redaction, so the union is the ceiling."""
    if requested is None:
        return ceiling
    if ceiling is None:
        return requested
    result = []
    seen = set()
    for pattern in list(ceiling) + list(requested):
        text = pattern_text(pattern)
        if text not in seen:
            seen.add(text)
            result.append(pattern)
    return result


def combine_values(option, ceiling, requested):
    """Combine a local ceiling with a requested (central) value.

    The result is always the more restrictive of the two values.  The function
    is symmetric, which lets it also be used to merge a transaction snapshot
    with a later local ceiling change.
    """
    if option == "capture_body":
        return _CAPTURE_MODE_NAMES[_capture_set(ceiling) & _capture_set(requested)]
    if option == "collect_local_variables":
        return _LOCAL_VARIABLE_MODE_NAMES[_capture_set(ceiling) & _capture_set(requested)]
    if option == "capture_headers":
        return _bool(ceiling) and _bool(requested)
    if option == "sanitize_field_names":
        return _sanitize_union(ceiling, requested)
    if option in ("span_stack_trace_min_duration", "span_frames_min_duration"):
        return _span_stack_value(max(_span_stack_rank(ceiling), _span_stack_rank(requested)))
    if option in (
        "local_var_max_length",
        "local_var_list_max_length",
        "local_var_dict_max_length",
        "source_lines_error_app_frames",
        "source_lines_error_library_frames",
        "source_lines_span_app_frames",
        "source_lines_span_library_frames",
    ):
        return _min_number(ceiling, requested)
    if option == "stack_trace_limit":
        return _min_number(ceiling, requested, unlimited_sentinel=-1)
    raise KeyError(option)


def serialize_value(option, value):
    """Convert an effective value back into a form the config setters accept."""
    if option in ("span_stack_trace_min_duration", "span_frames_min_duration"):
        if isinstance(value, timedelta):
            microseconds = value.total_seconds() * 1_000_000
        else:
            microseconds = float(value) * 1_000_000
        # Unitless durations are interpreted as milliseconds by the agent.
        return "%d" % int(microseconds / 1000)
    if option == "sanitize_field_names":
        return list(value or [])
    if option == "capture_headers":
        return bool(value)
    if option in ("capture_body", "collect_local_variables"):
        return str(value)
    return value


DISCLOSURE_OPTIONS = frozenset(
    (
        "capture_body",
        "capture_headers",
        "collect_local_variables",
        "sanitize_field_names",
        "local_var_max_length",
        "local_var_list_max_length",
        "local_var_dict_max_length",
        "source_lines_error_app_frames",
        "source_lines_error_library_frames",
        "source_lines_span_app_frames",
        "source_lines_span_library_frames",
        "stack_trace_limit",
        "span_stack_trace_min_duration",
        "span_frames_min_duration",
    )
)


def values_from_config(config):
    """Extract the disclosure-relevant values from a config-like object."""
    values = {}
    for option in DISCLOSURE_OPTIONS:
        if hasattr(config, option):
            values[option] = getattr(config, option)
    return values


class EventData(dict):
    """A dict that can carry the disclosure snapshot without serializing it.

    JSON encoders treat this class as a plain dictionary, so the snapshot can
    travel through the pipeline without ever being exported.
    """

    __slots__ = ("disclosure",)

    def __init__(self, *args, **kwargs):
        self.disclosure = kwargs.pop("disclosure", None)
        super(EventData, self).__init__(*args, **kwargs)


def annotate(event, values):
    """Attach a disclosure snapshot to an event for later egress filtering."""
    if isinstance(event, EventData):
        if event.disclosure is None:
            event.disclosure = values
        return event
    return EventData(event, disclosure=values)


def snapshot(config):
    """Take a disclosure snapshot for a transaction."""
    return values_from_config(config)


def stricter_values(values, ceiling):
    """Return ``values`` tightened by ``ceiling`` for all disclosure options.

    ``ceiling`` is the currently allowed maximum.  Values that were captured
    earlier are only ever narrowed, never widened.
    """
    if not ceiling:
        return dict(values or {})
    if not values:
        return dict(ceiling)
    result = dict(values)
    for option in DISCLOSURE_OPTIONS:
        if option not in ceiling:
            continue
        if option in result:
            result[option] = combine_values(option, result[option], ceiling[option])
        else:
            result[option] = ceiling[option]
    return result


def coerce_value(option, value):
    """Normalise an incoming option value to the effective representation."""
    if option in (
        "span_stack_trace_min_duration",
        "span_frames_min_duration",
    ):
        if isinstance(value, timedelta):
            return value
        raw = str(value).strip().lower()
        if raw in ("-1", "-1ms", "-1s"):
            return timedelta(seconds=-1)
        if raw in ("0", "0ms", "0s"):
            return timedelta(seconds=0)
        match = re.match(r"^(-?\d+(?:\.\d+)?)(us|ms|s|m)?$", raw)
        if not match:
            return timedelta(seconds=0)
        number, unit = match.groups()
        factor = {"us": 0.000001, "ms": 0.001, "s": 1, "m": 60, None: 0.001}[unit]
        return timedelta(seconds=float(number) * factor)
    if option == "capture_body":
        return _CAPTURE_MODE_NAMES.get(_capture_set(value), "off")
    if option == "collect_local_variables":
        return _LOCAL_VARIABLE_MODE_NAMES.get(_capture_set(value), "off")
    if option == "capture_headers":
        return _bool(value)
    if option == "sanitize_field_names":
        if value is None:
            return []
        if isinstance(value, str):
            value = value.split(",")
        return [starmatch_to_regex(item) if isinstance(item, str) else item for item in value]
    if option in (
        "local_var_max_length",
        "local_var_list_max_length",
        "local_var_dict_max_length",
        "source_lines_error_app_frames",
        "source_lines_error_library_frames",
        "source_lines_span_app_frames",
        "source_lines_span_library_frames",
        "stack_trace_limit",
    ):
        return int(value)
    raise KeyError(option)


def _event_context(event):
    context = event.get("context")
    return context if isinstance(context, dict) else None


def _stacktraces(event):
    """Yield every stacktrace list contained in an event."""
    top = event.get("stacktrace")
    if isinstance(top, list):
        yield top
    exception = event.get("exception")
    while isinstance(exception, dict):
        stacktrace = exception.get("stacktrace")
        if isinstance(stacktrace, list):
            yield stacktrace
        cause = exception.get("cause")
        if isinstance(cause, list) and cause and isinstance(cause[0], dict):
            exception = cause[0]
        else:
            break
    log = event.get("log")
    if isinstance(log, dict) and isinstance(log.get("stacktrace"), list):
        yield log["stacktrace"]


def _mode_allows(value, event_type):
    allowed = _capture_set(value)
    if event_type == SPAN:
        # Span stack traces use the "transactions" local-variable mode.
        event_type = TRANSACTION
    return event_type in allowed


def _sanitize_match(key, patterns):
    if not key:
        return False
    key = key.lower()
    for pattern in patterns:
        if hasattr(pattern, "match"):
            if pattern.match(key.strip()):
                return True
            continue
        text = str(pattern).lower()
        if fnmatch.fnmatch(key, text):
            return True
        # A serialized starmatch pattern (``(?:...)\Z``) can also arrive here
        # when a snapshot was taken before the patterns were compiled.
        try:
            if re.match(text, key):
                return True
        except re.error:
            pass
    return False


def _sanitize_mapping(mapping, patterns):
    if not isinstance(mapping, dict):
        return mapping
    result = {}
    for key, value in mapping.items():
        if _sanitize_match(key, patterns):
            result[key] = MASK
        elif isinstance(value, dict):
            result[key] = _sanitize_mapping(value, patterns)
        else:
            result[key] = value
    return result


def _sanitize_string_items(value, patterns):
    if not isinstance(value, str) or "=" not in value:
        return value
    items = []
    for item in value.split("&"):
        key, sep, rest = item.partition("=")
        if sep and _sanitize_match(key, patterns):
            items.append(key + "=" + MASK)
        else:
            items.append(item)
    return "&".join(items)


def _sanitize_event(event, patterns):
    if not patterns:
        return
    context = _event_context(event)
    if context:
        request = context.get("request")
        if isinstance(request, dict):
            if isinstance(request.get("headers"), dict):
                request["headers"] = _sanitize_mapping(request["headers"], patterns)
            if isinstance(request.get("cookies"), dict):
                request["cookies"] = _sanitize_mapping(request["cookies"], patterns)
            if isinstance(request.get("env"), dict):
                request["env"] = _sanitize_mapping(request["env"], patterns)
            if "body" in request:
                request["body"] = _sanitize_string_items(request["body"], patterns)
        response = context.get("response")
        if isinstance(response, dict) and isinstance(response.get("headers"), dict):
            response["headers"] = _sanitize_mapping(response["headers"], patterns)
    for stacktrace in _stacktraces(event):
        for frame in stacktrace:
            if isinstance(frame, dict):
                frame["vars"] = varmap(
                    lambda key, value: MASK if _sanitize_match(key, patterns) else value,
                    frame.get("vars"),
                )


_LIST_MARKER_RE = re.compile(r"^\(\d+ more elements\)$")


def _shorten_list(value, list_length):
    value = list(value)
    removed = 0
    if len(value) >= 2 and value[-2] == "..." and isinstance(value[-1], str) and _LIST_MARKER_RE.match(value[-1]):
        # Already shortened by an earlier pass. Recompute the original count so
        # tightening the limit further does not lose the already-removed count.
        removed += int(value[-1].split()[0].strip("("))
        value = value[:-2]
    total = len(value) + removed
    if total > list_length:
        value = value[:list_length] + ["...", "(%d more elements)" % (total - list_length)]
    return value


def _shorten_dict(value, dict_length):
    value = dict(value)
    removed = 0
    if "<truncated>" in value and isinstance(value["<truncated>"], str):
        match = re.match(r"^\((\d+) more elements\)$", value["<truncated>"])
        if match:
            removed = int(match.group(1))
            value.pop("<truncated>")
    total = len(value) + removed
    if total > dict_length:
        trimmed = {key: item for key, item in itertools.islice(value.items(), dict_length)}
        trimmed["<truncated>"] = "(%d more elements)" % (total - dict_length)
        return trimmed
    return value


def _shorten_value(value, values):
    from elasticapm.utils.encoding import shorten

    if isinstance(value, str):
        return shorten(value, string_length=values.get("local_var_max_length", 200))
    if isinstance(value, (list, tuple, set, frozenset)):
        return _shorten_list(value, values.get("local_var_list_max_length", 10))
    if isinstance(value, dict):
        return _shorten_dict(value, values.get("local_var_dict_max_length", 10))
    return value


def _filter_vars(event, event_type, values):
    allowed = _mode_allows(values.get("collect_local_variables", "off"), event_type)
    for stacktrace in _stacktraces(event):
        for frame in stacktrace:
            if not isinstance(frame, dict) or "vars" not in frame:
                continue
            if not allowed:
                frame.pop("vars", None)
                continue
            variables = frame.get("vars")
            if isinstance(variables, dict):
                frame["vars"] = {key: _shorten_value(value, values) for key, value in variables.items()}


def _trim_source_context(frame, allowed_lines):
    if not isinstance(frame, dict):
        return
    if not allowed_lines:
        frame.pop("pre_context", None)
        frame.pop("context_line", None)
        frame.pop("post_context", None)
        return
    # get_lines_from_file is called with context_lines = int(setting / 2).
    context_lines = int(allowed_lines / 2)
    if context_lines <= 0:
        frame.pop("pre_context", None)
        frame.pop("context_line", None)
        frame.pop("post_context", None)
        return
    pre_context = frame.get("pre_context")
    if isinstance(pre_context, list):
        frame["pre_context"] = pre_context[-context_lines:]
    post_context = frame.get("post_context")
    if isinstance(post_context, list):
        frame["post_context"] = post_context[:context_lines]


def _filter_source_context(event, event_type, values):
    if event_type == ERROR:
        app_key = "source_lines_error_app_frames"
        library_key = "source_lines_error_library_frames"
    else:
        app_key = "source_lines_span_app_frames"
        library_key = "source_lines_span_library_frames"
    for stacktrace in _stacktraces(event):
        for frame in stacktrace:
            if not isinstance(frame, dict):
                continue
            if frame.get("library_frame"):
                allowed = values.get(library_key, 0)
            else:
                allowed = values.get(app_key, 0)
            _trim_source_context(frame, allowed)


def _filter_stack_limit(event, event_type, values):
    limit = values.get("stack_trace_limit", -1)
    if limit == -1:
        return
    for stacktrace in _stacktraces(event):
        if limit == 0:
            stacktrace[:] = []
        elif len(stacktrace) > limit:
            if event_type == ERROR:
                # Errors keep the outer frames, matching iter_traceback_frames.
                stacktrace[:] = stacktrace[-limit:]
            else:
                # Spans keep the innermost frames, matching iter_stack_frames.
                stacktrace[:] = stacktrace[:limit]


def _filter_span_stacktrace(event, event_type, values):
    if event_type != SPAN:
        return
    threshold = values.get("span_stack_trace_min_duration")
    if threshold is None:
        return
    if not isinstance(threshold, timedelta):
        threshold = timedelta(seconds=float(threshold))
    if threshold.total_seconds() < 0:
        event.pop("stacktrace", None)
        return
    duration = event.get("duration")
    if isinstance(duration, (int, float)) and duration < threshold.total_seconds() * 1000:
        event.pop("stacktrace", None)


def filter_event(event_type, event, values, copy_event=False):
    """Apply a disclosure policy to an already built event.

    ``values`` is a mapping of option name to the allowed effective value.  The
    function only removes, redacts or truncates data, so legitimate diagnostics
    such as the transaction name or a stack trace's frame list remain intact.
    """
    if not isinstance(event, dict) or not values:
        return event
    if copy_event:
        event = copy.deepcopy(event)
    try:
        if event_type in (ERROR, TRANSACTION):
            context = _event_context(event)
            request = context.get("request") if context else None
            if isinstance(request, dict) and "body" in request:
                if not _mode_allows(values.get("capture_body", "off"), event_type):
                    request["body"] = MASK
            if not _bool(values.get("capture_headers", True)):
                if isinstance(request, dict):
                    request.pop("headers", None)
                response = context.get("response") if context else None
                if isinstance(response, dict):
                    response.pop("headers", None)

        patterns = values.get("sanitize_field_names")
        if patterns:
            _sanitize_event(event, patterns)
        _filter_vars(event, event_type, values)
        _filter_source_context(event, event_type, values)
        _filter_stack_limit(event, event_type, values)
        _filter_span_stacktrace(event, event_type, values)
    except Exception:
        # Never drop a legitimate event because the ceiling could not be
        # applied.  The transport's processor wrapper would otherwise treat
        # this as a processor failure and discard the event.
        logger.warning("Failed to apply local disclosure ceiling", exc_info=True)
    return event


def disclosure_report(local_values, requested_values, effective_values):
    """Build an auditable view of which options were clamped locally."""
    report = {}
    for option in sorted(DISCLOSURE_OPTIONS):
        if option not in local_values:
            continue
        central = requested_values.get(option)
        effective = effective_values.get(option)
        report[option] = {
            "local": local_values[option],
            "central": central,
            "effective": effective,
            "clamped": option in requested_values and central != effective,
        }
    return report
