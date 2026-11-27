import sys
import traceback
from collections import namedtuple

DEFAULT_FIELDS = (
    "time",
    "level",
    "name",
    "module",
    "function",
    "line",
    "thread",
    "process",
)

STAGES = {
    "filter": "record filtering",
    "format": "record formatting",
    "serialize": "record serialization",
    "queue": "enqueue of the record",
    "queue-get": "dequeue of the record",
    "write": "synchronous sink write",
    "queued-write": "background thread sink write",
    "coroutine": "asynchronous sink coroutine",
    "stop": "sink termination",
}

MAX_FIELD_LENGTH = 256

ErrorReportPolicy = namedtuple(  # noqa: PYI024
    "ErrorReportPolicy", ("restricted", "fields", "traceback", "exception")
)

FULL_REPORT = ErrorReportPolicy(False, (), True, "full")
RESTRICTED_REPORT = ErrorReportPolicy(True, DEFAULT_FIELDS, True, "type")


def parse_error_report(value):
    if value is None or value == "full":
        return FULL_REPORT

    if value == "restricted":
        return RESTRICTED_REPORT

    if isinstance(value, str):
        raise ValueError(
            "Invalid error report, it should be 'full' or 'restricted', not: '%s'" % value
        )

    if not isinstance(value, dict):
        raise TypeError(
            "Invalid error report, it should be 'full', 'restricted' or a dict, not: '%s'"
            % type(value).__name__
        )

    unknown_keys = set(value) - {"fields", "traceback", "exception"}

    if unknown_keys:
        raise TypeError("Invalid error report, unexpected key: '%s'" % sorted(unknown_keys)[0])

    fields = value.get("fields", DEFAULT_FIELDS)

    if isinstance(fields, str) or not isinstance(fields, (list, tuple)):
        raise TypeError(
            "Invalid error report, 'fields' should be a list of strings, not: '%s'"
            % type(fields).__name__
        )

    for field in fields:
        if not isinstance(field, str):
            raise TypeError(
                "Invalid error report, 'fields' should only contain strings, not: '%s'"
                % type(field).__name__
            )

    fields = tuple(fields)

    traceback_frames = value.get("traceback", True)

    if not isinstance(traceback_frames, bool):
        raise TypeError(
            "Invalid error report, 'traceback' should be a boolean, not: '%s'"
            % type(traceback_frames).__name__
        )

    exception = value.get("exception", "type")

    if exception not in ("type", "none"):
        raise ValueError(
            "Invalid error report, 'exception' should be 'type' or 'none', not: '%r'" % (exception,)
        )

    return ErrorReportPolicy(True, fields, traceback_frames, exception)


def _sanitize(text):
    result = []
    for character in text:
        code = ord(character)
        if character == "\n":
            result.append("\\n")
        elif character == "\r":
            result.append("\\r")
        elif character == "\t":
            result.append("\\t")
        elif code < 32 or code == 127:
            result.append("\\x%02x" % code)
        elif 0xD800 <= code <= 0xDFFF:
            # Escape surrogates so that the report can always be encoded to the "sys.stderr" stream.
            result.append("\\u%04x" % code)
        else:
            result.append(character)
    return "".join(result)


def _truncate(text):
    text = _sanitize(text)
    if len(text) > MAX_FIELD_LENGTH:
        return text[: MAX_FIELD_LENGTH - 3] + "..."
    return text


REDACTED_FIELDS = frozenset(("message", "template", "extra", "exception"))


def _project_value(field, value):
    # User-provided payloads are never projected, even if explicitly listed. The "message" and
    # "extra" values are the log data itself, while the exception "value" attribute would disclose
    # the same data that the restricted report deliberately hides from the traceback.
    if field in REDACTED_FIELDS:
        return "<redacted>"
    try:
        if field == "level":
            return _truncate(str(value.name))
        if field == "time":
            return _truncate(value.isoformat())
        if field == "elapsed":
            return _truncate(str(value))
        if isinstance(value, str):
            return _truncate(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return _truncate(repr(value))
    except Exception:
        return "<unprintable>"


def _format_record(record, fields):
    if record is None:
        return "None"

    projection = {}

    for field in fields:
        try:
            value = record[field]
        except Exception:
            projection[field] = "<missing>"
        else:
            projection[field] = _project_value(field, value)

    return repr(projection)


def _format_exception_type(type_):
    if type_ is None:
        return "None"
    try:
        return str(type_.__name__)
    except Exception:
        return "<unknown>"


def _format_frames(traceback_):
    try:
        # Source lines are intentionally not looked up, as they are not needed for diagnostics and
        # could disclose sensitive literals contained in the code.
        summary = traceback.StackSummary.extract(traceback.walk_tb(traceback_), lookup_lines=False)
    except Exception:
        return []

    frames = []

    for frame in summary:
        try:
            frames.append(
                '  File "%s", line %s, in %s\n'
                % (_sanitize(frame.filename), frame.lineno, _sanitize(frame.name))
            )
        except Exception:
            continue

    return frames


def _describe_stage(stage):
    if stage is None:
        return "unknown"

    description = STAGES.get(stage)

    if description is None:
        return _truncate(stage)

    return "%s (%s)" % (stage, description)


class ErrorInterceptor:
    def __init__(self, should_catch, handler_id, report=None):
        self._should_catch = should_catch
        self._handler_id = handler_id
        self._report = FULL_REPORT if report is None else report
        self._handler_name = None

    def should_catch(self):
        return self._should_catch

    def set_handler_name(self, name):
        self._handler_name = name

    def print(self, record=None, *, exception=None, stage=None):
        if not sys.stderr:
            return

        if exception is None:
            type_, value, traceback_ = sys.exc_info()
        else:
            type_, value, traceback_ = (type(exception), exception, exception.__traceback__)

        try:
            if self._report.restricted:
                try:
                    self._print_restricted(record, type_, traceback_, stage)
                except Exception:
                    # A restricted report is best-effort: an unexpected failure while writing it
                    # must never escape the logging call, otherwise "catch=True" would not prevent
                    # the application from crashing.
                    return
            else:
                self._print_full(record, type_, value, traceback_)
        except OSError:
            pass
        finally:
            del type_, value, traceback_

    def _print_full(self, record, type_, value, traceback_):
        sys.stderr.write("--- Logging error in Loguru Handler #%d ---\n" % self._handler_id)
        try:
            record_repr = str(record)
        except Exception:
            record_repr = "/!\\ Unprintable record /!\\"
        sys.stderr.write("Record was: %s\n" % record_repr)
        traceback.print_exception(type_, value, traceback_, None, sys.stderr)
        sys.stderr.write("--- End of logging error ---\n")

    def _print_restricted(self, record, type_, traceback_, stage):
        lines = ["--- Logging error in Loguru Handler #%d ---\n" % self._handler_id]

        if self._handler_name is not None:
            lines.append("Handler: %s\n" % _truncate(self._handler_name))

        lines.append("Stage: %s\n" % _describe_stage(stage))
        lines.append("Record: %s\n" % _format_record(record, self._report.fields))

        if self._report.exception != "none":
            lines.append("Exception: %s\n" % _format_exception_type(type_))

        if self._report.traceback and traceback_ is not None:
            frames = _format_frames(traceback_)
            if frames:
                lines.append("Traceback (most recent call last):\n")
                lines.extend(frames)

        lines.append("--- End of logging error ---\n")

        sys.stderr.write("".join(lines))
