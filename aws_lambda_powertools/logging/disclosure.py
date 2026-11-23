from __future__ import annotations

import copy
import json
import logging
from collections.abc import Mapping
from threading import RLock
from typing import TYPE_CHECKING, Any

from aws_lambda_powertools.logging.constants import LOGGER_INTERNAL_RECORD_ATTRS
from aws_lambda_powertools.logging.formatter import RESERVED_LOG_ATTRS, LambdaPowertoolsFormatter

if TYPE_CHECKING:
    from collections.abc import Iterable

    from aws_lambda_powertools.logging.logger import Logger

# Record attributes used internally when replaying buffered records. They are
# never part of the log output and must not be treated as customer fields.
INTERNAL_RECORD_KEYS = frozenset(RESERVED_LOG_ATTRS) | frozenset(LOGGER_INTERNAL_RECORD_ATTRS)

# Exception details are kept for the internal handler. The external handler only
# receives the application defined error category.
EXCEPTION_FIELD_NAMES = frozenset(
    {
        "exception",
        "exception_name",
        "exception_notes",
        "stack_trace",
        "exc_info",
        "exc_text",
        "stack_info",
    },
)

_MISSING = object()


class DisclosurePolicy:
    """Defines which fields an external log handler may disclose.

    A field is a dot separated path, for example ``order_id`` or
    ``message.order_id``. A single ``*`` segment matches one level, and ``**``
    matches any remaining levels. Structured messages are containers: approving
    ``message`` alone does not approve the keys of a dict message, use
    ``message.<key>`` or ``message.*`` to disclose those dimensions explicitly.

    The policy is mutable because audit approvals change at runtime. A record
    buffered before an approval change keeps the approvals that existed when it
    was created; the handler intersects them with the approvals at send time.
    """

    def __init__(
        self,
        approved_fields: Iterable[str],
        *,
        error_categories: Mapping[object, str] | None = None,
        default_error_category: str | None = None,
    ) -> None:
        self._lock = RLock()
        self._approved_fields = frozenset(approved_fields)
        self._error_categories = dict(error_categories or {})
        self._default_error_category = default_error_category

    @property
    def approved_fields(self) -> frozenset[str]:
        """Snapshot of the fields approved right now."""
        with self._lock:
            return self._approved_fields

    def approve(self, *fields: str) -> None:
        """Approve fields for future records and future sends."""
        with self._lock:
            self._approved_fields = self._approved_fields | frozenset(fields)

    def revoke(self, *fields: str) -> None:
        """Revoke fields so neither buffered nor future records disclose them."""
        with self._lock:
            self._approved_fields = self._approved_fields - frozenset(fields)

    def set_approved_fields(self, fields: Iterable[str]) -> None:
        """Replace the approved field set, e.g. after an audit decision."""
        with self._lock:
            self._approved_fields = frozenset(fields)

    def error_category(self, exc_info: object) -> str | None:
        """Return the application defined category for an exception, if any."""
        if not isinstance(exc_info, tuple) or len(exc_info) < 2 or exc_info[1] is None:
            return None

        exc = exc_info[1]
        candidates: list[object] = [type(exc), type(exc).__name__, type(exc).__qualname__]
        candidates.extend(type(exc).__mro__)
        candidates.append(f"{type(exc).__module__}.{type(exc).__qualname__}")

        with self._lock:
            for candidate in candidates:
                if candidate in self._error_categories:
                    category = self._error_categories[candidate]
                    return category if isinstance(category, str) else None

            return self._default_error_category


def _match_segments(pattern: list[str], path: list[str], pattern_index: int, path_index: int) -> bool:
    if pattern_index == len(pattern):
        return path_index == len(path)

    token = pattern[pattern_index]
    if token == "**":
        return any(
            _match_segments(pattern, path, pattern_index + 1, next_index)
            for next_index in range(path_index, len(path) + 1)
        )

    if path_index == len(path):
        return False

    if token in {"*", path[path_index]}:
        return _match_segments(pattern, path, pattern_index + 1, path_index + 1)

    return False


def _matches(path: str, approved_fields: frozenset[str]) -> bool:
    return any(_match_segments(field.split("."), path.split("."), 0, 0) for field in approved_fields)


def _copy_value(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:  # noqa: BLE001 - arbitrary customer values may not be copyable
        return value


def _project_value(value: Any, path: str, approved_fields: frozenset[str]) -> Any:
    """Return a projected copy of value or _MISSING when no dimension is approved."""
    if isinstance(value, Mapping):
        # A structured message is a container of business dimensions. Its own
        # approval must not implicitly approve every key it happens to contain.
        if path != "message" and _matches(path, approved_fields):
            return _copy_value(value)

        projected: dict[Any, Any] = {}
        for key, child_value in value.items():
            child_path = f"{path}.{key}"
            projected_child = _project_value(child_value, child_path, approved_fields)
            if projected_child is not _MISSING:
                projected[key] = projected_child

        return projected if projected else _MISSING

    if isinstance(value, list | tuple):
        if _matches(path, approved_fields):
            return _copy_value(value)

        projected_items = []
        for item in value:
            projected_item = _project_value(item, f"{path}.*", approved_fields)
            if projected_item is not _MISSING:
                projected_items.append(projected_item)

        return projected_items if projected_items else _MISSING

    if _matches(path, approved_fields):
        return _copy_value(value)

    return _MISSING


def _resolve_placeholder(value: Any, record_dict: dict[str, Any]) -> Any:
    if isinstance(value, str) and "%(" in value:
        try:
            return value % record_dict
        except (KeyError, TypeError, ValueError):
            return value
    return value


class DisclosureFormatter(LambdaPowertoolsFormatter):
    """Formatter that only serializes the sanitized disclosure payload.

    The handler builds a payload containing approved fields and the application
    defined error category. This formatter never reads the live logger context,
    so changing keys after a record was buffered cannot leak into that record.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload = getattr(record, "_powertools_disclosure_payload", "")
        return self.serialize(log=payload)


class DisclosureHandler(logging.StreamHandler):
    """Stream handler that applies an optional disclosure policy.

    Use it as the external destination of a Logger. The internal handler keeps
    receiving complete records while this handler only receives approved fields.

    A buffered record stores the approved fields from its creation time. When the
    record is flushed, or emitted immediately because it does not fit in the
    buffer, this handler intersects those approvals with the current policy
    approvals and drops every field that is no longer approved at either point.
    """

    def __init__(
        self,
        policy: DisclosurePolicy,
        *,
        stream: Any = None,
        formatter: logging.Formatter | None = None,
    ) -> None:
        super().__init__(stream)
        self.policy = policy
        self._logger: Logger | None = None
        self.setFormatter(formatter or DisclosureFormatter())

    def bind_logger(self, logger: Logger) -> None:
        """Attach the source logger so real-time records can be projected."""
        self._logger = logger

    def emit(self, record: logging.LogRecord) -> None:
        try:
            sanitized_record = self._sanitize_record(record)
            if sanitized_record is None:
                return

            message = self.format(sanitized_record)
            if message:
                self.stream.write(message + self.terminator)
                self.flush()
        except Exception:  # noqa: BLE001 - logging handlers must not break the caller
            self.handleError(record)

    def _sanitize_record(self, record: logging.LogRecord) -> logging.LogRecord | None:
        approved_fields = self._effective_approvals(record)
        if approved_fields is None:
            return None

        log_keys, log_context = self._log_state(record)
        payload = self._build_payload(record, approved_fields, log_keys, log_context)
        if not payload:
            return None

        # Build a fresh LogRecord instead of copying the caller's record. A
        # caller-supplied external formatter must not be able to read unapproved
        # extras, messages or exception objects from record.__dict__.
        sanitized_record = logging.LogRecord(
            name=record.name,
            level=record.levelno,
            pathname=record.pathname,
            lineno=record.lineno,
            msg=payload,
            args=(),
            exc_info=None,
            func=record.funcName,
        )
        sanitized_record.levelname = record.levelname
        sanitized_record.created = record.created
        sanitized_record.msecs = record.msecs
        sanitized_record.relativeCreated = record.relativeCreated
        sanitized_record.thread = record.thread
        sanitized_record.threadName = record.threadName
        sanitized_record.processName = record.processName
        sanitized_record.process = record.process
        sanitized_record.module = record.module
        sanitized_record.filename = record.filename
        sanitized_record.exc_text = None
        sanitized_record.stack_info = None

        for key, value in payload.items():
            if key != "message":
                setattr(sanitized_record, key, value)

        sanitized_record._powertools_disclosure_payload = payload
        return sanitized_record

    def _effective_approvals(self, record: logging.LogRecord) -> frozenset[str] | None:
        snapshots = getattr(record, "_powertools_disclosure_snapshots", None)
        if snapshots is None:
            # Real-time emission: creation and send happen at the same moment.
            return self.policy.approved_fields

        if not isinstance(snapshots, list | tuple):
            return self.policy.approved_fields

        creation_approvals: frozenset[str] | None = None
        for policy, approved_fields in snapshots:
            if policy is self.policy:
                creation_approvals = frozenset(approved_fields)
                break

        if creation_approvals is None:
            # This handler policy did not exist when the record was buffered.
            return None

        return creation_approvals & self.policy.approved_fields

    def _log_state(self, record: logging.LogRecord) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        buffered_keys = getattr(record, "_powertools_log_keys", None)
        buffered_context = getattr(record, "_powertools_log_context", None)

        if isinstance(buffered_keys, Mapping) or isinstance(buffered_context, Mapping):
            return buffered_keys or {}, buffered_context or {}

        if self._logger is None:
            return {}, {}

        try:
            return dict(self._logger._buffer_log_keys()), dict(self._logger._buffer_log_context())
        except Exception:  # noqa: BLE001 - orphaned child loggers have no formatter yet
            return {}, {}

    def _build_payload(
        self,
        record: logging.LogRecord,
        approved_fields: frozenset[str],
        log_keys: Mapping[str, Any],
        log_context: Mapping[str, Any],
    ) -> dict[str, Any]:
        record_dict = dict(record.__dict__)
        record_dict["asctime"] = self.formatter.formatTime(record)
        record_dict.setdefault("levelname", record.levelname)

        source: dict[str, Any] = {}
        for key, value in log_keys.items():
            source[key] = _resolve_placeholder(value, record_dict)
        for key, value in log_context.items():
            source[key] = _resolve_placeholder(value, record_dict)

        for key, value in record.__dict__.items():
            if key in INTERNAL_RECORD_KEYS or key in EXCEPTION_FIELD_NAMES:
                continue
            source[key] = value

        payload: dict[str, Any] = {}
        for key, value in source.items():
            projected = _project_value(value, key, approved_fields)
            if projected is not _MISSING and projected is not None:
                payload[key] = projected

        projected_message = _project_value(self._message_value(record), "message", approved_fields)
        if projected_message is not _MISSING and projected_message is not None:
            payload["message"] = projected_message

        self._add_standard_fields(record, payload, approved_fields)

        error_category = self.policy.error_category(record.exc_info)
        if error_category is not None:
            payload["error_category"] = error_category

        return payload

    def _add_standard_fields(
        self,
        record: logging.LogRecord,
        payload: dict[str, Any],
        approved_fields: frozenset[str],
    ) -> None:
        if "level" not in payload and _matches("level", approved_fields):
            payload["level"] = record.levelname
        if "timestamp" not in payload and _matches("timestamp", approved_fields):
            payload["timestamp"] = self.formatter.formatTime(record)

    def _message_value(self, record: logging.LogRecord) -> Any:
        if record.args:
            return record.getMessage()

        message = record.msg
        if isinstance(message, str):
            try:
                parsed = json.loads(message)
            except (TypeError, ValueError):
                return message

            if isinstance(parsed, Mapping | list | tuple):
                return parsed

        return message
