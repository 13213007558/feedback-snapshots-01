"""Disclosure policy tests for buffered external log handlers."""

from __future__ import annotations

import io
import json
import logging
import os
import random
import string
from typing import Any

import pytest

from aws_lambda_powertools import Logger
from aws_lambda_powertools.logging.buffer import LoggerBufferConfig
from aws_lambda_powertools.logging.disclosure import DisclosureHandler, DisclosurePolicy
from aws_lambda_powertools.shared import constants


class CapturingHandler(DisclosureHandler):
    """DisclosureHandler that keeps the payload for assertions without parsing streams."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.payloads: list[dict[str, Any]] = []

    def emit(self, record: Any) -> None:
        super().emit(record)
        payload = getattr(record, "_powertools_disclosure_payload", None)
        if payload:
            self.payloads.append(payload)


@pytest.fixture()
def trace_id():
    def _set(value: str) -> None:
        os.environ[constants.XRAY_TRACE_ID_ENV] = value

    yield _set
    os.environ.pop(constants.XRAY_TRACE_ID_ENV, None)


@pytest.fixture()
def service_name():
    return "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(15))


def read_json_lines(stream: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


def build_policy() -> DisclosurePolicy:
    return DisclosurePolicy(
        approved_fields={
            "level",
            "message",
            "message.order_id",
            "message.customer_id",
            "message.trace_context",
            "order_id",
            "service",
            "timestamp",
            "correlation_id",
        },
        error_categories={ValueError: "validation_error"},
        default_error_category="internal_error",
    )


def test_buffered_record_uses_creation_and_send_approvals(
    service_name,
    trace_id,
    monkeypatch,
):
    # GIVEN a parent logger and a child logger sharing one trace and buffer configuration
    monkeypatch.setenv(constants.POWERTOOLS_LOG_LEVEL_ENV, "DEBUG")
    internal_stream = io.StringIO()
    external_stream = io.StringIO()
    buffer_config = LoggerBufferConfig(max_bytes=4096, buffer_at_verbosity="DEBUG")

    parent_logger = Logger(service=service_name, stream=internal_stream, buffer_config=buffer_config)
    child_logger = Logger(service=service_name, child=True)

    policy = build_policy()
    external_handler = CapturingHandler(policy=policy, stream=external_stream)
    parent_logger.addHandler(external_handler)

    # GIVEN a buffered structured message with several business dimensions
    trace_id("1-disclosure-buffered")
    child_logger.set_correlation_id("correlation-before")
    message = {
        "order_id": "order-123",
        "customer_id": "customer-9",
        "trace_context": {"span": "span-before"},
        "internal_note": "do not disclose",
    }
    message_snapshot = json.loads(json.dumps(message))

    # WHEN the message is buffered
    child_logger.debug(message)
    assert read_json_lines(internal_stream) == []

    # AND audit revokes one field, approves a new one, and changes the correlation id
    policy.revoke("message.customer_id")
    policy.approve("message.approved_later")
    child_logger.set_correlation_id("correlation-after")

    # AND an error flushes the buffer
    try:
        raise ValueError("payment failed")
    except ValueError:
        child_logger.exception("checkout failed")

    internal_logs = read_json_lines(internal_stream)
    external_logs = read_json_lines(external_stream)

    # THEN the internal handler still sees the original message and failure details
    assert internal_logs[0]["message"] == message_snapshot
    assert internal_logs[0]["correlation_id"] == "correlation-before"
    assert internal_logs[1]["exception_name"] == "ValueError"
    assert "payment failed" in internal_logs[1]["exception"]
    assert internal_logs[1]["stack_trace"]

    # THEN the external handler receives only fields approved at both points
    buffered_external = external_logs[0]
    assert buffered_external["message"] == {
        "order_id": "order-123",
        "trace_context": {"span": "span-before"},
    }
    assert buffered_external["correlation_id"] == "correlation-before"
    assert "error_category" not in buffered_external
    assert "customer_id" not in buffered_external["message"]
    assert "internal_note" not in buffered_external["message"]

    # AND the live error record exposes only the application-defined category
    assert external_logs[1]["error_category"] == "validation_error"
    assert "exception" not in external_logs[1]
    assert "payment failed" not in external_stream.getvalue()

    # AND the caller-owned message was not rewritten by either handler
    assert message == message_snapshot


def test_next_realtime_log_uses_new_approvals(service_name, trace_id, monkeypatch):
    # GIVEN a logger with an external disclosure handler
    monkeypatch.setenv(constants.POWERTOOLS_LOG_LEVEL_ENV, "DEBUG")
    internal_stream = io.StringIO()
    external_stream = io.StringIO()
    buffer_config = LoggerBufferConfig(max_bytes=4096, buffer_at_verbosity="DEBUG")
    logger = Logger(service=service_name, stream=internal_stream, buffer_config=buffer_config)
    policy = build_policy()
    policy.approve("message.approved_later")
    logger.addHandler(CapturingHandler(policy=policy, stream=external_stream))
    trace_id("1-disclosure-realtime")

    # WHEN a real-time message carries the newly approved field
    message = {"order_id": "order-456", "approved_later": "new-dimension", "internal_note": "hidden"}
    logger.info(message)

    external_logs = read_json_lines(external_stream)
    internal_logs = read_json_lines(internal_stream)

    # THEN the new approval applies to logs created after it was granted
    assert external_logs[0]["message"] == {"order_id": "order-456", "approved_later": "new-dimension"}
    assert internal_logs[0]["message"] == message


def test_oversized_record_discloses_immediately_without_mutating_caller(
    service_name,
    trace_id,
    monkeypatch,
):
    # GIVEN a small buffer that cannot hold the next structured record
    monkeypatch.setenv(constants.POWERTOOLS_LOG_LEVEL_ENV, "DEBUG")
    internal_stream = io.StringIO()
    external_stream = io.StringIO()
    buffer_config = LoggerBufferConfig(max_bytes=64, buffer_at_verbosity="DEBUG")
    logger = Logger(service=service_name, stream=internal_stream, buffer_config=buffer_config)
    policy = build_policy()
    policy.revoke("message.customer_id")
    logger.addHandler(CapturingHandler(policy=policy, stream=external_stream))
    trace_id("1-disclosure-oversized")

    message = {
        "order_id": "order-789",
        "customer_id": "customer-1",
        "internal_note": "x" * 512,
    }
    message_snapshot = json.loads(json.dumps(message))

    # WHEN the oversized record is emitted immediately instead of buffered
    with pytest.warns(UserWarning, match="Cannot add item to the buffer"):
        logger.debug(message)

    external_logs = read_json_lines(external_stream)
    internal_logs = read_json_lines(internal_stream)

    # THEN the immediate send obeys the same disclosure rule
    assert external_logs[0]["message"] == {"order_id": "order-789"}
    assert "customer_id" not in external_logs[0]["message"]
    assert "internal_note" not in external_logs[0]["message"]

    # AND the internal handler still receives the complete record
    assert internal_logs[0]["message"] == message_snapshot

    # AND the caller-owned object is untouched
    assert message == message_snapshot
    assert isinstance(message["internal_note"], str)


def test_disclosure_policy_does_not_approve_nested_message_implicitly(service_name, trace_id):
    # GIVEN a policy that approves only the message container
    internal_stream = io.StringIO()
    external_stream = io.StringIO()
    logger = Logger(service=service_name, stream=internal_stream)
    policy = DisclosurePolicy({"level", "message", "service", "timestamp"}, default_error_category="internal_error")
    logger.addHandler(CapturingHandler(policy=policy, stream=external_stream))
    trace_id("1-disclosure-container")

    # WHEN a dict message carries an unapproved dimension
    logger.info({"order_id": "order-000", "secret": "hidden"})

    external_logs = read_json_lines(external_stream)

    # THEN the container approval does not leak nested dimensions
    assert "secret" not in external_logs[0]
    assert "order_id" not in external_logs[0]


def test_external_handler_ignores_unapproved_exception_details(service_name, trace_id):
    # GIVEN an external handler with only an application-defined error category
    internal_stream = io.StringIO()
    external_stream = io.StringIO()
    logger = Logger(service=service_name, stream=internal_stream)
    policy = DisclosurePolicy(
        {"level", "message", "service", "timestamp", "exception_name"},
        error_categories={RuntimeError: "dependency_failure"},
        default_error_category="internal_error",
    )
    logger.addHandler(CapturingHandler(policy=policy, stream=external_stream))
    trace_id("1-disclosure-exception")

    # WHEN an exception is logged
    try:
        raise RuntimeError("database password is hunter2")
    except RuntimeError:
        logger.exception("operation failed")

    internal_logs = read_json_lines(internal_stream)
    external_logs = read_json_lines(external_stream)

    # THEN internals keep troubleshooting details and externals only the category
    assert internal_logs[0]["exception_name"] == "RuntimeError"
    assert "hunter2" in internal_logs[0]["exception"]
    assert external_logs[0]["error_category"] == "dependency_failure"
    assert "exception" not in external_logs[0]
    assert "exception_name" not in external_logs[0]
    assert "stack_trace" not in external_logs[0]
    assert "hunter2" not in external_stream.getvalue()


def test_disclosure_handler_format_never_reads_live_logger_context(service_name, trace_id):
    # GIVEN a policy and a handler that is not bound to a logger
    policy = DisclosurePolicy({"level", "message", "service", "timestamp"})
    handler = CapturingHandler(policy=policy, stream=io.StringIO())
    logger = Logger(service=service_name)
    trace_id("1-disclosure-format")

    # WHEN a record is formatted through the handler's formatter
    logger.info("plain message")
    record = logger._logger.makeRecord(
        name=service_name,
        level=20,
        fn=__file__,
        lno=1,
        msg="plain message",
        args=(),
        exc_info=None,
        func="test",
    )
    rendered = json.loads(handler.formatter.format(record))

    # THEN only the sanitized payload reaches the external formatter
    assert rendered == ""
    assert isinstance(policy.approved_fields, frozenset)


def test_external_formatter_only_sees_approved_record_attributes(service_name, trace_id):
    # GIVEN an external handler with a formatter that inspects record attributes
    internal_stream = io.StringIO()
    external_stream = io.StringIO()
    logger = Logger(service=service_name, stream=internal_stream)

    class AttributeFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            return json.dumps({key: value for key, value in record.__dict__.items() if key == "internal_note"})

    handler = DisclosureHandler(
        policy=DisclosurePolicy({"level", "message", "service", "timestamp"}),
        stream=external_stream,
        formatter=AttributeFormatter(),
    )
    logger.addHandler(handler)
    trace_id("1-disclosure-formatter")

    # WHEN a log carries an unapproved extra
    logger.info("approved", extra={"internal_note": "hidden"})

    # THEN the external formatter cannot see the unapproved attribute
    assert json.loads(external_stream.getvalue()) == {}
    assert internal_stream.getvalue()
