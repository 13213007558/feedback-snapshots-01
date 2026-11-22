from __future__ import annotations

import copy
import io
import json
import logging
import random
import string
from typing import TYPE_CHECKING

import pytest

from aws_lambda_powertools import Logger
from aws_lambda_powertools.logging.formatter import LambdaPowertoolsFormatter

if TYPE_CHECKING:
    from collections.abc import Iterable

# Dimensions the third party is approved to see; everything else stays internal
APPROVED_EXTERNAL_KEYS = frozenset({"level", "message", "service", "timestamp", "order_id"})


class AllowlistProjectionFormatter(LambdaPowertoolsFormatter):
    """Projects the service formatter's rendered log onto an approved set of keys.

    The full record is rendered by the source formatter and then reduced to the
    allowlist, so appended keys, extras and exceptions reach this handler but only
    approved dimensions are emitted. The shared LogRecord is never mutated, keeping
    the internal handler's output and caller-owned objects intact.
    """

    def __init__(
        self,
        source_formatter: LambdaPowertoolsFormatter,
        allowed_keys: Iterable[str],
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.source_formatter = source_formatter
        self.allowed_keys = frozenset(allowed_keys)

    def format(self, record: logging.LogRecord) -> str:
        rendered = json.loads(self.source_formatter.format(record))
        projected = {key: value for key, value in rendered.items() if key in self.allowed_keys}
        return self.serialize(projected)


@pytest.fixture
def internal_stream():
    return io.StringIO()


@pytest.fixture
def external_stream():
    return io.StringIO()


@pytest.fixture
def service_name():
    chars = string.ascii_letters + string.digits
    return "".join(random.SystemRandom().choice(chars) for _ in range(15))


@pytest.fixture
def logger(service_name, internal_stream, external_stream):
    # GIVEN one Powertools Logger fanning out to an internal target (full context)
    # and an external target (approved dimensions only)
    logger = Logger(service=service_name, stream=internal_stream)
    external_handler = logging.StreamHandler(stream=external_stream)
    external_handler.setFormatter(
        AllowlistProjectionFormatter(
            source_formatter=logger.registered_formatter,
            allowed_keys=APPROVED_EXTERNAL_KEYS,
        ),
    )
    logger.addHandler(external_handler)
    return logger


def read_json(stream):
    return json.loads(stream.getvalue().strip())


def test_info_log_projects_per_target(logger, internal_stream, external_stream):
    # GIVEN a business log whose extra carries sensitive internal context
    extra = {
        "order_id": "order-123",
        "customer_document": "111.444.777-35",
        "internal_trace": {"span_id": "abc", "attempt": 2},
    }
    extra_snapshot = copy.deepcopy(extra)

    # WHEN the log is emitted once
    logger.info("order charged", extra=extra)

    # THEN the internal record keeps the full context
    internal_log = read_json(internal_stream)
    assert internal_log["message"] == "order charged"
    assert internal_log["order_id"] == "order-123"
    assert internal_log["customer_document"] == "111.444.777-35"
    assert internal_log["internal_trace"] == {"span_id": "abc", "attempt": 2}

    # AND the external record keeps only approved dimensions
    external_log = read_json(external_stream)
    assert external_log["message"] == "order charged"
    assert external_log["order_id"] == "order-123"
    assert "customer_document" not in external_log
    assert "internal_trace" not in external_log
    assert set(external_log) <= APPROVED_EXTERNAL_KEYS

    # AND the caller-owned object is left untouched
    assert extra == extra_snapshot


def test_exception_log_projects_per_target(logger, internal_stream, external_stream):
    # GIVEN a failing operation logged with sensitive context
    extra = {"order_id": "order-123", "gateway_token": "secret-token"}
    extra_snapshot = copy.deepcopy(extra)

    # WHEN an exception log is emitted once
    try:
        raise ValueError("gateway timeout")
    except ValueError:
        logger.exception("charge failed", extra=extra)

    # THEN the internal record keeps full troubleshooting details
    internal_log = read_json(internal_stream)
    assert internal_log["message"] == "charge failed"
    assert internal_log["exception_name"] == "ValueError"
    assert "gateway timeout" in internal_log["exception"]
    assert "stack_trace" in internal_log
    assert internal_log["gateway_token"] == "secret-token"

    # AND the external record keeps only approved dimensions, no failure internals
    external_log = read_json(external_stream)
    assert external_log["message"] == "charge failed"
    assert external_log["order_id"] == "order-123"
    assert "exception" not in external_log
    assert "exception_name" not in external_log
    assert "stack_trace" not in external_log
    assert "gateway_token" not in external_log
    assert set(external_log) <= APPROVED_EXTERNAL_KEYS

    # AND the caller-owned object is left untouched
    assert extra == extra_snapshot


def test_append_keys_projects_per_target(logger, internal_stream, external_stream):
    # GIVEN the application enriches the logger with persistent context
    logger.append_keys(order_id="order-123", internal_session="sess-abc")
    extra = {"cart_size": 3}
    extra_snapshot = copy.deepcopy(extra)

    # WHEN a log is emitted once
    logger.info("cart checked out", extra=extra)

    # THEN the internal record carries every appended key
    internal_log = read_json(internal_stream)
    assert internal_log["order_id"] == "order-123"
    assert internal_log["internal_session"] == "sess-abc"
    assert internal_log["cart_size"] == 3

    # AND the external record carries only appended keys that are approved
    external_log = read_json(external_stream)
    assert external_log["order_id"] == "order-123"
    assert "internal_session" not in external_log
    assert "cart_size" not in external_log
    assert set(external_log) <= APPROVED_EXTERNAL_KEYS

    # AND logger state never leaks into the caller-owned object
    assert extra == extra_snapshot
