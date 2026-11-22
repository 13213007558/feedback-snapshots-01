"""Privacy regression tests for Logger when Lambda reuses the execution environment."""

from __future__ import annotations

import io
import json
import random
import string
from collections import namedtuple

import pytest

from aws_lambda_powertools import Logger

CUSTOMER_FIELDS = ("customer_id", "customer_email", "correlation_id")


def make_lambda_context(request_id: str, function_name: str = "order-processor"):
    return namedtuple(
        "LambdaContext",
        ["function_name", "memory_limit_in_mb", "invoked_function_arn", "aws_request_id"],
    )(
        function_name,
        256,
        f"arn:aws:lambda:eu-west-1:809313241:function:{function_name}",
        request_id,
    )


def parse_log_records(stdout: io.StringIO) -> tuple[list[str], list[dict]]:
    lines = [line for line in stdout.getvalue().splitlines() if line.strip()]
    return lines, [json.loads(line) for line in lines]


def assert_platform_identifiers(log: dict, context) -> None:
    assert log["function_name"] == context.function_name
    assert log["function_memory_size"] == context.memory_limit_in_mb
    assert log["function_arn"] == context.invoked_function_arn
    assert log["function_request_id"] == context.aws_request_id


def assert_previous_customer_values_are_not_reused(raw_line: str, previous_event: dict) -> None:
    for field in CUSTOMER_FIELDS:
        if previous_event.get(field):
            assert previous_event[field] not in raw_line, f"Previous invocation value leaked: {field}"


@pytest.fixture
def stdout():
    return io.StringIO()


@pytest.fixture
def service_name():
    chars = string.ascii_letters + string.digits
    return "".join(random.SystemRandom().choice(chars) for _ in range(15))


def test_warm_invocation_does_not_reuse_customer_keys_after_normal_return(stdout, service_name):
    # GIVEN a single Logger instance shared by every invocation in the execution environment
    logger = Logger(service=service_name, stream=stdout)

    @logger.inject_lambda_context(clear_state=True)
    def handler(event, context):
        logger.append_keys(customer_id=event["customer_id"], correlation_id=event["correlation_id"])
        if event.get("customer_email"):
            logger.append_keys(customer_email=event["customer_email"])
        logger.info("Processed request")

    first_context = make_lambda_context("request-first")
    second_context = make_lambda_context("request-second")

    first_event = {
        "customer_id": "customer-A-9c4a",
        "customer_email": "alice@example.com",
        "correlation_id": "corr-A-9c4a",
    }
    second_event = {
        "customer_id": "customer-B-1e2b",
        "correlation_id": "corr-B-1e2b",
    }

    # WHEN the same logger handles a normal invocation and then the next customer request
    handler(first_event, first_context)
    handler(second_event, second_context)

    # THEN only the two real JSON records emitted by the handler are evaluated
    lines, logs = parse_log_records(stdout)
    assert len(logs) == 2, "Expected exactly one log record per invocation"
    first_log, second_log = logs

    # AND the first record still carries its customer context and platform identifiers
    assert first_log["customer_id"] == first_event["customer_id"]
    assert first_log["customer_email"] == first_event["customer_email"]
    assert first_log["correlation_id"] == first_event["correlation_id"]
    assert first_log["level"] == "INFO"
    assert "exception_name" not in first_log
    assert_platform_identifiers(first_log, first_context)

    # AND the second record only carries the second customer context
    assert second_log["customer_id"] == second_event["customer_id"]
    assert second_log["correlation_id"] == second_event["correlation_id"]
    assert second_log["level"] == "INFO"
    assert "exception_name" not in second_log
    assert_platform_identifiers(second_log, second_context)

    # AND no customer value from the previous invocation survives into the next one
    assert_previous_customer_values_are_not_reused(lines[1], first_event)
    assert "customer_email" not in second_log


def test_warm_invocation_does_not_reuse_customer_keys_after_uncaught_exception(stdout, service_name):
    # GIVEN a single Logger instance shared by every invocation in the execution environment
    logger = Logger(service=service_name, stream=stdout)

    @logger.inject_lambda_context(clear_state=True)
    def handler(event, context):
        logger.append_keys(customer_id=event["customer_id"], correlation_id=event["correlation_id"])
        if event.get("customer_email"):
            logger.append_keys(customer_email=event["customer_email"])

        if event.get("fail"):
            try:
                raise RuntimeError(f"Unable to charge customer {event['customer_id']}")
            except RuntimeError:
                logger.exception("Customer request failed")
                raise

        logger.info("Processed request")

    first_context = make_lambda_context("request-failing")
    second_context = make_lambda_context("request-after-failure")

    first_event = {
        "customer_id": "customer-A-5d7c",
        "customer_email": "alice@example.com",
        "correlation_id": "corr-A-5d7c",
        "fail": True,
    }
    second_event = {
        "customer_id": "customer-B-2f8d",
        "correlation_id": "corr-B-2f8d",
    }

    # WHEN the first invocation exits abnormally and the same logger handles the next customer request
    with pytest.raises(RuntimeError, match="Unable to charge customer customer-A-5d7c"):
        handler(first_event, first_context)
    handler(second_event, second_context)

    # THEN only the two real JSON records emitted by the handler are evaluated
    lines, logs = parse_log_records(stdout)
    assert len(logs) == 2, "Expected exactly one log record per invocation"
    failed_log, next_log = logs

    # AND the failed invocation keeps its platform identifiers, customer context and exception classification
    assert failed_log["level"] == "ERROR"
    assert failed_log["message"] == "Customer request failed"
    assert failed_log["exception_name"] == "RuntimeError"
    assert "customer-A-5d7c" in failed_log["exception"]
    assert failed_log["customer_id"] == first_event["customer_id"]
    assert failed_log["customer_email"] == first_event["customer_email"]
    assert failed_log["correlation_id"] == first_event["correlation_id"]
    assert_platform_identifiers(failed_log, first_context)

    # AND the next invocation is acknowledged as a normal request, not as an exception
    assert next_log["level"] == "INFO"
    assert next_log["message"] == "Processed request"
    assert "exception" not in next_log
    assert "exception_name" not in next_log
    assert "stack_trace" not in next_log
    assert next_log["customer_id"] == second_event["customer_id"]
    assert next_log["correlation_id"] == second_event["correlation_id"]
    assert_platform_identifiers(next_log, second_context)

    # AND no customer value or previous request identifier survives the abnormal exit
    assert_previous_customer_values_are_not_reused(lines[1], first_event)
    assert "customer_email" not in next_log
    assert first_context.aws_request_id not in lines[1]
    assert first_context.invoked_function_arn == second_context.invoked_function_arn


def test_warm_invocation_keeps_normal_and_exception_classification_separate(stdout, service_name):
    # GIVEN a single Logger instance shared by every invocation in the execution environment
    logger = Logger(service=service_name, stream=stdout)

    @logger.inject_lambda_context(clear_state=True)
    def handler(event, context):
        logger.append_keys(customer_id=event["customer_id"], correlation_id=event["correlation_id"])
        if event.get("fail"):
            try:
                raise ValueError(f"Invalid payload for customer {event['customer_id']}")
            except ValueError:
                logger.exception("Validation failed")
                raise

        logger.info("Processed request")

    first_context = make_lambda_context("request-success")
    second_context = make_lambda_context("request-invalid")

    first_event = {
        "customer_id": "customer-A-3a9f",
        "correlation_id": "corr-A-3a9f",
    }
    second_event = {
        "customer_id": "customer-B-6d1c",
        "correlation_id": "corr-B-6d1c",
        "fail": True,
    }

    # WHEN a normal invocation is followed by a failing one handled by the same logger
    handler(first_event, first_context)
    with pytest.raises(ValueError, match="Invalid payload for customer customer-B-6d1c"):
        handler(second_event, second_context)

    # THEN the two real JSON records keep their own customer context and classification
    lines, logs = parse_log_records(stdout)
    assert len(logs) == 2, "Expected exactly one log record per invocation"
    success_log, failure_log = logs

    assert success_log["level"] == "INFO"
    assert success_log["message"] == "Processed request"
    assert "exception" not in success_log
    assert "exception_name" not in success_log
    assert success_log["customer_id"] == first_event["customer_id"]
    assert_platform_identifiers(success_log, first_context)

    assert failure_log["level"] == "ERROR"
    assert failure_log["message"] == "Validation failed"
    assert failure_log["exception_name"] == "ValueError"
    assert "customer-B-6d1c" in failure_log["exception"]
    assert failure_log["customer_id"] == second_event["customer_id"]
    assert failure_log["correlation_id"] == second_event["correlation_id"]
    assert_platform_identifiers(failure_log, second_context)

    # AND no customer value from the previous invocation survives into the failure record
    assert_previous_customer_values_are_not_reused(lines[1], first_event)
    assert first_context.aws_request_id not in lines[1]
