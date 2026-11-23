import sys

from aws_lambda_powertools import Logger
from aws_lambda_powertools.logging.buffer import LoggerBufferConfig
from aws_lambda_powertools.logging.disclosure import DisclosureHandler, DisclosurePolicy
from aws_lambda_powertools.utilities.typing import LambdaContext

logger_buffer_config = LoggerBufferConfig(max_bytes=20480, buffer_at_verbosity="DEBUG")
logger = Logger(level="DEBUG", buffer_config=logger_buffer_config)

# (1)!
external_policy = DisclosurePolicy(
    approved_fields={
        "level",
        "message",
        "message.order_id",
        "message.customer_id",
        "order_id",
        "service",
        "timestamp",
        "correlation_id",
    },
    error_categories={ValueError: "validation_error"},
    default_error_category="internal_error",
)
external_handler = DisclosureHandler(policy=external_policy, stream=sys.stdout)
logger.addHandler(external_handler)


def lambda_handler(event: dict, context: LambdaContext):
    # (2)!
    logger.append_keys(order_id=event["order_id"])

    order = {
        "order_id": event["order_id"],
        "customer_id": event["customer_id"],
        "internal_note": "only for internal troubleshooting",
    }
    logger.debug(order)  # (3)!

    # (4)!
    external_policy.revoke("message.customer_id")
    logger.set_correlation_id(event["correlation_id"])

    try:
        raise ValueError("invalid order")
    except ValueError:
        logger.exception("order failed")  # (5)!
