"""
Restricted Context utility.

Provides a consistent, sealed identity context for Lambda functions that
serve both HTTP API requests and internal SQS events. Only entry points that
verify the event can build the context; shared handlers receive just the
principal and workspace, never the raw authenticated event.

Example
-------
    from aws_lambda_powertools.utilities.restricted_context import (
        RestrictedContext,
        build_restricted_context,
    )

    def shared_handler(context: RestrictedContext, payload: dict) -> dict:
        ...
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from aws_lambda_powertools.utilities.restricted_context.api import (
    DEFAULT_PRINCIPAL_CLAIM,
    DEFAULT_WORKSPACE_CLAIM,
    build_restricted_context_from_api_event,
)
from aws_lambda_powertools.utilities.restricted_context.context import RestrictedContext
from aws_lambda_powertools.utilities.restricted_context.exceptions import (
    RestrictedContextConstructionError,
    RestrictedContextError,
    UnrecognizedEventError,
    UnverifiedEventError,
)
from aws_lambda_powertools.utilities.restricted_context.sqs import (
    build_restricted_context_from_sqs_record,
    build_restricted_contexts_from_sqs_event,
)

__all__ = [
    'RestrictedContext',
    'RestrictedContextConstructionError',
    'RestrictedContextError',
    'UnrecognizedEventError',
    'UnverifiedEventError',
    'build_restricted_context',
    'build_restricted_context_from_api_event',
    'build_restricted_context_from_sqs_record',
    'build_restricted_contexts_from_sqs_event',
]


def _is_api_event(event: Mapping[str, Any]) -> bool:
    # HTTP API v2 puts routeKey at the event root; REST v1 puts httpMethod in requestContext
    if 'routeKey' in event:
        return True
    request_context = event.get('requestContext')
    if not isinstance(request_context, Mapping):
        return False
    return 'httpMethod' in request_context


def _is_sqs_event(event: Mapping[str, Any]) -> bool:
    records = event.get('Records')
    if not isinstance(records, list) or not records:
        return False
    first = records[0]
    return isinstance(first, Mapping) and first.get('eventSource') == 'aws:sqs'


def build_restricted_context(
    event: Mapping[str, Any],
    *,
    allowed_queue_arns: Collection[str] | None = None,
    allowed_sender_ids: Collection[str] | None = None,
    principal_claim: str = DEFAULT_PRINCIPAL_CLAIM,
    workspace_claim: str = DEFAULT_WORKSPACE_CLAIM,
) -> RestrictedContext | list[tuple[RestrictedContext, dict[str, Any]]]:
    """Dispatch an event to the matching verified entry point.

    API Gateway events resolve to a single :class:`RestrictedContext`;
    SQS events resolve to one ``(context, payload)`` pair per record.

    Raises:
        UnrecognizedEventError: when the event matches neither supported shape.
        UnverifiedEventError: when the event is recognized but cannot be verified.
    """
    if not isinstance(event, Mapping):
        raise UnrecognizedEventError('event must be a mapping')
    if _is_api_event(event):
        return build_restricted_context_from_api_event(
            event,
            principal_claim=principal_claim,
            workspace_claim=workspace_claim,
        )
    if _is_sqs_event(event):
        if not allowed_queue_arns:
            raise UnverifiedEventError('an SQS event requires an explicit allowed_queue_arns allow list')
        return build_restricted_contexts_from_sqs_event(
            event,
            allowed_queue_arns=allowed_queue_arns,
            allowed_sender_ids=allowed_sender_ids,
        )
    raise UnrecognizedEventError('event is neither an API Gateway nor an SQS event')
