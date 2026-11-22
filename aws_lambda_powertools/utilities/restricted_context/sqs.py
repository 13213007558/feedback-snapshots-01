"""
Internal SQS entry point for the restricted context.

A queue record is accepted only when it originates from an explicitly
allowed queue and its body carries an identity envelope with a principal and
a workspace. Only those two fields cross the boundary; the remaining body is
returned untouched as the ordinary business payload.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Iterable, Mapping
from typing import Any

from aws_lambda_powertools.utilities.restricted_context.context import (
    RestrictedContext,
    _create_restricted_context,
)
from aws_lambda_powertools.utilities.restricted_context.exceptions import UnverifiedEventError

SQS_EVENT_SOURCE = 'aws:sqs'
DEFAULT_PRINCIPAL_FIELD = 'principal_id'
DEFAULT_WORKSPACE_FIELD = 'workspace_id'
_PAYLOAD_FIELD = 'payload'


def _verify_record_source(
    record: Any,
    allowed_queue_arns: Collection[str],
    allowed_sender_ids: Collection[str],
) -> None:
    if not isinstance(record, Mapping):
        raise UnverifiedEventError('SQS record is not an object')
    if record.get('eventSource') != SQS_EVENT_SOURCE:
        raise UnverifiedEventError('record does not come from an SQS event source')

    queue_arn = record.get('eventSourceARN')
    if queue_arn not in allowed_queue_arns:
        raise UnverifiedEventError(
            f'record queue {queue_arn!r} is not in the allowed queue list',
        )

    if allowed_sender_ids:
        attributes = record.get('attributes')
        sender_id = attributes.get('SenderId') if isinstance(attributes, Mapping) else None
        if sender_id not in allowed_sender_ids:
            raise UnverifiedEventError(f'record sender {sender_id!r} is not in the allowed sender list')


def _parse_body(record: Mapping[str, Any]) -> Mapping[str, Any]:
    raw_body = record.get('body')
    if isinstance(raw_body, str):
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, TypeError) as exc:
            raise UnverifiedEventError('SQS record body is not valid JSON') from exc
    elif isinstance(raw_body, Mapping):
        body = raw_body
    else:
        raise UnverifiedEventError('SQS record body is missing')
    if not isinstance(body, Mapping):
        raise UnverifiedEventError('SQS record body is not a JSON object')
    return body


def _identity_value(body: Mapping[str, Any], field: str, label: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value.strip():
        raise UnverifiedEventError(f'SQS record body is missing an authenticated {label}')
    return value


def build_restricted_context_from_sqs_record(
    record: Mapping[str, Any],
    *,
    allowed_queue_arns: Collection[str],
    allowed_sender_ids: Collection[str] | None = None,
    principal_field: str = DEFAULT_PRINCIPAL_FIELD,
    workspace_field: str = DEFAULT_WORKSPACE_FIELD,
) -> tuple[RestrictedContext, dict[str, Any]]:
    """Verify one SQS record and return its context plus business payload.

    Parameters:
        record: a single element of the SQS event ``Records`` list.
        allowed_queue_arns: queue ARNs this entry point accepts.
        allowed_sender_ids: optional SQS ``SenderId`` allow list.
        principal_field: body field holding the authenticated principal.
        workspace_field: body field holding the authenticated workspace.

    Returns:
        A ``(context, payload)`` tuple. ``payload`` is the ordinary business
        body with the two identity fields removed, so handlers can read every
        normal business attribute without touching identity data.

    Raises:
        UnverifiedEventError: when the record fails any verification step.
    """
    _verify_record_source(record, allowed_queue_arns, allowed_sender_ids or ())
    body = dict(_parse_body(record))

    principal_id = _identity_value(body, principal_field, 'principal')
    workspace_id = _identity_value(body, workspace_field, 'workspace')

    context = _create_restricted_context(principal_id, workspace_id)
    payload = body
    payload.pop(principal_field, None)
    payload.pop(workspace_field, None)
    nested_payload = payload.pop(_PAYLOAD_FIELD, None)
    if isinstance(nested_payload, Mapping):
        payload = dict(nested_payload)
    return context, payload


def build_restricted_contexts_from_sqs_event(
    event: Mapping[str, Any],
    *,
    allowed_queue_arns: Collection[str],
    allowed_sender_ids: Collection[str] | None = None,
    principal_field: str = DEFAULT_PRINCIPAL_FIELD,
    workspace_field: str = DEFAULT_WORKSPACE_FIELD,
) -> list[tuple[RestrictedContext, dict[str, Any]]]:
    """Verify every record of an SQS event.

    Raises:
        UnverifiedEventError: on the first record that cannot be verified,
            failing closed so no unverified record reaches the shared handler.
    """
    records = event.get('Records')
    if not isinstance(records, Iterable) or isinstance(records, str | bytes | Mapping):
        raise UnverifiedEventError('SQS event has no Records list')
    return [
        build_restricted_context_from_sqs_record(
            record,
            allowed_queue_arns=allowed_queue_arns,
            allowed_sender_ids=allowed_sender_ids,
            principal_field=principal_field,
            workspace_field=workspace_field,
        )
        for record in records
    ]
