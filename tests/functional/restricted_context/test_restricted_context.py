"""Acceptance tests for the Restricted Context utility.

The same Lambda serves HTTP API traffic and internal SQS events. Only the
entry points confirm identity and hand a sealed RestrictedContext to the
shared handler; unverified events never obtain one.
"""

from __future__ import annotations

from typing import Any

import pytest

from aws_lambda_powertools.utilities.restricted_context import (
    RestrictedContext,
    RestrictedContextConstructionError,
    UnrecognizedEventError,
    UnverifiedEventError,
    build_restricted_context,
    build_restricted_context_from_api_event,
    build_restricted_context_from_sqs_record,
    build_restricted_contexts_from_sqs_event,
)

TRUSTED_QUEUE_ARN = 'arn:aws:sqs:us-east-1:123456789012:trusted-internal-queue'
TRUSTED_SENDER_ID = 'AIDAIENQZJOLO23YVJ4VO'


def _synthetic_api_event() -> dict[str, Any]:
    """A synthetic API Gateway REST event with an authenticated authorizer."""
    return {
        'version': '1.0',
        'resource': '/orders',
        'path': '/orders',
        'httpMethod': 'POST',
        'headers': {'Authorization': 'Bearer eyJhbGciOiJub25lIn0.payload.sig'},
        'queryStringParameters': None,
        'body': '{"order_id": "o-100", "amount": 42}',
        'requestContext': {
            'httpMethod': 'POST',
            'path': '/orders',
            'requestId': 'synthetic-request-id',
            'authorizer': {
                'claims': {
                    'sub': 'user-7788',
                    'workspace_id': 'workspace-blue',
                    'email': 'owner@example.com',
                    'roles': ['billing-admin'],
                    'session_token': 'super-secret-session-claim',
                },
            },
        },
        'isBase64Encoded': False,
    }


def _synthetic_sqs_event() -> dict[str, Any]:
    """Two synthetic records from the trusted internal queue."""
    return {
        'Records': [
            {
                'messageId': '11111111-1111-1111-1111-111111111111',
                'receiptHandle': 'handle-one',
                'body': (
                    '{"principal_id": "user-7788", "workspace_id": "workspace-blue", '
                    '"order_id": "o-200", "amount": 15, "note": "first business payload"}'
                ),
                'attributes': {
                    'ApproximateReceiveCount': '1',
                    'SentTimestamp': '1700000000000',
                    'SenderId': TRUSTED_SENDER_ID,
                },
                'messageAttributes': {},
                'md5OfBody': 'stub-md5-one',
                'eventSource': 'aws:sqs',
                'eventSourceARN': TRUSTED_QUEUE_ARN,
                'awsRegion': 'us-east-1',
            },
            {
                'messageId': '22222222-2222-2222-2222-222222222222',
                'receiptHandle': 'handle-two',
                'body': (
                    '{"principal_id": "user-9900", "workspace_id": "workspace-green", '
                    '"order_id": "o-201", "amount": 7, "items": ["sku-1", "sku-2"]}'
                ),
                'attributes': {
                    'ApproximateReceiveCount': '1',
                    'SentTimestamp': '1700000000001',
                    'SenderId': TRUSTED_SENDER_ID,
                },
                'messageAttributes': {},
                'md5OfBody': 'stub-md5-two',
                'eventSource': 'aws:sqs',
                'eventSourceARN': TRUSTED_QUEUE_ARN,
                'awsRegion': 'us-east-1',
            },
        ],
    }


def shared_handler(context: RestrictedContext, payload: dict[str, Any]) -> dict[str, Any]:
    """The shared internal processor: it may only see the restricted context."""
    # No way to reach raw claims, headers, tokens or the full event from here.
    assert set(restricted_attribute_names(context)) == {'principal_id', 'workspace_id'}
    return {
        'principal_id': context.principal_id,
        'workspace_id': context.workspace_id,
        'processed_payload': payload,
    }


def restricted_attribute_names(context: RestrictedContext) -> tuple[str, ...]:
    return tuple(name for name in dir(context) if not name.startswith('_'))


def test_api_event_produces_restricted_context_for_shared_handler() -> None:
    # Given a synthetic, authenticated API request
    event = _synthetic_api_event()

    # When the entry point confirms identity and calls the shared handler
    context = build_restricted_context_from_api_event(event)
    result = shared_handler(context, payload={'order_id': 'o-100', 'amount': 42})

    # Then the handler gets exactly the confirmed principal and workspace
    assert isinstance(context, RestrictedContext)
    assert context.principal_id == 'user-7788'
    assert context.workspace_id == 'workspace-blue'
    assert result == {
        'principal_id': 'user-7788',
        'workspace_id': 'workspace-blue',
        'processed_payload': {'order_id': 'o-100', 'amount': 42},
    }


def test_api_context_never_exposes_non_approved_claims() -> None:
    context = build_restricted_context_from_api_event(_synthetic_api_event())

    # Only the two approved attributes are visible; sensitive claims stay behind
    assert restricted_attribute_names(context) == ('principal_id', 'workspace_id')
    assert not hasattr(context, 'email')
    assert not hasattr(context, 'roles')
    assert not hasattr(context, 'session_token')
    assert not hasattr(context, 'claims')


def test_two_sqs_records_each_get_verified_context_and_readable_payload() -> None:
    # Given an SQS event with two queued records
    event = _synthetic_sqs_event()

    # When the entry point verifies the batch and invokes the shared handler
    pairs = build_restricted_contexts_from_sqs_event(
        event,
        allowed_queue_arns={TRUSTED_QUEUE_ARN},
        allowed_sender_ids={TRUSTED_SENDER_ID},
    )
    results = [shared_handler(context, payload) for context, payload in pairs]

    # Then each record yields a confirmed context and its ordinary business payload
    assert len(pairs) == 2
    assert pairs[0][0].principal_id == 'user-7788'
    assert pairs[0][0].workspace_id == 'workspace-blue'
    assert pairs[0][1] == {'order_id': 'o-200', 'amount': 15, 'note': 'first business payload'}
    assert pairs[1][0].principal_id == 'user-9900'
    assert pairs[1][0].workspace_id == 'workspace-green'
    assert pairs[1][1] == {'order_id': 'o-201', 'amount': 7, 'items': ['sku-1', 'sku-2']}
    assert results[0]['processed_payload']['order_id'] == 'o-200'


def test_sqs_identity_fields_are_stripped_from_business_payload() -> None:
    record = _synthetic_sqs_event()['Records'][0]
    context, payload = build_restricted_context_from_sqs_record(
        record,
        allowed_queue_arns={TRUSTED_QUEUE_ARN},
    )

    assert isinstance(context, RestrictedContext)
    assert 'principal_id' not in payload
    assert 'workspace_id' not in payload
    assert payload['order_id'] == 'o-200'


def test_unverified_api_event_cannot_obtain_shared_context() -> None:
    # No authorizer at all
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_api_event({'requestContext': {'httpMethod': 'GET'}})

    # Authorizer present but missing the workspace claim
    missing_workspace = {
        'requestContext': {'authorizer': {'claims': {'sub': 'user-1'}}},
    }
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_api_event(missing_workspace)

    # Identity supplied via headers/query must never be accepted
    forged = {
        'headers': {'X-Forwarded-User': 'user-1', 'X-Workspace': 'workspace-blue'},
        'queryStringParameters': {'workspace_id': 'workspace-blue'},
        'requestContext': {'httpMethod': 'GET'},
    }
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_api_event(forged)


def test_unverified_sqs_record_cannot_obtain_shared_context() -> None:
    record = _synthetic_sqs_event()['Records'][0]

    # Record from a queue that is not on the allow list
    foreign_queue = {**record, 'eventSourceARN': 'arn:aws:sqs:us-east-1:000:foreign-queue'}
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            foreign_queue,
            allowed_queue_arns={TRUSTED_QUEUE_ARN},
        )

    # Record from an unexpected sender
    foreign_sender = {**record, 'attributes': {**record['attributes'], 'SenderId': 'AIDAEVIL'}}
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            foreign_sender,
            allowed_queue_arns={TRUSTED_QUEUE_ARN},
            allowed_sender_ids={TRUSTED_SENDER_ID},
        )

    # Body without the identity envelope
    no_identity = {**record, 'body': '{"order_id": "o-300"}'}
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            no_identity,
            allowed_queue_arns={TRUSTED_QUEUE_ARN},
        )

    # A batch fails closed on the first unverified record, returning nothing
    mixed_event = {'Records': [record, foreign_queue]}
    with pytest.raises(UnverifiedEventError):
        build_restricted_contexts_from_sqs_event(
            mixed_event,
            allowed_queue_arns={TRUSTED_QUEUE_ARN},
        )


def test_context_cannot_be_constructed_or_mutated_outside_entry_points() -> None:
    with pytest.raises(RestrictedContextConstructionError):
        RestrictedContext('user-7788', 'workspace-blue')

    context = build_restricted_context_from_api_event(_synthetic_api_event())
    with pytest.raises(AttributeError):
        context.principal_id = 'forged-user'  # type: ignore[misc]
    with pytest.raises(AttributeError):
        context.workspace_id = 'forged-workspace'  # type: ignore[misc]


def test_dispatcher_routes_both_legal_events_and_rejects_unknown_shapes() -> None:
    api_context = build_restricted_context(_synthetic_api_event())
    assert isinstance(api_context, RestrictedContext)

    sqs_pairs = build_restricted_context(
        _synthetic_sqs_event(),
        allowed_queue_arns={TRUSTED_QUEUE_ARN},
    )
    assert isinstance(sqs_pairs, list) and len(sqs_pairs) == 2

    with pytest.raises(UnrecognizedEventError):
        build_restricted_context({'source': 'aws:something-else', 'detail': {}})

    with pytest.raises(UnverifiedEventError):
        build_restricted_context(_synthetic_sqs_event())


def test_dispatcher_recognizes_http_api_v2_events() -> None:
    v2_event = {
        'version': '2.0',
        'routeKey': 'POST /orders',
        'requestContext': {
            'authorizer': {'jwt': {'claims': {'sub': 'user-v2', 'workspace_id': 'workspace-v2'}}},
        },
    }
    context = build_restricted_context(v2_event)

    assert isinstance(context, RestrictedContext)
    assert context.principal_id == 'user-v2'
    assert context.workspace_id == 'workspace-v2'
