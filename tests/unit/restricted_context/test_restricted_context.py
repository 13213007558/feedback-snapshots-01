"""Unit tests for Restricted Context entry points and sealed context."""

from __future__ import annotations

from typing import Any

import pytest

from aws_lambda_powertools.utilities.restricted_context import (
    RestrictedContext,
    RestrictedContextConstructionError,
    UnverifiedEventError,
    build_restricted_context_from_api_event,
    build_restricted_context_from_sqs_record,
    build_restricted_contexts_from_sqs_event,
)

QUEUE_ARN = 'arn:aws:sqs:eu-west-1:123456789012:internal'


def test_http_api_v2_jwt_claims_are_supported() -> None:
    event = {
        'version': '2.0',
        'routeKey': 'POST /orders',
        'requestContext': {
            'authorizer': {'jwt': {'claims': {'sub': 'u-1', 'workspace_id': 'ws-1'}}},
        },
    }
    context = build_restricted_context_from_api_event(event)
    assert context.principal_id == 'u-1'
    assert context.workspace_id == 'ws-1'


def test_lambda_authorizer_principal_id_and_context_are_supported() -> None:
    event = {
        'requestContext': {
            'httpMethod': 'GET',
            'authorizer': {'principalId': 'u-2', 'context': {'workspace': 'ws-2'}},
        },
    }
    context = build_restricted_context_from_api_event(event)
    assert context.principal_id == 'u-2'
    assert context.workspace_id == 'ws-2'


def test_custom_claim_names_are_supported() -> None:
    event = {
        'requestContext': {
            'authorizer': {'claims': {'client_id': 'c-3', 'tenant': 'ws-3'}},
        },
    }
    context = build_restricted_context_from_api_event(
        event,
        principal_claim='client_id',
        workspace_claim='tenant',
    )
    assert context.principal_id == 'c-3'
    assert context.workspace_id == 'ws-3'


@pytest.mark.parametrize(
    'authorizer',
    [
        {'claims': {'workspace_id': 'ws-1'}},
        {'claims': {'sub': '', 'workspace_id': 'ws-1'}},
        {'claims': {'sub': 'u-1'}},
        {'claims': {'sub': 'u-1', 'workspace_id': '   '}},
        {'claims': {'sub': 9, 'workspace_id': 'ws-1'}},
    ],
)
def test_api_event_without_complete_identity_is_rejected(authorizer: dict[str, Any]) -> None:
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_api_event({'requestContext': {'authorizer': authorizer}})


def test_event_without_request_context_is_rejected() -> None:
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_api_event({'headers': {}})


def _record(body: Any, **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        'eventSource': 'aws:sqs',
        'eventSourceARN': QUEUE_ARN,
        'attributes': {'SenderId': 'sender-1'},
        'body': body,
    }
    record.update(overrides)
    return record


def test_sqs_record_with_object_body_and_nested_payload() -> None:
    record = _record(
        {
            'principal_id': 'u-4',
            'workspace_id': 'ws-4',
            'payload': {'order_id': 'o-4', 'tags': ['a', 'b']},
        },
    )
    context, payload = build_restricted_context_from_sqs_record(
        record,
        allowed_queue_arns={QUEUE_ARN},
    )
    assert context.principal_id == 'u-4'
    assert context.workspace_id == 'ws-4'
    assert payload == {'order_id': 'o-4', 'tags': ['a', 'b']}


def test_sqs_invalid_json_body_is_rejected() -> None:
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            _record('not-json'),
            allowed_queue_arns={QUEUE_ARN},
        )


def test_sqs_non_object_body_is_rejected() -> None:
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            _record('[1, 2, 3]'),
            allowed_queue_arns={QUEUE_ARN},
        )


def test_sqs_record_without_allowed_queue_is_rejected() -> None:
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            _record('{"principal_id": "u", "workspace_id": "w"}'),
            allowed_queue_arns={'arn:aws:sqs:eu-west-1:123456789012:other'},
        )


def test_sqs_record_missing_event_source_is_rejected() -> None:
    record = _record('{"principal_id": "u", "workspace_id": "w"}')
    record.pop('eventSource')
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(record, allowed_queue_arns={QUEUE_ARN})


def test_sqs_malformed_attributes_and_records_are_rejected() -> None:
    record = _record(
        '{"principal_id": "u", "workspace_id": "w"}',
        attributes='not-a-mapping',
    )
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            record,
            allowed_queue_arns={QUEUE_ARN},
            allowed_sender_ids={'sender-1'},
        )

    non_mapping_record = 'not-a-record'
    with pytest.raises(UnverifiedEventError):
        build_restricted_context_from_sqs_record(
            non_mapping_record,
            allowed_queue_arns={QUEUE_ARN},
        )

    with pytest.raises(UnverifiedEventError):
        build_restricted_contexts_from_sqs_event(
            {'Records': 'not-a-list'},
            allowed_queue_arns={QUEUE_ARN},
        )


def test_context_is_hashable_and_repr_does_not_leak_extra_data() -> None:
    record = _record('{"principal_id": "u-5", "workspace_id": "ws-5", "secret": "s"}')
    context, payload = build_restricted_context_from_sqs_record(record, allowed_queue_arns={QUEUE_ARN})
    same_identity_record = _record('{"principal_id": "u-5", "workspace_id": "ws-5"}')
    same_context, _ = build_restricted_context_from_sqs_record(
        same_identity_record,
        allowed_queue_arns={QUEUE_ARN},
    )

    assert hash(context) == hash(same_context)
    assert context == same_context
    assert repr(context) == "RestrictedContext(principal_id='u-5', workspace_id='ws-5')"
    assert 'secret' not in repr(context)
    assert 'secret' in payload


def test_direct_construction_is_blocked_even_with_keyword_arguments() -> None:
    with pytest.raises(RestrictedContextConstructionError):
        RestrictedContext(principal_id='u', workspace_id='w')
