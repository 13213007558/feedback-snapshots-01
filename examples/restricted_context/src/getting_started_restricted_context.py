import json

from aws_lambda_powertools.utilities.restricted_context import (
    RestrictedContext,
    RestrictedContextError,
    build_restricted_context,
)

TRUSTED_QUEUE_ARNS = {'arn:aws:sqs:eu-west-1:123456789012:trusted-internal-queue'}


def shared_processor(context: RestrictedContext, payload: dict) -> dict:
    """Shared handler: it only ever sees the confirmed principal and workspace."""
    return {
        'principal_id': context.principal_id,
        'workspace_id': context.workspace_id,
        'payload': payload,
    }


def lambda_handler(event: dict, context: dict) -> dict:
    try:
        result = build_restricted_context(event, allowed_queue_arns=TRUSTED_QUEUE_ARNS)
    except RestrictedContextError:
        # Fail closed: unverified or unrecognized events never reach the shared processor
        return {'statusCode': 403, 'body': json.dumps({'message': 'unverified event'})}

    if isinstance(result, RestrictedContext):
        body = json.loads(event.get('body') or '{}')
        return {'statusCode': 200, 'body': json.dumps(shared_processor(result, body))}

    responses = [shared_processor(record_context, payload) for record_context, payload in result]
    return {'statusCode': 200, 'body': json.dumps({'records': responses})}
