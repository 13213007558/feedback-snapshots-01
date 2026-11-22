---
title: Restricted Context
description: Utility
status: new
---

<!-- markdownlint-disable MD043 -->

The Restricted Context utility gives a Lambda that serves both HTTP API requests and internal SQS events one consistent, sealed identity object to pass to its shared business logic.

Only an entry point that has verified the event can build a [`RestrictedContext`](#restrictedcontext). The context exposes exactly two read-only attributes — the confirmed principal and workspace — and nothing else. Raw events, headers, tokens and claims never cross the trust boundary, and an event that cannot be verified fails closed with an `UnverifiedEventError` instead of producing a context.

## Key features

* Sealed `RestrictedContext` that cannot be instantiated or mutated outside the verified entry points
* Verified entry points for API Gateway REST/HTTP API events and SQS queue records
* Explicit allow lists for SQS queue ARNs and sender IDs
* Ordinary business payloads stay fully readable while identity fields are stripped from the payload
* A single `build_restricted_context` dispatcher for functions handling both event sources

## Getting started

### Installation

There is no extra dependency: Restricted Context is part of the core library.

### Terminology

| Term | Meaning |
| ---- | ------- |
| Entry point | The code that first receives the AWS event and is allowed to verify identity |
| Shared handler | Internal business logic that must only receive a verified `RestrictedContext` |
| Principal | The authenticated caller identity (for example a `sub` claim) |
| Workspace | The tenant/scope the caller is confirmed to act in |

### HTTP API events

Identity is read exclusively from `requestContext.authorizer`, never from headers, query strings or the request body. Both REST API (v1) and HTTP API (v2) events are supported, including JWT `claims` and Lambda authorizer (`principalId`/`context`) responses.

```python hl_lines="4 10"
from aws_lambda_powertools.utilities.restricted_context import (
    UnverifiedEventError,
    build_restricted_context_from_api_event,
)


def lambda_handler(event: dict, context: dict) -> dict:
    try:
        restricted = build_restricted_context_from_api_event(event)
    except UnverifiedEventError:
        return {"statusCode": 403, "body": "unverified event"}

    return {"principal_id": restricted.principal_id, "workspace_id": restricted.workspace_id}
```

Custom claim names can be configured with `principal_claim` and `workspace_claim`.

### Internal SQS events

A queue record is accepted only when its `eventSourceARN` is in `allowed_queue_arns` (and, optionally, its SQS `SenderId` is in `allowed_sender_ids`). The record body must carry the authenticated principal and workspace; these fields are removed from the payload that reaches the shared handler, while every other business field is returned untouched.

```python hl_lines="5 6 13"
from aws_lambda_powertools.utilities.restricted_context import (
    build_restricted_contexts_from_sqs_event,
)

TRUSTED_QUEUES = {"arn:aws:sqs:eu-west-1:123456789012:trusted-internal-queue"}


def lambda_handler(event: dict, context: dict) -> list:
    verified_records = build_restricted_contexts_from_sqs_event(
        event,
        allowed_queue_arns=TRUSTED_QUEUES,
    )
    return [
        shared_processor(restricted, payload)
        for restricted, payload in verified_records
    ]
```

A body can be flat (`{"principal_id": ..., "workspace_id": ..., ...business}`) or wrap its business data in a `payload` object; identity field names are configurable through `principal_field` and `workspace_field`.

### One handler for both sources

`build_restricted_context` detects the event shape and routes it to the matching entry point. SQS events require an explicit `allowed_queue_arns` allow list; unknown event shapes raise `UnrecognizedEventError`.

=== "getting_started_restricted_context.py"

    ```python hl_lines="5 9 16"
    --8<-- "examples/restricted_context/src/getting_started_restricted_context.py"
    ```

## RestrictedContext

| Attribute | Type | Description |
| --------- | ---- | ----------- |
| `principal_id` | `str` | Identity confirmed by the entry point |
| `workspace_id` | `str` | Tenant/workspace confirmed by the entry point |

The class uses `__slots__`, is immutable, and can only be constructed by an entry point. Calling `RestrictedContext(...)` directly raises `RestrictedContextConstructionError`, and assigning to an attribute raises `AttributeError`.

## Failing closed

| Condition | Exception raised |
| --------- | ---------------- |
| Missing `requestContext.authorizer`, principal or workspace | `UnverifiedEventError` |
| SQS record from a queue/sender outside the allow lists | `UnverifiedEventError` |
| SQS body missing identity fields, not JSON, or not an object | `UnverifiedEventError` |
| SQS batch containing an unverified record | `UnverifiedEventError` on the first bad record |
| Event matching neither API Gateway nor SQS shape | `UnrecognizedEventError` |

In every failure case no context is produced, so unverified input cannot reach the shared handler.
