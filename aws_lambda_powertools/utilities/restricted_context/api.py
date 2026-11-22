"""
HTTP API entry point for the restricted context.

Only :class:`RestrictedContext` identity is extracted from an API Gateway
event, and only from the authenticated ``requestContext.authorizer`` subtree.
Headers, query strings, path parameters and the request body are never read
as identity, so a caller cannot forge the principal or workspace.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aws_lambda_powertools.utilities.restricted_context.context import (
    RestrictedContext,
    _create_restricted_context,
)
from aws_lambda_powertools.utilities.restricted_context.exceptions import UnverifiedEventError

DEFAULT_PRINCIPAL_CLAIM = 'sub'
DEFAULT_WORKSPACE_CLAIM = 'workspace_id'
# Lambda authorizer responses may surface the workspace under a context key.
_WORKSPACE_CONTEXT_KEYS = ('workspace_id', 'workspace')


def _claims(authorizer: Mapping[str, Any]) -> Mapping[str, Any]:
    claims = authorizer.get('claims')
    if isinstance(claims, Mapping):
        return claims
    jwt = authorizer.get('jwt')
    if isinstance(jwt, Mapping) and isinstance(jwt.get('claims'), Mapping):
        return jwt['claims']
    return authorizer


def _resolve_principal(authorizer: Mapping[str, Any], claims: Mapping[str, Any], principal_claim: str) -> str:
    candidate = claims.get(principal_claim)
    if candidate is None and principal_claim == DEFAULT_PRINCIPAL_CLAIM:
        candidate = authorizer.get('principalId')
    if not isinstance(candidate, str) or not candidate.strip():
        raise UnverifiedEventError(
            'HTTP event is missing an authenticated principal in requestContext.authorizer',
        )
    return candidate


def _resolve_workspace(authorizer: Mapping[str, Any], claims: Mapping[str, Any], workspace_claim: str) -> str:
    candidate = claims.get(workspace_claim)
    if candidate is None:
        authorizer_context = authorizer.get('context')
        if isinstance(authorizer_context, Mapping):
            for key in _WORKSPACE_CONTEXT_KEYS:
                if key in authorizer_context:
                    candidate = authorizer_context[key]
                    break
    if not isinstance(candidate, str) or not candidate.strip():
        raise UnverifiedEventError(
            'HTTP event is missing an authenticated workspace in requestContext.authorizer',
        )
    return candidate


def build_restricted_context_from_api_event(
    event: Mapping[str, Any],
    *,
    principal_claim: str = DEFAULT_PRINCIPAL_CLAIM,
    workspace_claim: str = DEFAULT_WORKSPACE_CLAIM,
) -> RestrictedContext:
    """Build a restricted context from a verified API Gateway event.

    Parameters:
        event: raw API Gateway REST/HTTP API (v1 or v2) Lambda event.
        principal_claim: claim name holding the principal inside the authorizer.
        workspace_claim: claim name holding the workspace inside the authorizer.

    Raises:
        UnverifiedEventError: when the event carries no authenticated
            principal or workspace. The shared handler is never invoked.
    """
    request_context = event.get('requestContext')
    if not isinstance(request_context, Mapping):
        raise UnverifiedEventError('HTTP event has no requestContext; identity cannot be confirmed')

    authorizer = request_context.get('authorizer')
    if not isinstance(authorizer, Mapping):
        raise UnverifiedEventError(
            'HTTP event has no requestContext.authorizer; identity cannot be confirmed',
        )

    claims = _claims(authorizer)
    principal_id = _resolve_principal(authorizer, claims, principal_claim)
    workspace_id = _resolve_workspace(authorizer, claims, workspace_claim)
    return _create_restricted_context(principal_id, workspace_id)
