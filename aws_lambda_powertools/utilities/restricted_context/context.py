"""
Sealed restricted context shared between entry points and internal handlers.

The context is the only object that carries identity across the trust
boundary. It intentionally exposes two read-only attributes and nothing else:
raw events, tokens, headers or claims never cross into the shared handler.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools.utilities.restricted_context.exceptions import (
    RestrictedContextConstructionError,
)

# Module-private token. Entry functions in this package close over it, so the
# only way to obtain a RestrictedContext is through a verified entry point.
_CONTEXT_SENTINEL: Any = object()


class RestrictedContext:
    """Immutable, sealed identity context.

    Attributes:
        principal_id: identity confirmed by the entry point (HTTP authorizer
            claim or verified internal message field).
        workspace_id: tenant/workspace confirmed by the entry point.
    """

    __slots__ = ('_principal_id', '_workspace_id', '_sentinel')

    _principal_id: str
    _workspace_id: str
    _sentinel: Any

    def __init__(self, principal_id: str, workspace_id: str, sentinel: Any = None) -> None:
        if sentinel is not _CONTEXT_SENTINEL:
            raise RestrictedContextConstructionError(
                'RestrictedContext can only be created by a verified entry point '
                '(build_restricted_context_from_api_event / '
                'build_restricted_context_from_sqs_record)',
            )
        object.__setattr__(self, '_principal_id', principal_id)
        object.__setattr__(self, '_workspace_id', workspace_id)
        object.__setattr__(self, '_sentinel', sentinel)

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def workspace_id(self) -> str:
        return self._workspace_id

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError('RestrictedContext is immutable')

    def __delattr__(self, name: str) -> None:
        raise AttributeError('RestrictedContext is immutable')

    def __repr__(self) -> str:
        return f'RestrictedContext(principal_id={self._principal_id!r}, workspace_id={self._workspace_id!r})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RestrictedContext):
            return NotImplemented
        return self._principal_id == other._principal_id and self._workspace_id == other._workspace_id

    def __hash__(self) -> int:
        return hash((self._principal_id, self._workspace_id))


def _create_restricted_context(principal_id: str, workspace_id: str) -> RestrictedContext:
    """Internal-only constructor used by the verified entry points."""
    return RestrictedContext(principal_id, workspace_id, _CONTEXT_SENTINEL)
