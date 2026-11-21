"""Audit logging for GraphQL mutation root fields.

This module lets a backend keep an audit trail of the mutation root fields that
are actually executed. Because client operation names are arbitrary and can be
customized, the audit entries identify the executed mutation by the name of the
schema root field rather than by the operation name.

The auditor is invoked from the execution phase only. Operations that merely get
parsed or validated, including requests that fail validation and never execute,
do not produce any audit entries. Mutation arguments and variable values are
never part of an audit entry.

For every executed mutation root field, the auditor receives exactly one entry
with status :data:`MutationAuditStatus.DENIED` when the configured authorizer
rejects the field, or a pair of entries with the statuses
:data:`MutationAuditStatus.AUTHORIZED` (recorded right before the field resolver
is called) and :data:`MutationAuditStatus.SUCCESS` (recorded after the field has
been resolved without an authorization failure).
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, NamedTuple, Protocol, runtime_checkable

from ..error import GraphQLError

if TYPE_CHECKING:
    from ..type import GraphQLResolveInfo

__all__ = [
    "MUTATION_AUTHORIZATION_ERROR_MESSAGE",
    "MutationAuditEntry",
    "MutationAuditStatus",
    "MutationAuditor",
    "MutationAuthorizationError",
    "MutationAuthorizer",
]


MUTATION_AUTHORIZATION_ERROR_MESSAGE = "Unauthorized mutation field."


class MutationAuditStatus(str, Enum):
    """Outcome recorded for an executed mutation root field.

    >>> [status.value for status in MutationAuditStatus]
    ['authorized', 'success', 'denied']
    """

    AUTHORIZED = "authorized"
    """The authorizer allowed the field, and its resolver is about to run."""

    SUCCESS = "success"
    """The authorized field was resolved without an authorization failure."""

    DENIED = "denied"
    """The authorizer rejected the field, and its resolver never ran."""


class MutationAuditEntry(NamedTuple):
    """A single audit entry for an executed mutation root field.

    Only the schema name of the mutation root field and its authorization
    outcome are recorded; mutation arguments and variable values are
    deliberately excluded so that sensitive input data never reaches the
    audit trail.

    >>> MutationAuditEntry("createUser", MutationAuditStatus.SUCCESS).field_name
    'createUser'
    >>> MutationAuditEntry("createUser", MutationAuditStatus.SUCCESS).status.value
    'success'
    """

    field_name: str
    """Name of the executed mutation root field in the schema."""

    status: MutationAuditStatus
    """Authorization outcome recorded for the field."""


@runtime_checkable
class MutationAuthorizer(Protocol):
    """Decide whether a mutation root field may be executed.

    The authorizer is called with the resolve info of the mutation root field
    before its resolver runs. Returning ``False`` denies the field: the
    resolver is skipped, a field error is added to the result, and the
    rejection is audited. Returning ``True`` allows the field to execute.

    >>> def allow_all(_info):
    ...     return True
    >>> isinstance(allow_all, MutationAuthorizer)
    True
    """

    def __call__(self, info: GraphQLResolveInfo) -> bool:
        """Authorize a mutation root field.

        :param info: Resolve info of the mutation root field.
        :returns: ``True`` if the field may be executed, ``False`` to deny it.
        """


@runtime_checkable
class MutationAuditor(Protocol):
    """Receive audit entries for executed mutation root fields.

    A simple auditor appends the entries to a list:

    >>> entries = []
    >>> isinstance(entries.append, MutationAuditor)
    True
    """

    def __call__(self, entry: MutationAuditEntry) -> None:
        """Record an audit entry.

        :param entry: Audit entry describing the executed mutation root field.
        """


class MutationAuthorizationError(GraphQLError):
    """Error raised internally when an authorizer denies a mutation field.

    The executor turns this into a regular located field error, so that a
    rejected field fails like any other erroring field while its rejection is
    still recorded in the audit trail.

    :param field_name: Name of the rejected mutation root field.

    >>> error = MutationAuthorizationError("deleteUser")
    >>> error.message
    'Unauthorized mutation field.'
    >>> error.field_name
    'deleteUser'
    >>> error.extensions
    {'code': 'FORBIDDEN', 'field': 'deleteUser'}
    """

    def __init__(self, field_name: str) -> None:
        self.field_name = field_name
        super().__init__(
            MUTATION_AUTHORIZATION_ERROR_MESSAGE,
            extensions={"code": "FORBIDDEN", "field": field_name},
        )
