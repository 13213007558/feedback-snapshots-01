"""Declaration policies controlling automatic entity creation.

A :class:`~kombu.Connection` owns a :class:`DeclarationPolicy` that decides
which broker entities (exchanges, queues and bindings) its clients are allowed
to create through automatic declaration paths such as
:func:`~kombu.common.maybe_declare`.

Publishing-only applications are typically not allowed to manage broker
topology: a separate initialization service creates the exchanges, queues and
bindings, while the producer is restricted to declaring the exchange it
publishes to (or nothing at all).

The default policy permits every entity kind, so applications that do not
configure one keep the historical behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

from .entity import Exchange, Queue
from .exceptions import DeclarationNotAllowed

if TYPE_CHECKING:
    from .entity import binding

__all__ = (
    'EXCHANGE_ENTITY', 'QUEUE_ENTITY', 'BINDING_ENTITY',
    'ALL_ENTITY_KINDS', 'DeclarationPolicy',
)

#: Automatic ``exchange.declare`` operations.
EXCHANGE_ENTITY = 'exchange'

#: Automatic ``queue.declare`` operations.
QUEUE_ENTITY = 'queue'

#: Automatic ``queue.bind`` / ``exchange.bind`` operations.
BINDING_ENTITY = 'binding'

#: Every entity kind managed by a declaration policy.
ALL_ENTITY_KINDS = frozenset(
    {EXCHANGE_ENTITY, QUEUE_ENTITY, BINDING_ENTITY})


def _entity_kind(entity) -> str:
    if isinstance(entity, Queue):
        return QUEUE_ENTITY
    if isinstance(entity, Exchange):
        return EXCHANGE_ENTITY
    return BINDING_ENTITY


class DeclarationPolicy:
    """Policy describing which entities may be declared automatically.

    Arguments:
    ---------
        allowed (Iterable[str]): Entity kinds that automatic declaration may
            create.  Any of :data:`EXCHANGE_ENTITY`, :data:`QUEUE_ENTITY`
            or :data:`BINDING_ENTITY`.  An empty iterable forbids every
            automatic declaration.  Defaults to all entity kinds, which
            preserves the historical behavior.

    Example:
    -------
        >>> from kombu import Connection
        >>> from kombu.declarations import (
        ...     DeclarationPolicy, EXCHANGE_ENTITY,
        ... )
        >>> # Producer may only declare the exchange it publishes to.
        >>> connection = Connection(
        ...     'memory://',
        ...     declaration_policy=DeclarationPolicy([EXCHANGE_ENTITY]),
        ... )
    """

    def __init__(self, allowed: Iterable[str] | None = None):
        if allowed is None:
            allowed = ALL_ENTITY_KINDS
        self.allowed = frozenset(allowed)

    def permits(self, entity) -> bool:
        """Return whether automatic declaration of ``entity`` is allowed."""
        return _entity_kind(entity) in self.allowed

    def check(self, entity) -> None:
        """Raise :class:`~kombu.exceptions.DeclarationNotAllowed` if forbidden."""
        kind = _entity_kind(entity)
        if kind not in self.allowed:
            raise DeclarationNotAllowed(
                f'Automatic {kind} declaration is not allowed by the '
                f'connection declaration policy '
                f'(allowed: {sorted(self.allowed) or "none"})'
            )

    def __eq__(self, other):
        if isinstance(other, DeclarationPolicy):
            return self.allowed == other.allowed
        return NotImplemented

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.allowed)

    def __repr__(self):
        return f'<DeclarationPolicy: allowed={sorted(self.allowed)}>'
