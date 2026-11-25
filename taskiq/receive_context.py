"""Trusted ownership of the context of an inbound task.

The receiver is the only component that knows which channel actually
delivered a message.  This module keeps that knowledge in an immutable
``ReceiveContext`` and exposes it through a context variable, so task
dependencies can make authorization decisions based on the delivery
channel instead of on message labels, which are controlled by the
sender and can be rewritten by middleware.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

# Imported at runtime so the dataclass annotations can be resolved by
# dependency introspection; there is no import cycle with the broker.
from taskiq.abc.broker import AsyncBroker
from taskiq.exceptions import SourceNotAuthorizedError

if TYPE_CHECKING:  # pragma: no cover
    from contextvars import Token


@dataclass(frozen=True, slots=True)
class ReceiveContext:
    """
    Trusted provenance of a single inbound delivery.

    Instances are created by the receiver from the delivery channel
    itself, before middlewares run and before any task dependency is
    resolved.  Nothing that arrives over the wire (task name, labels or
    arguments) can change these values, and middlewares that mutate the
    task message cannot replace them.

    :param broker: broker that accepted the delivery.
    :param source: channel that actually produced the delivery. For a
        composite broker this is the inner broker, otherwise it is the
        broker itself.
    :param task_name: task identity bound before middleware execution.
    :param task_id: id of the inbound message.
    """

    broker: "AsyncBroker"
    source: "AsyncBroker | None"
    task_name: str
    task_id: str

    def is_from(self, *sources: "AsyncBroker") -> bool:
        """
        Check whether the delivery came from one of the given channels.

        Approval is based on object identity of the broker that actually
        delivered the message, never on a serialized value.

        :param sources: approved brokers.
        :return: True if the delivery came from one of them.
        """
        return self.source is not None and any(
            self.source is source for source in sources
        )

    def matches(self, *entrypoints: "AsyncBroker") -> bool:
        """
        Check whether the delivery belongs to one of the given entrypoints.

        Both the broker that accepted the delivery (for example a
        ``MultiBroker``) and the inner channel that actually produced it
        count as the entrypoint. This lets a task be bound either to the
        composite broker or to one of its inner brokers.

        :param entrypoints: approved brokers.
        :return: True if the delivery came through one of them.
        """
        return any(entrypoint is self.broker for entrypoint in entrypoints) or (
            self.is_from(*entrypoints)
        )

    def require_source(self, *sources: "AsyncBroker") -> None:
        """
        Ensure the delivery came from one of the given channels.

        :param sources: approved brokers.
        :raises SourceNotAuthorizedError: if the source is not approved.
        """
        if not self.is_from(*sources):
            raise SourceNotAuthorizedError(task_name=self.task_name)


_receive_context: ContextVar[ReceiveContext | None] = ContextVar(
    "taskiq_receive_context",
    default=None,
)


def get_receive_context() -> ReceiveContext | None:
    """
    Return the receive context bound to the current task.

    :return: receive context or None when called outside task execution.
    """
    return _receive_context.get()


def bind_receive_context(context: ReceiveContext) -> "Token[ReceiveContext | None]":
    """
    Bind a receive context to the current execution context.

    :param context: context to bind.
    :return: token that restores the previous value.
    """
    return _receive_context.set(context)


def reset_receive_context(token: "Token[ReceiveContext | None]") -> None:
    """
    Restore the receive context that was active before binding.

    :param token: token returned by :func:`bind_receive_context`.
    """
    _receive_context.reset(token)


@contextmanager
def use_receive_context(context: ReceiveContext) -> Iterator[ReceiveContext]:
    """
    Bind a receive context for the duration of a block.

    :param context: context to bind.
    :yield: the bound context.
    """
    token = bind_receive_context(context)
    try:
        yield context
    finally:
        reset_receive_context(token)
