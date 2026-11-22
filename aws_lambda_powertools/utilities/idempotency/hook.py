from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.idempotency.persistence.datarecord import DataRecord


class IdempotentHookFunction(Protocol):
    """
    The IdempotentHookFunction.
    This class defines the calling signature for IdempotentHookFunction callbacks.
    """

    def __call__(self, response: Any, idempotent_data: DataRecord) -> Any: ...


class IdempotentResponsePermissionCheck(Protocol):
    """
    The IdempotentResponsePermissionCheck.
    This class defines the calling signature for the optional callback that decides whether the
    caller of an idempotent replay is still authorized to receive the response stored in the
    completed idempotency record.

    It receives the deserialized response that would be returned and the idempotency record.
    Return a truthy value to allow the replay, or a falsy value to block it; the utility then
    raises ``IdempotencyPermissionDeniedError`` without re-running the wrapped function.
    """

    def __call__(self, response: Any, idempotent_data: DataRecord) -> bool: ...
