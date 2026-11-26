from openfga_sdk.client.models.tuple import ClientTuple, convert_tuple_keys
from openfga_sdk.exceptions import (
    ApiValueError,
    AuthenticationError,
    ForbiddenException,
    NotFoundException,
    OpenApiException,
    UnauthorizedException,
    ValidationException,
)
from openfga_sdk.models.batch_check_item import BatchCheckItem
from openfga_sdk.models.batch_check_single_result import BatchCheckSingleResult
from openfga_sdk.models.check_error import CheckError
from openfga_sdk.models.check_request_tuple_key import CheckRequestTupleKey
from openfga_sdk.models.contextual_tuple_keys import ContextualTupleKeys


# Server-side internal errors that represent a transient failure and can be
# retried. Validation/authorization errors are terminal.
RETRYABLE_BATCH_CHECK_INTERNAL_ERRORS = frozenset(
    {
        "internal_error",
        "deadline_exceeded",
        "resource_exhausted",
        "unavailable",
        "aborted",
    }
)


def is_retryable_batch_check_error(err: Exception) -> bool:
    """
    Return whether a failed BatchCheck request can be retried without losing an
    authoritative result. Throttling, transient server failures and transport
    errors qualify; validation/auth/not-found errors are terminal.
    """
    if isinstance(
        err,
        AuthenticationError
        | UnauthorizedException
        | ForbiddenException
        | NotFoundException
        | ValidationException
        | ApiValueError,
    ):
        return False

    status = getattr(err, "status", None)
    if status is None:
        # Transport-level failures (reset connection, timeout) have no status;
        # they are safe to retry because no result was returned.
        return not isinstance(err, OpenApiException)
    if status == 429 or status >= 500:
        return status != 501
    return False


def _error_code_value(value) -> str | None:
    """
    Normalize a generated error-code model (which is a placeholder object, not a
    real enum) or a plain string to its wire value.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value
    return None


def is_retryable_batch_check_result(result) -> bool:
    """
    Return whether a per-item BatchCheck result represents a transient failure
    that should be retried rather than reported as a final outcome.
    """
    if result is None or getattr(result, "error", None) is None:
        return False
    internal_error = _error_code_value(result.error.internal_error)
    return internal_error in RETRYABLE_BATCH_CHECK_INTERNAL_ERRORS


def unconfirmed_batch_check_error(err: Exception) -> CheckError:
    """
    Build the CheckError reported for checks whose outcome could not be confirmed.
    """
    message = getattr(err, "reason", None) or str(err) or type(err).__name__
    status = getattr(err, "status", None)
    if status is not None:
        message = f"{type(err).__name__} (HTTP {status}): {message}"
    else:
        message = f"{type(err).__name__}: {message}"
    return CheckError(message=message)


def resolve_batch_check_result(result: BatchCheckSingleResult):
    """
    Turn a server BatchCheckSingleResult into ``(allowed, confirmed, error)``.
    A result without ``allowed`` and without an explicit error is ambiguous, so
    it is reported as unconfirmed rather than silently treated as a denial.
    """
    if result is None:
        return None
    if result.error is not None:
        # Server-reported validation/authorization errors are authoritative:
        # the check was definitively rejected. Transient internal errors have
        # already been filtered out for retry before reaching this point.
        return (False, True, result.error)
    if result.allowed is None:
        return (None, False, None)
    return (result.allowed, True, None)


def construct_batch_item(check) -> BatchCheckItem:
    batch_item = BatchCheckItem(
        tuple_key=CheckRequestTupleKey(
            user=check.user,
            relation=check.relation,
            object=check.object,
        ),
        context=check.context,
        correlation_id=check.correlation_id,
    )

    if check.contextual_tuples:
        batch_item.contextual_tuples = ContextualTupleKeys(
            tuple_keys=convert_tuple_keys(check.contextual_tuples)
        )

    return batch_item


class ClientBatchCheckItem:
    def __init__(
        self,
        user: str,
        relation: str,
        object: str,
        correlation_id: str | None = None,
        contextual_tuples: list[ClientTuple] | None = None,
        context: dict[str, int | str] | None = None,
    ) -> None:
        self._user = user
        self._relation = relation
        self._object = object
        self._correlation_id = correlation_id
        self._contextual_tuples = contextual_tuples
        self._context = context

    @property
    def user(self) -> str:
        """
        Return user
        """
        return self._user

    @user.setter
    def user(self, value: str) -> None:
        """
        Set user
        """
        self._user = value

    @property
    def relation(self) -> str:
        """
        Return relation
        """
        return self._relation

    @relation.setter
    def relation(self, value: str) -> None:
        """
        Set relation
        """
        self._relation = value

    @property
    def object(self) -> str:
        """
        Return object
        """
        return self._object

    @object.setter
    def object(self, value: str) -> None:
        """
        Set object
        """
        self._object = value

    @property
    def correlation_id(self) -> str | None:
        """
        Return correlation id
        """
        return self._correlation_id

    @correlation_id.setter
    def correlation_id(self, value: str | None) -> None:
        """
        Set correlation id
        """
        self._correlation_id = value

    @property
    def contextual_tuples(self) -> list[ClientTuple] | None:
        """
        Return contextual tuples
        """
        return self._contextual_tuples

    @contextual_tuples.setter
    def contextual_tuples(self, value: list[ClientTuple] | None) -> None:
        """
        Set contextual tuples
        """
        self._contextual_tuples = value

    @property
    def context(self) -> dict[str, int | str] | None:
        """
        Return context
        """
        return self._context

    @context.setter
    def context(self, value: dict[str, int | str] | None) -> None:
        """
        Set context
        """
        self._context = value
