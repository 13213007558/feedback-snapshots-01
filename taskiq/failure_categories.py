"""Stable, non-sensitive failure categories."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from enum import Enum
from typing import Any, Protocol


class FailureCategory(str, Enum):
    """Coarse failure categories safe to show to queue consumers."""

    UNKNOWN = "unknown"
    CLIENT_ERROR = "client_error"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    TRANSIENT = "transient"
    UNAVAILABLE = "unavailable"
    INTERNAL = "internal"


class FailureCategoryCarrier(Protocol):
    """Result shape accepted by :func:`resolve_failure_category`."""

    failure_category: str | None
    error: BaseException | None


FailureClassifier = Callable[[BaseException], "FailureCategory | str | None"]


class CategorizedTaskError(Exception):
    """Exception carrying a safe machine-readable failure category."""

    def __init__(
        self,
        failure_category: FailureCategory | str,
        message: str | None = None,
        *,
        retryable: bool | None = None,
    ) -> None:
        self.failure_category = _category_value(failure_category)
        self.retryable = retryable
        super().__init__(message or f"Task failed: {self.failure_category}")


def _category_value(category: FailureCategory | str | None) -> str | None:
    if category is None:
        return None
    if isinstance(category, FailureCategory):
        return category.value
    return str(category)


def classify_failure(exception: BaseException | None) -> str:
    """
    Classify an exception without reading its potentially sensitive message.

    Exception-provided ``failure_category`` attributes take precedence.

    :param exception: Exception raised by a task.
    :return: Stable category value.
    """
    if exception is None:
        return FailureCategory.UNKNOWN.value

    explicit = getattr(exception, "failure_category", None)
    if explicit is not None:
        value = _category_value(explicit)
        if value:
            return value

    category_by_type: tuple[tuple[Any, FailureCategory], ...] = (
        (asyncio.CancelledError, FailureCategory.CANCELLED),
        (TimeoutError, FailureCategory.TIMEOUT),
        (PermissionError, FailureCategory.PERMISSION_DENIED),
        (FileNotFoundError, FailureCategory.NOT_FOUND),
        (ConnectionError, FailureCategory.TRANSIENT),
        (ValueError | TypeError, FailureCategory.VALIDATION),  # type: ignore[arg-type]
        (NotImplementedError, FailureCategory.INTERNAL),
        (RuntimeError, FailureCategory.INTERNAL),
    )
    for exception_type, category in category_by_type:
        if isinstance(exception, exception_type):
            return category.value
    return FailureCategory.UNKNOWN.value


def resolve_failure_category(
    result_or_exception: FailureCategoryCarrier | BaseException | None,
    classifier: FailureClassifier = classify_failure,
) -> str:
    """
    Resolve a category from either a result or an exception.

    :param result_or_exception: Result or raised exception.
    :param classifier: Optional category resolver.
    :return: Category string.
    """
    exception: BaseException | None
    explicit: Any = None
    if result_or_exception is None:
        exception = None
    elif isinstance(result_or_exception, BaseException):
        exception = result_or_exception
    else:
        explicit = getattr(result_or_exception, "failure_category", None)
        exception = getattr(result_or_exception, "error", None)

    if explicit is not None:
        value = _category_value(explicit)
        if value:
            return value

    classified = classifier(exception) if exception is not None else None
    value = _category_value(classified)
    return value or classify_failure(exception)


ErrorCategory = FailureCategory
classify_error = classify_failure
