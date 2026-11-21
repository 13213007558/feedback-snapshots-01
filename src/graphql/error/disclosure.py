"""Configurable error disclosure policy.

GraphQL servers use their default error formatting to diagnose internal faults.
That default exposes the raw exception message (and, when logged, the traceback)
to every client.  Public clients must instead only see a *safe error category*
together with the response ``path`` so they can tell which field failed, while the
original exception stays available to the server for internal handling.

This module provides a small, framework-agnostic layer that sits between the
:class:`~graphql.execution.ExecutionResult` produced by graphql-core and the JSON
serialized back to the client.  It distinguishes two kinds of failures:

* **Public validation errors** -- errors that the application explicitly approves
  for disclosure.  Raise :class:`PublicGraphQLError` (or any
  :class:`~graphql.GraphQLError` carrying the :data:`PUBLIC_EXTENSION` marker) and
  the original message and allowlisted extensions are forwarded unchanged.
* **Resolver/internal failures** -- every other exception, including arbitrary
  exceptions thrown by resolvers.  These are reduced to a fixed category so that
  database URLs, stack details and other internals never leak.

The disclosure :class:`~graphql.error.disclosure.ErrorDisclosurePolicy` is
configurable through :class:`DisclosureMode` and a few constructor options, so the
same schema can run locked-down in production and verbose in development.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterable
from enum import Enum
from typing import TYPE_CHECKING, Any

from .graphql_error import GraphQLError, GraphQLFormattedError

if TYPE_CHECKING:
    from ..execution import ExecutionResult, FormattedExecutionResult

__all__ = [
    "PUBLIC_EXTENSION",
    "DefaultErrorCodes",
    "DisclosureMode",
    "ErrorDisclosurePolicy",
    "PublicGraphQLError",
    "disclose_execution_result",
]

#: Extension key marking a :class:`~graphql.GraphQLError` as approved for public
#: disclosure.  The value is ignored; the mere presence of the key opts the error
#: out of internal-error masking.
PUBLIC_EXTENSION = "public"


class DisclosureMode(Enum):
    """How aggressively error details are disclosed to clients.

    :value STRICT: Only application-approved public errors keep their message.
        Every other failure is reported as a generic internal error.  This is the
        safe default for public deployments.
    :value DEBUG: Like ``STRICT`` for the message, but a generated ``errorId`` and
        the error category are exposed so testers can correlate a client response
        with a server log entry.
    :value TRUSTED: Forward the original message of every error.  Only use this for
        internal/trusted clients -- resolver messages may contain secrets.
    """

    STRICT = "strict"
    DEBUG = "debug"
    TRUSTED = "trusted"


class DefaultErrorCodes:
    """Stable, machine-readable error categories returned to clients.

    The values are part of the public contract, so they are intentionally generic
    and never carry internal details.  Public validation errors keep the
    application-supplied ``code`` extension instead of using a default.
    """

    INTERNAL = "INTERNAL_SERVER_ERROR"


# A handler that receives the original (unmasked) error for logging, tracing or
# metrics.  It must not raise -- doing so would break response serialization.
InternalErrorHandler = Callable[[GraphQLError], Any]


class PublicGraphQLError(GraphQLError):
    """A validation/input error that the application approves for disclosure.

    The message and any allowlisted extensions are forwarded to the client.  Use
    this for expected, user-facing failures such as invalid arguments or failed
    domain rules.  Constructor arguments are the same as :class:`GraphQLError`;
    the :data:`PUBLIC_EXTENSION` marker is added automatically to the extensions.

    >>> error = PublicGraphQLError(
    ...     'Email address is not formatted correctly.',
    ...     path=['createUser', 'email'],
    ...     extensions={'field': 'email'},
    ... )
    >>> error.extensions[PUBLIC_EXTENSION]
    True
    >>> error.message
    'Email address is not formatted correctly.'
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the public error, adding the public marker extension."""
        extensions = dict(kwargs.pop("extensions", None) or {})
        extensions.setdefault(PUBLIC_EXTENSION, True)
        super().__init__(*args, extensions=extensions, **kwargs)


def _is_public(error: GraphQLError) -> bool:
    """Return whether the application explicitly approved this error."""
    extensions = error.extensions or {}
    return PUBLIC_EXTENSION in extensions


def _unwrap_original(error: GraphQLError) -> BaseException | None:
    """Return the underlying resolver exception, if any."""
    original = error.original_error
    if original is not None and original is not error:
        return original
    cause = error.cause
    return cause if isinstance(cause, BaseException) and cause is not error else None


class ErrorDisclosurePolicy:
    """Turn raw GraphQL errors into safe, categorized client errors.

    :param mode: Controls how much detail is disclosed.
    :param internal_message: Generic message used for masked internal errors.
    :param include_locations: Whether to keep source ``locations``.  ``path`` is
        always retained because clients need it to associate an error with a field.
    :param public_extension_keys: Extension keys that may appear on a public error.
        All other extensions (including the :data:`PUBLIC_EXTENSION` marker) are
        stripped from the client payload.
    :param on_internal_error: Optional callback invoked with the original error for
        every masked internal failure, so the server can log/trace the real
        exception while the client only sees the category.
    :param error_id_factory: Optional zero-argument callable producing a correlation
        id.  Required (and used) only in :attr:`DisclosureMode.DEBUG`.

    A single policy instance is reusable and stateless apart from its configuration,
    so it can be shared across requests and subscriptions.

    >>> ErrorDisclosurePolicy().disclose_error(
    ...     PublicGraphQLError('Bad input', path=['field']))['message']
    'Bad input'
    >>> ErrorDisclosurePolicy().disclose_error(
    ...     GraphQLError('secret database DSN', path=['field']))['message']
    'Internal server error.'
    """

    def __init__(
        self,
        mode: DisclosureMode = DisclosureMode.STRICT,
        *,
        internal_message: str = "Internal server error.",
        include_locations: bool = True,
        public_extension_keys: Iterable[str] = ("code", "field"),
        on_internal_error: InternalErrorHandler | None = None,
        error_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.mode = mode
        self.internal_message = internal_message
        self.include_locations = include_locations
        self.public_extension_keys = frozenset(public_extension_keys)
        self.on_internal_error = on_internal_error
        self.error_id_factory = error_id_factory

    # -- classification -----------------------------------------------------

    def is_public(self, error: GraphQLError) -> bool:
        """Return whether this error is an application-approved public error.

        :param error: The error to classify.
        :returns: ``True`` when the error carries the :data:`PUBLIC_EXTENSION`
            marker, otherwise ``False``.

        >>> ErrorDisclosurePolicy().is_public(PublicGraphQLError('Bad input'))
        True
        """
        return _is_public(error)

    def original_error(self, error: GraphQLError) -> BaseException | None:
        """Return the underlying resolver exception, kept for internal handling.

        :param error: The error whose original exception is requested.
        :returns: The wrapped exception, or ``None`` when the error has no
            distinct cause.

        >>> cause = RuntimeError('boom')
        >>> error = GraphQLError('Resolver failed', cause=cause)
        >>> ErrorDisclosurePolicy().original_error(error) is cause
        True
        """
        return _unwrap_original(error)

    # -- per-error formatting ----------------------------------------------

    def disclose_error(self, error: GraphQLError) -> GraphQLFormattedError:
        """Format one error for the client according to the policy.

        The response ``path`` is always preserved.  Public errors keep their
        message and allowlisted extensions; internal failures are replaced by a
        generic category.  The original error is handed to the internal handler
        before it is masked.

        :param error: The raw error produced during parsing, validation or
            execution.
        :returns: A client-safe formatted error.

        >>> formatted = ErrorDisclosurePolicy().disclose_error(
        ...     GraphQLError('secret', path=['viewer', 'name']))
        >>> formatted['path']
        ['viewer', 'name']
        >>> formatted['message']
        'Internal server error.'
        """
        path = error.path
        if self.is_public(error):
            return self._format_public(error, path)
        return self._format_internal(error, path)

    def _base(self, error: GraphQLError, path: list[str | int] | None) -> dict:
        formatted: dict[str, Any] = {}
        if self.include_locations and error.locations is not None:
            formatted["locations"] = [
                location.formatted for location in error.locations
            ]
        if path is not None:
            formatted["path"] = path
        return formatted

    def _format_public(
        self, error: GraphQLError, path: list[str | int] | None
    ) -> GraphQLFormattedError:
        formatted = self._base(error, path)
        formatted["message"] = error.message or "An unknown error occurred."
        extensions = self._public_extensions(error)
        if extensions:
            formatted["extensions"] = extensions
        return formatted  # type: ignore[return-value]

    def _public_extensions(self, error: GraphQLError) -> dict[str, Any]:
        extensions = error.extensions or {}
        allowed = self.public_extension_keys
        return {
            key: value
            for key, value in extensions.items()
            if key in allowed and key != PUBLIC_EXTENSION
        }

    def _format_internal(
        self, error: GraphQLError, path: list[str | int] | None
    ) -> GraphQLFormattedError:
        # Give the server the real exception before masking it.
        if self.on_internal_error is not None:
            self.on_internal_error(error)

        formatted = self._base(error, path)
        if self.mode is DisclosureMode.TRUSTED:
            formatted["message"] = error.message or self.internal_message
        else:
            formatted["message"] = self.internal_message

        extensions: dict[str, Any] = {"code": DefaultErrorCodes.INTERNAL}
        if self.mode is DisclosureMode.DEBUG:
            extensions["errorId"] = self._next_error_id()
        formatted["extensions"] = extensions
        return formatted  # type: ignore[return-value]

    def _next_error_id(self) -> str:
        if self.error_id_factory is None:
            raise ValueError(
                "An error_id_factory must be configured to use DisclosureMode.DEBUG"
            )
        return self.error_id_factory()

    # -- whole results ------------------------------------------------------

    def disclose_result(self, result: ExecutionResult) -> FormattedExecutionResult:
        """Format an :class:`~graphql.execution.ExecutionResult` for the client.

        ``data`` is passed through untouched (it already follows the GraphQL
        null-propagation rules); only the ``errors`` are sanitized.

        :param result: The raw execution result returned by ``execute`` or
            ``subscribe``.
        :returns: A client-safe formatted execution result.

        >>> from graphql import ExecutionResult
        >>> ErrorDisclosurePolicy().disclose_result(
        ...     ExecutionResult(
        ...         data={'field': None},
        ...         errors=[GraphQLError('secret', path=['field'])]
        ...     ))['errors'][0]['message']
        'Internal server error.'
        """
        formatted: FormattedExecutionResult = {"data": result.data}
        if result.errors:
            formatted["errors"] = [
                self.disclose_error(error) for error in result.errors
            ]
        if result.extensions is not None:
            formatted["extensions"] = result.extensions
        return formatted

    async def disclose_subscription(
        self, results: AsyncIterator[ExecutionResult]
    ) -> AsyncIterator[FormattedExecutionResult]:
        """Sanitize each event of a subscription response stream.

        Subscription events are independent :class:`ExecutionResult` objects, so the
        same per-event masking rules apply as for queries and mutations.

        :param results: The raw async iterator of subscription execution results.
        :returns: An async iterator of client-safe formatted results.

        >>> import asyncio
        >>> async def demo():
        ...     from graphql import ExecutionResult
        ...     async def raw_events():
        ...         yield ExecutionResult(
        ...             errors=[GraphQLError('secret', path=['e'])])
        ...     policy = ErrorDisclosurePolicy()
        ...     stream = policy.disclose_subscription(raw_events())
        ...     event = await stream.__anext__()
        ...     return event['errors'][0]['message']
        >>> asyncio.run(demo())
        'Internal server error.'
        """
        async for event in results:
            yield self.disclose_result(event)


def disclose_execution_result(
    result: ExecutionResult,
    mode: DisclosureMode = DisclosureMode.STRICT,
    **kwargs: Any,
) -> FormattedExecutionResult:
    """Build a one-off policy and format an execution result for the client.

    :param result: The raw execution result to sanitize.
    :param mode: Controls how much detail is disclosed.
    :returns: A client-safe formatted execution result.

    Any additional keyword arguments are forwarded to
    :class:`ErrorDisclosurePolicy`.

    >>> from graphql import ExecutionResult
    >>> disclose_execution_result(
    ...     ExecutionResult(errors=[PublicGraphQLError('Bad input')])
    ... )['errors'][0]['message']
    'Bad input'
    """
    policy = ErrorDisclosurePolicy(mode=mode, **kwargs)
    return policy.disclose_result(result)
