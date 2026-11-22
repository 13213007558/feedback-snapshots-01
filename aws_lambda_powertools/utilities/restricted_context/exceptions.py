"""
Restricted Context exceptions
"""

from __future__ import annotations


class RestrictedContextError(Exception):
    """Base exception for every Restricted Context failure."""


class UnverifiedEventError(RestrictedContextError):
    """Raised when an event cannot be verified at an entry point.

    An unverified event must never reach the shared handler: no
    :class:`~aws_lambda_powertools.utilities.restricted_context.context.RestrictedContext`
    is produced for it.
    """


class RestrictedContextConstructionError(RestrictedContextError):
    """Raised when code outside the entry points tries to build a context."""


class UnrecognizedEventError(RestrictedContextError):
    """Raised when an event matches neither the HTTP API nor the SQS shape."""
