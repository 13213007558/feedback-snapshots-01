"""Flask-Limiter extension for rate limiting."""

from __future__ import annotations

from . import _version
from ._extension import Limiter, RequestLimit
from ._limits import (
    ApplicationLimit,
    Limit,
    MetaLimit,
    RouteLimit,
)
from .constants import ExemptionScope, HeaderNames, StorageFailurePolicy
from .errors import RateLimitExceeded, StorageUnavailable

__all__ = [
    "ExemptionScope",
    "HeaderNames",
    "Limiter",
    "Limit",
    "RouteLimit",
    "ApplicationLimit",
    "MetaLimit",
    "RateLimitExceeded",
    "RequestLimit",
    "StorageFailurePolicy",
    "StorageUnavailable",
]

__version__ = _version.__version__
