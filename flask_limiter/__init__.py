"""Flask-Limiter extension for rate limiting."""

from __future__ import annotations

from . import _version
from ._atomic import (
    AtomicBudget,
    AtomicReservationStorage,
    ReservationResult,
)
from ._extension import Limiter, RequestLimit
from ._limits import (
    ApplicationLimit,
    Limit,
    MetaLimit,
    MultiLimit,
    RouteLimit,
)
from .constants import ExemptionScope, HeaderNames
from .errors import RateLimitExceeded

__all__ = [
    "ExemptionScope",
    "HeaderNames",
    "Limiter",
    "Limit",
    "RouteLimit",
    "MultiLimit",
    "ApplicationLimit",
    "MetaLimit",
    "AtomicBudget",
    "AtomicReservationStorage",
    "ReservationResult",
    "RateLimitExceeded",
    "RequestLimit",
]

__version__ = _version.__version__
