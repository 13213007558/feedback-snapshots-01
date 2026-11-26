"""Exception types raised by Bleach.

The work-budget types are implemented in :mod:`bleach.budget`; this module
re-exports them under the conventional ``bleach.exceptions`` import path.
"""

from bleach.budget import (
    BudgetExceeded,
    BudgetExceededError,
    WorkBudgetExceeded,
)

__all__ = [
    "BudgetExceeded",
    "BudgetExceededError",
    "WorkBudgetExceeded",
]
