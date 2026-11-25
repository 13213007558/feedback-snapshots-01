"""Re-import of the synchronous Audit API for compatibility."""

from __future__ import annotations

from pymongo.audit_shared import (
    AuditBatch,
    AuditResumePoint,
    AuditRevocation,
    AuditTrail,
)
from pymongo.synchronous.audit import *  # noqa: F403
from pymongo.synchronous.audit import __doc__ as original_doc

__doc__ = original_doc
__all__ = [  # noqa: F405
    "AuditBatch",
    "AuditCursor",
    "AuditResumePoint",
    "AuditRevocation",
    "AuditSubscription",
    "AuditTrail",
]
