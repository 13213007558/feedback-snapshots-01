"""Security-oriented result and diagnostic primitives."""

from taskiq.failure_categories import (
    CategorizedTaskError,
    FailureCategory,
    classify_failure,
)
from taskiq.secure_results import (
    DiagnosticGrant,
    InMemoryRecordSink,
    PublicTaskFailure,
    PublicTaskFailureError,
    PublicTaskStatus,
    RecordSink,
    RedactingResultBackend,
    SecureResultBackend,
    TaskDiagnostic,
)

__all__ = [
    "CategorizedTaskError",
    "DiagnosticGrant",
    "FailureCategory",
    "InMemoryRecordSink",
    "PublicTaskFailure",
    "PublicTaskFailureError",
    "PublicTaskStatus",
    "RecordSink",
    "RedactingResultBackend",
    "SecureResultBackend",
    "TaskDiagnostic",
    "classify_failure",
]
