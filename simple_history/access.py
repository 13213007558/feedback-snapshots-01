from dataclasses import dataclass
from typing import Any, Protocol


class HistoryAccessEventType:
    """Types of accesses to a historical version through the admin."""

    VIEW = "view"
    REVERT = "revert"


class HistoryAccessStatus:
    """Outcomes of an attempt to access a historical version."""

    GRANTED = "granted"
    DENIED = "denied"


class HistoryAccessDenialReason:
    """Reasons recorded when access to a historical version is denied."""

    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class HistoryAccessEvent:
    """
    Describes a single attempt to read or restore a historical version.

    Only administrative metadata is carried; the historical record's field
    contents are deliberately excluded so that sensitive data never reaches
    the access log.
    """

    event_type: str
    status: str
    object_id: str
    app_label: str
    model_name: str
    history_id: str | None = None
    user_id: Any | None = None
    denial_reason: str | None = None


class HistoryAccessRecorder(Protocol):
    """Interface an application implements to persist access events."""

    def __call__(self, event: HistoryAccessEvent) -> None:
        ...
