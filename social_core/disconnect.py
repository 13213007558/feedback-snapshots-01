"""Structured outcomes for concurrent account disconnection attempts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from social_core.exceptions import AuthPolicyError, SocialAuthBaseException

DisconnectItemState = Literal["completed", "protected", "retryable", "failed"]
DisconnectReportState = Literal[
    "completed",
    "partially_completed",
    "protected",
    "retryable",
    "failed",
]


@dataclass(frozen=True)
class DisconnectItemResult:
    """Outcome for one association or parallel disconnect request."""

    key: str
    state: DisconnectItemState
    retryable: bool
    uncertain: bool = False
    provider: str | None = None
    uid: str | None = None
    error_code: str | None = None
    recovery: str | None = None

    def public_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "state": self.state,
            "retryable": self.retryable,
            "uncertain": self.uncertain,
            "provider": self.provider,
            "uid": self.uid,
            "error_code": self.error_code,
            "recovery": self.recovery,
        }


@dataclass(frozen=True)
class DisconnectReport:
    """Aggregate parallel outcomes without collapsing partial and retry states."""

    items: tuple[DisconnectItemResult, ...]

    @classmethod
    def from_outcomes(
        cls,
        outcomes: dict[str, object] | list[tuple[str, object]],
    ) -> DisconnectReport:
        pairs = list(outcomes.items()) if isinstance(outcomes, dict) else outcomes
        return cls(
            tuple(classify_disconnect_outcome(key, outcome) for key, outcome in pairs)
        )

    @property
    def completed(self) -> tuple[DisconnectItemResult, ...]:
        return tuple(item for item in self.items if item.state == "completed")

    @property
    def protected(self) -> tuple[DisconnectItemResult, ...]:
        return tuple(item for item in self.items if item.state == "protected")

    @property
    def retryable_items(self) -> tuple[DisconnectItemResult, ...]:
        return tuple(item for item in self.items if item.state == "retryable")

    @property
    def failed(self) -> tuple[DisconnectItemResult, ...]:
        return tuple(item for item in self.items if item.state == "failed")

    @property
    def can_retry(self) -> bool:
        return bool(self.retryable_items)

    @property
    def state(self) -> DisconnectReportState:
        if not self.items:
            return "completed"
        if len(self.completed) == len(self.items):
            return "completed"
        if self.completed:
            return "partially_completed"
        if self.retryable_items:
            return "retryable"
        if len(self.protected) == len(self.items):
            return "protected"
        return "failed"

    def public_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "can_retry": self.can_retry,
            "completed_keys": [item.key for item in self.completed],
            "protected_keys": [item.key for item in self.protected],
            "retryable_keys": [item.key for item in self.retryable_items],
            "failed_keys": [item.key for item in self.failed],
            "items": [item.public_dict() for item in self.items],
        }


def classify_disconnect_outcome(key: str, outcome: object) -> DisconnectItemResult:
    """Convert a return value or captured parallel future exception to UI state."""
    provider: str | None = None
    uid: str | None = None
    if isinstance(outcome, SocialAuthBaseException):
        context = outcome.context or {}
        provider_value = context.get("provider")
        uid_value = context.get("uid")
        provider = provider_value if isinstance(provider_value, str) else None
        uid = uid_value if isinstance(uid_value, str) else None

    if not isinstance(outcome, BaseException):
        return DisconnectItemResult(
            key=key,
            state="completed",
            retryable=False,
            provider=provider,
            uid=uid,
        )

    if isinstance(outcome, AuthPolicyError) and outcome.code == "disconnect_disallowed":
        return DisconnectItemResult(
            key=key,
            state="protected",
            retryable=False,
            provider=provider,
            uid=uid,
            error_code=outcome.code,
            recovery=outcome.recovery,
        )

    retryable = False
    uncertain = False
    error_code: str | None = None
    recovery: str | None = None
    if isinstance(outcome, SocialAuthBaseException):
        error_code = outcome.code
        recovery = outcome.recovery
        retryable = outcome.recovery == "retry_later"
        uncertain = outcome.code in {"connection_failed", "timeout"}
    elif isinstance(outcome, (TimeoutError, ConnectionError)):
        retryable = True
        uncertain = True
        recovery = "retry_later"
        error_code = (
            "timeout" if isinstance(outcome, TimeoutError) else "connection_failed"
        )

    return DisconnectItemResult(
        key=key,
        state="retryable" if retryable else "failed",
        retryable=retryable,
        uncertain=uncertain,
        provider=provider,
        uid=uid,
        error_code=error_code,
        recovery=recovery,
    )
