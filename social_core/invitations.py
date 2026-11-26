"""Flow-scoped invitation validation hooks for association pipelines.

Social Auth core does not persist invitations. Applications own issuance and
revocation and can implement :class:`InvitationValidator` (or override
:meth:`social_core.strategy.BaseStrategy.validate_invitation`). Checks are
deliberately live: a decision made while resuming a partial pipeline is not
reused immediately before an association or profile write.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .exceptions import AuthInvitationError, AuthInvitationRevoked

InvitationInvalid = AuthInvitationError
InvitationRevoked = AuthInvitationRevoked

INVITATION_ID_KWARG = "invitation_id"
INVITATION_KWARG = "invitation"
INVITATION_PARTIAL_TOKENS_SESSION_NAME = "invitation_partial_tokens"


class InvitationStage:
    PARTIAL_VALIDATE = "partial_validate"
    PARTIAL_RESUME = "partial_resume"
    ASSOCIATION_SAVE = "association_save"
    PROFILE_SYNC = "profile_sync"


@dataclass(frozen=True)
class InvitationCheck:
    """The flow identity and boundary for a live authorization check."""

    invitation_id: str
    stage: str
    provider: str | None = None
    user: Any = None
    user_id: object | None = None
    session_key: str | None = None
    partial: Any = None
    partial_token: str | None = None
    uid: str | None = None
    changed_fields: frozenset[str] = field(default_factory=frozenset)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InvitationDecision:
    invitation_id: str
    stage: str
    allowed: bool
    status: str
    end_state: str | None = None
    version: int = 0


@runtime_checkable
class InvitationValidator(Protocol):
    def validate_invitation(
        self, check: InvitationCheck
    ) -> InvitationDecision | bool | None: ...


def invitation_id_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("id", "invitation_id", "invite_id"):
            invitation_id = value.get(key)
            if isinstance(invitation_id, str) and invitation_id:
                return invitation_id
    if isinstance(value, str) and value:
        return value
    return None


def invitation_id_from_mapping(mapping: Any) -> str | None:
    """Return the canonical invitation identity saved in pipeline kwargs."""
    if not isinstance(mapping, dict):
        return None
    for key in (
        INVITATION_ID_KWARG,
        INVITATION_KWARG,
        "invite_id",
        "invitation_token",
        "invite_token",
    ):
        invitation_id = invitation_id_from_value(mapping.get(key))
        if invitation_id is not None:
            return invitation_id
    return None


def remember_invitation_partial(
    strategy: Any, invitation_id: str | None, token: str
) -> None:
    """Index a partial token under its flow-scoped invitation in session."""
    if not invitation_id:
        return
    raw_tokens = strategy.session_get(INVITATION_PARTIAL_TOKENS_SESSION_NAME, {})
    tokens = dict(raw_tokens) if isinstance(raw_tokens, Mapping) else {}
    tokens[invitation_id] = token
    strategy.session_set(INVITATION_PARTIAL_TOKENS_SESSION_NAME, tokens)


def session_owns_invitation_partial(
    strategy: Any, invitation_id: str | None, token: str | None
) -> bool:
    if not invitation_id or not token:
        return False
    tokens = strategy.session_get(INVITATION_PARTIAL_TOKENS_SESSION_NAME, {})
    return isinstance(tokens, Mapping) and tokens.get(invitation_id) == token
