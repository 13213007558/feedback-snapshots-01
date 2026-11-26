from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from social_core.exceptions import (
    AuthInvitationError,
    AuthInvitationRevoked,
)
from social_core.invitations import InvitationCheck, InvitationDecision


class InvitationStatus:
    ISSUED = "issued"
    APPROVED = "approved"
    ACTIVE = "active"
    REVOKED = "revoked"
    COMPLETED = "completed"
    EXPIRED = "expired"


class InvitationEndState:
    REVOKED = "revoked"
    COMPLETED = "completed"
    EXPIRED = "expired"


@dataclass
class Invitation:
    id: str
    user_id: object | None = None
    session_key: str | None = None
    provider: str | None = None
    status: str = InvitationStatus.APPROVED
    version: int = 1

    @property
    def end_state(self) -> str | None:
        if self.status == InvitationStatus.REVOKED:
            return InvitationEndState.REVOKED
        if self.status == InvitationStatus.COMPLETED:
            return InvitationEndState.COMPLETED
        if self.status == InvitationStatus.EXPIRED:
            return InvitationEndState.EXPIRED
        return None


@dataclass(frozen=True)
class InvitationRecord:
    sequence: int
    action: str
    invitation_id: str
    stage: str | None = None
    status: str | None = None
    allowed: bool | None = None
    end_state: str | None = None
    provider: str | None = None
    user_id: object | None = None
    session_key: str | None = None
    partial_token: str | None = None


class MemoryInvitationCenter:
    """Application-side in-memory invitation registry for tests and probes."""

    def __init__(self) -> None:
        self.invitations: dict[str, Invitation] = {}
        self.records: list[InvitationRecord] = []
        self._sequence = 0

    def _record(self, **values: Any) -> InvitationRecord:
        self._sequence += 1
        record = InvitationRecord(sequence=self._sequence, **values)
        self.records.append(record)
        return record

    def issue(
        self,
        invitation_id: str,
        *,
        user: Any = None,
        user_id: object | None = None,
        session_key: str | None = None,
        provider: str | None = None,
        status: str = InvitationStatus.APPROVED,
    ) -> Invitation:
        principal_id = user_id if user_id is not None else getattr(user, "id", None)
        invitation = Invitation(
            id=invitation_id,
            user_id=principal_id,
            session_key=session_key,
            provider=provider,
            status=status,
        )
        self.invitations[invitation_id] = invitation
        self._record(
            action="issue",
            invitation_id=invitation_id,
            status=status,
            end_state=invitation.end_state,
            provider=provider,
            user_id=principal_id,
            session_key=session_key,
        )
        return invitation

    def revoke(self, invitation_id: str) -> Invitation:
        invitation = self._get(invitation_id)
        invitation.status = InvitationStatus.REVOKED
        invitation.version += 1
        self._record(
            action="revoke",
            invitation_id=invitation_id,
            status=invitation.status,
            end_state=invitation.end_state,
            provider=invitation.provider,
            user_id=invitation.user_id,
            session_key=invitation.session_key,
        )
        return invitation

    def complete(self, invitation_id: str) -> Invitation:
        invitation = self._get(invitation_id)
        invitation.status = InvitationStatus.COMPLETED
        invitation.version += 1
        self._record(
            action="complete",
            invitation_id=invitation_id,
            status=invitation.status,
            end_state=invitation.end_state,
            provider=invitation.provider,
            user_id=invitation.user_id,
            session_key=invitation.session_key,
        )
        return invitation

    def _get(self, invitation_id: str) -> Invitation:
        try:
            return self.invitations[invitation_id]
        except KeyError as error:
            raise AuthInvitationError(
                code="invitation_invalid",
                stage="pipeline",
                invitation_id=invitation_id,
            ) from error

    def validate_invitation(self, check: InvitationCheck) -> InvitationDecision:
        invitation = self.invitations.get(check.invitation_id)
        if invitation is None:
            self._record_check(check, allowed=False, status="missing")
            raise AuthInvitationError(
                code="invitation_invalid",
                stage=_error_stage(check.stage),
                invitation_id=check.invitation_id,
            )

        mismatch = self._binding_mismatch(invitation, check)
        if mismatch is not None:
            self._record_check(
                check,
                allowed=False,
                status=invitation.status,
                end_state=invitation.end_state,
            )
            raise AuthInvitationError(
                code="user_mismatch" if mismatch == "user" else "invitation_invalid",
                stage=_error_stage(check.stage),
                invitation_id=check.invitation_id,
                context={"binding_mismatch": mismatch},
            )

        if invitation.status == InvitationStatus.REVOKED:
            self._record_check(
                check,
                allowed=False,
                status=invitation.status,
                end_state=invitation.end_state,
            )
            raise AuthInvitationRevoked(
                stage=_error_stage(check.stage),
                invitation_id=check.invitation_id,
            )

        allowed = invitation.status in {
            InvitationStatus.ISSUED,
            InvitationStatus.APPROVED,
            InvitationStatus.ACTIVE,
        }
        decision = InvitationDecision(
            invitation_id=invitation.id,
            stage=check.stage,
            allowed=allowed,
            status=invitation.status,
            end_state=invitation.end_state,
            version=invitation.version,
        )
        self._record_check(
            check,
            allowed=allowed,
            status=invitation.status,
            end_state=invitation.end_state,
        )
        if not allowed:
            raise AuthInvitationError(
                code="invitation_invalid",
                stage=_error_stage(check.stage),
                invitation_id=check.invitation_id,
            )
        return decision

    def _binding_mismatch(
        self, invitation: Invitation, check: InvitationCheck
    ) -> str | None:
        principal_id = check.user_id
        if principal_id is None and check.user is not None:
            principal_id = getattr(check.user, "id", check.user)
        if (
            invitation.user_id is not None
            and principal_id is not None
            and str(invitation.user_id) != str(principal_id)
        ):
            return "user"
        if (
            invitation.session_key is not None
            and check.session_key is not None
            and invitation.session_key != check.session_key
        ):
            return "session"
        if (
            invitation.provider is not None
            and check.provider is not None
            and invitation.provider != check.provider
        ):
            return "provider"
        return None

    def _record_check(
        self,
        check: InvitationCheck,
        *,
        allowed: bool,
        status: str,
        end_state: str | None = None,
    ) -> None:
        self._record(
            action="check",
            invitation_id=check.invitation_id,
            stage=check.stage,
            status=status,
            allowed=allowed,
            end_state=end_state,
            provider=check.provider,
            user_id=check.user_id,
            session_key=check.session_key,
            partial_token=check.partial_token,
        )

    def checks(self, invitation_id: str | None = None) -> list[InvitationRecord]:
        return [
            record
            for record in self.records
            if record.action == "check"
            and (invitation_id is None or record.invitation_id == invitation_id)
        ]


def _error_stage(stage: str) -> str:
    if stage.startswith("partial_"):
        return "callback"
    return "pipeline"
