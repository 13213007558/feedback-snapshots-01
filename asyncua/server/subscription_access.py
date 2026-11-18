"""
Admission control for subscription ownership and TransferSubscriptions.

A subscription belongs to the authenticated session that created it.  The
session identity is taken from the server-side authentication result, never
from a client supplied SubscriptionId or from the mere fact that a request
arrived on an activated session.  Operations addressed by SubscriptionId
(Create/Modify/DeleteMonitoredItems, SetMonitoringMode, SetPublishingMode,
ModifySubscription, Republish, Publish acknowledgements, DeleteSubscriptions)
are only accepted from the owning session.

TransferSubscriptions is the one operation that may move ownership.  It is
gated by a :class:`SubscriptionTransferPolicy` so a deployment can state
explicitly whether a reconnecting same-principal session or a different
principal may take a subscription over.  The default policy allows the same
session and an explicitly identified same principal, and denies everything
else.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from asyncua import ua


@dataclass(frozen=True)
class SubscriptionOwner:
    """The authenticated session that currently owns a subscription."""

    session_id: ua.NodeId
    principal: str | None
    epoch: int = 0


@dataclass(frozen=True)
class SubscriptionTransferRequest:
    """Everything a transfer policy is allowed to base its decision on."""

    subscription_id: int
    owner: SubscriptionOwner
    requester_session_id: ua.NodeId
    requester_principal: str | None
    send_initial_values: bool = True

    @property
    def same_session(self) -> bool:
        return self.owner.session_id == self.requester_session_id

    @property
    def same_principal(self) -> bool:
        return self.requester_principal is not None and self.requester_principal == self.owner.principal


class SubscriptionTransferPolicy(Protocol):
    """Admission hook consulted before any subscription changes owner."""

    def can_transfer(self, request: SubscriptionTransferRequest) -> bool:
        """Return True only when the requester may take over the subscription."""
        ...


class SamePrincipalTransferPolicy:
    """Default policy: same session, or an identified same principal reconnect.

    A principal is only considered equal when both sides carry a non-None
    authenticated identity.  Anonymous sessions therefore cannot take over each
    other's subscriptions merely by presenting the same SubscriptionId.
    """

    def __init__(self, *, allow_same_session: bool = True, allow_same_principal: bool = True) -> None:
        self.allow_same_session = allow_same_session
        self.allow_same_principal = allow_same_principal

    def can_transfer(self, request: SubscriptionTransferRequest) -> bool:
        if request.same_session:
            return self.allow_same_session
        if request.same_principal:
            return self.allow_same_principal
        return False


class DenyAllTransferPolicy:
    """Refuse every TransferSubscriptions request."""

    def can_transfer(self, request: SubscriptionTransferRequest) -> bool:
        return False


class AllowAllTransferPolicy:
    """Explicit opt-in to cross-principal transfer.

    Only use this in deployments where every authenticated session is trusted
    to operate every subscription on the server.
    """

    def can_transfer(self, request: SubscriptionTransferRequest) -> bool:
        return True


class CallableTransferPolicy:
    """Adapter for a plain callable admission function."""

    def __init__(self, decide: Callable[[SubscriptionTransferRequest], bool]) -> None:
        self._decide = decide

    def can_transfer(self, request: SubscriptionTransferRequest) -> bool:
        return bool(self._decide(request))
