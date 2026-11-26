"""Authentication-method constraints for the client migration window.

The policy keeps three facts separate: the authenticator that actually
succeeded, the grant/privilege being exercised, and the transition state.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.oauth2.rfc6749.errors import UnauthorizedClientError

LEGACY_METHOD = "legacy-record"
SIGNATURE_METHOD = "signature-record"

NORMAL_PRIVILEGE = "normal"
PRIVILEGED_PRIVILEGE = "privileged"
MAINTENANCE_ACTION = "maintenance_revocation"

REASON_ALLOWED = "allowed"
REASON_UNKNOWN_METHOD = "unknown_authentication_method"
REASON_GRANT_NOT_APPROVED = "grant_not_approved_for_client"
REASON_STRONG_METHOD_REQUIRED = "signature_method_required_for_privileged_grant"
REASON_TRANSITION_CLOSED = "legacy_transition_window_closed"
REASON_OPERATION_NOT_REGISTERED = "legacy_maintenance_operation_not_registered"


@dataclass(frozen=True)
class PolicyDecision:
    """Internal result of checking an authentication method."""

    allowed: bool
    auth_method: str
    action: str
    reason: str = REASON_ALLOWED
    privilege: str | None = None
    operation_id: str | None = None
    public_error: str | None = None

    @property
    def assurance_tier(self) -> str:
        if self.auth_method == SIGNATURE_METHOD:
            return "strong_signature"
        if self.auth_method == LEGACY_METHOD:
            return "legacy_record"
        return "unknown"


class ApprovalLedger:
    """Append-only audit records."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **entry: Any) -> dict[str, Any]:
        record = {"seq": len(self.records) + 1, **entry}
        self.records.append(record)
        return record

    def issued_tokens(self) -> list[dict[str, Any]]:
        return [record for record in self.records if record.get("kind") == "issuance"]

    def approvals(self) -> list[dict[str, Any]]:
        return [
            record
            for record in self.issued_tokens()
            if record.get("outcome") == "issued"
        ]


@dataclass
class TransitionWindow:
    """Current state of the legacy-to-signature migration window."""

    open: bool = True
    closes_at: float | None = None
    clock: Callable[[], float] = time.time

    def is_open(self) -> bool:
        if not self.open:
            return False
        return self.closes_at is None or self.clock() < self.closes_at

    def close(self) -> None:
        self.open = False


@dataclass
class MaintenanceOperation:
    """A maintenance operation that legacy authentication may perform."""

    id: str
    token_value: str
    legacy_allowed: bool = True
    completed: bool = False


class FictionalClient:
    """One shared client registration accepting both test methods."""

    def __init__(
        self,
        client_id: str = "fictional-client-7558",
        *,
        legacy_secret: str = "legacy-maintenance-secret",
        signing_secret: str = "new-signature-secret",
    ) -> None:
        self.client_id = client_id
        self.legacy_secret = legacy_secret
        self.signing_secret = signing_secret
        self.auth_methods = frozenset({LEGACY_METHOD, SIGNATURE_METHOD})
        self.approved_grant_types = frozenset({"client_credentials"})

    def check_endpoint_auth_method(self, method: str, endpoint: str) -> bool:
        return method in self.auth_methods and endpoint in {
            "token",
            "revocation",
            "introspection",
        }

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in self.approved_grant_types


def sign_client_assertion(client_id: str, timestamp: str, secret: str) -> str:
    message = f"{client_id}:{timestamp}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class RecordingMethodValidator:
    """Authlib client-authentication callable that records invocations."""

    method = "record"
    credential_field = "credential"

    def __init__(self, client: FictionalClient) -> None:
        self.client = client
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        query_client: Callable[[str], FictionalClient],
        request: Any,
    ):
        presented = request.form.get(self.credential_field, "")
        observed = {
            "method": self.method,
            "presented": bool(presented),
            "valid": False,
        }
        self.calls.append(observed)
        if not presented or not self.verify(request, presented):
            return None

        client = query_client(self.client.client_id)
        observed["valid"] = True
        observed["client_id"] = client.client_id
        return client

    def verify(self, request: Any, presented: str) -> bool:
        raise NotImplementedError


class LegacyRecordValidator(RecordingMethodValidator):
    method = LEGACY_METHOD
    credential_field = "legacy_credential"

    def verify(self, request: Any, presented: str) -> bool:
        return hmac.compare_digest(presented, self.client.legacy_secret)


class SignatureRecordValidator(RecordingMethodValidator):
    method = SIGNATURE_METHOD
    credential_field = "signature"

    def verify(self, request: Any, presented: str) -> bool:
        client_id = request.form.get("client_id", "")
        timestamp = request.form.get("timestamp", "")
        expected = sign_client_assertion(
            client_id,
            timestamp,
            self.client.signing_secret,
        )
        return hmac.compare_digest(presented, expected)


class AuthenticationMethodPolicy:
    """Grant- and transition-aware authentication method constraints."""

    def __init__(
        self,
        *,
        transition: TransitionWindow | None = None,
        ledger: ApprovalLedger | None = None,
        privileged_scopes: frozenset[str] | set[str] | tuple[str, ...] = frozenset(
            {"admin", "high_privilege", "privileged"}
        ),
        privileged_grant_types: frozenset[str]
        | set[str]
        | tuple[str, ...] = frozenset(),
    ) -> None:
        self.transition = transition or TransitionWindow()
        self.ledger = ledger
        self.privileged_scopes = frozenset(privileged_scopes)
        self.privileged_grant_types = frozenset(privileged_grant_types)

    def privilege_for_scope(self, scope: str | None) -> str:
        scopes = set((scope or "").split())
        if scopes & self.privileged_scopes:
            return PRIVILEGED_PRIVILEGE
        return NORMAL_PRIVILEGE

    def privilege_for_request(self, grant_type: str, scope: str | None) -> str:
        if grant_type in self.privileged_grant_types:
            return PRIVILEGED_PRIVILEGE
        return self.privilege_for_scope(scope)

    def evaluate_issuance(
        self,
        *,
        client: FictionalClient,
        auth_method: str | None,
        grant_type: str,
        scope: str | None,
    ) -> PolicyDecision:
        privilege = self.privilege_for_request(grant_type, scope)

        if auth_method not in {LEGACY_METHOD, SIGNATURE_METHOD}:
            return PolicyDecision(
                False,
                auth_method or "none",
                "issuance",
                REASON_UNKNOWN_METHOD,
                privilege=privilege,
                public_error="invalid_client",
            )

        if auth_method == LEGACY_METHOD and not self.transition.is_open():
            return PolicyDecision(
                False,
                auth_method,
                "issuance",
                REASON_TRANSITION_CLOSED,
                privilege=privilege,
                public_error="invalid_client",
            )

        if not client.check_grant_type(grant_type):
            return PolicyDecision(
                False,
                auth_method,
                "issuance",
                REASON_GRANT_NOT_APPROVED,
                privilege=privilege,
                public_error="unauthorized_client",
            )

        if privilege == PRIVILEGED_PRIVILEGE and auth_method != SIGNATURE_METHOD:
            return PolicyDecision(
                False,
                auth_method,
                "issuance",
                REASON_STRONG_METHOD_REQUIRED,
                privilege=privilege,
                public_error="unauthorized_client",
            )

        return PolicyDecision(
            True,
            auth_method,
            "issuance",
            privilege=privilege,
        )

    def evaluate_maintenance(
        self,
        *,
        client: FictionalClient,
        auth_method: str | None,
        operation: MaintenanceOperation | None,
    ) -> PolicyDecision:
        operation_id = operation.id if operation is not None else None

        if auth_method not in {LEGACY_METHOD, SIGNATURE_METHOD}:
            return PolicyDecision(
                False,
                auth_method or "none",
                MAINTENANCE_ACTION,
                REASON_UNKNOWN_METHOD,
                operation_id=operation_id,
                public_error="invalid_client",
            )

        if auth_method == LEGACY_METHOD and not self.transition.is_open():
            return PolicyDecision(
                False,
                auth_method,
                MAINTENANCE_ACTION,
                REASON_TRANSITION_CLOSED,
                operation_id=operation_id,
                public_error="invalid_client",
            )

        if auth_method == LEGACY_METHOD and (
            operation is None or not operation.legacy_allowed
        ):
            return PolicyDecision(
                False,
                auth_method,
                MAINTENANCE_ACTION,
                REASON_OPERATION_NOT_REGISTERED,
                operation_id=operation_id,
                public_error="unauthorized_client",
            )

        return PolicyDecision(
            True,
            auth_method,
            MAINTENANCE_ACTION,
            operation_id=operation_id,
        )

    def check(
        self,
        decision: PolicyDecision,
        *,
        request: Any | None = None,
        client_id: str | None = None,
        **context: Any,
    ) -> PolicyDecision:
        if request is not None:
            request.policy_decision = decision

        if self.ledger is not None:
            self.ledger.record(
                kind="policy_decision",
                outcome="allowed" if decision.allowed else "denied",
                client_id=client_id,
                auth_method=decision.auth_method,
                assurance_tier=decision.assurance_tier,
                action=decision.action,
                reason=decision.reason,
                privilege=decision.privilege,
                operation_id=decision.operation_id,
                **context,
            )

        if not decision.allowed:
            if decision.public_error == "invalid_client":
                raise InvalidClientError()
            raise UnauthorizedClientError()

        return decision
