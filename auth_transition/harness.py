"""In-memory Authlib harness used by the migration scenario."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import ClientCredentialsGrant
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oauth2.rfc7009 import RevocationEndpoint

from .policy import LEGACY_METHOD
from .policy import NORMAL_PRIVILEGE
from .policy import SIGNATURE_METHOD
from .policy import ApprovalLedger
from .policy import AuthenticationMethodPolicy
from .policy import FictionalClient
from .policy import LegacyRecordValidator
from .policy import MaintenanceOperation
from .policy import SignatureRecordValidator
from .policy import TransitionWindow
from .policy import sign_client_assertion

AUTH_METHOD_ORDER = [LEGACY_METHOD, SIGNATURE_METHOD]
FIXED_TIMESTAMP = "1764111600"


class LocalFormRequest(OAuth2Request):
    """OAuth2 request backed by a plain form dictionary."""

    def __init__(self, form: dict[str, Any], uri: str) -> None:
        super().__init__("POST", uri, headers={})
        self._form = dict(form)
        self.payload = BasicOAuth2Payload(self._form)

    @property
    def form(self) -> dict[str, Any]:
        return self._form


@dataclass
class LocalResponse:
    status_code: int
    body: dict[str, Any] | str
    headers: list[tuple[str, str]]


@dataclass
class StoredToken:
    access_token: str
    client_id: str
    scope: str
    auth_method: str
    assurance_tier: str
    privilege: str
    revoked: bool = False
    revocation_method: str | None = None
    revocation_operation: str | None = None

    def check_client(self, client: FictionalClient) -> bool:
        return self.client_id == client.client_id

    def is_revoked(self) -> bool:
        return self.revoked

    def is_expired(self) -> bool:
        return False


class InMemoryState:
    def __init__(self) -> None:
        self.tokens: dict[str, StoredToken] = {}
        self.operations_by_token: dict[str, MaintenanceOperation] = {}
        self.writes: list[dict[str, Any]] = []

    def write(self, kind: str, ref: str, **details: Any) -> dict[str, Any]:
        event = {"seq": len(self.writes) + 1, "kind": kind, "ref": ref, **details}
        self.writes.append(event)
        return event

    def register_operation(
        self,
        operation_id: str,
        token_value: str,
        *,
        legacy_allowed: bool = True,
    ) -> MaintenanceOperation:
        operation = MaintenanceOperation(
            id=operation_id,
            token_value=token_value,
            legacy_allowed=legacy_allowed,
        )
        self.operations_by_token[token_value] = operation
        self.write("maintenance_registered", operation_id, token=token_value)
        return operation


class ConstrainedClientCredentialsGrant(ClientCredentialsGrant):
    policy: AuthenticationMethodPolicy

    def authenticate_token_endpoint_client(self):
        client = super().authenticate_token_endpoint_client()
        self.request.client = client
        decision = self.policy.evaluate_issuance(
            client=client,
            auth_method=self.request.auth_method,
            grant_type=self.GRANT_TYPE,
            scope=self.request.payload.scope,
        )
        self.policy.check(
            decision,
            request=self.request,
            client_id=client.client_id,
            grant_type=self.GRANT_TYPE,
            scope=self.request.payload.scope,
        )
        return client


def make_client_credentials_grant_class(
    policy: AuthenticationMethodPolicy,
    auth_methods: list[str] | None = None,
):
    return type(
        "PolicyClientCredentialsGrant",
        (ConstrainedClientCredentialsGrant,),
        {
            "TOKEN_ENDPOINT_AUTH_METHODS": auth_methods or AUTH_METHOD_ORDER,
            "policy": policy,
        },
    )


def make_revocation_endpoint_class(harness: AuthTransitionHarness):
    class ConstrainedRevocationEndpoint(RevocationEndpoint):
        ENDPOINT_NAME = "revocation"
        CLIENT_AUTH_METHODS = AUTH_METHOD_ORDER

        def query_token(self, token_string: str, token_type_hint: str | None):
            return harness.state.tokens.get(token_string)

        def authenticate_token(self, request, client):
            token = super().authenticate_token(request, client)
            if token is None:
                return None

            operation = harness.state.operations_by_token.get(token.access_token)
            decision = harness.policy.evaluate_maintenance(
                client=client,
                auth_method=request.auth_method,
                operation=operation,
            )
            harness.policy.check(
                decision,
                request=request,
                client_id=client.client_id,
                token=token.access_token,
            )
            request.maintenance_operation = operation
            return token

        def revoke_token(self, token: StoredToken, request) -> None:
            operation = getattr(request, "maintenance_operation", None)
            token.revoked = True
            token.revocation_method = request.auth_method
            token.revocation_operation = operation.id if operation else None
            harness.state.write(
                "token_revoked",
                token.access_token,
                auth_method=request.auth_method,
                operation_id=token.revocation_operation,
            )

            if operation is not None:
                operation.completed = True
                harness.state.write(
                    "maintenance_completed",
                    operation.id,
                    token=token.access_token,
                    auth_method=request.auth_method,
                )

            harness.ledger.record(
                kind="maintenance",
                action="revocation",
                outcome="completed",
                client_id=token.client_id,
                auth_method=request.auth_method,
                assurance_tier=harness.policy_decision_tier(request),
                operation_id=token.revocation_operation,
                token=token.access_token,
            )

    return ConstrainedRevocationEndpoint


class AuthTransitionHarness:
    """Wire a real AuthorizationServer to the migration policy."""

    def __init__(self, *, transition_open: bool = True) -> None:
        self.ledger = ApprovalLedger()
        self.transition = TransitionWindow(open=transition_open)
        self.policy = AuthenticationMethodPolicy(
            transition=self.transition,
            ledger=self.ledger,
        )
        self.client = FictionalClient()
        self.state = InMemoryState()
        self.legacy_validator = LegacyRecordValidator(self.client)
        self.signature_validator = SignatureRecordValidator(self.client)
        self.token_counter = 0

        self.server = AuthorizationServer()
        self.server.query_client = self.query_client
        self.server.save_token = self.save_token
        self.server.create_oauth2_request = lambda request: request
        self.server.handle_response = self.handle_response
        self.server.send_signal = lambda *args, **kwargs: None
        self.server.register_client_auth_method(
            LEGACY_METHOD,
            self.legacy_validator,
        )
        self.server.register_client_auth_method(
            SIGNATURE_METHOD,
            self.signature_validator,
        )

        grant_class = make_client_credentials_grant_class(self.policy)
        self.server.register_grant(grant_class)
        self.server.register_token_generator("default", self.generate_token)
        self.server.register_endpoint(make_revocation_endpoint_class(self))

    def query_client(self, client_id: str) -> FictionalClient:
        if client_id != self.client.client_id:
            from authlib.oauth2.rfc6749.errors import InvalidClientError

            raise InvalidClientError()
        return self.client

    @staticmethod
    def handle_response(status_code, body, headers) -> LocalResponse:
        return LocalResponse(status_code, body, list(headers))

    def policy_decision_tier(self, request) -> str:
        decision = getattr(request, "policy_decision", None)
        if decision is not None:
            return decision.assurance_tier
        return self.policy.evaluate_issuance(
            client=self.client,
            auth_method=getattr(request, "auth_method", None),
            grant_type="client_credentials",
            scope=getattr(request.payload, "scope", None) if request.payload else None,
        ).assurance_tier

    def auth_form(self, auth_method: str) -> dict[str, str]:
        form = {"client_id": self.client.client_id}
        if auth_method == LEGACY_METHOD:
            form["legacy_credential"] = self.client.legacy_secret
        elif auth_method == SIGNATURE_METHOD:
            form["timestamp"] = FIXED_TIMESTAMP
            form["signature"] = sign_client_assertion(
                self.client.client_id,
                FIXED_TIMESTAMP,
                self.client.signing_secret,
            )
        else:
            raise ValueError(f"Unknown auth method: {auth_method}")
        return form

    def generate_token(
        self,
        *,
        grant_type: str,
        client: FictionalClient,
        scope: str | None,
        request: LocalFormRequest,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.token_counter += 1
        return {
            "access_token": f"fictional-access-token-{self.token_counter}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope or "",
        }

    def save_token(self, token: dict[str, Any], request: LocalFormRequest) -> None:
        decision = request.policy_decision
        stored = StoredToken(
            access_token=token["access_token"],
            client_id=request.client.client_id,
            scope=token.get("scope", ""),
            auth_method=request.auth_method,
            assurance_tier=decision.assurance_tier,
            privilege=decision.privilege or NORMAL_PRIVILEGE,
        )
        self.state.tokens[stored.access_token] = stored
        self.state.write(
            "token_saved",
            stored.access_token,
            auth_method=stored.auth_method,
            assurance_tier=stored.assurance_tier,
            privilege=stored.privilege,
        )
        self.ledger.record(
            kind="issuance",
            outcome="issued",
            client_id=stored.client_id,
            auth_method=stored.auth_method,
            assurance_tier=stored.assurance_tier,
            grant_type="client_credentials",
            privilege=stored.privilege,
            token=stored.access_token,
        )

    def issue(
        self,
        auth_method: str,
        *,
        privileged: bool = False,
    ) -> tuple[LocalResponse, LocalFormRequest]:
        form = self.auth_form(auth_method)
        form["grant_type"] = "client_credentials"
        form["scope"] = "admin" if privileged else "read"
        request = LocalFormRequest(form, "https://auth.test/oauth/token")
        response = self.server.create_token_response(request)
        return response, request

    def revoke(
        self,
        token_value: str,
        auth_method: str,
    ) -> tuple[LocalResponse, LocalFormRequest]:
        form = self.auth_form(auth_method)
        form["token"] = token_value
        request = LocalFormRequest(form, "https://auth.test/oauth/revoke")
        response = self.server.create_endpoint_response("revocation", request)
        return response, request

    def register_maintenance(
        self,
        operation_id: str,
        token_value: str,
        *,
        legacy_allowed: bool = True,
    ) -> MaintenanceOperation:
        return self.state.register_operation(
            operation_id,
            token_value,
            legacy_allowed=legacy_allowed,
        )

    def close_transition(self) -> None:
        self.transition.close()


def run_scenario() -> AuthTransitionHarness:
    """Run the requested local issue/privilege/revoke/close sequence."""

    harness = AuthTransitionHarness()

    normal_response, _ = harness.issue(LEGACY_METHOD)
    assert normal_response.status_code == 200

    denied_response, denied_request = harness.issue(LEGACY_METHOD, privileged=True)
    assert denied_response.status_code == 400
    assert denied_response.body == {"error": "unauthorized_client"}
    assert (
        denied_request.policy_decision.reason
        == "signature_method_required_for_privileged_grant"
    )

    privileged_response, _ = harness.issue(SIGNATURE_METHOD, privileged=True)
    assert privileged_response.status_code == 200

    normal_token = normal_response.body["access_token"]
    harness.register_maintenance("maintenance-revoke-normal", normal_token)
    revoke_response, _ = harness.revoke(normal_token, LEGACY_METHOD)
    assert revoke_response.status_code == 200

    harness.close_transition()

    after_close_response, _ = harness.issue(SIGNATURE_METHOD)
    assert after_close_response.status_code == 200
    after_close_token = after_close_response.body["access_token"]
    harness.register_maintenance("maintenance-after-close", after_close_token)

    closed_revoke_response, closed_request = harness.revoke(
        after_close_token,
        LEGACY_METHOD,
    )
    assert closed_revoke_response.status_code == 400
    assert closed_revoke_response.body == {"error": "invalid_client"}
    assert closed_request.policy_decision.reason == "legacy_transition_window_closed"

    return harness
