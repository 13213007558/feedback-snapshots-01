import base64
import threading
import time
import uuid
from dataclasses import dataclass

import pytest
from flask import Flask
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749.errors import InvalidGrantError
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant
from authlib.oauth2.rfc7009 import RevocationEndpoint

CLIENT_ID = "device-client"
CLIENT_SECRET = "fictional-secret"
DEVICE_ID = "device-1"
USER_ID = "user-1"
JWT_KEY = OctKey.import_key("fictional-hmac-secret")


class MemoryClient:
    def get_client_id(self):
        return CLIENT_ID

    def check_client_secret(self, client_secret):
        return client_secret == CLIENT_SECRET

    def check_endpoint_auth_method(self, method, endpoint):
        return method == "client_secret_basic"

    def check_grant_type(self, grant_type):
        return grant_type == "refresh_token"

    def get_allowed_scope(self, scope):
        return scope or "profile"

    def check_redirect_uri(self, redirect_uri):
        return True

    def check_response_type(self, response_type):
        return True


@dataclass
class MemoryToken:
    access_token: str
    refresh_token: str | None
    grant_id: str
    client_id: str = CLIENT_ID
    user_id: str = USER_ID
    scope: str = "profile"
    access_revoked: bool = False
    refresh_revoked: bool = False

    def check_client(self, client):
        return self.client_id == client.get_client_id()

    def get_scope(self):
        return self.scope

    def is_expired(self):
        return False

    def is_revoked(self):
        return self.access_revoked or self.refresh_revoked


@dataclass
class GrantRecord:
    grant_id: str
    device_id: str
    status: str = "active"
    version: int = 0


@dataclass
class PendingRefreshSave:
    token: dict
    grant_id: str
    old_refresh_token: str
    expected_version: int


@dataclass
class LateSave:
    token: dict
    grant_id: str
    reason: str


class InMemoryGrantStore:
    def __init__(self):
        self.lock = threading.RLock()
        self.grants = {}
        self.tokens = []
        self.current_grant_by_device = {}
        self.late_saves = []

    def authorize(self, grant_id, access_token, refresh_token):
        with self.lock:
            self.grants[grant_id] = GrantRecord(grant_id, DEVICE_ID)
            token = MemoryToken(access_token, refresh_token, grant_id)
            self.tokens.append(token)
            self.current_grant_by_device[DEVICE_ID] = grant_id
            return token

    def find(self, token_value, token_type_hint=None):
        with self.lock:
            if token_type_hint == "access_token":
                return next(
                    (
                        token
                        for token in self.tokens
                        if token.access_token == token_value
                    ),
                    None,
                )
            if token_type_hint == "refresh_token":
                return next(
                    (
                        token
                        for token in self.tokens
                        if token.refresh_token == token_value
                    ),
                    None,
                )

            token = next(
                (token for token in self.tokens if token.access_token == token_value),
                None,
            )
            if token:
                return token
            return next(
                (token for token in self.tokens if token.refresh_token == token_value),
                None,
            )

    def active_refresh_token(self, token_value):
        token = self.find(token_value, "refresh_token")
        if not token or token.refresh_revoked:
            return None
        with self.lock:
            grant = self.grants[token.grant_id]
            if grant.status != "active":
                return None
        return token

    def revoke_presented(self, token, presented_value):
        with self.lock:
            token.access_revoked = True
            if presented_value != token.refresh_token:
                return token

            token.refresh_revoked = True
            grant = self.grants[token.grant_id]
            if grant.status == "active":
                grant.status = "revoked"
                grant.version += 1

            for record in self.tokens:
                if record.grant_id == token.grant_id:
                    record.access_revoked = True
                    record.refresh_revoked = True
            return token

    def revoke_rotation(self, token):
        with self.lock:
            token.access_revoked = True
            token.refresh_revoked = True

    def prepare_refresh(self, credential, token):
        with self.lock:
            grant = self.grants[credential.grant_id]
            if grant.status != "active" or credential.refresh_revoked:
                raise InvalidGrantError()
            return PendingRefreshSave(
                token=dict(token),
                grant_id=credential.grant_id,
                old_refresh_token=credential.refresh_token,
                expected_version=grant.version,
            )

    def commit_refresh(self, pending):
        with self.lock:
            grant = self.grants[pending.grant_id]
            old_token = self.find(pending.old_refresh_token, "refresh_token")
            fenced = (
                grant.status == "active"
                and grant.version == pending.expected_version
                and old_token is not None
                and not old_token.refresh_revoked
            )
            if not fenced:
                self.late_saves.append(
                    LateSave(
                        token=pending.token,
                        grant_id=pending.grant_id,
                        reason="grant-generation-revoked",
                    )
                )
                raise InvalidGrantError()

            new_token = MemoryToken(
                access_token=pending.token["access_token"],
                refresh_token=pending.token.get("refresh_token"),
                grant_id=pending.grant_id,
                scope=pending.token.get("scope", "profile"),
            )
            self.tokens.append(new_token)
            old_token.access_revoked = True
            old_token.refresh_revoked = True
            return new_token


def basic_headers():
    value = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    return {"Authorization": f"Basic {value}"}


def make_access_token(grant_id, token_format):
    if token_format == "jwt":
        now = int(time.time())
        claims = {
            "iss": "https://memory-as.test",
            "sub": USER_ID,
            "client_id": CLIENT_ID,
            "scope": "profile",
            "grant_id": grant_id,
            "iat": now,
            "exp": now + 3600,
            "jti": f"jti-{uuid.uuid4().hex}",
        }
        return jwt.encode({"alg": "HS256", "typ": "at+jwt"}, claims, JWT_KEY)
    return f"opaque-{grant_id}-{uuid.uuid4().hex}"


def build_app(token_format, store, save_entered=None, release_save=None):
    app = Flask(__name__)
    app.testing = True

    client = MemoryClient()

    def query_client(client_id):
        return client if client_id == CLIENT_ID else None

    def token_generator(
        client,
        grant_type,
        user=None,
        scope=None,
        expires_in=None,
        include_refresh_token=True,
        request=None,
    ):
        grant_id = request.refresh_token.grant_id
        token = {
            "token_type": "Bearer",
            "access_token": make_access_token(grant_id, token_format),
            "expires_in": 3600,
            "scope": scope or "profile",
        }
        if include_refresh_token:
            token["refresh_token"] = f"refresh-{grant_id}-{uuid.uuid4().hex}"
        return token

    def save_token(token, request):
        pending = store.prepare_refresh(request.refresh_token, token)
        if save_entered is not None:
            save_entered.set()
            assert release_save.wait(5)
        return store.commit_refresh(pending)

    server = AuthorizationServer(app, query_client, save_token)
    server.register_token_generator("default", token_generator)

    class MemoryRefreshTokenGrant(RefreshTokenGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic"]
        INCLUDE_NEW_REFRESH_TOKEN = True

        def authenticate_refresh_token(self, refresh_token):
            return store.active_refresh_token(refresh_token)

        def authenticate_user(self, credential):
            return credential.user_id

        def revoke_old_credential(self, credential):
            store.revoke_rotation(credential)

    server.register_grant(MemoryRefreshTokenGrant)

    class MemoryRevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint):
            return store.find(token, token_type_hint)

        def revoke_token(self, token, request):
            store.revoke_presented(token, request.form["token"])

    server.register_endpoint(MemoryRevocationEndpoint)

    @app.post("/oauth/token")
    def issue_token():
        return server.create_token_response()

    @app.post("/oauth/revoke")
    def revoke_token():
        return server.create_endpoint_response("revocation")

    return app, server


@pytest.mark.parametrize("token_format", ["opaque", "jwt"])
def test_late_refresh_save_cannot_publish_after_revocation(token_format):
    store = InMemoryGrantStore()
    store.authorize(
        "grant-old",
        make_access_token("grant-old", token_format),
        "old-refresh-token",
    )

    save_entered = threading.Event()
    release_save = threading.Event()
    app, _ = build_app(token_format, store, save_entered, release_save)

    old_response = {}

    def run_old_refresh():
        try:
            response = app.test_client().post(
                "/oauth/token",
                headers=basic_headers(),
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": "old-refresh-token",
                },
            )
            old_response["status_code"] = response.status_code
            old_response["body"] = response.get_json()
        except BaseException as exc:  # pragma: no cover - failure diagnostics
            old_response["error"] = exc

    worker = threading.Thread(target=run_old_refresh)
    worker.start()
    assert save_entered.wait(5)

    revocation_client = app.test_client()
    first_revocation = revocation_client.post(
        "/oauth/revoke",
        headers=basic_headers(),
        data={"token": "old-refresh-token"},
    )

    store.authorize(
        "grant-new",
        make_access_token("grant-new", token_format),
        "new-refresh-token",
    )

    repeated_revocation = revocation_client.post(
        "/oauth/revoke",
        headers=basic_headers(),
        data={"token": "old-refresh-token"},
    )

    release_save.set()
    worker.join(5)
    assert not worker.is_alive()
    if "error" in old_response:
        raise old_response["error"]

    assert first_revocation.status_code == 200
    assert repeated_revocation.status_code == 200
    assert first_revocation.get_json() == {}
    assert repeated_revocation.get_json() == {}

    assert old_response["status_code"] == 400
    assert old_response["body"]["error"] == "invalid_grant"
    assert "access_token" not in old_response["body"]

    old_grant = store.grants["grant-old"]
    new_grant = store.grants["grant-new"]
    assert old_grant.status == "revoked"
    assert old_grant.version == 1
    assert new_grant.status == "active"
    assert new_grant.version == 0
    assert store.current_grant_by_device[DEVICE_ID] == "grant-new"

    old_token = store.find("old-refresh-token", "refresh_token")
    assert old_token.refresh_revoked is True
    assert old_token.access_revoked is True
    new_token = store.find("new-refresh-token", "refresh_token")
    assert new_token.refresh_revoked is False
    assert new_token.access_revoked is False

    assert len(store.late_saves) == 1
    late_save = store.late_saves[0]
    assert late_save.grant_id == "grant-old"
    assert late_save.reason == "grant-generation-revoked"
    assert store.find(late_save.token["access_token"], "access_token") is None
    if token_format == "jwt":
        claims = jwt.decode(late_save.token["access_token"], JWT_KEY).claims
        assert claims["grant_id"] == "grant-old"

    refresh_response = app.test_client().post(
        "/oauth/token",
        headers=basic_headers(),
        data={
            "grant_type": "refresh_token",
            "refresh_token": "new-refresh-token",
        },
    )
    assert refresh_response.status_code == 200
    body = refresh_response.get_json()

    access_record = store.find(body["access_token"], "access_token")
    refresh_record = store.find(body["refresh_token"], "refresh_token")
    assert access_record.grant_id == "grant-new"
    assert refresh_record.grant_id == "grant-new"
    assert access_record.access_token == body["access_token"]
    assert store.grants["grant-new"].status == "active"
    assert store.find("new-refresh-token", "refresh_token").refresh_revoked is True

    if token_format == "jwt":
        claims = jwt.decode(body["access_token"], JWT_KEY).claims
        assert claims["grant_id"] == "grant-new"
    else:
        assert body["access_token"].startswith("opaque-grant-new-")


def test_refresh_creation_revalidates_after_validation():
    store = InMemoryGrantStore()
    store.authorize(
        "grant-old",
        make_access_token("grant-old", "opaque"),
        "old-refresh-token",
    )
    app, server = build_app("opaque", store)
    save_calls = []

    def forbidden_save(token, request):
        save_calls.append(token)

    server._save_token = forbidden_save

    with app.test_request_context(
        "/oauth/token",
        method="POST",
        headers=basic_headers(),
        data={
            "grant_type": "refresh_token",
            "refresh_token": "old-refresh-token",
        },
    ):
        request = server.create_oauth2_request(None)
        grant = server.get_token_grant(request)
        grant.validate_token_request()

        store.revoke_presented(
            store.find("old-refresh-token", "refresh_token"),
            "old-refresh-token",
        )

        with pytest.raises(InvalidGrantError):
            grant.create_token_response()

    assert store.grants["grant-old"].status == "revoked"
    assert save_calls == []
    assert len(store.tokens) == 1
