"""Verification evidence for the DCR capability chain.

These assertions pin every decision shown in demo.py to a layer and an RFC
error code. Run with the repository test runner or directly:

    .venv/bin/pytest examples/dcr_capability_chain/test_chain.py -q
"""

import base64

import pytest

from examples.dcr_capability_chain.app import create_app
from examples.dcr_capability_chain.models import Client
from examples.dcr_capability_chain.policy import Policy


def _basic(client_id, secret):
    raw = f"{client_id}:{secret}".encode()
    return base64.b64encode(raw).decode()


def _register(http, token, body):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return http.post("/register", json=body, headers=headers)


STANDARD_BODY = {
    "client_name": "Standard",
    "redirect_uris": ["https://std.example.com/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile orders:read",
    "token_endpoint_auth_method": "client_secret_basic",
}
PREMIUM_BODY = {
    "client_name": "Premium",
    "redirect_uris": ["https://prem.example.com/cb"],
    "grant_types": [
        "authorization_code",
        "refresh_token",
        "client_credentials",
    ],
    "response_types": ["code"],
    "scope": "openid orders:read orders:write",
    "token_endpoint_auth_method": "client_secret_basic",
}


@pytest.fixture()
def ctx():
    policy = Policy()
    app, db, _ = create_app(policy=policy)
    return policy, db, app.test_client()


# --- Layer 0: discovery ----------------------------------------------------
def test_discovery_advertises_server_ceiling_only(ctx):
    _, _, http = ctx
    meta = http.get("/.well-known/oauth-authorization-server").get_json()
    assert "client_credentials" in meta["grant_types_supported"]
    assert meta["registration_endpoint"] == "https://as.example.test/register"
    # Per-partner entitlements are intentionally not in discovery.
    assert "partner-standard" not in meta


# --- Two distinct approval records -----------------------------------------
def test_standard_partner_registered_within_approval(ctx):
    _, _, http = ctx
    resp = _register(http, "iat-standard-001", STANDARD_BODY)
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    assert body["scope"].split() == sorted(["openid", "profile", "orders:read"])
    assert "registration_access_token" in body  # RFC 7592 management token


def test_premium_partner_gets_machine_grant_and_write(ctx):
    _, _, http = ctx
    body = _register(http, "iat-premium-001", PREMIUM_BODY).get_json()
    assert "client_credentials" in body["grant_types"]
    assert "orders:write" in body["scope"].split()


# --- Rejection feedback ----------------------------------------------------
def test_unapproved_grant_rejected_as_invalid_client_metadata(ctx):
    _, _, http = ctx
    overreach = dict(STANDARD_BODY)
    overreach["grant_types"] = ["authorization_code", "client_credentials"]
    resp = _register(http, "iat-standard-001", overreach)
    assert resp.status_code == 400
    err = resp.get_json()
    assert err["error"] == "invalid_client_metadata"
    assert "grant_types" in err["error_description"]


def test_unknown_scope_rejected_by_claims_layer(ctx):
    _, _, http = ctx
    bad = dict(PREMIUM_BODY, scope="openid admin:root")
    resp = _register(http, "iat-premium-001", bad)
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_client_metadata"


def test_missing_and_bogus_initial_access_token_are_401(ctx):
    _, _, http = ctx
    no_token = _register(http, None, STANDARD_BODY)
    assert no_token.status_code == 401
    assert "error" not in no_token.get_json()  # RFC 6750: no code, no auth header
    assert no_token.headers["WWW-Authenticate"] == "Bearer"

    bad_token = _register(http, "iat-unknown", STANDARD_BODY)
    assert bad_token.status_code == 401
    assert bad_token.get_json()["error"] == "invalid_token"


# --- Grant layer enforcement -----------------------------------------------
def _premium_client(http):
    return _register(http, "iat-premium-001", PREMIUM_BODY).get_json()


def test_premium_grant_issues_requested_scopes(ctx):
    _, _, http = ctx
    client = _premium_client(http)
    resp = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:write"},
        headers={
            "Authorization": "Basic "
            + _basic(client["client_id"], client["client_secret"])
        },
    )
    assert resp.status_code == 200
    assert resp.get_json()["scope"] == "orders:write"


def test_grant_layer_clamps_unentitled_scope(ctx):
    _, _, http = ctx
    client = _premium_client(http)
    resp = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:write email"},
        headers={
            "Authorization": "Basic "
            + _basic(client["client_id"], client["client_secret"])
        },
    )
    # email is a server-supported scope but not on this client's record, so it
    # is filtered rather than producing an error.
    assert resp.status_code == 200
    assert resp.get_json()["scope"] == "orders:write"


def test_grant_layer_rejects_unknown_scope_as_invalid_scope(ctx):
    _, _, http = ctx
    client = _premium_client(http)
    resp = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "admin:root"},
        headers={
            "Authorization": "Basic "
            + _basic(client["client_id"], client["client_secret"])
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_scope"


def test_standard_client_denied_client_credentials_grant(ctx):
    _, _, http = ctx
    client = _register(http, "iat-standard-001", STANDARD_BODY).get_json()
    resp = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:read"},
        headers={
            "Authorization": "Basic "
            + _basic(client["client_id"], client["client_secret"])
        },
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "unauthorized_client"


# --- Expansion request (RFC 7592) ------------------------------------------
def test_expansion_denied_then_allowed_after_policy_widening(ctx):
    policy, _, http = ctx
    client = _register(http, "iat-standard-001", STANDARD_BODY).get_json()
    rat = client["registration_access_token"]
    uri = client["registration_client_uri"].replace("https://as.example.test", "")
    widened = dict(
        STANDARD_BODY,
        client_id=client["client_id"],
        grant_types=[
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        scope="openid profile orders:read orders:write",
    )

    before = http.put(uri, json=widened, headers={"Authorization": f"Bearer {rat}"})
    assert before.status_code == 400
    assert before.get_json()["error"] == "invalid_client_metadata"

    policy.widen(
        "partner-standard",
        grant_types=["client_credentials"],
        scopes=["orders:write"],
    )
    after = http.put(uri, json=widened, headers={"Authorization": f"Bearer {rat}"})
    assert after.status_code == 200
    assert "client_credentials" in after.get_json()["grant_types"]


# --- Smooth tightening of an existing client -------------------------------
def test_tightening_takes_effect_without_touching_client_row():
    baseline = Policy()
    baseline.widen(
        "partner-standard",
        grant_types=["client_credentials"],
        scopes=["orders:write"],
    )
    legacy = Client(
        client_id="cid-legacy",
        client_secret="sec-legacy",
        partner_id="partner-standard",
        metadata={
            "grant_types": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "scope": "openid orders:read orders:write",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "redirect_uris": ["https://legacy.example.com/cb"],
        },
    )
    app, db, _ = create_app(policy=baseline, legacy_client=legacy)
    http = app.test_client()
    auth = {"Authorization": "Basic " + _basic("cid-legacy", "sec-legacy")}

    before = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:write"},
        headers=auth,
    )
    assert before.status_code == 200

    record = db.policy.get("partner-standard")
    record["grant_types"] = ["authorization_code", "refresh_token"]
    record["scopes"] = ["openid", "profile", "email", "orders:read"]

    after = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:write"},
        headers=auth,
    )
    assert after.status_code == 400
    assert after.get_json()["error"] == "unauthorized_client"

    row = db.session.query(Client).filter_by(client_id="cid-legacy").one()
    # The stored snapshot still lists the grant; enforcement is policy-driven.
    assert "client_credentials" in row.client_metadata["grant_types"]
    assert row.check_grant_type("authorization_code") is True
    assert row.check_grant_type("client_credentials") is False
    assert row.get_allowed_scope("openid orders:write") == "openid"
