"""Runnable narrative of the DCR capability verification chain.

Run from the repository root:

    .venv/bin/python -m examples.dcr_capability_chain.demo

It uses Flask's in-process test client (no socket, no port) and prints, for
every step, which layer decided and what the client saw.
"""

import json

from .app import create_app
from .models import Client
from .policy import Policy


def line(title=""):
    print("\n" + "=" * 72)
    if title:
        print(title)
        print("-" * 72)


def show(label, response):
    body = response.get_json()
    print(f"[{label}] HTTP {response.status_code}")
    print(json.dumps(body, indent=2, ensure_ascii=False))
    if "WWW-Authenticate" in response.headers:
        print("WWW-Authenticate:", response.headers["WWW-Authenticate"])
    return body


def register(http, token, body):
    return http.post(
        "/register",
        json=body,
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


def main():
    policy = Policy()
    app, db, server = create_app(policy=policy)
    http = app.test_client()

    line("LAYER 0 - Discovery (RFC 8414): server ceiling, not per-partner rights")
    show("discovery", http.get("/.well-known/oauth-authorization-server"))

    # ------------------------------------------------------------------
    line("RECORD A - Standard partner registration (approved: code/refresh, read)")
    std_body = {
        "client_name": "Standard Partner SPA",
        "redirect_uris": ["https://std.example.com/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "openid profile orders:read",
        "token_endpoint_auth_method": "client_secret_basic",
    }
    std = show(
        "register standard (all requested -> approved)",
        register(http, "iat-standard-001", std_body),
    )

    line("RECORD B - Premium partner registration (also client_credentials + write)")
    prem_body = {
        "client_name": "Premium Partner Service",
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
    prem = show(
        "register premium (all requested -> approved)",
        register(http, "iat-premium-001", prem_body),
    )

    # ------------------------------------------------------------------
    line("REJECT 1 - Standard partner asks for client_credentials at registration")
    overreach = dict(std_body)
    overreach["grant_types"] = ["authorization_code", "client_credentials"]
    show(
        "register standard with unapproved grant",
        register(http, "iat-standard-001", overreach),
    )

    line("REJECT 2 - Unknown scope value is invalid even for a premium partner")
    bad_scope = dict(prem_body)
    bad_scope["scope"] = "openid admin:root"
    show(
        "register premium with unknown scope",
        register(http, "iat-premium-001", bad_scope),
    )

    line("REJECT 3 - No / bogus initial access token -> RFC 6750 401")
    show("register without token", register(http, None, std_body))
    show("register with bad token", register(http, "iat-does-not-exist", std_body))

    # ------------------------------------------------------------------
    line("GRANT LAYER - Premium client mints a client_credentials token")
    tok_ok = http.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "scope": "orders:read orders:write",
        },
        headers={
            "Authorization": "Basic " + _basic(prem["client_id"], prem["client_secret"])
        },
    )
    show("premium token (both scopes granted)", tok_ok)

    line("GRANT LAYER - Scope clamping: request a scope the client was not given")
    tok_clamp = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:write email"},
        headers={
            "Authorization": "Basic " + _basic(prem["client_id"], prem["client_secret"])
        },
    )
    show("premium token (email silently filtered)", tok_clamp)

    line("GRANT LAYER - Standard client cannot use client_credentials")
    tok_deny = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:read"},
        headers={
            "Authorization": "Basic " + _basic(std["client_id"], std["client_secret"])
        },
    )
    show("standard token -> unauthorized_client", tok_deny)

    # ------------------------------------------------------------------
    line("EXPANSION - Standard partner applies for a wider capability (RFC 7592)")
    rat = std["registration_access_token"]
    uri = std["registration_client_uri"].replace("https://as.example.test", "")
    widen_body = {
        "client_id": std["client_id"],
        "client_name": "Standard Partner SPA",
        "redirect_uris": ["https://std.example.com/cb"],
        "grant_types": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "response_types": ["code"],
        "scope": "openid profile orders:read orders:write",
        "token_endpoint_auth_method": "client_secret_basic",
    }
    show(
        "PUT before approval -> invalid_client_metadata",
        http.put(uri, json=widen_body, headers={"Authorization": f"Bearer {rat}"}),
    )

    print("\n-- Operator widens the partner approval record --")
    policy.widen(
        "partner-standard",
        grant_types=["client_credentials"],
        scopes=["orders:write"],
    )
    print("policy now:", json.dumps(policy.get("partner-standard"), ensure_ascii=False))

    show(
        "PUT after approval -> 200, capabilities widened",
        http.put(uri, json=widen_body, headers={"Authorization": f"Bearer {rat}"}),
    )
    tok_after = http.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "scope": "orders:write"},
        headers={
            "Authorization": "Basic " + _basic(std["client_id"], std["client_secret"])
        },
    )
    show("standard token after widening -> granted", tok_after)

    # ------------------------------------------------------------------
    line("TIGHTENING - Existing client smoothly reined in via policy only")
    # A legacy client stored with a broad snapshot from before the tightening.
    legacy = Client(
        client_id="cid-legacy",
        client_secret="sec-legacy",
        partner_id="partner-standard",
        metadata={
            "client_name": "Legacy Client",
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
    # Baseline policy mirrors what the partner was approved for when the legacy
    # client was first onboarded: the machine grant and write were still allowed.
    baseline = Policy()
    baseline.widen(
        "partner-standard",
        grant_types=["client_credentials"],
        scopes=["orders:write"],
    )
    app2, db2, _ = create_app(policy=baseline, legacy_client=legacy)
    http2 = app2.test_client()

    print("\n-- Before tightening: legacy snapshot includes client_credentials --")
    show(
        "legacy token before tightening",
        http2.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "orders:write"},
            headers={"Authorization": "Basic " + _basic("cid-legacy", "sec-legacy")},
        ),
    )

    print("\n-- Operator removes client_credentials + orders:write for the partner --")
    rec = db2.policy.get("partner-standard")
    rec["grant_types"] = ["authorization_code", "refresh_token"]
    rec["scopes"] = ["openid", "profile", "email", "orders:read"]
    print("policy now:", json.dumps(rec, ensure_ascii=False))
    print("(client row is untouched; check_grant_type reads the live policy)")

    show(
        "legacy token after tightening -> unauthorized_client",
        http2.post(
            "/oauth/token",
            data={"grant_type": "client_credentials", "scope": "orders:write"},
            headers={"Authorization": "Basic " + _basic("cid-legacy", "sec-legacy")},
        ),
    )
    # Authorization-code grant still allowed, but write scope is now filtered.
    row = db2.session.query(Client).filter_by(client_id="cid-legacy").one()
    print(
        "check_grant_type('authorization_code') =",
        row.check_grant_type("authorization_code"),
    )
    print(
        "get_allowed_scope('openid orders:write') =",
        repr(row.get_allowed_scope("openid orders:write")),
    )

    line("DONE")


def _basic(client_id, secret):
    import base64

    raw = f"{client_id}:{secret}".encode()
    return base64.b64encode(raw).decode()


if __name__ == "__main__":
    main()
