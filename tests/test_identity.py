"""Tests for distinguishable missing identity results in rate limit key functions."""

from __future__ import annotations

import logging

import hiro
import pytest
from flask import Blueprint, Flask, jsonify, request
from limits.errors import ConfigurationError

from flask_limiter import (
    AnonymousIdentityRejected,
    Limiter,
    MissingIdentity,
    MissingIdentityPolicy,
    UnconfirmedIdentityRejected,
)
from flask_limiter.constants import ConfigVars
from flask_limiter.util import get_remote_address


class IdentityService:
    """
    Stand in for the external identity lookup used by the application.

    The service is deliberately a single lookup per request: the key function
    calls :meth:`lookup` and the extension caches the result for the request.
    """

    def __init__(self) -> None:
        self.available = True
        self.calls = 0

    def lookup(self) -> str | MissingIdentity:
        self.calls += 1

        if not self.available:
            return MissingIdentity.UNCONFIRMED

        username = request.headers.get("X-User")

        if not username:
            return MissingIdentity.ANONYMOUS

        return username


def make_app(extension_factory, **limiter_kwargs):
    service = IdentityService()
    app, limiter = extension_factory(key_func=service.lookup, **limiter_kwargs)

    return app, limiter, service


def test_anonymous_tracked_in_its_own_bucket(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["2/minute"])

    @app.route("/public")
    @limiter.missing_identity_policy(
        {MissingIdentity.ANONYMOUS: "track", MissingIdentity.UNCONFIRMED: "track"}
    )
    def public():
        return jsonify(keys=[limit.key for limit in limiter.current_limits])

    @app.route("/private")
    def private():
        return "private"

    with app.test_client() as client:
        response = client.get("/public")
        assert response.status_code == 200
        anonymous_key = response.json["keys"][0]
        assert "anonymous" in anonymous_key
        # the anonymous bucket is reserved and can never be an account name
        assert "alice" not in anonymous_key

        assert client.get("/public").status_code == 200
        assert client.get("/public").status_code == 429
        # an authenticated account is not affected by the anonymous bucket
        assert client.get("/public", headers={"X-User": "alice"}).status_code == 200
        assert client.get("/private", headers={"X-User": "alice"}).status_code == 200


def test_unconfirmed_not_charged_to_another_account(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["1/minute"])

    @app.route("/resource")
    @limiter.missing_identity_policy("track")
    def resource():
        return jsonify(keys=[limit.key for limit in limiter.current_limits])

    with app.test_client() as client:
        # alice has her own confirmed bucket and uses up its single hit
        alice = client.get("/resource", headers={"X-User": "alice"})
        assert alice.status_code == 200
        assert "alice" in alice.json["keys"][0]

        # the identity service becomes unavailable: the request must not be
        # attributed to alice nor blocked by her exhausted bucket
        service.available = False
        unconfirmed = client.get("/resource", headers={"X-User": "alice"})
        assert unconfirmed.status_code == 200
        unconfirmed_key = unconfirmed.json["keys"][0]
        assert "alice" not in unconfirmed_key
        assert "unconfirmed" in unconfirmed_key

        # the unconfirmed bucket is itself limited in isolation
        blocked = client.get("/resource", headers={"X-User": "alice"})
        assert blocked.status_code == 429


def test_endpoint_policy_applies_to_default_limits(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["10/minute"])

    @app.route("/profile")
    @limiter.missing_identity_policy("reject")
    def profile():
        return jsonify(limits=[limit.limit.amount for limit in limiter.current_limits])

    @app.route("/feed")
    @limiter.missing_identity_policy(
        {MissingIdentity.ANONYMOUS: "skip", MissingIdentity.UNCONFIRMED: "reject"}
    )
    def feed():
        return "feed"

    with app.test_client() as client:
        # genuinely anonymous: allowed on the public feed, rejected on profile
        assert client.get("/feed").status_code == 200
        assert client.get("/profile").status_code == 401

        # authenticated requests pass on both and are evaluated against the
        # default 10/minute limit, not some other endpoint's limit
        assert client.get("/feed", headers={"X-User": "alice"}).status_code == 200
        profile_response = client.get("/profile", headers={"X-User": "alice"})
        assert profile_response.status_code == 200
        assert profile_response.json["limits"] == [10]

        # identity service unavailable: rejected wherever policy is reject
        service.available = False
        assert client.get("/profile").status_code == 503
        assert client.get("/feed").status_code == 503


def test_decorated_and_default_limits_share_one_lookup(extension_factory):
    app, limiter, service = make_app(
        extension_factory, default_limits=["100/minute"], missing_identity_policy="track"
    )

    @app.route("/")
    @limiter.limit("5/minute", override_defaults=False)
    def root():
        return jsonify(
            [
                {"amount": limit.limit.amount, "key": limit.key}
                for limit in limiter.current_limits
            ]
        )

    with app.test_client() as client:
        service.available = False
        response = client.get("/", headers={"X-User": "alice"})
        assert response.status_code == 200
        # both the decorated and the inherited default limit are evaluated
        # against the same reserved unconfirmed bucket, in a single lookup
        assert service.calls == 1
        assert {entry["amount"] for entry in response.json} == {5, 100}
        assert all("unconfirmed" in entry["key"] for entry in response.json)
        assert all("alice" not in entry["key"] for entry in response.json)


def test_rejections_are_typed(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["10/minute"])

    @app.route("/profile")
    @limiter.missing_identity_policy("reject")
    def profile():
        return "profile"

    with app.test_request_context("/profile"):
        with pytest.raises(AnonymousIdentityRejected):
            limiter._Limiter__evaluate_limits(
                "profile", limiter.limit_manager.default_limits
            )

    service.available = False
    with app.test_request_context("/profile"):
        with pytest.raises(UnconfirmedIdentityRejected):
            limiter._Limiter__evaluate_limits(
                "profile", limiter.limit_manager.default_limits
            )


def test_extension_default_policy_and_endpoint_override(extension_factory):
    app, limiter, service = make_app(
        extension_factory,
        default_limits=["10/minute"],
        missing_identity_policy="reject",
    )

    @app.route("/override")
    @limiter.missing_identity_policy({MissingIdentity.ANONYMOUS: "skip"})
    def override():
        return "ok"

    @app.route("/inherits")
    def inherits():
        return "ok"

    with app.test_client() as client:
        assert client.get("/override").status_code == 200
        assert client.get("/inherits").status_code == 401
        # the unconfirmed reason was not configured by the endpoint, so the
        # extension default (reject) still applies
        service.available = False
        assert client.get("/override").status_code == 503


def test_extension_policy_from_config(extension_factory):
    app, limiter, service = make_app(
        extension_factory,
        config={
            ConfigVars.DEFAULT_LIMITS: "10/minute",
            ConfigVars.MISSING_IDENTITY_POLICY: {
                "anonymous": "skip",
                "unconfirmed": "reject",
            },
        },
    )

    @app.route("/")
    def root():
        return "ok"

    with app.test_client() as client:
        assert client.get("/").status_code == 200
        service.available = False
        assert client.get("/").status_code == 503


def test_blueprint_policy(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["10/minute"])
    admin = Blueprint("admin", __name__, url_prefix="/admin")

    @admin.route("/")
    def index():
        return "admin"

    limiter.missing_identity_policy(admin, "reject")
    app.register_blueprint(admin)

    with app.test_client() as client:
        assert client.get("/admin/").status_code == 401
        assert client.get("/admin/", headers={"X-User": "alice"}).status_code == 200


def test_nested_blueprint_policy_inherits_and_overrides(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["10/minute"])
    parent = Blueprint("parent", __name__, url_prefix="/parent")
    child = Blueprint("child", __name__, url_prefix="/child")
    public = Blueprint("public", __name__, url_prefix="/public")

    @child.route("/")
    def child_index():
        return "child"

    @public.route("/")
    def public_index():
        return "public"

    limiter.missing_identity_policy(parent, "reject")
    limiter.missing_identity_policy(
        public, {MissingIdentity.ANONYMOUS: "skip", MissingIdentity.UNCONFIRMED: "reject"}
    )
    parent.register_blueprint(child)
    parent.register_blueprint(public)
    app.register_blueprint(parent)

    with app.test_client() as client:
        # inherits the parent policy
        assert client.get("/parent/child/").status_code == 401
        # explicitly overrides anonymous handling while inheriting the parent's
        # unconfirmed handling
        assert client.get("/parent/public/").status_code == 200
        service.available = False
        assert client.get("/parent/public/").status_code == 503


def test_single_identity_lookup_per_request(extension_factory):
    app, limiter, service = make_app(
        extension_factory,
        default_limits=["10/minute", "100/hour"],
        meta_limits=["1000/day"],
    )

    @app.route("/")
    @limiter.limit("5/minute", missing_identity_policy="track")
    def root():
        return "ok"

    with app.test_client() as client:
        assert client.get("/", headers={"X-User": "alice"}).status_code == 200
        assert service.calls == 1
        assert client.get("/").status_code == 200
        assert service.calls == 2


def test_plain_falsy_results_still_skip(extension_factory):
    app, limiter = extension_factory(default_limits=["1/minute"], key_func=lambda: None)

    @app.route("/")
    def root():
        return "ok"

    with app.test_client() as client:
        for _ in range(5):
            assert client.get("/").status_code == 200


def test_empty_string_is_logged_and_skipped(extension_factory, caplog):
    caplog.set_level(logging.ERROR)
    app, limiter = extension_factory(default_limits=["1/minute"], key_func=lambda: "")

    @app.route("/")
    def root():
        return "ok"

    with app.test_client() as client:
        for _ in range(3):
            assert client.get("/").status_code == 200

    assert any("Empty value found in parameters" in record.message for record in caplog.records)


def test_invalid_policy_is_rejected(extension_factory):
    app, limiter, service = make_app(extension_factory)

    with pytest.raises(ConfigurationError):
        limiter.missing_identity_policy("fubar")

    with pytest.raises(ConfigurationError):
        limiter.limit("1/minute", missing_identity_policy={"mystery": "skip"})


def test_direct_limit_policy_is_used_without_endpoint_config(extension_factory):
    app, limiter, service = make_app(extension_factory)

    @app.route("/")
    @limiter.limit("10/minute", missing_identity_policy="reject")
    def root():
        return "ok"

    with app.test_client() as client:
        assert client.get("/").status_code == 401
        assert client.get("/", headers={"X-User": "alice"}).status_code == 200


def test_track_buckets_do_not_share_across_reasons(extension_factory):
    app, limiter, service = make_app(extension_factory, default_limits=["1/minute"])

    @app.route("/")
    @limiter.missing_identity_policy("track")
    def root():
        return jsonify(keys=[limit.key for limit in limiter.current_limits])

    with app.test_client() as client:
        anonymous = client.get("/").json["keys"][0]
        service.available = False
        unconfirmed = client.get("/").json["keys"][0]

    assert anonymous != unconfirmed
    assert "anonymous" in anonymous
    assert "unconfirmed" in unconfirmed
