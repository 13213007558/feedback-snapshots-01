"""Tests for how meta limits are charged when a request breaches multiple rules."""

from __future__ import annotations

import hiro
import pytest
from flask import Flask, make_response
from limits.errors import ConfigurationError

from flask_limiter import ExemptionScope, Limiter, MetaLimit
from flask_limiter.constants import ConfigVars
from flask_limiter.util import get_remote_address


def build_app(
    count_by: str | None = None,
    *,
    fail_on_first_breach: bool = True,
    meta_limits: list | None = None,
    config: dict | None = None,
):
    app = Flask(__name__)

    for key, value in (config or {}).items():
        app.config[key] = value

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        meta_limits=(
            meta_limits if meta_limits is not None else [MetaLimit("2/day", count_by=count_by)]
        ),
        fail_on_first_breach=fail_on_first_breach,
        on_meta_breach=lambda _: make_response("meta", 429),
    )

    @app.route("/multi")
    @limiter.limit("1/second")
    @limiter.limit("1/minute")
    def multi():
        return "ok"

    @app.route("/exempt")
    @limiter.exempt(flags=ExemptionScope.META)
    def exempt():
        return "exempt"

    return app, limiter


def responses(client, path="/multi", count=5):
    return [client.get(path) for _ in range(count)]


def classify(response) -> str:
    if response.status_code == 200:
        return "ok"
    if response.data == b"meta":
        return "meta"

    return "limit"


@pytest.mark.parametrize(
    ("count_by", "expected"),
    [
        ("request", ["ok", "limit", "limit", "meta", "meta"]),
        ("rule", ["ok", "limit", "meta", "meta", "meta"]),
    ],
)
def test_count_by_request_vs_rule(count_by, expected):
    app, _ = build_app(count_by)

    with hiro.Timeline().freeze():
        with app.test_client() as client:
            results = responses(client)

    assert [response.status_code for response in results] == [
        200,
        429,
        429,
        429,
        429,
    ]
    assert [classify(response) for response in results] == expected
    assert b"1 per 1 second" in results[1].data


@pytest.mark.parametrize(
    ("count_by", "expected"),
    [
        ("request", ["ok", "limit", "limit", "meta", "meta"]),
        ("rule", ["ok", "limit", "meta", "meta", "meta"]),
    ],
)
@pytest.mark.parametrize("fail_on_first_breach", [True, False])
def test_meta_breach_independent_of_fail_on_first_breach(count_by, expected, fail_on_first_breach):
    app, _ = build_app(count_by, fail_on_first_breach=fail_on_first_breach)

    with hiro.Timeline().freeze():
        with app.test_client() as client:
            results = responses(client)

    assert [classify(response) for response in results] == expected


def test_shared_scope_breach_charges_meta_once_per_request():
    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        meta_limits=[MetaLimit("1/day", count_by="request")],
        on_meta_breach=lambda _: make_response("meta", 429),
    )
    shared = limiter.shared_limit("1/minute", scope="projects")

    @app.route("/p1")
    @shared
    def p1():
        return "p1"

    @app.route("/p2")
    @shared
    def p2():
        return "p2"

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as client:
            assert client.get("/p1").status_code == 200
            # The same shared bucket is breached from a different route, but a request
            # is only charged once under ``count_by="request"``.
            assert client.get("/p2").data != b"meta"
            # The single meta unit is now exhausted.
            assert client.get("/p2").data == b"meta"
            timeline.forward(60)
            assert client.get("/p1").data == b"meta"


def test_meta_exempt_route_is_not_charged():
    app, _ = build_app("rule")

    with hiro.Timeline().freeze():
        with app.test_client() as client:
            assert client.get("/multi").status_code == 200
            assert client.get("/multi").data != b"meta"
            for _ in range(3):
                assert client.get("/multi").data == b"meta"
            assert client.get("/exempt").status_code == 200
            # The exempt route neither reads nor resets the meta budget.
            assert client.get("/multi").data == b"meta"


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("rule", ["ok", "limit", "meta", "meta", "meta"]),
        ("request", ["ok", "limit", "limit", "meta", "meta"]),
    ],
)
def test_count_by_from_config(configured, expected):
    app, limiter = build_app(
        meta_limits=[MetaLimit("2/day")],
        config={ConfigVars.META_LIMITS_COUNT_BY: configured},
    )
    assert limiter._meta_limits_count_by == configured

    with hiro.Timeline().freeze():
        with app.test_client() as client:
            results = responses(client)

    assert [classify(response) for response in results] == expected


def test_per_limit_count_by_overrides_limiter_default():
    app, limiter = build_app(
        meta_limits=[MetaLimit("2/day", count_by="rule")],
        config={ConfigVars.META_LIMITS_COUNT_BY: "request"},
    )

    with hiro.Timeline().freeze():
        with app.test_client() as client:
            results = responses(client)

    assert [classify(response) for response in results] == [
        "ok",
        "limit",
        "meta",
        "meta",
        "meta",
    ]


def test_limiter_default_is_request():
    app, limiter = build_app(meta_limits=[MetaLimit("2/day")])
    assert limiter._meta_limits_count_by == "request"


def test_invalid_count_by_rejected():
    with pytest.raises(ConfigurationError):
        MetaLimit("2/day", count_by="nonsense")

    app = Flask(__name__)
    with pytest.raises(ConfigurationError):
        Limiter(
            get_remote_address,
            app=app,
            storage_uri="memory://",
            meta_limits_count_by="nonsense",
        )
