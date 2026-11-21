from __future__ import annotations

import json

import hiro
from flask import Flask, jsonify

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def two_tier_app():
    """
    An application that publishes a per-caller minute quota while also
    enforcing a project wide internal budget. Only the public quota is
    allowed to populate the rate limiting headers; the internal budget is
    still counted and rejects requests once exhausted.
    """
    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        headers_enabled=True,
        fail_on_first_breach=False,
    )

    public_quota = limiter.limit("3/minute", scope="public-quota")
    internal_budget = limiter.limit("10/hour", scope="internal-budget", expose_headers=False)

    @app.route("/work")
    @public_quota
    @internal_budget
    def work():
        return jsonify(status="ok")

    @app.errorhandler(429)
    def ratelimit_handler(error):
        return jsonify(error="rate limit exceeded", detail=error.description), 429

    return app, limiter


def exhaust_public_window(cli):
    for remaining in (2, 1, 0):
        response = cli.get("/work")
        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "3"
        assert response.headers["X-RateLimit-Remaining"] == str(remaining)
        assert 0 < int(response.headers["Retry-After"]) <= 60


def test_public_tier_exhaustion_does_not_expose_internal_budget():
    app, _ = two_tier_app()

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            exhaust_public_window(cli)

            response = cli.get("/work")
            assert response.status_code == 429
            assert response.headers["X-RateLimit-Limit"] == "3"
            assert response.headers["X-RateLimit-Remaining"] == "0"
            assert 0 < int(response.headers["Retry-After"]) <= 60

            body = json.dumps(response.get_json())
            assert "3 per 1 minute" in body
            assert "10 per 1 hour" not in body

            timeline.forward(60)
            assert cli.get("/work").status_code == 200


def test_internal_tier_exhaustion_hides_its_size_and_window():
    app, _ = two_tier_app()

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            # consume 9 of the 10 per hour internal budget while staying
            # inside the 3 per minute public quota
            for _ in range(3):
                for _ in range(3):
                    assert cli.get("/work").status_code == 200
                timeline.forward(60)
            assert cli.get("/work").status_code == 200
            timeline.forward(60)

            response = cli.get("/work")
            assert response.status_code == 429

            # only the public quota may be described in the response; this
            # request was still counted against it (3/minute) even though the
            # internal budget is what rejected it
            assert response.headers["X-RateLimit-Limit"] == "3"
            assert response.headers["X-RateLimit-Remaining"] == "2"
            assert 0 < int(response.headers["Retry-After"]) <= 60

            body = json.dumps(response.get_json())
            assert "10 per 1 hour" not in body
            assert "This user has exceeded an allotted request count" in body

            # the hidden budget keeps rejecting requests even after the
            # public minute window has rolled over
            timeline.forward(60)
            assert cli.get("/work").status_code == 429


def test_disclosed_limit_is_used_while_internal_budget_has_headroom():
    app, _ = two_tier_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            for remaining in (2, 1, 0):
                response = cli.get("/work")
                assert response.status_code == 200
                # the internal budget still has headroom, but only the public
                # quota is described in the headers
                assert response.headers["X-RateLimit-Limit"] == "3"
                assert response.headers["X-RateLimit-Remaining"] == str(remaining)


def test_expose_headers_is_reported_per_limit():
    app, limiter = two_tier_app()
    collected = []
    current = []

    @app.after_request
    def collect(response):
        collected.extend(limiter.current_limits)
        current.append(limiter.current_limit)
        return response

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/work").status_code == 200
            exposed = {limit.limit.amount: limit.expose_headers for limit in collected}
            assert exposed == {3: True, 10: False}

            assert current[0] is not None
            assert current[0].limit.amount == 3
            assert current[0].expose_headers is True


def test_hidden_limit_breach_falls_back_to_generic_description():
    app, limiter = two_tier_app()

    @app.route("/internal-only")
    @limiter.limit("1/minute", scope="internal-only", expose_headers=False)
    def internal_only():
        return "ok"

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/internal-only").status_code == 200
            response = cli.get("/internal-only")
            assert response.status_code == 429
            assert "X-RateLimit-Limit" not in response.headers
            assert "Retry-After" not in response.headers
            assert "1 per 1 minute" not in response.text
            assert "This user has exceeded an allotted request count" in response.text
