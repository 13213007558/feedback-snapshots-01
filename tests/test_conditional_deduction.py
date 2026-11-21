from __future__ import annotations

from flask import Flask, request
from limits.storage import MemoryStorage
from limits.strategies import STRATEGIES
from werkzeug.exceptions import BadRequest

from flask_limiter import Limiter


class CountingStorage(MemoryStorage):
    """
    In-memory storage stand-in that records every rate limiting operation and
    can be made to fail on demand for individual operations.

    Every call to :meth:`incr` (a deduction), :meth:`get` and
    :meth:`get_expiry` (window stats used for headers) is appended to
    :attr:`calls` together with the storage key, so a test can assert exactly
    which rule was deducted and how often.
    """

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, str]] = []
        self.fail_on: set[str] = set()

    def incr(self, key: str, expiry: float, amount: int = 1) -> int:
        self.calls.append(("incr", key))
        if "incr" in self.fail_on:
            raise RuntimeError("storage incr unavailable")

        return super().incr(key, expiry, amount)

    def get(self, key: str) -> int:
        self.calls.append(("get", key))
        if "get" in self.fail_on:
            raise RuntimeError("storage get unavailable")

        return super().get(key)

    def get_expiry(self, key: str) -> float:
        self.calls.append(("get_expiry", key))
        if "get_expiry" in self.fail_on:
            raise RuntimeError("storage get_expiry unavailable")

        return super().get_expiry(key)

    @property
    def deduction_keys(self) -> list[str]:
        return [key for op, key in self.calls if op == "incr"]

    @property
    def deduction_count(self) -> int:
        return len(self.deduction_keys)

    def deductions_for(self, fragment: str) -> list[str]:
        return [key for key in self.deduction_keys if fragment in key]


def _build_limiter(**limiter_kwargs) -> tuple[Flask, Limiter, CountingStorage]:
    app = Flask(__name__)
    limiter = Limiter(
        key_func=lambda: "127.0.0.1",
        app=app,
        headers_enabled=True,
        in_memory_fallback_enabled=True,
        **limiter_kwargs,
    )
    storage = CountingStorage()
    limiter._storage = storage
    limiter._limiter = STRATEGIES["fixed-window"](storage)

    return app, limiter, storage


def _fallback_counter(limiter: Limiter) -> int:
    fallback_storage = limiter._fallback_limiter.storage

    return sum(fallback_storage.storage.values())


def test_allowed_request_deducts_the_rule_once():
    app, limiter, storage = _build_limiter()

    @app.route("/captcha")
    @limiter.limit("5/minute", deduct_when=lambda response: response.status_code == 200)
    def captcha():
        return "ok"

    with app.test_client() as client:
        response = client.get("/captcha")

    assert response.status_code == 200
    # The single final decision deducted the rule exactly once on the primary storage.
    assert storage.deduction_count == 1
    assert storage.deductions_for("captcha")
    # No deduction leaked into the fallback storage.
    assert _fallback_counter(limiter) == 0
    assert response.headers["X-RateLimit-Limit"] == "5"
    assert response.headers["X-RateLimit-Remaining"] == "4"


def test_business_failure_does_not_deduct_but_preserves_status_and_headers():
    app, limiter, storage = _build_limiter()

    @app.route("/captcha")
    @limiter.limit("5/minute", deduct_when=lambda response: response.status_code == 200)
    def captcha():
        raise BadRequest()

    with app.test_client() as client:
        response = client.get("/captcha")

    assert response.status_code == 400
    # deduct_when decided not to consume the rule, so neither storage is touched for a deduction.
    assert storage.deduction_count == 0
    assert _fallback_counter(limiter) == 0
    # Headers still describe the untouched, fully available rule.
    assert response.headers["X-RateLimit-Limit"] == "5"
    assert response.headers["X-RateLimit-Remaining"] == "5"


def test_header_storage_failure_falls_back_without_double_deduction():
    app, limiter, storage = _build_limiter()

    @app.route("/captcha")
    @limiter.limit("5/minute", deduct_when=lambda response: response.status_code == 200)
    def captcha():
        return "ok"

    with app.test_client() as client:
        # The deduction succeeds; only the window stats lookup used by the
        # header injection fails, forcing the in-memory fallback to take over.
        storage.fail_on = {"get_expiry"}
        response = client.get("/captcha")

    assert response.status_code == 200
    assert limiter._storage_dead is True
    # The rule was deducted once by the original decision and never again when
    # the fallback storage generated the headers.
    assert storage.deduction_count == 1
    assert storage.deductions_for("captcha")
    assert _fallback_counter(limiter) == 0
    # The fallback storage still produced coherent headers and the response survived.
    assert response.headers["X-RateLimit-Limit"] == "5"
    assert response.headers["X-RateLimit-Remaining"] == "5"


def test_each_response_maps_to_the_rule_actually_deducted():
    app, limiter, storage = _build_limiter()

    @app.route("/captcha")
    @limiter.limit("5/minute", deduct_when=lambda response: response.status_code == 200)
    def captcha():
        if request.args.get("fail"):
            raise BadRequest()

        return "ok"

    @app.route("/other")
    @limiter.limit("7/minute", deduct_when=lambda response: response.status_code == 200)
    def other():
        return "ok"

    with app.test_client() as client:
        captcha_response = client.get("/captcha")
        other_response = client.get("/other")
        failed_response = client.get("/captcha?fail=1")

    assert captcha_response.status_code == 200
    assert other_response.status_code == 200
    assert failed_response.status_code == 400

    # Only the two successful responses deducted, each attributable to its own rule via the key.
    assert storage.deduction_count == 2
    assert len(storage.deductions_for("captcha")) == 1
    assert len(storage.deductions_for("other")) == 1
    # The business failure reused the same captcha rule/key but, being a 400, added no deduction.
    assert all("captcha" in key for key in storage.deductions_for("captcha"))


def test_deduction_storage_failure_is_swallowed_and_not_retried():
    app, limiter, storage = _build_limiter(swallow_errors=True)

    @app.route("/captcha")
    @limiter.limit("5/minute", deduct_when=lambda response: response.status_code == 200)
    def captcha():
        return "ok"

    with app.test_client() as client:
        storage.fail_on = {"incr"}
        response = client.get("/captcha")

    # Swallowing errors keeps the original response and its status code intact.
    assert response.status_code == 200
    # The single decision attempted the deduction once; the failure was never retried.
    assert storage.deduction_count == 1
    assert _fallback_counter(limiter) == 0


def test_deduction_storage_failure_propagates_when_not_swallowed():
    app, limiter, storage = _build_limiter(swallow_errors=False)

    @app.route("/captcha")
    @limiter.limit("5/minute", deduct_when=lambda response: response.status_code == 200)
    def captcha():
        return "ok"

    with app.test_client() as client:
        storage.fail_on = {"incr"}
        response = client.get("/captcha")

    # Without swallowing, the storage failure surfaces as a 500 instead of the view response.
    assert response.status_code == 500
    # Exactly one deduction attempt was made before the error surfaced.
    assert storage.deduction_count == 1
    assert _fallback_counter(limiter) == 0
