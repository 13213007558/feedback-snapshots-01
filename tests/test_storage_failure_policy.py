from __future__ import annotations

from collections import Counter

import hiro
import pytest
from flask import Flask
from limits.storage import MemoryStorage
from limits.strategies import STRATEGIES
from limits.errors import ConfigurationError

from flask_limiter import Limiter, StorageFailurePolicy, StorageUnavailable
from flask_limiter.util import get_remote_address


class ControllableStorage(MemoryStorage):
    """
    In-memory storage with an outage switch that records the operations it
    served. Used to interleave healthy and degraded requests deterministically.
    """

    def __init__(self) -> None:
        super().__init__()
        self.down = False
        self.calls: Counter[str] = Counter()
        self.checks = 0

    def _guard(self, operation: str) -> None:
        self.calls[operation] += 1
        if self.down:
            raise ConnectionError("storage is down")

    def incr(self, key: str, expiry: float, amount: int = 1) -> int:
        self._guard("incr")
        return super().incr(key, expiry, amount=amount)

    def get(self, key: str) -> int:
        self._guard("get")
        return super().get(key)

    def check(self) -> bool:
        self.checks += 1
        if self.down:
            raise ConnectionError("storage is down")
        return True


def build_app(
    *,
    storage_failure_policy: StorageFailurePolicy | str | None = None,
) -> tuple[Flask, Limiter, ControllableStorage]:
    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100/minute"],
        storage_uri="memory://",
        in_memory_fallback=["5/hour"],
        headers_enabled=True,
        storage_failure_policy=storage_failure_policy,
    )
    storage = ControllableStorage()
    limiter._storage = storage
    limiter._limiter = STRATEGIES["fixed-window"](storage)

    @app.route("/login")
    @limiter.limit("10/minute", storage_failure_policy=StorageFailurePolicy.DENY)
    def login():
        return "login"

    @app.route("/update")
    @limiter.limit("10/minute", storage_failure_policy=StorageFailurePolicy.DENY)
    def update():
        return "update"

    @app.route("/help")
    @limiter.storage_failure_policy(StorageFailurePolicy.FALLBACK)
    def help_page():
        return "help"

    return app, limiter, storage


def fallback_counts(limiter: Limiter) -> Counter[str]:
    assert limiter._fallback_storage is not None
    return Counter(limiter._fallback_storage.storage)


def test_per_endpoint_storage_failure_policies() -> None:
    app, limiter, storage = build_app(storage_failure_policy=StorageFailurePolicy.DENY)

    with app.test_client() as client, hiro.Timeline() as timeline:
        # Healthy baseline: all three endpoints share the primary storage.
        assert client.get("/login").status_code == 200
        assert client.get("/update").status_code == 200
        assert client.get("/help").status_code == 200
        assert sum(Counter(storage.storage).values()) == 3
        assert sum(fallback_counts(limiter).values()) == 0

        storage.down = True

        # Interleave the three request types while the shared storage is down.
        # The public page degrades to the configured in-memory quota; the
        # authentication and mutation endpoints stay closed.
        assert client.get("/help").status_code == 200
        assert client.get("/login").status_code == 503
        assert client.get("/update").status_code == 503
        assert client.get("/help").status_code == 200
        assert client.get("/login").status_code == 503
        assert client.get("/help").status_code == 200
        assert client.get("/update").status_code == 503
        assert client.get("/help").status_code == 200
        assert client.get("/help").status_code == 200

        # The configured fallback quota (5/hour) is exhausted for the public
        # page only; auth endpoints never consumed fallback budget.
        assert client.get("/help").status_code == 429
        assert sum(fallback_counts(limiter).values()) == 6
        assert set(fallback_counts(limiter)) == {"LIMITER/127.0.0.1/help_page/5/1/hour"}
        assert sum(Counter(storage.storage).values()) == 3
        assert client.get("/login").status_code == 503
        assert client.get("/update").status_code == 503
        assert sum(fallback_counts(limiter).values()) == 6

        # Restore the shared storage. The probe moves all routes back to the
        # primary backend, including the public endpoint.
        storage.down = False
        # Past the first recovery probe backoff while remaining in the same
        # one minute counting window.
        timeline.forward(2)
        assert client.get("/login").status_code == 200
        assert not limiter._storage_dead

        fallback_snapshot = fallback_counts(limiter)
        assert sum(fallback_snapshot.values()) == 6

        before_help = Counter(storage.storage)
        assert client.get("/help").status_code == 200
        after_help = Counter(storage.storage)
        help_key = "LIMITER/127.0.0.1/help_page/100/1/minute"
        assert after_help[help_key] == before_help[help_key] + 1
        assert fallback_counts(limiter) == fallback_snapshot

        before_login = Counter(storage.storage)
        assert client.get("/login").status_code == 200
        after_login = Counter(storage.storage)
        login_key = "LIMITER/127.0.0.1/login/10/1/minute"
        assert after_login[login_key] == before_login[login_key] + 1
        assert fallback_counts(limiter) == fallback_snapshot


def test_public_fallback_does_not_relax_auth_endpoints() -> None:
    app, limiter, storage = build_app(storage_failure_policy=StorageFailurePolicy.DENY)
    storage.down = True

    with app.test_client() as client:
        # The very first request to notice the outage is the public page.
        assert client.get("/help").status_code == 200
        assert limiter._storage_dead
        assert client.get("/login").status_code == 503
        assert client.get("/update").status_code == 503
        assert sum(Counter(storage.storage).values()) == 0
        assert sum(fallback_counts(limiter).values()) == 1


def test_global_fallback_policy_can_be_overridden_per_endpoint() -> None:
    app, limiter, storage = build_app(storage_failure_policy=StorageFailurePolicy.FALLBACK)
    storage.down = True

    with app.test_client() as client:
        assert client.get("/help").status_code == 200
        assert client.get("/login").status_code == 503
        assert client.get("/update").status_code == 503


def test_mapping_policy_selects_per_endpoint_without_decorators() -> None:
    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100/minute"],
        storage_uri="memory://",
        in_memory_fallback=["2/hour"],
        storage_failure_policy={
            "login": StorageFailurePolicy.DENY,
            "help_page": "fallback",
        },
    )
    storage = ControllableStorage()
    limiter._storage = storage
    limiter._limiter = STRATEGIES["fixed-window"](storage)

    @app.route("/login")
    def login():
        return "login"

    @app.route("/help")
    def help_page():
        return "help"

    storage.down = True
    with app.test_client() as client:
        assert client.get("/help").status_code == 200
        assert client.get("/login").status_code == 503
        assert client.get("/help").status_code == 200
        assert client.get("/login").status_code == 503
        assert client.get("/help").status_code == 429


def test_callable_policy_receives_endpoint() -> None:
    seen: list[str] = []

    def policy(endpoint: str) -> StorageFailurePolicy:
        seen.append(endpoint)

        return (
            StorageFailurePolicy.FALLBACK if endpoint == "help_page" else StorageFailurePolicy.DENY
        )

    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100/minute"],
        storage_uri="memory://",
        in_memory_fallback=["2/hour"],
        storage_failure_policy=policy,
    )
    storage = ControllableStorage()
    limiter._storage = storage
    limiter._limiter = STRATEGIES["fixed-window"](storage)

    @app.route("/login")
    def login():
        return "login"

    @app.route("/help")
    def help_page():
        return "help"

    storage.down = True
    with app.test_client() as client:
        assert client.get("/help").status_code == 200
        assert client.get("/login").status_code == 503
    assert "help_page" in seen
    assert "login" in seen


def test_storage_failure_policy_rejects_unknown_values() -> None:
    app = Flask(__name__)
    with pytest.raises(ConfigurationError):
        Limiter(
            get_remote_address,
            app=app,
            storage_uri="memory://",
            storage_failure_policy="sometimes",
        )


def test_storage_unavailable_is_a_service_unavailable_error() -> None:
    assert issubclass(StorageUnavailable, Exception)
    assert StorageUnavailable.code == 503


def test_blueprint_policy_applies_to_all_member_routes() -> None:
    from flask import Blueprint

    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["100/minute"],
        storage_uri="memory://",
        in_memory_fallback=["2/hour"],
        storage_failure_policy=StorageFailurePolicy.DENY,
    )
    storage = ControllableStorage()
    limiter._storage = storage
    limiter._limiter = STRATEGIES["fixed-window"](storage)

    public = Blueprint("public", __name__, url_prefix="/public")
    limiter.storage_failure_policy(StorageFailurePolicy.FALLBACK)(public)

    @public.route("/docs")
    def docs():
        return "docs"

    @public.route("/readme")
    def readme():
        return "readme"

    @app.route("/login")
    def login():
        return "login"

    app.register_blueprint(public)
    storage.down = True

    with app.test_client() as client:
        assert client.get("/public/docs").status_code == 200
        assert client.get("/public/readme").status_code == 200
        # The blueprint did not change the global policy for other routes.
        assert client.get("/login").status_code == 503
