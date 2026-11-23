from __future__ import annotations

import threading
import time

import hiro
import pytest
from flask import Blueprint, Flask, jsonify, request
from limits.errors import ConfigurationError
from limits.storage import MemoryStorage, Storage
from limits.strategies import FixedWindowRateLimiter

from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter._atomic import atomic_backend_for
from flask_limiter.util import get_remote_address

ACCOUNTS = {
    "token-alice": {"employee": "alice", "projects": {"P-100", "P-200"}},
    "token-bob": {"employee": "bob", "projects": {"P-100", "P-200"}},
    "token-carol": {"employee": "carol", "projects": set()},
}


def make_app(**limiter_args):
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://", **limiter_args)

    def employee() -> str:
        return ACCOUNTS.get(request.headers.get("X-Account", ""), {}).get("employee", "")

    def project() -> str:
        account = ACCOUNTS.get(request.headers.get("X-Account", ""))
        project_name = request.headers.get("X-Project", "")

        if not account or project_name not in account["projects"]:
            return ""

        return project_name

    claim = limiter.multi_limit(
        [
            ("employee", "4/hour", employee),
            ("project", "2/hour", project),
        ],
        name="claim-submit",
        scope="claims",
    )

    @app.post("/claims")
    @claim
    def submit():
        return jsonify(
            remaining={
                f"{limit.dimension}:{limit.limit.amount}": limit.remaining
                for limit in limiter.current_limits
            }
        )

    @app.errorhandler(RateLimitExceeded)
    def rejected(exc: RateLimitExceeded):
        return (
            jsonify(
                rule=exc.rejected_rule,
                dimension=exc.rejected_dimension,
                remaining=exc.remaining_by_dimension(),
                reset=exc.reset_at_by_dimension(),
            ),
            429,
        )

    return app, limiter


def submit(cli, token: str, project_name: str | None = None):
    headers = {"X-Account": token}

    if project_name:
        headers["X-Project"] = project_name

    return cli.post("/claims", headers=headers)


def test_group_is_all_or_nothing_and_employee_keeps_allowance():
    app, _ = make_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 200

            rejected = submit(cli, "token-alice", "P-100")
            assert rejected.status_code == 429
            assert rejected.get_json()["dimension"] == "project"
            # the employee budget was not consumed by the rejected request
            assert rejected.get_json()["remaining"] == {"employee": 2, "project": 0}

            rejected_bob = submit(cli, "token-bob", "P-100")
            assert rejected_bob.status_code == 429
            assert rejected_bob.get_json()["remaining"]["employee"] == 4


def test_parallel_requests_compete_for_last_project_allowance():
    app, _ = make_app()
    barrier = threading.Barrier(2)
    results: list[tuple[str, int, dict | None]] = []

    def worker(token: str) -> None:
        with app.test_client() as cli:
            barrier.wait()
            response = submit(cli, token, "P-100")
            results.append((token, response.status_code, response.get_json()))

    with hiro.Timeline().freeze():
        threads = [
            threading.Thread(target=worker, args=(token,)) for token in ("token-alice", "token-bob")
        ]
        # consume all but the last project allowance first
        with app.test_client() as cli:
            assert submit(cli, "token-alice", "P-100").status_code == 200

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

    assert sorted(status for _, status, _ in results) == [200, 429]
    loser = next(payload for _, status, payload in results if status == 429)
    assert loser["dimension"] == "project"
    assert loser["remaining"]["project"] == 0
    # the losing employee's personal budget is untouched by the rejected request
    assert loser["remaining"]["employee"] == 3


def test_budget_referenced_by_route_and_blueprint_is_charged_once():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
    blueprint = Blueprint("claims", __name__, url_prefix="/claims")

    def employee() -> str:
        return request.headers.get("X-Account", "")

    @app.post("/single")
    @limiter.multi_limit(
        [("employee", "2/hour", employee)],
        name="route-group",
        scope="claims",
    )
    def single():
        return "ok"

    blueprint_limit = limiter.multi_limit(
        [("employee", "2/hour", employee)],
        name="blueprint-group",
        scope="claims",
    )
    blueprint_limit(blueprint)

    @blueprint.post("/")
    def blueprint_route():
        return "ok"

    app.register_blueprint(blueprint)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # both routes reference the same employee/scope budget, and each request
            # must charge it exactly once
            assert cli.post("/single", headers={"X-Account": "alice"}).status_code == 200
            assert cli.post("/claims/", headers={"X-Account": "alice"}).status_code == 200
            # a budget charged twice per request would already be exhausted
            assert cli.post("/single", headers={"X-Account": "alice"}).status_code == 429


def test_route_and_inherited_blueprint_budgets_are_deduplicated_in_one_request():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
    blueprint = Blueprint("claims", __name__, url_prefix="/claims")

    def employee() -> str:
        return request.headers.get("X-Account", "")

    inherited = limiter.multi_limit(
        [("employee", "1/hour", employee)],
        name="blueprint-group",
        scope="claims",
    )
    inherited(blueprint)

    @blueprint.post("/submit")
    @limiter.multi_limit(
        [("employee", "1/hour", employee)],
        name="route-group",
        scope="claims",
    )
    def submit():
        return "ok"

    app.register_blueprint(blueprint)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # the inherited declaration and the route declaration resolve to the same
            # key; charging that key twice would reject the very first request
            assert cli.post("/claims/submit", headers={"X-Account": "alice"}).status_code == 200
            assert cli.post("/claims/submit", headers={"X-Account": "alice"}).status_code == 429


def test_unauthorized_project_only_charges_the_employee_budget():
    app, limiter = make_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            for _ in range(4):
                response = submit(cli, "token-carol", "P-100")
                assert response.status_code == 200

            rejected = submit(cli, "token-carol", "P-100")
            assert rejected.status_code == 429
            assert rejected.get_json()["dimension"] == "employee"
            assert rejected.get_json()["remaining"] == {"employee": 0}

            # the unauthorized project never got a bucket of its own
            project_keys = [key for key in limiter.storage.storage if "dimension=project" in key]
            assert project_keys == []


def test_employee_budget_is_shared_across_projects_and_windows_reset():
    app, limiter = make_app()

    with hiro.Timeline().freeze() as timeline:
        with app.test_client() as cli:
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-200").status_code == 200

            # P-100's project budget still has one claim, use it up
            assert submit(cli, "token-alice", "P-100").status_code == 200
            rejected_project = submit(cli, "token-alice", "P-100")
            assert rejected_project.status_code == 429
            assert rejected_project.get_json()["dimension"] == "project"
            # the employee budget was not charged by the rejected request
            assert rejected_project.get_json()["remaining"]["employee"] == 1

            # employee window is shared across projects and is now exhausted by P-200
            assert submit(cli, "token-alice", "P-200").status_code == 200
            rejected_employee = submit(cli, "token-alice", "P-200")
            assert rejected_employee.status_code == 429
            assert rejected_employee.get_json()["dimension"] == "employee"
            assert rejected_employee.get_json()["remaining"]["employee"] == 0

            timeline.forward(3600)
            assert submit(cli, "token-alice", "P-100").status_code == 200


def test_denied_from_entering_business_on_rejection():
    app, _ = make_app()
    calls: list[str] = []

    @app.before_request
    def record():
        if request.endpoint == "submit":
            calls.append("entered")

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 429

    # before_request runs for every request, so count only successful view calls
    assert len(calls) == 3


def test_storage_failure_before_write_consumes_nothing():
    app, limiter = make_app()
    strategy = limiter._limiter
    original_hit = strategy.hit

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            failed = {"done": False}

            def failing_hit(item, *identifiers, cost=1):
                # fail after the employee budget was written, before the project
                # budget is written
                if not failed["done"] and "dimension=project" in item.key_for(*identifiers):
                    failed["done"] = True
                    raise RuntimeError("injected storage failure before write")

                return original_hit(item, *identifiers, cost=cost)

            strategy.hit = failing_hit
            # Flask renders the injected server error as a 500 response
            assert submit(cli, "token-alice", "P-100").status_code == 500
            strategy.hit = original_hit

            # neither budget was consumed: both successful requests still fit
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 200
            rejected = submit(cli, "token-alice", "P-100")
            assert rejected.status_code == 429
            assert rejected.get_json()["remaining"] == {"employee": 2, "project": 0}


def test_rejection_uses_the_window_that_decided():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

    @app.post("/claims/<project>")
    @limiter.multi_limit(
        [
            ("employee", "2/minute; 10/hour"),
            ("project", "1/hour", lambda: request.view_args["project"]),
        ],
        name="claim-submit",
    )
    def claim(project: str):
        return "ok"

    @app.errorhandler(RateLimitExceeded)
    def rejected(exc: RateLimitExceeded):
        return jsonify(
            remaining=exc.remaining_by_dimension(),
            employee=exc.remaining_for("employee"),
            reset=exc.reset_at_by_dimension(),
        ), 429

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.post("/claims/P-100").status_code == 200
            project_rejected = cli.post("/claims/P-100")
            assert project_rejected.status_code == 429
            # the minute window is the tightest employee budget
            assert project_rejected.get_json()["employee"] == 1
            # reset reports the earliest window that restores allowance
            assert project_rejected.get_json()["reset"]["employee"] == int(time.time() + 61)

            other_project = cli.post("/claims/P-200")
            assert other_project.status_code == 200


def test_identity_and_cost_are_resolved_after_authorization():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

    def authorized_project() -> str:
        # the project is only trusted after the application checked the pairing;
        # an unauthorized project must not fall into a shared bucket
        project = request.view_args["project"]
        account = request.headers.get("X-Account", "")
        allowed = {"alice": {"P-100", "P-200"}, "bob": {"P-200"}}

        return project if project in allowed.get(account, set()) else ""

    @app.post("/claims/<project>")
    @limiter.multi_limit(
        [
            ("employee", "10/hour", lambda: request.headers.get("X-Account", "")),
            ("project", "1/hour", authorized_project),
        ],
        name="claim-submit",
    )
    def claim(project: str):
        return "ok"

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.post("/claims/P-100", headers={"X-Account": "alice"}).status_code == 200
            # bob is not authorized for P-100: only his employee budget applies
            assert cli.post("/claims/P-100", headers={"X-Account": "bob"}).status_code == 200
            assert cli.post("/claims/P-100", headers={"X-Account": "bob"}).status_code == 200

            project_keys = [key for key in limiter.storage.storage if "dimension=project" in key]
            # the unauthorized request did not create or charge a project bucket
            assert len(project_keys) == 1
            assert "P-100" in project_keys[0]


def test_rejected_request_does_not_reserve_conditional_budgets_before_response():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

    @app.post("/claims")
    @limiter.multi_limit(
        [("employee", "1/hour", lambda: request.headers.get("X-Employee", ""))],
        name="claim-submit",
        deduct_when=lambda response: response.status_code == 200,
    )
    def claim():
        return "ok", 400

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # a failed response must not charge the group
            assert cli.post("/claims", headers={"X-Employee": "alice"}).status_code == 400
            assert cli.post("/claims", headers={"X-Employee": "alice"}).status_code == 400
            keys = [key for key in limiter.storage.storage if "employee" in key]
            assert keys == []


class NonAtomicStorage(Storage):
    base_exceptions = ValueError

    def incr(self, key, expiry, amount=1):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def get_expiry(self, key):
        raise NotImplementedError

    def check(self):
        return True

    def reset(self):
        return None

    def clear(self, key):
        return None


def test_declaring_a_group_on_non_atomic_storage_fails_immediately():
    app = Flask(__name__)
    limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
    storage = NonAtomicStorage()
    limiter._storage = storage
    limiter._limiter = FixedWindowRateLimiter(storage)
    limiter._atomic_backend = None

    with pytest.raises(ConfigurationError, match="atomic"):

        @limiter.multi_limit([("employee", "1/hour")], name="claim-submit")
        def view():
            return "ok"


def test_grouped_declaration_on_non_atomic_storage_fails_at_init():
    limiter = Limiter(get_remote_address)
    limiter.multi_limit(
        [("employee", "1/hour")],
        name="claim-submit",
    )
    storage = NonAtomicStorage()
    limiter._storage = storage
    limiter._limiter = FixedWindowRateLimiter(storage)
    limiter._atomic_backend = None
    limiter._grouped_admission = True

    with pytest.raises(ConfigurationError, match="atomic"):
        limiter._ensure_grouped_admission_capability()


def test_memory_backend_is_available():
    backend = atomic_backend_for(MemoryStorage(), FixedWindowRateLimiter(MemoryStorage()))
    assert backend is not None
