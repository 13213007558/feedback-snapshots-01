from __future__ import annotations

import hiro
import pytest
from flask import Flask, jsonify, request
from limits.errors import ConfigurationError

from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_limiter.util import get_remote_address

#: Employees and the projects they are authorized to submit claims for. The
#: project number is only confirmed after the backend has checked the pairing.
ACCOUNTS = {
    "token-alice": {"employee": "alice", "projects": {"P-100", "P-200"}},
    "token-bob": {"employee": "bob", "projects": {"P-100"}},
    "token-carol": {"employee": "carol", "projects": set()},
}


def claim_app(*, fail_on_first_breach: bool = True, headers_enabled: bool = False):
    """
    Three in-memory accounts (alice, bob, carol), each submitting claims against a
    project number that is only trusted after ``authorize_project`` confirms it.
    """

    app = Flask(__name__)
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri="memory://",
        headers_enabled=headers_enabled,
        fail_on_first_breach=fail_on_first_breach,
    )

    def current_employee() -> str:
        token = request.headers.get("X-Account", "")
        return ACCOUNTS.get(token, {}).get("employee", "")

    def authorized_project() -> str:
        token = request.headers.get("X-Account", "")
        project = request.headers.get("X-Project", "")
        account = ACCOUNTS.get(token)

        if not account or project not in account["projects"]:
            return ""

        return project

    submit_limit = limiter.multi_limit(
        [
            # 4 claims per employee per window
            ("employee", "4/hour", current_employee),
            # 2 claims per project per window, only when the employee is authorized
            ("project", "2/hour", authorized_project),
        ],
        name="claim-submit",
        scope="claims",
    )

    @app.post("/claims")
    @submit_limit
    def submit_claim():
        return jsonify(
            employee=current_employee(),
            project=authorized_project(),
            remaining={
                request_limit.dimension: request_limit.remaining
                for request_limit in limiter.current_limits
            },
        )

    @app.errorhandler(RateLimitExceeded)
    def handle_rate_limit(exc: RateLimitExceeded):
        return (
            jsonify(
                rule=exc.rejected_rule,
                dimension=exc.rejected_dimension,
                limit=str(exc.limit.limit),
                remaining=exc.remaining_by_dimension(),
            ),
            429,
        )

    return app, limiter


def submit(cli, token: str, project: str | None):
    headers = {"X-Account": token}

    if project is not None:
        headers["X-Project"] = project

    return cli.post("/claims", headers=headers)


def test_employee_and_project_budgets_are_counted_independently(extension_factory):
    app, limiter = claim_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # alice uses two claims of project P-100
            first = submit(cli, "token-alice", "P-100")
            second = submit(cli, "token-alice", "P-100")
            assert first.status_code == second.status_code == 200
            assert second.get_json()["remaining"] == {"employee": 2, "project": 0}

            # the project budget is now exhausted, the employee budget is not
            rejected = submit(cli, "token-alice", "P-100")
            assert rejected.status_code == 429
            assert rejected.get_json() == {
                "rule": "claim-submit",
                "dimension": "project",
                "limit": "2 per 1 hour",
                "remaining": {"employee": 1, "project": 0},
            }

            # bob still has the employee budget, but the shared project is used up
            rejected_bob = submit(cli, "token-bob", "P-100")
            assert rejected_bob.status_code == 429
            assert rejected_bob.get_json()["dimension"] == "project"
            # bob's employee dimension was evaluated and still has room; it is
            # deducted once for the rejected attempt (so 4 - 1 = 3 remaining)
            assert rejected_bob.get_json()["remaining"] == {"employee": 3, "project": 0}


def test_employee_budget_is_not_borrowed_by_another_project(extension_factory):
    app, _ = claim_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # alice spreads the same employee budget over two authorized projects
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-200").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-200").status_code == 200

            rejected = submit(cli, "token-alice", "P-100")
            assert rejected.status_code == 429
            assert rejected.get_json()["dimension"] == "employee"
            # both of alice's projects are now exhausted (2 used each), and her own
            # employee budget is used up as well
            assert rejected.get_json()["remaining"] == {"employee": 0, "project": 0}

            # bob is not authorized for P-200, so the project dimension is skipped
            # rather than charged to a project budget he does not own
            bob_on_p200 = submit(cli, "token-bob", "P-200")
            assert bob_on_p200.status_code == 200
            assert bob_on_p200.get_json()["remaining"] == {"employee": 3}

            # P-100 is exhausted for the shared project budget, but bob's employee
            # budget is untouched by alice's usage
            bob_on_p100 = submit(cli, "token-bob", "P-100")
            assert bob_on_p100.status_code == 429
            assert bob_on_p100.get_json()["dimension"] == "project"
            assert bob_on_p100.get_json()["remaining"]["employee"] == 2


def test_employee_without_project_access_is_only_counted_per_employee(extension_factory):
    app, _ = claim_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # carol may not use any project: the project dimension is skipped instead of
            # being charged to a project bucket she doesn't own
            for expected_remaining in (3, 2, 1, 0):
                response = submit(cli, "token-carol", "P-100")
                assert response.status_code == 200
                # only the employee dimension was evaluated
                assert response.get_json()["remaining"] == {"employee": expected_remaining}

            rejected = submit(cli, "token-carol", "P-100")
            assert rejected.status_code == 429
            assert rejected.get_json()["dimension"] == "employee"
            assert rejected.get_json()["remaining"] == {"employee": 0}

            # no project budget was consumed by carol's unauthorized requests
            assert submit(cli, "token-bob", "P-100").status_code == 200
            assert submit(cli, "token-bob", "P-100").status_code == 200


def test_dimensions_without_identity_are_skipped_not_shared(extension_factory):
    app, _ = claim_app()

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            # no project header at all: only the employee budget applies
            response = submit(cli, "token-carol", None)
            assert response.status_code == 200
            assert set(response.get_json()["remaining"]) == {"employee"}


def test_dimensions_get_separate_namespaces_even_for_equal_values(extension_factory):
    app, limiter = extension_factory()
    calls = []

    @app.route("/t")
    @limiter.multi_limit(
        [
            ("employee", "1/hour", lambda: "same"),
            ("project", "1/hour", lambda: "same"),
        ],
        name="same-value",
        scope="scope",
    )
    def t():
        calls.append(1)
        return "ok"

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/t").status_code == 200
            # both dimensions had their own key: neither was already exhausted
            assert len(calls) == 1
            assert cli.get("/t").status_code == 429


def test_multi_limit_scope_is_shared_between_routes(extension_factory):
    app, limiter = extension_factory()

    limit = limiter.multi_limit(
        [("employee", "2/hour", lambda: request.headers.get("X-Account", "anon"))],
        name="shared-submit",
        scope="claims",
    )

    @app.route("/claims/a", methods=["POST"])
    @limit
    def a():
        return "a"

    @app.route("/claims/b", methods=["POST"])
    @limit
    def b():
        return "b"

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.post("/claims/a").status_code == 200
            assert cli.post("/claims/b").status_code == 200
            assert cli.post("/claims/a").status_code == 429
            assert cli.post("/claims/b").status_code == 429


def test_all_dimensions_are_charged_even_when_first_breach_stops_other_rules(extension_factory):
    app, limiter = claim_app(fail_on_first_breach=True)
    observed: list[RateLimitExceeded] = []

    @app.errorhandler(RateLimitExceeded)
    def record(exc: RateLimitExceeded):
        observed.append(exc)
        return jsonify(dimension=exc.rejected_dimension), 429

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 200
            assert submit(cli, "token-alice", "P-100").status_code == 429

    assert observed
    # the employee dimension was still deducted on the rejected request even though
    # the project dimension (sorted first by window size) triggered the rejection
    assert observed[-1].rejected_dimension == "project"
    assert observed[-1].remaining_for("employee") == 1


def test_headers_report_the_rejected_dimension(extension_factory):
    app, _ = claim_app(headers_enabled=True)

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert submit(cli, "token-alice", "P-100").status_code == 200
            response = submit(cli, "token-alice", "P-100")
            assert response.status_code == 200
            assert response.headers["X-RateLimit-Limit"] == "2"
            assert response.headers["X-RateLimit-Remaining"] == "0"

            rejected = submit(cli, "token-alice", "P-100")
            assert rejected.status_code == 429


def test_declaration_can_be_used_as_a_context_manager(extension_factory):
    app, limiter = extension_factory()
    limit = limiter.multi_limit(
        [
            ("employee", "2/hour", lambda: "alice"),
            ("project", "2/hour", lambda: "P-100"),
        ],
        name="context",
        scope="context",
    )

    @app.route("/t")
    def t():
        with limit:
            return "ok"

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/t").status_code == 200
            assert cli.get("/t").status_code == 200
            assert cli.get("/t").status_code == 429


def test_multi_limit_validates_dimension_declarations(extension_factory):
    _, limiter = extension_factory()

    with pytest.raises(ConfigurationError):
        limiter.multi_limit([("employee",)])

    with pytest.raises(ConfigurationError):
        limiter.multi_limit([("", "1/hour")])


def test_dimension_predicate_can_disable_a_dimension(extension_factory):
    app, limiter = extension_factory()
    enabled = {"project": False}

    @app.route("/t")
    @limiter.multi_limit(
        [
            ("employee", "10/hour", lambda: "alice"),
            ("project", "1/hour", lambda: "P-100", lambda: enabled["project"]),
        ],
        name="disabled-dimension",
        scope="claims",
    )
    def t():
        return "ok"

    with hiro.Timeline().freeze():
        with app.test_client() as cli:
            assert cli.get("/t").status_code == 200
            assert cli.get("/t").status_code == 200
            enabled["project"] = True
            # the project dimension starts being counted, and its 1/hour budget
            # is consumed by the next request; the following one is rejected
            assert cli.get("/t").status_code == 200
            assert cli.get("/t").status_code == 429
