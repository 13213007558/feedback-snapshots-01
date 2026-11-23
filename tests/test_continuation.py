import threading
import unittest
from datetime import timedelta
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from flask import Blueprint
from flask import Flask
from flask import redirect
from flask import request

from flask_login import confirm_login
from flask_login import consume_continuation
from flask_login import ContinuationPolicy
from flask_login import continuation_token
from flask_login import fresh_login_required
from flask_login import login_required
from flask_login import login_user
from flask_login import LoginManager
from flask_login import logout_user
from flask_login import MemoryContinuationStore
from flask_login import pending_continuations
from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.allowed = {}

    def grant(self, entry, endpoint):
        self.allowed.setdefault(entry, set()).add(endpoint)

    def revoke(self, entry, endpoint):
        self.allowed.get(entry, set()).discard(endpoint)

    def may_access(self, entry, endpoint):
        return endpoint in self.allowed.get(entry, set())


class ContinuationAppMixin:
    """Builds an app with employee and vendor blueprints sharing one login."""

    continuation_enabled = True
    use_session_for_next = False

    def create_app(self, clock=None, use_session_for_next=None):
        if use_session_for_next is None:
            use_session_for_next = self.use_session_for_next
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "deterministic"
        app.config["SESSION_PROTECTION"] = None
        app.config["CONTINUATION_ENABLED"] = self.continuation_enabled
        app.config["USE_SESSION_FOR_NEXT"] = use_session_for_next
        app.config["CONTINUATION_SAFE_HOME"] = {
            "employee": "/employee/",
            "vendor": "/vendor/",
        }

        login_manager = LoginManager()
        login_manager.init_app(app)
        login_manager.login_view = "login"
        login_manager.refresh_view = "confirm"
        if clock is not None:
            login_manager.continuation_store = MemoryContinuationStore(clock=clock)
        login_manager.continuation_policy = {
            "*": ContinuationPolicy(
                ttl=timedelta(minutes=10),
                authorizer=lambda user, record: user.may_access(
                    record.entry, record.endpoint
                ),
            )
        }

        @app.route("/login", methods=["GET", "POST"])
        def login():
            if request.method == "POST":
                user = USERS.get(request.form.get("user"))
                if user is not None:
                    login_user(user, remember=request.form.get("remember") == "1")
                entry = request.values.get("entry")
                return redirect(consume_continuation(entry=entry))
            entry = request.args.get("entry")
            return continuation_token(entry=entry) or ""

        @app.route("/confirm", methods=["GET", "POST"])
        def confirm():
            if request.method == "POST":
                confirm_login()
                entry = request.values.get("entry")
                return redirect(consume_continuation(entry=entry))
            return "confirm"

        @app.route("/logout")
        def logout():
            logout_user()
            return ""

        @app.route("/pending")
        def pending():
            entry = request.args.get("entry")
            return ",".join(pending_continuations(entry=entry))

        @app.route("/token")
        def token():
            entry = request.args.get("entry")
            return continuation_token(entry=entry) or ""

        employee = Blueprint("employee", __name__, url_prefix="/employee")
        vendor = Blueprint("vendor", __name__, url_prefix="/vendor")

        @employee.route("/")
        def employee_home():
            return "employee home"

        @employee.route("/orders")
        @login_required
        def orders():
            return "orders"

        @employee.route("/settings")
        @fresh_login_required
        def settings():
            return "settings"

        @vendor.route("/")
        def vendor_home():
            return "vendor home"

        @vendor.route("/invoices")
        @login_required
        def invoices():
            return "invoices"

        @vendor.route("/catalog")
        @fresh_login_required
        def catalog():
            return "catalog"

        app.register_blueprint(employee)
        app.register_blueprint(vendor)

        @login_manager.user_loader
        def load_user(user_id):
            return USERS.get(user_id)

        @app.errorhandler(404)
        def handle_404(error):
            raise error

        return app, login_manager


def _flow(response):
    """Return the continuation token carried by a login redirect."""
    location = response.headers["Location"]
    query = parse_qs(urlsplit(location).query)
    return query["continuation"][0]


def _path_with_query(response):
    location = response.headers["Location"]
    parsed = urlsplit(location)
    return parsed.path + ("?" + parsed.query if parsed.query else "")


USERS = {}


def setUpModule():
    USERS["alice"] = User("alice")


class ContinuationQueryStringTestCase(ContinuationAppMixin, unittest.TestCase):
    """Continuation identifiers travel on the query string."""

    continuation_enabled = True
    use_session_for_next = False

    def setUp(self):
        self.user = User("alice")
        USERS["alice"] = self.user
        self.user.grant("employee", "employee.orders")
        self.user.grant("vendor", "vendor.invoices")
        self.app, self.login_manager = self.create_app()

    def complete(self, client, token, entry=None):
        data = {"user": "alice"}
        query = f"continuation={token}"
        if entry is not None:
            data["entry"] = entry
            query += f"&continuation_entry={entry}"
        return client.post(f"/login?{query}", data=data)

    def test_parallel_flows_complete_in_reverse_order_with_revocation(self):
        first = self.app.test_client()
        second = self.app.test_client()

        employee_nav = first.get("/employee/orders?status=open&page=2")
        vendor_nav = second.get("/vendor/invoices?year=2026&state=due")
        self.assertEqual(employee_nav.status_code, 302)
        self.assertEqual(vendor_nav.status_code, 302)

        employee_token = _flow(employee_nav)
        vendor_token = _flow(vendor_nav)
        self.assertNotEqual(employee_token, vendor_token)

        # Revoke the vendor landing after the navigation was registered.
        self.user.revoke("vendor", "vendor.invoices")

        # Complete the vendor flow first; it is no longer authorized.
        vendor_done = self.complete(second, vendor_token)
        self.assertEqual(_path_with_query(vendor_done), "/vendor/")

        # Then complete the employee flow; it keeps its path and query.
        employee_done = self.complete(first, employee_token)
        self.assertEqual(
            _path_with_query(employee_done),
            "/employee/orders?status=open&page=2",
        )

        # Both records were consumed exactly once.
        self.assertEqual(len(self.login_manager.continuation_store), 0)

    def test_authorized_flow_redirects_to_its_registered_target(self):
        client = self.app.test_client()
        nav = client.get("/employee/orders?status=open&page=2")
        done = self.complete(client, _flow(nav))
        self.assertEqual(
            _path_with_query(done), "/employee/orders?status=open&page=2"
        )
        self.assertEqual(done.status_code, 302)

    def test_revoked_flow_falls_back_to_its_entry_home(self):
        client = self.app.test_client()
        nav = client.get("/vendor/invoices?year=2026")
        self.user.revoke("vendor", "vendor.invoices")
        done = self.complete(client, _flow(nav))
        self.assertEqual(_path_with_query(done), "/vendor/")

    def test_allowed_routes_reject_unlisted_endpoint(self):
        self.login_manager.continuation_policy = {
            "*": ContinuationPolicy(
                allowed_endpoints={"employee.orders"},
            )
        }
        self.user.grant("vendor", "vendor.invoices")
        client = self.app.test_client()
        nav = client.get("/vendor/invoices?year=2026")
        done = self.complete(client, _flow(nav))
        self.assertEqual(_path_with_query(done), "/vendor/")

    def test_expired_flow_falls_back_to_safe_home(self):
        now = [1000.0]
        app, login_manager = self.create_app(clock=lambda: now[0])
        self.app = app
        client = app.test_client()
        nav = client.get("/employee/orders")
        token = _flow(nav)

        now[0] += 601

        done = self.complete(client, token)
        self.assertEqual(_path_with_query(done), "/employee/")
        self.assertEqual(len(login_manager.continuation_store), 0)

    def test_flow_bound_to_subject_is_not_claimable_by_another(self):
        self.user.grant("employee", "employee.orders")
        with self.app.app_context():
            record = self.login_manager.register_continuation(
                target="/employee/orders",
                entry="employee",
                user=self.user,
                endpoint="employee.orders",
            )

        other = User("bob")
        USERS["bob"] = other
        other.grant("employee", "employee.orders")
        client = self.app.test_client()

        # Bob cannot claim Alice's record and does not remove it.
        bob_done = client.post(
            f"/login?continuation={record.token}", data={"user": "bob"}
        )
        self.assertEqual(_path_with_query(bob_done), "/employee/")
        self.assertEqual(len(self.login_manager.continuation_store), 1)

        # Alice still can.
        alice_done = client.post(
            f"/login?continuation={record.token}", data={"user": "alice"}
        )
        self.assertEqual(_path_with_query(alice_done), "/employee/orders")
        self.assertEqual(len(self.login_manager.continuation_store), 0)

    def test_flow_cannot_be_redeemed_under_another_entry(self):
        self.user.grant("employee", "employee.orders")
        client = self.app.test_client()
        token = _flow(client.get("/employee/orders?status=open"))

        # Presenting the employee flow as a vendor confirmation must not
        # consume or reveal it; the fallback stays with the record's entry.
        done = self.complete(client, token, entry="vendor")
        self.assertEqual(_path_with_query(done), "/employee/")
        self.assertEqual(len(self.login_manager.continuation_store), 1)

        employee_done = self.complete(client, token, entry="employee")
        self.assertEqual(
            _path_with_query(employee_done), "/employee/orders?status=open"
        )

    def test_anonymous_request_cannot_consume(self):
        with self.app.app_context():
            record = self.login_manager.register_continuation(
                target="/employee/orders",
                entry="employee",
                user=self.user,
                endpoint="employee.orders",
            )
        client = self.app.test_client()
        done = client.post(
            f"/login?continuation={record.token}&continuation_entry=employee",
            data={},
        )
        self.assertEqual(done.status_code, 302)
        self.assertEqual(_path_with_query(done), "/employee/")
        self.assertEqual(len(self.login_manager.continuation_store), 1)

    def test_missing_continuation_falls_back_to_safe_home(self):
        client = self.app.test_client()
        done = client.post("/login", data={"user": "alice"})
        self.assertEqual(_path_with_query(done), "/")

    def test_concurrent_completion_consumes_at_most_once(self):
        client = self.app.test_client()
        nav = client.get("/employee/orders?status=open")
        token = _flow(nav)
        store = self.login_manager.continuation_store
        self.assertEqual(store.__class__, MemoryContinuationStore)

        barrier = threading.Barrier(2)
        results = []
        errors = []

        def complete():
            try:
                local = self.app.test_client()
                barrier.wait()
                response = local.post(
                    f"/login?continuation={token}&continuation_entry=employee",
                    data={"user": "alice"},
                )
                results.append(_path_with_query(response))
            except Exception as error:  # pragma: no cover - fail loudly
                errors.append(error)

        threads = [threading.Thread(target=complete) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(results.count("/employee/orders?status=open"), 1)
        self.assertEqual(results.count("/employee/"), 1)
        self.assertEqual(len(store), 0)

    def test_remembered_confirmation_uses_same_constraints(self):
        self.user.grant("vendor", "vendor.catalog")
        client = self.app.test_client()
        client.post("/login", data={"user": "alice", "remember": "1"})
        with client.session_transaction() as sess:
            sess.clear()

        nav = client.get("/vendor/catalog?sort=name")
        self.assertEqual(nav.status_code, 302)
        token = _flow(nav)

        confirm_page = client.post(f"/confirm?continuation={token}", data={})
        self.assertEqual(_path_with_query(confirm_page), "/vendor/catalog?sort=name")

        # A second confirmation attempt cannot reuse the consumed record.
        again = client.post(f"/confirm?continuation={token}", data={})
        self.assertEqual(_path_with_query(again), "/")

    def test_remembered_confirmation_honors_revocation(self):
        client = self.app.test_client()
        client.post("/login", data={"user": "alice", "remember": "1"})
        with client.session_transaction() as sess:
            sess.clear()

        nav = client.get("/vendor/catalog?sort=name")
        token = _flow(nav)
        self.user.revoke("vendor", "vendor.catalog")

        done = client.post(f"/confirm?continuation={token}", data={})
        self.assertEqual(_path_with_query(done), "/vendor/")


class ContinuationConfigurationTestCase(ContinuationAppMixin, unittest.TestCase):
    def setUp(self):
        self.user = User("alice")
        USERS["alice"] = self.user
        self.user.grant("employee", "employee.orders")

    def test_disabled_keeps_legacy_next_redirect(self):
        app, login_manager = self.create_app()
        app.config["CONTINUATION_ENABLED"] = False
        client = app.test_client()
        nav = client.get("/employee/orders?status=open")
        self.assertEqual(
            nav.headers["Location"], "/login?next=%2Femployee%2Forders%3Fstatus%3Dopen"
        )
        self.assertEqual(len(login_manager.continuation_store), 0)

    def test_config_policy_is_used(self):
        app, login_manager = self.create_app()
        app.config["CONTINUATION_POLICY"] = {
            "*": {
                "ttl": 60,
                "allowed_endpoints": {"employee.orders"},
                "safe_home": "/employee/",
            }
        }
        client = app.test_client()
        token = _flow(client.get("/employee/orders"))
        done = client.post(
            f"/login?continuation={token}&continuation_entry=employee",
            data={"user": "alice"},
        )
        self.assertEqual(_path_with_query(done), "/employee/orders")

    def test_policy_callable_receives_entry(self):
        app, login_manager = self.create_app()
        seen = []

        def policy_factory(entry):
            seen.append(entry)
            return ContinuationPolicy(allowed_endpoints={"employee.orders"})

        login_manager.continuation_policy = policy_factory
        client = app.test_client()
        client.get("/employee/orders")
        self.assertIn("employee", seen)


class ContinuationSessionTestCase(ContinuationAppMixin, unittest.TestCase):
    """Continuation identifiers travel through the session."""

    continuation_enabled = True
    use_session_for_next = True

    def setUp(self):
        self.user = User("alice")
        USERS["alice"] = self.user
        self.user.grant("employee", "employee.orders")
        self.user.grant("vendor", "vendor.invoices")
        self.app, self.login_manager = self.create_app()

    def test_two_entries_hand_distinct_flow_ids_to_login(self):
        client = self.app.test_client()
        employee_nav = client.get("/employee/orders?status=open")
        vendor_nav = client.get("/vendor/invoices?year=2026")
        self.assertEqual(employee_nav.status_code, 302)
        self.assertEqual(vendor_nav.status_code, 302)
        # Session mode does not leak the flow identifier into the URL.
        self.assertNotIn("continuation", employee_nav.headers["Location"])
        self.assertNotIn("continuation", vendor_nav.headers["Location"])

        employee_token = client.get("/login?entry=employee").data.decode()
        vendor_token = client.get("/login?entry=vendor").data.decode()
        self.assertTrue(employee_token)
        self.assertTrue(vendor_token)
        self.assertNotEqual(employee_token, vendor_token)

        with client.session_transaction() as sess:
            self.assertEqual(
                set(sess["continuation_entries"]),
                {"employee", "vendor"},
            )

    def test_parallel_flows_complete_in_reverse_order_with_revocation(self):
        client = self.app.test_client()
        client.get("/employee/orders?status=open&page=2")
        client.get("/vendor/invoices?year=2026&state=due")

        # Each entry exposes its own flow identifier to the shared login page.
        employee_token = client.get("/login?entry=employee").data.decode()
        vendor_token = client.get("/login?entry=vendor").data.decode()
        self.assertNotEqual(employee_token, vendor_token)
        self.user.revoke("vendor", "vendor.invoices")

        vendor_done = client.post(
            "/login", data={"user": "alice", "entry": "vendor"}
        )
        self.assertEqual(_path_with_query(vendor_done), "/vendor/")

        employee_done = client.post(
            "/login", data={"user": "alice", "entry": "employee"}
        )
        self.assertEqual(
            _path_with_query(employee_done),
            "/employee/orders?status=open&page=2",
        )

        # The consumed identifiers were removed, no other flow was touched.
        with client.session_transaction() as sess:
            self.assertNotIn(employee_token, sess.get("continuation_tokens", []))
            self.assertNotIn(vendor_token, sess.get("continuation_tokens", []))

    def test_other_tab_flow_survives_one_completion(self):
        client = self.app.test_client()
        client.get("/employee/orders?status=open")
        client.get("/vendor/invoices?year=2026")

        employee_token = client.get("/login?entry=employee").data.decode()
        vendor_token = client.get("/login?entry=vendor").data.decode()

        client.post("/login", data={"user": "alice", "entry": "employee"})

        # The vendor flow is still pending in the same session.
        self.assertEqual(
            client.get("/login?entry=vendor").data.decode(), vendor_token
        )
        self.assertNotEqual(employee_token, vendor_token)
        self.assertEqual(
            client.get("/pending?entry=vendor").data.decode(), vendor_token
        )

    def test_remembered_confirmation_uses_same_constraints(self):
        self.user.grant("vendor", "vendor.catalog")
        client = self.app.test_client()
        client.post("/login", data={"user": "alice", "remember": "1"})
        with client.session_transaction() as sess:
            sess.clear()

        client.get("/vendor/catalog?sort=name")
        token = client.get("/token?entry=vendor").data.decode()
        self.assertTrue(token)

        done = client.post("/confirm", data={"entry": "vendor"})
        self.assertEqual(_path_with_query(done), "/vendor/catalog?sort=name")

        # Replaying the consumed flow falls back to the safe home.
        replay = client.post(
            f"/confirm?continuation={token}&continuation_entry=vendor",
            data={"entry": "vendor"},
        )
        self.assertEqual(_path_with_query(replay), "/vendor/")
