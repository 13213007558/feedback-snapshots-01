import unittest

from flask import Flask
from flask import session

from flask_login import current_user
from flask_login import login_recovery_result
from flask_login import login_required
from flask_login import login_user
from flask_login import LoginManager
from flask_login import RecoveryReason
from flask_login import RecoveryResult
from flask_login import RecoverySource
from flask_login import UserDirectoryUnavailable
from flask_login import UserMixin
from flask_login import UserNotFound
from flask_login import user_recovery_completed

COOKIE_NAME = "remember"

# Sensitive fragments that must never appear in a published audit record.
SECRET_COOKIE_FRAGMENT = "1|"
SECRET_DIRECTORY_TEXT = "ldap://directory.internal secret-token"


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

    def get_id(self):
        return str(self.id)


class ControllableDirectory:
    """A stand-in user directory whose answer is controlled per request."""

    def __init__(self):
        self.mode = "ok"
        self.calls = []

    def load(self, user_id):
        self.calls.append(user_id)
        if self.mode == "ok":
            return User(user_id)
        if self.mode == "invalid":
            raise UserNotFound(SECRET_DIRECTORY_TEXT)
        if self.mode == "unavailable":
            raise UserDirectoryUnavailable(SECRET_DIRECTORY_TEXT)
        raise RuntimeError("unexpected directory mode")


class RecoveryTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = ControllableDirectory()
        self.audit = []

        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "deterministic"
        self.app.config["SESSION_PROTECTION"] = None
        self.app.config["REMEMBER_COOKIE_NAME"] = COOKIE_NAME
        # The remember cookie is renewed on every authenticated request.
        self.app.config["REMEMBER_COOKIE_REFRESH_EACH_REQUEST"] = True

        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)

        @self.login_manager.user_loader
        def load_user(user_id):
            return self.directory.load(user_id)

        @self.login_manager.request_loader
        def load_from_request(request):
            # Only authenticates requests that carry no browser login state.
            if session.get("_user_id") is not None or COOKIE_NAME in request.cookies:
                return None
            token = request.headers.get("X-Api-User")
            return User(token) if token else None

        @self.app.route("/login")
        def login():
            return str(login_user(User("1"), remember=True))

        @self.app.route("/protected")
        @login_required
        def protected():
            # The view reads the current user like an application would.
            return f"user={current_user.get_id()}"

        @self.app.route("/recovery")
        def recovery():
            result = login_recovery_result()
            return ",".join(
                [
                    result.reason.value,
                    "none" if result.source is None else result.source.value,
                    "|".join(source.value for source in result.sources),
                ]
            )

        @self.app.route("/render")
        @login_required
        def render():
            from flask import render_template_string

            # Access the user from the view and again from the template.
            _ = current_user.get_id()
            return render_template_string(
                "{{ current_user.get_id() }}:{{ login_recovery_result().reason.value }}"
            )

        self.app.jinja_env.globals["login_recovery_result"] = login_recovery_result

        @self.app.errorhandler(404)
        def handle_404(e):
            raise e

        user_recovery_completed.connect(self._record)
        self.addCleanup(user_recovery_completed.disconnect, self._record)

    def _record(self, sender, result):
        self.audit.append(result)

    # -- helpers -----------------------------------------------------------
    def _remember_cookie_headers(self, response):
        return [
            header
            for header in response.headers.getlist("Set-Cookie")
            if header.startswith(f"{COOKIE_NAME}=")
        ]

    def _has_remember_cookie(self, client):
        return client.get_cookie(COOKIE_NAME) is not None

    def _clear_session(self, client):
        with client.session_transaction() as sess:
            sess.clear()

    def _login_and_close_browser(self, client):
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self._has_remember_cookie(client))
        # Simulate the browser closing: the session is gone, the cookie stays.
        self._clear_session(client)

    # -- end to end lifecycle ---------------------------------------------
    def test_success_outage_recovery_lifecycle_and_cookie_renewal(self):
        with self.app.test_client() as client:
            self._login_and_close_browser(client)

            # 1. A successful recovery renews the remember cookie.
            self.directory.mode = "ok"
            self.audit.clear()
            response = client.get("/protected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "user=1")
            self.assertEqual(len(self._remember_cookie_headers(response)), 1)

            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.SUCCESS)
            self.assertEqual(result.source, RecoverySource.REMEMBER_COOKIE)
            self.assertEqual(result.sources, (RecoverySource.REMEMBER_COOKIE,))
            self.assertEqual(
                result.reasons,
                {RecoverySource.REMEMBER_COOKIE: RecoveryReason.SUCCESS},
            )

            # The restored session now coexists with the remember cookie.
            with client.session_transaction() as sess:
                self.assertEqual(sess.get("_user_id"), "1")

            # 2. The directory is temporarily unavailable. The protected page
            #    stays unauthorized and the cookie must not be renewed.
            self.directory.mode = "unavailable"
            self.audit.clear()
            response = client.get("/protected")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(self._remember_cookie_headers(response), [])
            # The browser still holds its original remember cookie.
            self.assertTrue(self._has_remember_cookie(client))
            # The session login material is preserved for the next recovery.
            with client.session_transaction() as sess:
                self.assertEqual(sess.get("_user_id"), "1")

            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.UNAVAILABLE)
            self.assertIsNone(result.source)
            # A single terminal verdict constrains the whole request.
            self.assertEqual(result.sources, (RecoverySource.SESSION,))

            # 3. The same browser recovers normally on the next request and
            #    the remember cookie is renewed again.
            self.directory.mode = "ok"
            self.audit.clear()
            response = client.get("/protected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "user=1")
            self.assertEqual(len(self._remember_cookie_headers(response)), 1)
            self.assertEqual(self.audit[-1].reason, RecoveryReason.SUCCESS)

    def test_outage_keeps_remember_only_material_for_next_recovery(self):
        with self.app.test_client() as client:
            self._login_and_close_browser(client)

            # Remember-only recovery hits a temporary outage.
            self.directory.mode = "unavailable"
            response = client.get("/protected")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(self._remember_cookie_headers(response), [])
            self.assertTrue(self._has_remember_cookie(client))

            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.UNAVAILABLE)
            self.assertEqual(result.sources, (RecoverySource.REMEMBER_COOKIE,))

            # The next, healthy request recovers from the untouched cookie.
            self.directory.mode = "ok"
            response = client.get("/protected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(self._remember_cookie_headers(response)), 1)
            self.assertEqual(self.audit[-1].reason, RecoveryReason.SUCCESS)
            self.assertEqual(self.audit[-1].source, RecoverySource.REMEMBER_COOKIE)

    # -- confirmed invalidation -------------------------------------------
    def test_invalid_clears_login_state_and_remember_cookie(self):
        with self.app.test_client() as client:
            self._login_and_close_browser(client)

            self.directory.mode = "invalid"
            self.audit.clear()
            response = client.get("/protected")
            self.assertEqual(response.status_code, 401)

            # The remember cookie is explicitly deleted, never renewed.
            cookie_headers = self._remember_cookie_headers(response)
            self.assertEqual(len(cookie_headers), 1)
            self.assertTrue(cookie_headers[0].startswith(f"{COOKIE_NAME}=;"))
            self.assertFalse(self._has_remember_cookie(client))

            with client.session_transaction() as sess:
                self.assertNotIn("_user_id", sess)
                self.assertNotIn("_fresh", sess)
                self.assertNotIn("_remember", sess)

            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.INVALID)
            self.assertIsNone(result.source)

    def test_next_request_after_invalidation_is_anonymous(self):
        with self.app.test_client() as client:
            self._login_and_close_browser(client)

            self.directory.mode = "invalid"
            client.get("/protected")

            # With the directory healthy again there is nothing to recover.
            self.directory.mode = "ok"
            self.audit.clear()
            response = client.get("/recovery")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "no_user,none,request")
            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.NO_USER)
            self.assertEqual(result.sources, (RecoverySource.REQUEST,))
            self.assertIsNone(result.source)

    def test_invalid_in_session_clears_cookie_even_with_refresh_enabled(self):
        with self.app.test_client() as client:
            client.get("/login")
            # Session and remember cookie now coexist in this browser.
            self.assertTrue(self._has_remember_cookie(client))

            self.directory.mode = "invalid"
            response = client.get("/protected")
            self.assertEqual(response.status_code, 401)
            cookie_headers = self._remember_cookie_headers(response)
            self.assertEqual(len(cookie_headers), 1)
            self.assertTrue(cookie_headers[0].startswith(f"{COOKIE_NAME}=;"))
            self.assertFalse(self._has_remember_cookie(client))
            self.assertEqual(self.audit[-1].reason, RecoveryReason.INVALID)

    def test_invalid_does_not_touch_unrelated_session_data(self):
        with self.app.test_client() as client:
            client.get("/login")
            with client.session_transaction() as sess:
                sess["next"] = "/dashboard"
                sess["other"] = "keep-me"

            self.directory.mode = "invalid"
            client.get("/protected")

            with client.session_transaction() as sess:
                self.assertNotIn("_user_id", sess)
                self.assertEqual(sess.get("next"), "/dashboard")
                self.assertEqual(sess.get("other"), "keep-me")

    # -- coexistence produces a single terminal state ---------------------
    def test_coexistence_yields_single_terminal_state(self):
        with self.app.test_client() as client:
            client.get("/login")
            # Both a session and a remember cookie are present.
            self.directory.mode = "unavailable"
            self.audit.clear()
            response = client.get("/recovery")

            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.UNAVAILABLE)
            # Only the session source is consulted; the verdict is terminal.
            self.assertEqual(result.sources, (RecoverySource.SESSION,))
            self.assertIsNone(result.source)
            self.assertEqual(
                result.reasons, {RecoverySource.SESSION: RecoveryReason.UNAVAILABLE}
            )
            # No renewal despite REMEMBER_COOKIE_REFRESH_EACH_REQUEST.
            self.assertEqual(self._remember_cookie_headers(response), [])

    # -- request loader remains independent -------------------------------
    def test_request_loader_still_authenticates_without_browser_state(self):
        with self.app.test_client() as client:
            self.audit.clear()
            response = client.get("/protected", headers={"X-Api-User": "9"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "user=9")

            result = self.audit[-1]
            self.assertEqual(result.reason, RecoveryReason.SUCCESS)
            self.assertEqual(result.source, RecoverySource.REQUEST)
            self.assertEqual(result.sources, (RecoverySource.REQUEST,))

    def test_request_loader_not_used_when_browser_state_present(self):
        with self.app.test_client() as client:
            self._login_and_close_browser(client)
            # Even with an API header, the browser cookie governs recovery.
            self.directory.mode = "unavailable"
            response = client.get("/protected", headers={"X-Api-User": "9"})
            self.assertEqual(response.status_code, 401)
            self.assertEqual(self.audit[-1].reason, RecoveryReason.UNAVAILABLE)
            self.assertEqual(
                self.audit[-1].sources, (RecoverySource.REMEMBER_COOKIE,)
            )

    # -- accessor and publication semantics -------------------------------
    def test_accessor_returns_same_object_for_whole_request(self):
        with self.app.test_client() as client:
            client.get("/login")
            self.audit.clear()
            response = client.get("/render")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "1:success")

            # Hook, view and template access all map to one recovery run.
            self.assertEqual(len(self.audit), 1)
            self.assertIsInstance(self.audit[0], RecoveryResult)

    def test_audit_published_once_across_hook_view_and_template(self):
        captured = []

        def before_request():
            # Trigger recovery from a before-request hook.
            captured.append(login_recovery_result())

        self.app.before_request(before_request)
        with self.app.test_client() as client:
            client.get("/login")
            self.audit.clear()
            response = client.get("/render")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(self.audit), 1)
            self.assertIs(captured[-1], self.audit[0])

    def test_audit_record_contains_no_sensitive_material(self):
        with self.app.test_client() as client:
            self._login_and_close_browser(client)
            self.directory.mode = "invalid"
            client.get("/protected")

        record = repr(self.audit[-1])
        self.assertNotIn(SECRET_COOKIE_FRAGMENT, record)
        self.assertNotIn(SECRET_DIRECTORY_TEXT, record)
        # Only enum categories are exposed.
        self.assertEqual(self.audit[-1].reason, RecoveryReason.INVALID)

    def test_unknown_exception_is_not_classified(self):
        class ExplodingDirectory(ControllableDirectory):
            def load(self, user_id):
                raise RuntimeError(SECRET_DIRECTORY_TEXT)

        app = Flask(__name__)
        app.testing = True
        app.config["SECRET_KEY"] = "deterministic"
        app.config["SESSION_PROTECTION"] = None
        app.config["REMEMBER_COOKIE_NAME"] = COOKIE_NAME
        manager = LoginManager()
        manager.init_app(app)
        exploding = ExplodingDirectory()

        @manager.user_loader
        def load_user(user_id):
            return exploding.load(user_id)

        @app.route("/login")
        def login():
            return str(login_user(User("1")))

        @app.route("/protected")
        @login_required
        def protected():
            return "ok"

        published = []
        user_recovery_completed.connect(lambda sender, result: published.append(result))
        with app.test_client() as client:
            client.get("/login")
            with self.assertRaises(RuntimeError):
                client.get("/protected")
        # No recovery record is published when an unexpected error escapes.
        self.assertEqual(published, [])

    def test_recovery_result_outside_request_is_none(self):
        self.assertIsNone(login_recovery_result())

    def test_no_credentials_result_for_anonymous_request(self):
        # An app without a request loader has no source to consult at all.
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "deterministic"
        app.config["SESSION_PROTECTION"] = None
        app.config["REMEMBER_COOKIE_NAME"] = COOKIE_NAME
        manager = LoginManager()
        manager.init_app(app)

        @manager.user_loader
        def load_user(user_id):
            return self.directory.load(user_id)

        @app.route("/recovery")
        def recovery():
            result = login_recovery_result()
            return ",".join(
                [
                    result.reason.value,
                    "none" if result.source is None else result.source.value,
                    "|".join(source.value for source in result.sources),
                ]
            )

        with app.test_client() as client:
            response = client.get("/recovery")
            self.assertEqual(response.data.decode(), "no_credentials,none,")
            # Accessing the same object again does not republish the result.
            result = login_recovery_result()
            self.assertEqual(result.reason, RecoveryReason.NO_CREDENTIALS)
            self.assertEqual(result.sources, ())
            self.assertIsNone(result.source)
            self.assertEqual(result.reasons, {})


if __name__ == "__main__":
    unittest.main()
