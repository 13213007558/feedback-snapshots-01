"""Integration tests that verify the provenance and freshness of a session.

A release check that only loads a page with a preset ``FlaskLoginClient``
user cannot tell a real login apart from a planted session. These tests
drive the three ways a session can acquire an identity (preset test-client
session, real form login, and remember-cookie restore) through the same
pages, and check for every step the page results, the signal sequence, the
session freshness, and the remember-cookie changes, so a failure points at
the first step that diverges.
"""

import unittest

from flask import Flask
from flask import request

from flask_login import confirm_login
from flask_login import current_user
from flask_login import FlaskLoginClient
from flask_login import fresh_login_required
from flask_login import login_fresh
from flask_login import login_required
from flask_login import login_user
from flask_login import LoginManager
from flask_login import logout_user
from flask_login import session_protected
from flask_login import user_loaded_from_cookie
from flask_login import user_logged_in
from flask_login import user_logged_out
from flask_login import user_login_confirmed
from flask_login import UserMixin

TRACKED_SIGNALS = {
    "user_logged_in": user_logged_in,
    "user_logged_out": user_logged_out,
    "user_loaded_from_cookie": user_loaded_from_cookie,
    "user_login_confirmed": user_login_confirmed,
    "session_protected": session_protected,
}


class User(UserMixin):
    def __init__(self, name, id):
        self.id = id
        self.name = name

    def get_id(self):
        return self.id


notch = User("Notch", "1")
USERS = {notch.id: notch}


def build_app(label, protection, remember_cookie_name):
    """An app with a normal page and a page that requires re-confirmation."""
    app = Flask(f"provenance_{label}")
    app.config["SECRET_KEY"] = "deterministic"
    app.config["SESSION_PROTECTION"] = protection
    app.config["REMEMBER_COOKIE_NAME"] = remember_cookie_name
    # Keep the remember cookie stable so a step can assert "unchanged".
    app.config["REMEMBER_COOKIE_REFRESH_EACH_REQUEST"] = False
    app.test_client_class = FlaskLoginClient

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.refresh_view = "refresh"

    @app.route("/login", methods=["POST"])
    def login():
        login_user(notch, remember=True)
        return "logged-in"

    @app.route("/profile")
    @login_required
    def profile():
        return f"{current_user.name}|fresh={login_fresh()}"

    @app.route("/sensitive")
    @fresh_login_required
    def sensitive():
        return "sensitive-ok"

    @app.route("/refresh")
    def refresh():
        return "refresh-page"

    @app.route("/confirm", methods=["POST"])
    def confirm():
        confirm_login()
        return "confirmed"

    @app.route("/logout", methods=["POST"])
    def logout():
        logout_user()
        return "logged-out"

    @login_manager.user_loader
    def load_user(user_id):
        return USERS.get(user_id)

    @app.errorhandler(404)
    def handle_404(e):
        raise e

    return app


class EventLog:
    """Records signals with the emitting app and the triggering request."""

    def __init__(self, apps):
        self.labels = {id(app): label for label, app in apps.items()}
        self.records = []
        self._handlers = []

    def __enter__(self):
        for name, signal in TRACKED_SIGNALS.items():
            handler = self._make_handler(name)
            signal.connect(handler)
            self._handlers.append((signal, handler))
        return self

    def __exit__(self, *exc):
        for signal, handler in self._handlers:
            signal.disconnect(handler)
        self._handlers.clear()

    def _make_handler(self, name):
        def record(sender, **kwargs):
            label = self.labels.get(id(sender), "unknown")
            self.records.append((label, name, f"{request.method} {request.path}"))

        return record


class Step:
    """One reproducible operation and everything expected around it.

    ``remember`` declares the remember-cookie change: "set", "deleted",
    "unchanged", or "absent". ``events`` declares the exact sequence of
    ``(app, signal, request)`` tuples emitted while performing the step.
    """

    def __init__(
        self,
        label,
        client=None,
        method="GET",
        path=None,
        status=200,
        body=None,
        location=None,
        events=(),
        remember=None,
    ):
        self.label = label
        self.client = client
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        self.location = location
        self.events = events
        self.remember = remember


class SessionProvenanceTestCase(unittest.TestCase):
    def setUp(self):
        self.basic_app = build_app("basic", "basic", "remember_basic")
        self.strong_app = build_app("strong", "strong", "remember_strong")
        self.apps = {"basic": self.basic_app, "strong": self.strong_app}
        self.cookie_names = {}

    def make_client(self, label, preset=False):
        app = self.apps[label]
        client = app.test_client(user=notch) if preset else app.test_client()
        self.cookie_names[client] = app.config["REMEMBER_COOKIE_NAME"]
        return client

    def event_log(self):
        return EventLog(self.apps)

    def _cookie_value(self, client, cookie_name):
        cookie = client.get_cookie(cookie_name)
        return None if cookie is None else cookie.value

    def _check_cookie(self, expectation, before, after, where):
        if expectation == "set":
            ok = after is not None and after != before
        elif expectation == "deleted":
            ok = before is not None and after is None
        elif expectation == "unchanged":
            ok = before is not None and before == after
        elif expectation == "absent":
            ok = after is None
        else:
            raise ValueError(f"unknown cookie expectation {expectation!r}")
        if not ok:
            self.fail(
                f"{where}: remember cookie should be {expectation},"
                f" went from {before!r} to {after!r}"
            )

    def run_steps(self, steps, log):
        # A stable client identity: every request carries the same
        # User-Agent so the session-protection identifier never changes.
        headers = {"User-Agent": "provenance-test/1.0"}
        cursor = 0
        for index, step in enumerate(steps):
            where = f"step {index} ({step.label})"
            cookie_name = self.cookie_names[step.client]
            before = self._cookie_value(step.client, cookie_name)

            if step.method == "CLEAR_SESSION":
                # Simulate the browser closing: drop the session, keep the
                # remember cookie.
                with step.client.session_transaction() as sess:
                    sess.clear()
            else:
                response = step.client.open(step.path, method=step.method, headers=headers)
                self.assertEqual(step.status, response.status_code, f"{where}: status")
                if step.body is not None:
                    self.assertEqual(
                        step.body,
                        response.data.decode("utf-8"),
                        f"{where}: body",
                    )
                if step.location is not None:
                    location = response.location or ""
                    self.assertTrue(
                        location.startswith(step.location),
                        f"{where}: redirect {location!r} does not start" f" with {step.location!r}",
                    )

            seen = log.records[cursor:]
            cursor = len(log.records)
            self.assertEqual(list(step.events), seen, f"{where}: events")

            if step.remember is not None:
                after = self._cookie_value(step.client, cookie_name)
                self._check_cookie(step.remember, before, after, where)

    def test_interleaved_apps_full_lifecycle(self):
        """Two apps (basic and strong) share one process and one event log.

        Requests are interleaved while the basic app walks the full flow:
        form login, remember-cookie restore, re-confirmation, and logout.
        """
        basic_form = self.make_client("basic")
        basic_second = self.make_client("basic")
        strong_form = self.make_client("strong")
        strong_preset = self.make_client("strong", preset=True)

        steps = [
            Step(
                "preset session on strong app is anonymous",
                strong_preset,
                path="/profile",
                status=302,
                location="/login",
                events=[("strong", "session_protected", "GET /profile")],
                remember="absent",
            ),
            Step(
                "form login on basic app",
                basic_form,
                method="POST",
                path="/login",
                body="logged-in",
                events=[("basic", "user_logged_in", "POST /login")],
                remember="set",
            ),
            Step(
                "form login on strong app",
                strong_form,
                method="POST",
                path="/login",
                body="logged-in",
                events=[("strong", "user_logged_in", "POST /login")],
                remember="set",
            ),
            Step(
                "second basic browser logs in",
                basic_second,
                method="POST",
                path="/login",
                body="logged-in",
                events=[("basic", "user_logged_in", "POST /login")],
                remember="set",
            ),
            Step(
                "basic profile is fresh after form login",
                basic_form,
                path="/profile",
                body="Notch|fresh=True",
                events=[],
                remember="unchanged",
            ),
            Step(
                "preset session on strong app stays anonymous",
                strong_preset,
                path="/profile",
                status=302,
                location="/login",
                events=[("strong", "session_protected", "GET /profile")],
            ),
            Step(
                "strong real login reaches confirm page",
                strong_form,
                path="/sensitive",
                body="sensitive-ok",
                events=[],
            ),
            Step(
                "basic real login reaches confirm page",
                basic_form,
                path="/sensitive",
                body="sensitive-ok",
                events=[],
                remember="unchanged",
            ),
            Step(
                "basic browser closes, remember cookie survives",
                basic_form,
                method="CLEAR_SESSION",
                events=[],
                remember="unchanged",
            ),
            Step(
                "basic session restored from remember cookie",
                basic_form,
                path="/profile",
                body="Notch|fresh=False",
                events=[("basic", "user_loaded_from_cookie", "GET /profile")],
                remember="unchanged",
            ),
            Step(
                "restored session must re-confirm for confirm page",
                basic_form,
                path="/sensitive",
                status=302,
                location="/refresh",
                events=[("basic", "session_protected", "GET /sensitive")],
            ),
            Step(
                "strong browser unaffected by basic restore",
                strong_form,
                path="/profile",
                body="Notch|fresh=True",
                events=[],
            ),
            Step(
                "re-confirm the restored session",
                basic_form,
                method="POST",
                path="/confirm",
                body="confirmed",
                events=[("basic", "user_login_confirmed", "POST /confirm")],
            ),
            Step(
                "confirmed session reaches confirm page",
                basic_form,
                path="/sensitive",
                body="sensitive-ok",
                events=[],
            ),
            Step(
                "logout the basic browser",
                basic_form,
                method="POST",
                path="/logout",
                body="logged-out",
                events=[("basic", "user_logged_out", "POST /logout")],
                remember="deleted",
            ),
            Step(
                "logged-out browser is anonymous again",
                basic_form,
                path="/profile",
                status=302,
                location="/login",
                events=[("basic", "session_protected", "GET /profile")],
                remember="absent",
            ),
            Step(
                "second basic browser keeps its identity",
                basic_second,
                path="/profile",
                body="Notch|fresh=True",
                events=[],
            ),
            Step(
                "strong browser keeps its identity",
                strong_form,
                path="/profile",
                body="Notch|fresh=True",
                events=[],
            ),
        ]

        with self.event_log() as log:
            self.run_steps(steps, log)

    def test_real_login_vs_preset_session(self):
        """The same account enters the same pages through a real form login
        and through a session preset by FlaskLoginClient, used exactly as
        the preset client created it."""
        basic_real = self.make_client("basic")
        basic_preset = self.make_client("basic", preset=True)
        strong_real = self.make_client("strong")
        strong_preset = self.make_client("strong", preset=True)

        steps = [
            Step(
                "real form login on basic app",
                basic_real,
                method="POST",
                path="/login",
                body="logged-in",
                events=[("basic", "user_logged_in", "POST /login")],
                remember="set",
            ),
            Step(
                "real form login on strong app",
                strong_real,
                method="POST",
                path="/login",
                body="logged-in",
                events=[("strong", "user_logged_in", "POST /login")],
                remember="set",
            ),
            Step(
                "real login reaches confirm page on basic app",
                basic_real,
                path="/sensitive",
                body="sensitive-ok",
                events=[],
            ),
            Step(
                "real login reaches confirm page on strong app",
                strong_real,
                path="/sensitive",
                body="sensitive-ok",
                events=[],
            ),
            Step(
                "preset session on basic app is downgraded to unfresh",
                basic_preset,
                path="/profile",
                body="Notch|fresh=False",
                events=[("basic", "session_protected", "GET /profile")],
                remember="absent",
            ),
            Step(
                "preset session on basic app must re-confirm",
                basic_preset,
                path="/sensitive",
                status=302,
                location="/refresh",
                events=[("basic", "session_protected", "GET /sensitive")],
            ),
            Step(
                "preset session on strong app is back to anonymous",
                strong_preset,
                path="/profile",
                status=302,
                location="/login",
                events=[("strong", "session_protected", "GET /profile")],
                remember="absent",
            ),
            Step(
                "anonymous preset session cannot reach confirm page",
                strong_preset,
                path="/sensitive",
                status=302,
                location="/login",
                events=[("strong", "session_protected", "GET /sensitive")],
            ),
        ]

        with self.event_log() as log:
            self.run_steps(steps, log)

        logged_in = [r for r in log.records if r[1] == "user_logged_in"]
        self.assertEqual(
            [
                ("basic", "user_logged_in", "POST /login"),
                ("strong", "user_logged_in", "POST /login"),
            ],
            logged_in,
            "only the real form logins may emit user_logged_in",
        )


if __name__ == "__main__":
    unittest.main()
