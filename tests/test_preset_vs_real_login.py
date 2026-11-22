"""Parallel tests that keep preloaded sessions separate from real authentication.

``FlaskLoginClient(user=...)`` only writes the ``_user_id`` and ``_fresh``
session keys. It never runs :func:`~flask_login.login_user`, so it cannot prove
anything about the authentication stage of a request: the ``user_logged_in``
signal, the ``_id`` session identifier and remember-me cookies are all created
by a real login instead.

The test cases below use two kinds of client against the same three endpoints
(public, ``login_required`` and ``fresh_login_required``):

* :class:`PresetSessionTestCase` documents what a preloaded session covers -
  access control once a user is already present in the session.
* :class:`RealAuthenticationTestCase` exercises the actual login, remember-me
  and confirm flows and the signals they emit.

A shared :class:`SignalRecorder` and session snapshot helper make the
asymmetry explicit, so dropping the real-authentication tests while keeping
the preset ones fails the coverage guard in
:class:`AuthenticationStageGuardTestCase`.
"""

import unittest
from contextlib import contextmanager

from flask import Flask
from flask import session

from flask_login import confirm_login
from flask_login import current_user
from flask_login import FlaskLoginClient
from flask_login import fresh_login_required
from flask_login import login_fresh
from flask_login import login_required
from flask_login import login_user
from flask_login import LoginManager
from flask_login import logout_user
from flask_login import UserMixin
from flask_login.signals import session_protected
from flask_login.signals import user_accessed
from flask_login.signals import user_loaded_from_cookie
from flask_login.signals import user_logged_in
from flask_login.signals import user_logged_out
from flask_login.signals import user_login_confirmed
from flask_login.signals import user_needs_refresh
from flask_login.signals import user_unauthorized

REMEMBER_COOKIE_NAME = "remember_token"


class User(UserMixin):
    def __init__(self, user_id, name, active=True):
        self.id = user_id
        self.name = name
        self.active = active

    @property
    def is_active(self):
        return self.active


notch = User(1, "Notch")
inactive = User(2, "Inactive", active=False)
USERS = {1: notch, 2: inactive}


class SignalRecorder:
    """Records every emission of the signals it is connected to."""

    def __init__(self):
        self.heard = []

    def record(self, signal_name):
        def handler(sender, **kwargs):
            self.heard.append((signal_name, sender, kwargs))

        return handler

    def names(self):
        return [name for name, _sender, _kwargs in self.heard]

    def assert_emitted(self, signal_name):
        if signal_name not in self.names():
            raise AssertionError(
                f"signal {signal_name!r} was not emitted; got {self.names()!r}"
            )

    def assert_not_emitted(self, signal_name):
        if signal_name in self.names():
            raise AssertionError(f"signal {signal_name!r} was unexpectedly emitted")

    def assert_count(self, signal_name, count):
        actual = self.names().count(signal_name)
        if actual != count:
            raise AssertionError(
                f"signal {signal_name!r} emitted {actual} time(s), expected {count}"
            )


TRACKED_SIGNALS = (
    ("user_logged_in", user_logged_in),
    ("user_logged_out", user_logged_out),
    ("user_loaded_from_cookie", user_loaded_from_cookie),
    ("user_login_confirmed", user_login_confirmed),
    ("user_unauthorized", user_unauthorized),
    ("user_needs_refresh", user_needs_refresh),
    ("user_accessed", user_accessed),
    ("session_protected", session_protected),
)


@contextmanager
def record_signals():
    recorder = SignalRecorder()
    receivers = [
        (signal, signal.connect(recorder.record(name)))
        for name, signal in TRACKED_SIGNALS
    ]
    try:
        yield recorder
    finally:
        for signal, receiver in receivers:
            signal.disconnect(receiver)


def create_app():
    """App exposing public, protected and freshness-gated endpoints."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "deterministic"
    # The preset client does not write an ``_id``; keep session protection off
    # so both clients are compared on access control rather than protection.
    app.config["SESSION_PROTECTION"] = None
    app.config["REMEMBER_COOKIE_NAME"] = REMEMBER_COOKIE_NAME
    app.test_client_class = FlaskLoginClient

    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return USERS.get(int(user_id))

    @app.route("/public")
    def public():
        return "public"

    @app.route("/protected")
    @login_required
    def protected():
        return "protected"

    @app.route("/fresh")
    @fresh_login_required
    def fresh():
        return "fresh"

    @app.route("/whoami")
    def whoami():
        return current_user.name if current_user.is_authenticated else "Anonymous"

    @app.route("/is-fresh")
    def is_fresh():
        return str(login_fresh())

    @app.route("/login")
    def login():
        return str(login_user(notch))

    @app.route("/login-non-fresh")
    def login_non_fresh():
        return str(login_user(notch, fresh=False))

    @app.route("/login-remember")
    def login_remember():
        return str(login_user(notch, remember=True))

    @app.route("/login-inactive")
    def login_inactive():
        return str(login_user(inactive))

    @app.route("/confirm-login")
    def confirm():
        confirm_login()
        return ""

    @app.route("/logout")
    def logout():
        return str(logout_user())

    @app.errorhandler(404)
    def handle_404(error):
        raise error

    return app


class SessionSnapshot:
    """The session and remember-cookie state observable from the client."""

    def __init__(self, client):
        with client.session_transaction() as sess:
            self.keys = sorted(sess.keys())
            self.user_id = sess.get("_user_id")
            self.fresh = sess.get("_fresh")
            self.has_identifier = "_id" in sess
        self.remember_cookie = client.get_cookie(REMEMBER_COOKIE_NAME)

    @property
    def has_remember_cookie(self):
        return self.remember_cookie is not None


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()


class AnonymousAccessTestCase(AppTestCase):
    """Baseline behavior for a client with no preloaded user."""

    def test_public_endpoint_is_open(self):
        with self.app.test_client() as client:
            response = client.get("/public")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "public")

    def test_protected_endpoint_is_unauthorized(self):
        with self.app.test_client() as client:
            with record_signals() as recorder:
                response = client.get("/protected")
            self.assertEqual(response.status_code, 401)
            recorder.assert_emitted("user_unauthorized")
            recorder.assert_not_emitted("user_logged_in")

    def test_fresh_endpoint_is_unauthorized(self):
        with self.app.test_client() as client:
            with record_signals() as recorder:
                response = client.get("/fresh")
            self.assertEqual(response.status_code, 401)
            recorder.assert_emitted("user_unauthorized")
            recorder.assert_not_emitted("user_needs_refresh")

    def test_no_session_or_remember_cookie_is_created(self):
        with self.app.test_client() as client:
            client.get("/public")
            snapshot = SessionSnapshot(client)
            self.assertEqual(snapshot.keys, [])
            self.assertIsNone(snapshot.user_id)
            self.assertFalse(snapshot.has_remember_cookie)


class PresetSessionTestCase(AppTestCase):
    """What ``FlaskLoginClient(user=...)`` can and cannot establish.

    The preset client only seeds ``_user_id`` and ``_fresh``. Requests then go
    through the normal *request loading* path (the user is reloaded by the
    user_loader), but the authentication stage is skipped entirely.
    """

    def test_preset_only_writes_identity_and_freshness(self):
        with self.app.test_client(user=notch) as client:
            snapshot = SessionSnapshot(client)
            self.assertEqual(snapshot.keys, ["_fresh", "_user_id"])
            self.assertEqual(snapshot.user_id, notch.get_id())
            self.assertTrue(snapshot.fresh)
            # A real login writes ``_id``; the preset shortcut does not.
            self.assertFalse(snapshot.has_identifier)
            self.assertFalse(snapshot.has_remember_cookie)

    def test_preset_covers_public_and_protected_endpoints(self):
        with self.app.test_client(user=notch) as client:
            self.assertEqual(client.get("/public").status_code, 200)
            protected = client.get("/protected")
            self.assertEqual(protected.status_code, 200)
            self.assertEqual(protected.data.decode(), "protected")
            self.assertEqual(client.get("/whoami").data.decode(), "Notch")

    def test_preset_does_not_emit_login_signal(self):
        with self.app.test_client(user=notch) as client:
            with record_signals() as recorder:
                client.get("/protected")
            recorder.assert_not_emitted("user_logged_in")
            # The user is still reloaded through the request machinery.
            recorder.assert_emitted("user_accessed")

    def test_preset_fresh_user_passes_fresh_endpoint(self):
        with self.app.test_client(user=notch) as client:
            with record_signals() as recorder:
                response = client.get("/fresh")
            self.assertEqual(response.status_code, 200)
            recorder.assert_not_emitted("user_needs_refresh")
            recorder.assert_not_emitted("user_login_confirmed")

    def test_preset_non_fresh_user_is_asked_to_refresh(self):
        with self.app.test_client(user=notch, fresh_login=False) as client:
            with record_signals() as recorder:
                response = client.get("/fresh")
            self.assertEqual(response.status_code, 401)
            recorder.assert_emitted("user_needs_refresh")
            # Presetting a stale session never confirms a login on its own.
            recorder.assert_not_emitted("user_login_confirmed")

    def test_preset_non_fresh_user_keeps_login_required_access(self):
        with self.app.test_client(user=notch, fresh_login=False) as client:
            response = client.get("/protected")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(client.get("/is-fresh").data.decode(), "False")

    def test_preset_cannot_simulate_remember_me_restoration(self):
        # The preset client has no remember cookie, so loading from a cookie
        # and the associated signal are never exercised by preset sessions.
        with self.app.test_client(user=notch) as client:
            with record_signals() as recorder:
                client.get("/protected")
            recorder.assert_not_emitted("user_loaded_from_cookie")
            self.assertFalse(SessionSnapshot(client).has_remember_cookie)

    def test_preset_logout_is_a_real_logout_stage(self):
        with self.app.test_client(user=notch) as client:
            with record_signals() as recorder:
                response = client.get("/logout")
            self.assertEqual(response.data.decode(), "True")
            recorder.assert_emitted("user_logged_out")
            self.assertEqual(SessionSnapshot(client).keys, [])


class RealAuthenticationTestCase(AppTestCase):
    """The authentication stage that preset sessions cannot substitute for."""

    def test_real_login_writes_full_session_and_emits_signal(self):
        with self.app.test_client() as client:
            with record_signals() as recorder:
                response = client.get("/login")
            self.assertEqual(response.data.decode(), "True")
            recorder.assert_emitted("user_logged_in")
            recorder.assert_count("user_logged_in", 1)

            snapshot = SessionSnapshot(client)
            self.assertEqual(snapshot.user_id, notch.get_id())
            self.assertTrue(snapshot.fresh)
            # Real logins establish the session protection identifier.
            self.assertTrue(snapshot.has_identifier)

    def test_real_login_then_request_keeps_access_without_relogin(self):
        with self.app.test_client() as client:
            client.get("/login")
            with record_signals() as recorder:
                response = client.get("/protected")
            self.assertEqual(response.status_code, 200)
            # The follow-up request only reloads the user; it does not log in.
            recorder.assert_not_emitted("user_logged_in")
            recorder.assert_emitted("user_accessed")

    def test_real_login_rejects_inactive_user(self):
        with self.app.test_client() as client:
            with record_signals() as recorder:
                response = client.get("/login-inactive")
            self.assertEqual(response.data.decode(), "False")
            recorder.assert_not_emitted("user_logged_in")
            self.assertEqual(client.get("/whoami").data.decode(), "Anonymous")
            self.assertIsNone(SessionSnapshot(client).user_id)

    def test_remember_login_sets_cookie_and_restores_unfresh_session(self):
        with self.app.test_client() as client:
            with record_signals() as recorder:
                client.get("/login-remember")
            recorder.assert_emitted("user_logged_in")
            self.assertTrue(SessionSnapshot(client).has_remember_cookie)

            # Drop the session as if the browser had closed; the remember
            # cookie must now restore the user in a non-fresh state.
            with client.session_transaction() as sess:
                sess.clear()

            with record_signals() as cookie_recorder:
                whoami = client.get("/whoami")
            self.assertEqual(whoami.data.decode(), "Notch")
            self.assertEqual(client.get("/is-fresh").data.decode(), "False")
            cookie_recorder.assert_emitted("user_loaded_from_cookie")
            cookie_recorder.assert_not_emitted("user_logged_in")

    def test_restored_remember_session_must_be_refreshed_for_fresh_endpoint(self):
        with self.app.test_client() as client:
            client.get("/login-remember")
            with client.session_transaction() as sess:
                sess.clear()

            with record_signals() as recorder:
                stale = client.get("/fresh")
            self.assertEqual(stale.status_code, 401)
            recorder.assert_emitted("user_needs_refresh")
            recorder.assert_not_emitted("user_login_confirmed")

            with record_signals() as confirm_recorder:
                client.get("/confirm-login")
            confirm_recorder.assert_emitted("user_login_confirmed")
            self.assertEqual(client.get("/is-fresh").data.decode(), "True")
            self.assertEqual(client.get("/fresh").status_code, 200)

    def test_real_logout_clears_session_and_cookie(self):
        with self.app.test_client() as client:
            client.get("/login-remember")
            self.assertTrue(SessionSnapshot(client).has_remember_cookie)

            with record_signals() as recorder:
                client.get("/logout")
            recorder.assert_emitted("user_logged_out")

            snapshot = SessionSnapshot(client)
            self.assertIsNone(snapshot.user_id)
            self.assertNotIn("_fresh", snapshot.keys)
            self.assertNotIn("_id", snapshot.keys)
            self.assertEqual(client.get("/whoami").data.decode(), "Anonymous")

    def test_logged_out_client_loses_protected_access(self):
        with self.app.test_client() as client:
            client.get("/login")
            self.assertEqual(client.get("/protected").status_code, 200)
            client.get("/logout")
            with record_signals() as recorder:
                response = client.get("/protected")
            self.assertEqual(response.status_code, 401)
            recorder.assert_emitted("user_unauthorized")

    def test_non_fresh_login_requires_confirmation(self):
        with self.app.test_client() as client:
            client.get("/login-non-fresh")
            self.assertEqual(client.get("/is-fresh").data.decode(), "False")
            with record_signals() as recorder:
                self.assertEqual(client.get("/fresh").status_code, 401)
                client.get("/confirm-login")
            recorder.assert_emitted("user_needs_refresh")
            recorder.assert_emitted("user_login_confirmed")
            self.assertEqual(client.get("/fresh").status_code, 200)


class AuthenticationStageGuardTestCase(AppTestCase):
    """Fails when preset-only testing silently replaces real authentication.

    These assertions encode the capabilities that a preloaded session does not
    provide. If a future change relied solely on ``FlaskLoginClient(user=...)``
    and removed the real-login coverage, the missing signals and session keys
    below would no longer be asserted anywhere else in the module.
    """

    def test_preset_session_lacks_identifier_that_real_login_creates(self):
        with self.app.test_client(user=notch) as preset:
            preset_snapshot = SessionSnapshot(preset)
        with self.app.test_client() as real:
            real.get("/login")
            real_snapshot = SessionSnapshot(real)

        self.assertFalse(preset_snapshot.has_identifier)
        self.assertTrue(real_snapshot.has_identifier)

    def test_preset_session_never_emits_login_or_cookie_signals(self):
        with self.app.test_client(user=notch) as preset:
            with record_signals() as recorder:
                preset.get("/protected")
            recorder.assert_not_emitted("user_logged_in")
            recorder.assert_not_emitted("user_loaded_from_cookie")
            recorder.assert_not_emitted("user_login_confirmed")

    def test_remember_cookie_is_only_available_through_real_login(self):
        with self.app.test_client(user=notch) as preset:
            preset.get("/protected")
            self.assertFalse(SessionSnapshot(preset).has_remember_cookie)
        with self.app.test_client() as real:
            real.get("/login-remember")
            self.assertTrue(SessionSnapshot(real).has_remember_cookie)


if __name__ == "__main__":
    unittest.main()
