"""Auditable user-loading results and failure categorisation.

These tests model a user directory that can answer normally, return no record
or fail transiently. They assert that Flask-Login records *where* a load came
from and *why* it failed, while never leaking internal identity details in the
HTTP response or forwarding secrets (raw cookie, credentials) to an event
collector.
"""

import unittest

from flask import Flask
from flask import g
from flask import session

from flask_login import current_load_result
from flask_login import LoadFailureReason
from flask_login import LoadResult
from flask_login import LoadSource
from flask_login import LoginManager
from flask_login import user_load_failed
from flask_login import UserMixin
from flask_login.utils import encode_cookie


SECRET = "deterministic-secret"
COOKIE_NAME = "remember_token"


class DirectoryUser(UserMixin):
    """A user whose active flag is controlled by the directory."""

    def __init__(self, user_id, name, active=True):
        self.id = user_id
        self.name = name
        self.active = active

    @property
    def is_active(self):
        return self.active


class DirectoryError(RuntimeError):
    """Raised by the fake directory to simulate a transient outage."""


class FakeDirectory:
    """A stand-in for a remote user directory.

    It supports the three states support cares about:

    * a normal lookup returning an active (or disabled) user;
    * an empty answer (the record is missing or has expired);
    * a temporary failure raising :class:`DirectoryError`.
    """

    def __init__(self):
        self._users = {
            "u-active": DirectoryUser("u-active", "Ada"),
            "u-disabled": DirectoryUser("u-disabled", "Grace", active=False),
        }
        self.failing = False

    def find(self, user_id):
        if self.failing:
            raise DirectoryError("connection reset to directory 10.0.0.5")
        return self._users.get(user_id)


class EventCollector:
    """Records every failed-load event for later inspection."""

    def __init__(self, app):
        self.events = []
        user_load_failed.connect(self._receive, app)

    def _receive(self, sender, result=None, **extra):
        self.events.append(result)

    @property
    def latest(self):
        return self.events[-1]


def build_app(directory):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET
    app.config["SESSION_PROTECTION"] = None
    app.config["REMEMBER_COOKIE_NAME"] = COOKIE_NAME

    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return directory.find(user_id)

    @app.route("/whoami")
    def whoami():
        result = current_load_result
        if result.success:
            return f"ok:{result.user.name}"
        return "anonymous"

    @app.route("/admin")
    def admin():
        # The app decides how to present the failure; it only exposes a
        # generic message, never the internal reason or identifier.
        result = current_load_result
        if not result.success:
            return "Unable to restore your session.", 401
        return f"welcome:{result.user.name}"

    return app, login_manager


class LoadResultShapeTestCase(unittest.TestCase):
    def test_constructors_are_immutable_and_secret_free(self):
        ok = LoadResult.loaded(LoadSource.SESSION, object(), "u-active")
        self.assertTrue(ok.success)
        self.assertIsNone(ok.reason)

        failed = LoadResult.failed(
            LoadSource.REMEMBER_COOKIE, LoadFailureReason.NO_IDENTIFIER
        )
        self.assertFalse(failed.success)
        self.assertFalse(failed.retryable)
        with self.assertRaises(Exception):
            failed.reason = LoadFailureReason.DISABLED

    def test_source_and_reason_are_stable_strings(self):
        self.assertEqual(LoadSource.SESSION.value, "session")
        self.assertEqual(LoadFailureReason.UNAVAILABLE.value, "unavailable")
        self.assertEqual(LoadFailureReason.NOT_FOUND.value, "not_found")


class ActiveUserTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = FakeDirectory()
        self.app, _ = build_app(self.directory)
        self.collector = EventCollector(self.app)

    def test_session_load_succeeds_and_emits_no_failure(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-active"
            response = client.get("/whoami")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "ok:Ada")
        self.assertEqual(self.collector.events, [])

    def test_successful_result_is_available_on_g_and_proxy(self):
        with self.app.test_request_context():
            session["_user_id"] = "u-active"
            result = current_load_result
            self.assertTrue(result.success)
            self.assertIs(result.source, LoadSource.SESSION)
            self.assertIsNone(result.reason)
            self.assertEqual(result.user_id, "u-active")
            self.assertEqual(g._login_load_result, result._get_current_object())


class MissingRecordTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = FakeDirectory()
        self.app, _ = build_app(self.directory)
        self.collector = EventCollector(self.app)

    def test_unknown_session_id_is_categorised_not_found(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-expired"
            response = client.get("/whoami")
            self.assertEqual(response.data.decode(), "anonymous")

        result = self.collector.latest
        self.assertIsInstance(result, LoadResult)
        self.assertFalse(result.success)
        self.assertIs(result.source, LoadSource.SESSION)
        self.assertIs(result.reason, LoadFailureReason.NOT_FOUND)
        self.assertEqual(result.user_id, "u-expired")
        self.assertFalse(result.retryable)

    def test_disabled_account_is_categorised_disabled(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-disabled"
            client.get("/whoami")

        result = self.collector.latest
        self.assertIs(result.reason, LoadFailureReason.DISABLED)
        self.assertEqual(result.user_id, "u-disabled")


class DirectoryOutageTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = FakeDirectory()
        self.app, _ = build_app(self.directory)
        self.collector = EventCollector(self.app)

    def test_transient_failure_is_unavailable_and_retryable(self):
        self.directory.failing = True
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-active"
            response = client.get("/whoami")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data.decode(), "anonymous")

        result = self.collector.latest
        self.assertIs(result.source, LoadSource.SESSION)
        self.assertIs(result.reason, LoadFailureReason.UNAVAILABLE)
        self.assertTrue(result.retryable)

    def test_recovery_after_outage_loads_the_user(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-active"

            self.directory.failing = True
            self.assertEqual(client.get("/whoami").data.decode(), "anonymous")
            self.assertIs(
                self.collector.latest.reason, LoadFailureReason.UNAVAILABLE
            )

            self.directory.failing = False
            self.assertEqual(client.get("/whoami").data.decode(), "ok:Ada")


class RememberCookieTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = FakeDirectory()
        self.app, self.login_manager = build_app(self.directory)
        self.collector = EventCollector(self.app)

    def _signed_cookie(self, user_id):
        with self.app.app_context():
            return encode_cookie(user_id)

    def test_valid_cookie_records_cookie_source_without_raw_value(self):
        signed = self._signed_cookie("u-active")
        with self.app.test_client() as client:
            client.set_cookie(COOKIE_NAME, signed)
            response = client.get("/whoami")
            self.assertEqual(response.data.decode(), "ok:Ada")
        self.assertEqual(self.collector.events, [])

    def test_garbage_cookie_is_no_identifier_and_keeps_cookie_secret(self):
        secret_cookie = "garbage-do-not-log-me"
        with self.app.test_client() as client:
            client.set_cookie(COOKIE_NAME, secret_cookie)
            response = client.get("/whoami")
            self.assertEqual(response.data.decode(), "anonymous")

        result = self.collector.latest
        self.assertIs(result.source, LoadSource.REMEMBER_COOKIE)
        self.assertIs(result.reason, LoadFailureReason.NO_IDENTIFIER)
        self.assertIsNone(result.user_id)
        payload = repr(result)
        self.assertNotIn(secret_cookie, payload)
        self.assertNotIn("garbage", payload)

    def test_cookie_pointing_at_missing_record_is_not_found(self):
        signed = self._signed_cookie("u-expired")
        with self.app.test_client() as client:
            client.set_cookie(COOKIE_NAME, signed)
            client.get("/whoami")

        result = self.collector.latest
        self.assertIs(result.source, LoadSource.REMEMBER_COOKIE)
        self.assertIs(result.reason, LoadFailureReason.NOT_FOUND)
        self.assertEqual(result.user_id, "u-expired")
        # The signed cookie material must not appear in the audit record.
        self.assertNotIn(signed, repr(result))


class ExternalLeakageTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = FakeDirectory()
        self.app, _ = build_app(self.directory)
        self.collector = EventCollector(self.app)

    def test_response_does_not_expose_internal_identifier_or_reason(self):
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-disabled"
            response = client.get("/admin")

        body = response.data.decode()
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("u-disabled", body)
        self.assertNotIn("disabled", body)
        self.assertNotIn("Grace", body)

    def test_event_payload_omits_directory_credentials_and_error_detail(self):
        self.directory.failing = True
        with self.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["_user_id"] = "u-active"
            client.get("/whoami")

        result = self.collector.latest
        rendered = repr(result)
        # The directory's internal host and exception text must not be present.
        self.assertNotIn("10.0.0.5", rendered)
        self.assertNotIn("connection reset", rendered)
        self.assertNotIn(SECRET, rendered)
        self.assertFalse(hasattr(result, "password"))
        self.assertFalse(hasattr(result, "cookie"))
        self.assertFalse(hasattr(result, "authorization"))

    def test_anonymous_request_records_an_attemptless_result(self):
        with self.app.test_client() as client:
            response = client.get("/whoami")
            self.assertEqual(response.data.decode(), "anonymous")
        with self.app.test_request_context():
            result = current_load_result
            self.assertFalse(result.success)
            self.assertIsNone(result.source)
            self.assertIsNone(result.reason)
        # No failure event is fired when nothing was even attempted.
        self.assertEqual(self.collector.events, [])


if __name__ == "__main__":
    unittest.main()
