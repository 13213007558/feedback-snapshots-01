import logging

import flask
import pytest
from flask_session.base import ServerSideSessionInterface


class DictStoreSessionInterface(ServerSideSessionInterface):
    """Stand-in backend that stores the session dict directly (cachelib-style)."""

    def __init__(self, app):
        self.store = {}
        super().__init__(app)

    def _retrieve_session_data(self, store_id):
        return self.store.get(store_id)

    def _delete_session(self, store_id):
        self.store.pop(store_id, None)

    def _upsert_session(self, session_lifetime, session, store_id):
        self.store[store_id] = dict(session)


class SerializedStoreSessionInterface(ServerSideSessionInterface):
    """Stand-in backend that serializes before storing (redis-style)."""

    def __init__(self, app):
        self.store = {}
        super().__init__(app)

    def _retrieve_session_data(self, store_id):
        serialized = self.store.get(store_id)
        if serialized is not None:
            return self.serializer.loads(serialized)
        return None

    def _delete_session(self, store_id):
        self.store.pop(store_id, None)

    def _upsert_session(self, session_lifetime, session, store_id):
        self.store[store_id] = self.serializer.dumps(dict(session))


def create_app(interface_cls, max_size=100):
    app = flask.Flask(__name__)
    app.config["SESSION_SERIALIZATION_FORMAT"] = "json"
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_MAX_SIZE"] = max_size

    @app.route("/set", methods=["POST"])
    def app_set():
        flask.session["value"] = flask.request.form["value"]
        return "value set"

    @app.route("/modify", methods=["POST"])
    def app_modify():
        flask.session["value"] = flask.request.form["value"]
        return "value set"

    @app.route("/get")
    def app_get():
        return flask.session.get("value", "no value set")

    app.session_interface = interface_cls(app)
    return app


def session_cookie(response):
    for header in response.headers.getlist("Set-Cookie"):
        if header.startswith("session="):
            return header
    return None


def store_id_from_cookie(cookie):
    sid = cookie.split(";")[0].split("=")[1]
    return f"session:{sid}"


@pytest.fixture(
    params=[DictStoreSessionInterface, SerializedStoreSessionInterface],
    ids=["dict-store", "serialized-store"],
)
def interface_cls(request):
    return request.param


class TestSessionSizeBudget:
    def test_small_session_saved(self, interface_cls):
        app = create_app(interface_cls)
        client = app.test_client()

        response = client.post("/set", data={"value": "42"})
        cookie = session_cookie(response)
        assert cookie is not None
        assert store_id_from_cookie(cookie) in app.session_interface.store
        assert client.get("/get").data == b"42"

    def test_oversized_update_rejected(self, interface_cls, caplog):
        app = create_app(interface_cls)
        client = app.test_client()

        # An initial small session is saved and a cookie is set
        response = client.post("/set", data={"value": "42"})
        cookie = session_cookie(response)
        assert cookie is not None
        store_id = store_id_from_cookie(cookie)
        previous_record = app.session_interface.store[store_id]

        # An oversized update to the existing session is rejected
        with caplog.at_level(logging.WARNING):
            response = client.post("/modify", data={"value": "x" * 500})

        # No new session cookie is issued for the rejected save
        assert session_cookie(response) is None

        # The rejection is logged, identifying the refused save operation
        assert store_id in caplog.text
        assert "SESSION_MAX_SIZE" in caplog.text

        # The previously stored record is preserved untouched
        assert app.session_interface.store[store_id] == previous_record

        # The previous state is still readable by the client
        assert client.get("/get").data == b"42"

    def test_unlimited_by_default(self, interface_cls):
        app = create_app(interface_cls, max_size=None)
        client = app.test_client()

        response = client.post("/set", data={"value": "x" * 500})
        cookie = session_cookie(response)
        assert cookie is not None
        assert store_id_from_cookie(cookie) in app.session_interface.store
