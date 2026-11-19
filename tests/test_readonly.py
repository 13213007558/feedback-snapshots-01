import os
import re
import shutil
import struct
import time

import flask
import pytest
from cachelib.file import FileSystemCache

from flask_session.base import ReadOnlySessionError
from flask_session.cachelib import CacheLibSession

SESSION_DIR = "testing_readonly_storage"


def _stored_expiry(cache: FileSystemCache, store_id: str) -> int:
    filename = cache._get_filename(store_id)
    with open(filename, "rb") as handle:
        return struct.unpack("I", handle.read(4))[0]


def create_app(readonly_endpoints):
    app = flask.Flask(__name__)
    app.config.update(
        SECRET_KEY="readonly-test-secret",
        SESSION_TYPE="cachelib",
        SESSION_SERIALIZATION_FORMAT="json",
        SESSION_PERMANENT=False,
        SESSION_READONLY_ENDPOINTS=readonly_endpoints,
        SESSION_CACHELIB=FileSystemCache(threshold=500, cache_dir=SESSION_DIR),
    )

    @app.route("/set", methods=["POST"])
    def app_set():
        flask.session["value"] = flask.request.form["value"]
        return "value set"

    @app.route("/get")
    def app_get():
        return flask.session.get("value", "no value set")

    @app.route("/inspect")
    def app_inspect():
        return flask.session.get("value", "no value set")

    @app.route("/ro-write")
    def app_ro_write():
        flask.session["boom"] = "should fail"
        return "unreachable"

    @app.route("/ro-delete")
    def app_ro_delete():
        del flask.session["value"]
        return "unreachable"

    import flask_session

    flask_session.Session(app)
    return app


@pytest.fixture()
def app():
    if os.path.isdir(SESSION_DIR):
        shutil.rmtree(SESSION_DIR)
    yield create_app(
        readonly_endpoints=(
            "app_inspect",
            re.compile(r"^app_ro_.*"),
        )
    )
    if os.path.isdir(SESSION_DIR):
        shutil.rmtree(SESSION_DIR)


def test_readonly_request_still_sets_vary_header(app):
    client = app.test_client()
    client.post("/set", data={"value": "42"})

    response = client.get("/inspect")
    assert response.data == b"42"
    assert response.headers["Vary"] == "Cookie"


def test_readonly_request_does_not_refresh_backend_ttl(app):
    client = app.test_client()
    client.post("/set", data={"value": "42"})

    interface = app.session_interface
    cookie = client.get_cookie("session")
    store_id = f"session:{cookie.value}"
    assert interface.cache.get(store_id) == {"value": "42"}

    expiry_before = _stored_expiry(interface.cache, store_id)
    time.sleep(1.1)
    response = client.get("/inspect")
    assert response.status_code == 200
    expiry_after = _stored_expiry(interface.cache, store_id)

    assert expiry_after == expiry_before
    assert interface.cache.get(store_id) == {"value": "42"}


def test_readonly_request_does_not_set_cookie(app):
    client = app.test_client()
    client.post("/set", data={"value": "42"})

    response = client.get("/inspect")
    assert "Set-Cookie" not in response.headers


def test_write_on_readonly_endpoint_blocks_backend_write(app, caplog):
    client = app.test_client()
    client.post("/set", data={"value": "42"})

    with caplog.at_level("ERROR"):
        response = client.get("/ro-write")
    assert response.status_code == 500
    assert "Exception on /ro-write" in caplog.text

    # The backend must be untouched after the blocked write.
    cookie = client.get_cookie("session")
    store_id = f"session:{cookie.value}"
    assert app.session_interface.cache.get(store_id) == {"value": "42"}


def test_delete_on_readonly_endpoint_returns_500_and_keeps_backend(app, caplog):
    client = app.test_client()
    client.post("/set", data={"value": "42"})

    with caplog.at_level("ERROR"):
        response = client.get("/ro-delete")
    assert response.status_code == 500
    assert "Exception on /ro-delete" in caplog.text

    cookie = client.get_cookie("session")
    store_id = f"session:{cookie.value}"
    assert app.session_interface.cache.get(store_id) == {"value": "42"}


def test_exact_endpoint_rule_description_is_actionable(app):
    with app.test_request_context("/inspect"):
        session = app.session_interface.open_session(app, flask.request)
        with pytest.raises(ReadOnlySessionError) as exc_info:
            session["x"] = 1
        assert "app_inspect" in str(exc_info.value)
        assert "endpoint 'app_inspect'" in str(exc_info.value)


def test_regex_rule_description_identifies_blocking_rule(app):
    with app.test_request_context("/ro-write"):
        session = app.session_interface.open_session(app, flask.request)
        with pytest.raises(ReadOnlySessionError) as exc_info:
            session.pop("missing", None)
        message = str(exc_info.value)
        assert "app_ro_write" in message
        assert "regex '^app_ro_.*'" in message


def test_all_mutation_apis_are_guarded(app):
    with app.test_request_context("/inspect"):
        session = app.session_interface.open_session(app, flask.request)
        for mutation in (
            lambda: session.__setitem__("a", 1),
            lambda: session.__delitem__("a"),
            lambda: session.update({"a": 1}),
            lambda: session.setdefault("a", 1),
            lambda: session.pop("a", None),
            lambda: session.popitem(),
            lambda: session.clear(),
        ):
            with pytest.raises(ReadOnlySessionError):
                mutation()


def test_writable_routes_remain_writable(app):
    client = app.test_client()
    assert client.post("/set", data={"value": "1"}).data == b"value set"
    assert client.post("/set", data={"value": "2"}).data == b"value set"
    assert client.get("/get").data == b"2"


def test_writable_route_reads_its_own_session_data(app):
    client = app.test_client()
    client.post("/set", data={"value": "persisted"})

    assert client.get("/get").data == b"persisted"
    new_client = app.test_client()
    with client.session_transaction() as transaction:
        assert transaction["value"] == "persisted"
    assert new_client.get("/get").data == b"no value set"


def test_readonly_session_type_used(app):
    with app.test_request_context():
        assert isinstance(flask.session, CacheLibSession)


def test_permanent_sessions_support_readonly_guards():
    application = create_app(readonly_endpoints=("app_inspect",))
    try:
        with application.test_request_context("/inspect"):
            session = application.session_interface._make_session(
                sid="sid-1", permanent=True
            )
            assert session.permanent is True
            with pytest.raises(ReadOnlySessionError):
                session["x"] = 1
    finally:
        if os.path.isdir(SESSION_DIR):
            shutil.rmtree(SESSION_DIR)


def test_callable_rule_and_invalid_rule_type():
    def is_admin_endpoint(endpoint):
        return endpoint == "app_inspect"

    try:
        application = create_app(readonly_endpoints=(is_admin_endpoint,))
        with application.test_request_context("/inspect"):
            session = application.session_interface.open_session(
                application, flask.request
            )
            with pytest.raises(ReadOnlySessionError) as exc_info:
                session.update({"x": 1})
            assert "callable 'is_admin_endpoint'" in str(exc_info.value)

        with pytest.raises(TypeError):
            create_app(readonly_endpoints=(123,))
    finally:
        if os.path.isdir(SESSION_DIR):
            shutil.rmtree(SESSION_DIR)
