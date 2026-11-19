"""Regression matrix for the ``Vary: Cookie`` contract of Flask-Session.

These tests enter through normal Flask routes and judge each response the
way a shared HTTP cache in front of the app would: by the final ``Vary``
header on the response, not by ``session.accessed``. A response whose
``Vary`` does not list ``Cookie`` may be served by a shared cache to other
users, so the matrix pins down exactly which handler shapes declare the
response as cookie-dependent.

The guarantee relies on Flask >= 3.1: ``RequestContext.session`` marks the
session as accessed on *any* use of the ``flask.session`` proxy (including
``in`` checks and key iteration), and ``save_session`` then emits
``Vary: Cookie``. On older Flask versions only ``__getitem__``/``get``/
``setdefault``/writes set ``accessed``, so handlers that merely check key
existence or iterate keys would *not* emit ``Vary: Cookie`` and would be
unsafe behind a shared cache.
"""

import flask
import flask_session
import pytest
from cachelib import SimpleCache


def vary_tokens(response):
    """Return the normalized token set of the response's Vary header."""
    vary = response.headers.get("Vary", "")
    return {token.strip().lower() for token in vary.split(",") if token.strip()}


def shared_cache_may_reuse(response):
    """A shared cache may reuse this response for other users only when
    the response does not vary on the Cookie header."""
    return "cookie" not in vary_tokens(response)


@pytest.fixture()
def app():
    app = flask.Flask(__name__)
    app.config["SESSION_TYPE"] = "cachelib"
    app.config["SESSION_CACHELIB"] = SimpleCache()
    app.config["SESSION_SERIALIZATION_FORMAT"] = "json"
    app.config["SESSION_PERMANENT"] = False

    @app.get("/no-touch")
    def no_touch():
        return "same for everyone"

    @app.get("/contains")
    def contains():
        return "has user" if "user" in flask.session else "anonymous"

    @app.get("/iterate")
    def iterate():
        return ",".join(flask.session.keys()) or "no keys"

    @app.get("/read")
    def read():
        return flask.session.get("user", "anonymous")

    @app.get("/modify")
    def modify():
        flask.session["user"] = "alice"
        return "user set"

    @app.get("/existing-vary-no-touch")
    def existing_vary_no_touch():
        response = flask.make_response("encoding dependent")
        response.vary.add("Accept-Encoding")
        return response

    @app.get("/existing-vary-read")
    def existing_vary_read():
        response = flask.make_response(flask.session.get("user", "anonymous"))
        response.vary.add("Accept-Encoding")
        return response

    flask_session.Session(app)
    return app


@pytest.mark.parametrize(
    "path, expected_vary, expected_shared",
    [
        # Handler never references the session: response is shared content.
        ("/no-touch", set(), True),
        # Anonymous request that only checks key existence still declares
        # Vary: Cookie (Flask >= 3.1 marks the session accessed on any
        # proxy use), so the cache keys the variants on the Cookie header.
        ("/contains", {"cookie"}, False),
        # Iterating keys is also a session access: same guarantee.
        ("/iterate", {"cookie"}, False),
        # Reading a value marks the session accessed: anonymous requests
        # must still declare Vary: Cookie even without an incoming cookie.
        ("/read", {"cookie"}, False),
        # Modifying the session always declares Vary: Cookie.
        ("/modify", {"cookie"}, False),
        # A pre-existing Vary is preserved untouched when the handler
        # never looks at the session.
        ("/existing-vary-no-touch", {"accept-encoding"}, True),
        # A pre-existing Vary is merged with Cookie when the session is
        # read; the original token must not be clobbered.
        ("/existing-vary-read", {"accept-encoding", "cookie"}, False),
    ],
)
def test_vary_matrix_anonymous(app, path, expected_vary, expected_shared):
    """Anonymous request (no session cookie) through each handler shape."""
    response = app.test_client().get(path)
    assert response.status_code == 200
    assert vary_tokens(response) == expected_vary
    assert shared_cache_may_reuse(response) is expected_shared


def test_no_vary_header_at_all_when_session_untouched(app):
    """Without any session access the Vary header must not appear."""
    response = app.test_client().get("/no-touch")
    assert "Vary" not in response.headers


def test_modify_sets_cookie_and_vary(app):
    """A modified session emits both Set-Cookie and Vary: Cookie."""
    response = app.test_client().get("/modify")
    assert "cookie" in vary_tokens(response)
    assert any("session=" in c for c in response.headers.getlist("Set-Cookie"))


def test_existing_vary_header_is_merged_not_replaced(app):
    """The final Vary header keeps the app's own token alongside Cookie."""
    response = app.test_client().get("/existing-vary-read")
    assert vary_tokens(response) == {"accept-encoding", "cookie"}


def test_contains_check_with_live_session_stays_varying(app):
    """With a real session cookie, a handler that only checks key
    existence returns personalized content and must still declare
    Vary: Cookie so a shared cache cannot serve it to other users."""
    client = app.test_client()
    client.get("/modify")
    response = client.get("/contains")
    assert response.data == b"has user"
    assert shared_cache_may_reuse(response) is False


def test_any_proxy_use_marks_session_accessed(app):
    """Anchor of the whole matrix: merely resolving ``flask.session``
    (Flask >= 3.1) sets ``accessed``, which is what triggers Vary: Cookie.
    If this ever regresses, the /contains and /iterate rows above become
    silently cacheable as shared content."""
    with app.test_request_context("/"):
        assert flask.session.accessed is True
