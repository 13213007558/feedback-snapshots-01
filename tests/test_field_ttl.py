"""Per-field absolute retention (``SESSION_FIELD_TTL``) tests.

These tests drive the real CacheLib ``FileSystemCache`` storage while a fake
clock controls every time read, both inside Flask-Session and inside CacheLib.
The same clock therefore governs application-level expiry, the absolute expiry
stamp embedded in the serialized record and the storage-level file TTL.
"""

import shutil
import struct
from datetime import timedelta

import flask
import flask_session
import pytest
from cachelib.file import FileSystemCache

import flask_session.base as session_base
import cachelib.file as cachelib_file
from flask_session.field_ttl import FIELD_EXPIRY_KEY


class FakeClock:
    """Replaces ``time.time`` for both Flask-Session and CacheLib."""

    def __init__(self, start: float = 1_000.0):
        self.now = start

    def time(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


@pytest.fixture()
def clock(monkeypatch):
    fake = FakeClock()
    # flask_session.base does `import time`; cachelib.file does
    # `from time import time`, so the two names are patched differently.
    monkeypatch.setattr(session_base.time, "time", fake.time)
    monkeypatch.setattr(cachelib_file, "time", fake.time)
    return fake


@pytest.fixture()
def app(tmp_path, monkeypatch):
    session_dir = tmp_path / "sessions"
    cache = FileSystemCache(cache_dir=str(session_dir), threshold=0)

    app = flask.Flask(__name__)
    app.secret_key = "field-ttl-secret"
    app.config.update(
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=cache,
        SESSION_SERIALIZATION_FORMAT="json",
        SESSION_PERMANENT=True,
        # Whole-session (cookie + storage record) lifetime: long.
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        # Per-field absolute retention, measured from the moment each is written.
        SESSION_FIELD_TTL={
            "contact_info": timedelta(seconds=10),
            "user_id": timedelta(seconds=30),
        },
    )

    @app.route("/write")
    def write():
        flask.session["contact_info"] = "555-0100"
        flask.session["user_id"] = 42
        flask.session["theme"] = "dark"
        return "written"

    @app.route("/read/<key>")
    def read(key):
        return str(flask.session.get(key))

    @app.route("/touch")
    def touch():
        # Read-only hit: renews cookie/storage via SESSION_REFRESH_EACH_REQUEST
        # but must not extend any per-field TTL.
        return repr(flask.session.get("contact_info"))

    @app.route("/rewrite-contact")
    def rewrite_contact():
        # Rewrite a single field so only its retention clock restarts.
        flask.session["contact_info"] = "555-0199"
        return "rewritten"

    flask_session.Session(app)
    yield app

    shutil.rmtree(session_dir, ignore_errors=True)


def session_sid(response):
    """Extract the session id from a response's Set-Cookie header."""
    for cookie_header in response.headers.getlist("Set-Cookie"):
        name, _, value = cookie_header.split(";", 1)[0].partition("=")
        if name == "session":
            return value
    raise AssertionError("session cookie was not set on the response")


def store_id(app, sid):
    return app.session_interface.key_prefix + sid


def raw_cache_record(app, sid):
    """Read the persisted record straight from CacheLib, bypassing the app."""
    return app.session_interface.cache.get(store_id(app, sid))


def raw_file_ttl_seconds(app, sid, clock):
    """Read the CacheLib file header: absolute expiry timestamp of the record."""
    filename = app.session_interface.cache._get_filename(store_id(app, sid))
    with open(filename, "rb") as handle:
        absolute_expiry = struct.unpack("I", handle.read(4))[0]
    return absolute_expiry, absolute_expiry - clock.now


def set_cookie_expires(response):
    cookie_header = response.headers.get("Set-Cookie", "")
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.lower().startswith("expires="):
            return part.split("=", 1)[1]
    return None


def has_session_cookie(response):
    return any(
        header.split(";", 1)[0].startswith("session=")
        for header in response.headers.getlist("Set-Cookie")
    )


def test_field_expiry_is_absolute_on_business_reads(app, clock):
    """Observation point 1: business reads after the short TTL miss the field,
    while fields without a per-field TTL survive."""
    client = app.test_client()

    response = client.get("/write")
    sid = session_sid(response)
    write_cookie_expires = set_cookie_expires(response)
    assert write_cookie_expires is not None

    # Before the short TTL elapses everything is readable.
    clock.advance(9)
    assert client.get("/read/contact_info").data == b"555-0100"
    assert client.get("/read/user_id").data == b"42"
    assert client.get("/read/theme").data == b"dark"

    # Plain read-only visits do not extend the write-based TTL.
    clock.advance(0.5)
    client.get("/touch")
    client.get("/touch")

    # At T+10 the 10-second contact_info retention has elapsed.
    clock.advance(0.5)
    assert client.get("/read/contact_info").data == b"None"
    # Non-tracked preference and longer-lived login state are still there.
    assert client.get("/read/theme").data == b"dark"
    assert client.get("/read/user_id").data == b"42"

    # The longer-lived login field expires on its own clock at T+30.
    clock.advance(20)
    assert client.get("/read/user_id").data == b"None"
    assert client.get("/read/theme").data == b"dark"


def test_expiry_is_visible_in_serialized_record(app, clock):
    """Observation point 2: the persisted record carries an absolute,
    write-based expiry that stays fixed across renewals, and pruned fields
    disappear from the next serialized write."""
    client = app.test_client()
    sid = session_sid(client.get("/write"))
    write_time = clock.now

    record = raw_cache_record(app, sid)
    assert record["contact_info"] == "555-0100"
    assert FIELD_EXPIRY_KEY in record
    # Absolute stamps anchored at write time, not at the current request.
    assert record[FIELD_EXPIRY_KEY]["contact_info"] == pytest.approx(write_time + 10)
    assert record[FIELD_EXPIRY_KEY]["user_id"] == pytest.approx(write_time + 30)
    # Non-tracked fields have no expiry entry.
    assert "theme" not in record[FIELD_EXPIRY_KEY]

    # Read-only renewals must not move the absolute field expiry.
    clock.advance(5)
    client.get("/touch")
    record = raw_cache_record(app, sid)
    assert record[FIELD_EXPIRY_KEY]["contact_info"] == pytest.approx(
        write_time + 10
    )

    # After expiry, the next request purges the field and re-persists.
    clock.advance(6)  # T+11
    client.get("/read/theme")
    record = raw_cache_record(app, sid)
    assert "contact_info" not in record
    assert "contact_info" not in record[FIELD_EXPIRY_KEY]
    assert record["theme"] == "dark"


def test_storage_ttl_and_cookie_renew_without_extending_fields(app, clock):
    """Observation point 3: backend renewal refreshes the CacheLib file TTL and
    re-emits the cookie, while per-field expiry stays anchored at write time."""
    client = app.test_client()
    write_response = client.get("/write")
    sid = session_sid(write_response)
    # Permanent sessions emit a cookie carrying the whole-session lifetime.
    assert has_session_cookie(write_response)

    absolute_file_expiry, remaining_file_ttl = raw_file_ttl_seconds(
        app, sid, clock
    )
    assert remaining_file_ttl == 3600  # whole-session lifetime

    # Advance the fake clock, then make a read-only (renewing) request.
    clock.advance(120)
    touch_response = client.get("/touch")
    # The permanent cookie is re-emitted on every request (cookie renewal)...
    assert has_session_cookie(touch_response)
    # ...and the CacheLib record TTL is refreshed back to the full lifetime.
    new_absolute_expiry, new_remaining_ttl = raw_file_ttl_seconds(
        app, sid, clock
    )
    assert new_absolute_expiry > absolute_file_expiry
    assert new_remaining_ttl == 3600

    # Yet the contact field, written at T0, still expired at T0+10. Renewal of
    # the storage record and cookie did not extend its per-field retention.
    assert client.get("/read/contact_info").data == b"None"
    record = raw_cache_record(app, sid)
    assert "contact_info" not in record
    # The session itself is alive, holding the non-expiring preference.
    assert record["theme"] == "dark"


def test_rewrite_restarts_only_that_field_clock(app, clock):
    client = app.test_client()
    sid = session_sid(client.get("/write"))
    first_write = clock.now

    clock.advance(8)
    # Rewrite only contact_info; its clock restarts, user_id keeps its stamp.
    client.get("/rewrite-contact")
    record = raw_cache_record(app, sid)
    assert record[FIELD_EXPIRY_KEY]["contact_info"] == pytest.approx(
        clock.now + 10
    )
    assert record[FIELD_EXPIRY_KEY]["user_id"] == pytest.approx(
        first_write + 30
    )


def test_reserved_key_is_protected(app):
    with app.test_request_context():
        with pytest.raises(ValueError):
            flask.session[FIELD_EXPIRY_KEY] = {"x": 1.0}


def test_mutation_paths_keep_expiry_bookkeeping():
    from flask_session.base import ServerSideSession

    session = ServerSideSession(field_ttl={"contact": 10, "user": 30})

    # update() and |= route through __setitem__ and stamp TTL keys only.
    session.update({"contact": "a", "theme": "dark"})
    assert "contact" in session.field_expiry
    assert "theme" not in session.field_expiry
    session.update(user=7)
    assert "user" in session.field_expiry and session["user"] == 7
    session |= {"contact": "b"}
    assert session["contact"] == "b"

    # setdefault stamps only when it actually inserts a key.
    assert session.setdefault("user", 1) == 7
    session.setdefault("fresh", 9)
    assert "fresh" not in session.field_expiry

    # pop/popitem/clear drop the matching expiry bookkeeping.
    session.pop("contact")
    assert "contact" not in session.field_expiry
    session.popitem()
    session.clear()
    assert not session.field_expiry


def test_invalid_field_ttl_configuration(tmp_path):
    bad_app = flask.Flask(__name__)
    bad_app.config.update(
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=FileSystemCache(
            cache_dir=str(tmp_path / "bad_ttl_cache"),
            threshold=0,
        ),
        SESSION_FIELD_TTL={"contact_info": 0},
    )
    with pytest.raises(ValueError):
        flask_session.Session(bad_app)
