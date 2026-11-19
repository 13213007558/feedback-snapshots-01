"""Per-field retention demo (fake clock + real CacheLib persistence).

Scenario: a customer-service flow stashes a contact detail in the session long
enough to fill a form, then wants that single field to disappear on its own
short timer. The login state (``user_id``) and the page preference (``theme``)
must keep following the normal, longer session lifetime.

The demo patches ``time.time`` for *both* Flask-Session and CacheLib with one
controllable fake clock, while using a real ``FileSystemCache`` so the records
are genuinely serialized to disk. It prints what happens at the three required
observation points after the short-lived field expires:

1. business reads      - ``flask.session`` no longer returns the field;
2. serialized record   - the on-disk CacheLib record (and its expiry table);
3. cookie renewal      - the storage record TTL / cookie keep refreshing, yet
                         never extend the field's write-based expiry.

Run it with the project's virtualenv::

    python examples/per_field_ttl.py
"""

import shutil
import struct
import tempfile
from datetime import timedelta
from pathlib import Path

import flask
from cachelib.file import FileSystemCache

import cachelib.file as cachelib_file
import flask_session.base as session_base
from flask_session.field_ttl import FIELD_EXPIRY_KEY


class FakeClock:
    """One fake clock driving both Flask-Session and CacheLib."""

    def __init__(self, start: float = 1_000.0):
        self.now = start

    def time(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        print(f"  ⏩  clock advanced by {seconds}s -> fake time {self.now:.0f}")


def build_app(session_dir):
    app = flask.Flask(__name__)
    app.secret_key = "demo-secret"
    app.config.update(
        SESSION_TYPE="cachelib",
        SESSION_CACHELIB=FileSystemCache(cache_dir=session_dir, threshold=0),
        SESSION_SERIALIZATION_FORMAT="json",
        SESSION_PERMANENT=True,
        # Whole session (storage record + cookie) lives an hour.
        PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
        # Per-field absolute retention, starting when each field is written.
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
        return f"{key}={flask.session.get(key)!r}"

    @app.route("/touch")
    def touch():
        # Read-only hit: renews storage/cookie but never a per-field timer.
        return flask.session.get("contact_info", "<gone>")

    import flask_session

    flask_session.Session(app)
    return app


def sid_of(response):
    for header in response.headers.getlist("Set-Cookie"):
        name, _, value = header.split(";", 1)[0].partition("=")
        if name == "session":
            return value
    raise RuntimeError("no session cookie")


def raw_record(app, sid):
    key = app.session_interface.key_prefix + sid
    return app.session_interface.cache.get(key)


def file_ttl(app, sid, clock):
    key = app.session_interface.key_prefix + sid
    filename = app.session_interface.cache._get_filename(key)
    with open(filename, "rb") as handle:
        absolute_expiry = struct.unpack("I", handle.read(4))[0]
    return absolute_expiry - clock.now


def main():
    session_dir = tempfile.mkdtemp(prefix="flask-session-field-ttl-")
    clock = FakeClock()
    # Patch the clock in both layers. CacheLib does `from time import time`.
    session_base.time.time = clock.time
    cachelib_file.time = clock.time

    try:
        app = build_app(session_dir)
        client = app.test_client()

        print("== Write contact_info (10s TTL), user_id (30s), theme (no TTL) ==")
        write_response = client.get("/write")
        sid = sid_of(write_response)
        write_time = clock.now
        record = raw_record(app, sid)
        print(f"  serialized expiry table: {record[FIELD_EXPIRY_KEY]}")
        print(f"  CacheLib record remaining TTL: {file_ttl(app, sid, clock):.0f}s")

        print("\n== Read-only visit (must not extend any field timer) ==")
        clock.advance(5)
        client.get("/touch")
        record = raw_record(app, sid)
        contact_expiry = record[FIELD_EXPIRY_KEY]["contact_info"]
        print(f"  contact_info still expires at {contact_expiry:.0f} "
              f"(write {write_time:.0f} + 10, unchanged)")

        print("\n== Renew storage/cookie again without touching the field ==")
        clock.advance(6)  # fake time T+11: contact_info (T+10) has expired
        touch_response = client.get("/touch")
        renewed = any(
            h.split(";", 1)[0].startswith("session=")
            for h in touch_response.headers.getlist("Set-Cookie")
        )
        print(f"  session cookie re-emitted on renewal: {renewed}")
        print(f"  CacheLib record remaining TTL after renewal: "
              f"{file_ttl(app, sid, clock):.0f}s (back to full hour)")

        print("\n== Observation point 1: business reads ==")
        print(f"  GET /read/contact_info -> {client.get('/read/contact_info').data.decode()}")
        print(f"  GET /read/user_id      -> {client.get('/read/user_id').data.decode()}")
        print(f"  GET /read/theme        -> {client.get('/read/theme').data.decode()}")

        print("\n== Observation point 2: actual serialized record on disk ==")
        record = raw_record(app, sid)
        print(f"  stored keys: {sorted(k for k in record if k != FIELD_EXPIRY_KEY)}")
        print(f"  expiry table left: {record[FIELD_EXPIRY_KEY]}")

        print("\n== Observation point 3: cookie/storage renewal vs field TTL ==")
        print("  record TTL and cookie were renewed above, yet contact_info "
              "stayed expired")
        print("  because its deadline was fixed at write time (T0+10).")

        print("\n== Login state expires on its own 30s clock, theme persists ==")
        clock.advance(20)  # fake time T+31
        print(f"  GET /read/user_id -> {client.get('/read/user_id').data.decode()}")
        print(f"  GET /read/theme   -> {client.get('/read/theme').data.decode()}")
    finally:
        session_base.time.time = __import__("time").time
        shutil.rmtree(session_dir, ignore_errors=True)
        print(f"\nCleaned up demo storage at {Path(session_dir).name}")


if __name__ == "__main__":
    main()
