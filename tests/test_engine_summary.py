from __future__ import annotations

import json
import unittest.mock
from pathlib import Path

import pytest
import sqlalchemy as sa
from flask import Flask

from flask_sqlalchemy import SQLAlchemy


def make_app(tmp_path: Path) -> Flask:
    app = Flask(__name__, instance_path=str(tmp_path / "instance"))
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    return app


@unittest.mock.patch.object(SQLAlchemy, "_make_engine", autospec=True)
def test_summary_overrides_defaults(
    make_engine: unittest.mock.Mock, tmp_path: Path
) -> None:
    """An app that overrides the extension defaults at every layer. The
    default bind uses a string URL, the 'analytics' bind uses a URL instance.
    """
    app = make_app(tmp_path)
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "postgresql://scott:tiger@db.example.com/appdb"
        "?sslmode=require&auth_token=t0psecret"
    )
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_size": 20,
        "connect_args": {"api_key": "s3cr3t", "connect_timeout": 10},
    }
    app.config["SQLALCHEMY_BINDS"] = {
        "analytics": {
            "url": sa.engine.URL.create("sqlite", database=":memory:"),
            "pool_recycle": 100,
        },
        "logs": "sqlite://",
    }
    db = SQLAlchemy(engine_options={"pool_size": 5, "max_overflow": 2, "echo": True})
    db.init_app(app)

    with app.app_context():
        summary = db.engine_config_summary()

    default = summary[None]
    assert default["driver"] == "postgresql"
    # The password and sensitive query parameter are redacted.
    assert "tiger" not in default["url"]
    assert "t0psecret" not in default["url"]
    assert "scott:***@db.example.com" in default["url"]
    assert "sslmode=require" in default["url"]
    # Config layers merge: config overrides init, init fills in the rest.
    assert default["pool_options"]["pool_size"] == 20
    assert default["pool_options"]["max_overflow"] == 2
    assert default["options"]["echo"] is True
    assert default["pool_options"]["echo_pool"] is False
    # Non-secret connect args are shown, secrets are redacted.
    assert default["options"]["connect_args"] == {
        "api_key": "***",
        "connect_timeout": 10,
    }
    assert default["sources"] == {
        "pool_size": "SQLALCHEMY_ENGINE_OPTIONS",
        "connect_args": "SQLALCHEMY_ENGINE_OPTIONS",
        "max_overflow": "SQLAlchemy(engine_options)",
        "echo": "SQLAlchemy(engine_options)",
        "url": "SQLALCHEMY_DATABASE_URI",
        "echo_pool": "SQLALCHEMY_ECHO",
    }
    assert sorted(default["hidden"]) == [
        "connect_args['api_key']",
        "url password",
        "url query parameter 'auth_token'",
    ]

    analytics = summary["analytics"]
    assert analytics["driver"] == "sqlite"
    assert analytics["url"] == "sqlite:///:memory:"
    assert analytics["pool_options"]["pool_recycle"] == 100
    assert analytics["pool_options"]["pool_size"] == 5
    assert analytics["pool_options"]["poolclass"] == "StaticPool"
    assert analytics["options"]["connect_args"] == {"check_same_thread": False}
    assert analytics["sources"]["url"] == "SQLALCHEMY_BINDS['analytics']"
    assert analytics["sources"]["pool_recycle"] == "SQLALCHEMY_BINDS['analytics']"
    assert analytics["sources"]["pool_size"] == "SQLAlchemy(engine_options)"
    assert analytics["sources"]["poolclass"] == "driver defaults"
    assert analytics["sources"]["connect_args"] == "driver defaults"
    assert analytics["hidden"] == []

    logs = summary["logs"]
    assert logs["sources"]["url"] == "SQLALCHEMY_BINDS['logs']"

    # Nothing secret appears anywhere in the summary.
    dumped = json.dumps(summary)
    assert "tiger" not in dumped
    assert "t0psecret" not in dumped
    assert "s3cr3t" not in dumped

    # The options actually delivered to the engines are unchanged.
    delivered = {call[0][1]: call[0][2] for call in make_engine.call_args_list}
    delivered_url = sa.engine.make_url(delivered[None]["url"])
    assert delivered_url.password == "tiger"
    assert delivered_url.query["auth_token"] == "t0psecret"
    assert delivered[None]["connect_args"]["api_key"] == "s3cr3t"
    assert delivered[None]["pool_size"] == 20
    assert delivered["analytics"]["pool_recycle"] == 100


def test_summary_keeps_defaults(tmp_path: Path) -> None:
    """An app that only sets a URL instance and keeps every default. Real
    engines are created to confirm the summary matches what is in effect.
    """
    app = make_app(tmp_path)
    app.config["SQLALCHEMY_DATABASE_URI"] = sa.engine.URL.create(
        "sqlite", database=":memory:"
    )
    db = SQLAlchemy(app)

    with app.app_context():
        summary = db.engine_config_summary()
        assert isinstance(db.engine.pool, sa.pool.StaticPool)
        assert db.engine.echo is False

    assert set(summary) == {None}
    default = summary[None]
    assert default["driver"] == "sqlite"
    assert default["url"] == "sqlite:///:memory:"
    assert default["pool_options"] == {
        "echo_pool": False,
        "poolclass": "StaticPool",
    }
    assert default["options"] == {
        "echo": False,
        "connect_args": {"check_same_thread": False},
    }
    assert default["sources"] == {
        "url": "SQLALCHEMY_DATABASE_URI",
        "echo": "SQLALCHEMY_ECHO",
        "echo_pool": "SQLALCHEMY_ECHO",
        "poolclass": "driver defaults",
        "connect_args": "driver defaults",
    }
    assert default["hidden"] == []


def test_summary_requires_app_context(tmp_path: Path) -> None:
    app = make_app(tmp_path)
    db = SQLAlchemy(app)

    with pytest.raises(RuntimeError):
        db.engine_config_summary()


def test_summary_unregistered_app(tmp_path: Path) -> None:
    app = make_app(tmp_path)
    db = SQLAlchemy()

    with app.app_context(), pytest.raises(RuntimeError):
        db.engine_config_summary()
