from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
import sqlalchemy as sa
from flask import Flask

from flask_sqlalchemy import SQLAlchemy


def _table_names(path: Path) -> set[str]:
    """Inspect a SQLite file directly, without going through SQLAlchemy."""
    with sqlite3.connect(str(path)) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()

    return {row[0] for row in rows if not row[0].startswith("sqlite_")}


def _make_app(tmp_path: Path) -> tuple[Flask, Path, Path]:
    application = Flask("test_schema_permissions", instance_path=str(tmp_path))
    main_db = tmp_path / "main.db"
    report_db = tmp_path / "report.db"
    application.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{main_db}"
    application.config["SQLALCHEMY_BINDS"] = {
        "reports": f"sqlite:///{report_db}",
    }
    return application, main_db, report_db


@pytest.mark.usefixtures("app_ctx")
def test_unset_config_allows_everything(app: Flask) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"a": "sqlite://"}
    db = SQLAlchemy(app)

    class Thing(db.Model):
        __bind_key__ = "a"
        id = sa.Column(sa.Integer, primary_key=True)

    db.create_all()
    db.reflect(bind_key="a")
    db.drop_all()


@pytest.mark.usefixtures("app_ctx")
def test_default_star_rule_is_judged_per_bind(app: Flask) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"reports": "sqlite://", "test": "sqlite://"}
    app.config["SQLALCHEMY_SCHEMA_PERMISSIONS"] = {
        "*": {"reflect"},
        "test": {"create_all", "drop_all", "reflect"},
    }
    db = SQLAlchemy(app)

    class Report(db.Model):
        __bind_key__ = "reports"
        id = sa.Column(sa.Integer, primary_key=True)

    # The default bind is only covered by the "*" rule, which denies create_all.
    with pytest.raises(PermissionError):
        db.create_all()

    with pytest.raises(PermissionError):
        db.create_all(bind_key=None)

    # The reports bind falls back to the "*" rule as well.
    with pytest.raises(PermissionError):
        db.create_all(bind_key="reports")

    # The explicit test bind rule is honored.
    db.create_all(bind_key="test")
    db.drop_all(bind_key="test")

    # reflect is allowed on every bind through the "*" default.
    db.reflect()


@pytest.mark.usefixtures("app_ctx")
def test_configured_bind_without_rule_is_denied(app: Flask) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"reports": "sqlite://"}
    app.config["SQLALCHEMY_SCHEMA_PERMISSIONS"] = {
        None: {"create_all", "drop_all", "reflect"}
    }
    db = SQLAlchemy(app)

    with pytest.raises(PermissionError):
        db.reflect(bind_key="reports")


def test_batch_with_unapproved_bind_changes_nothing(tmp_path: Path) -> None:
    app, main_db, report_db = _make_app(tmp_path)
    app.config["SQLALCHEMY_SCHEMA_PERMISSIONS"] = {
        None: {"create_all", "drop_all", "reflect"},
        "reports": {"reflect"},
    }
    db = SQLAlchemy(app)

    class MainTable(db.Model):
        id = sa.Column(sa.Integer, primary_key=True)

    class ReportTable(db.Model):
        __bind_key__ = "reports"
        id = sa.Column(sa.Integer, primary_key=True)

    with app.app_context():
        # The default "__all__" batch contains "reports", which may not create.
        with pytest.raises(PermissionError):
            db.create_all()

        # An explicit list containing an unapproved bind is rejected too.
        with pytest.raises(PermissionError):
            db.create_all(bind_key=[None, "reports"])

    # Neither database file gained any table.
    assert _table_names(main_db) == set()
    assert _table_names(report_db) == set()


def test_approved_bind_keeps_original_semantics(tmp_path: Path) -> None:
    app, main_db, report_db = _make_app(tmp_path)
    app.config["SQLALCHEMY_SCHEMA_PERMISSIONS"] = {
        None: {"create_all", "drop_all", "reflect"},
        "reports": {"reflect"},
    }
    db = SQLAlchemy(app)

    class MainTable(db.Model):
        id = sa.Column(sa.Integer, primary_key=True)

    with app.app_context():
        # Create a table directly in the reports database so it can be reflected.
        reports_engine = db.engines["reports"]
        reports_metadata = sa.MetaData()
        sa.Table(
            "existing_report",
            reports_metadata,
            sa.Column("id", sa.Integer, primary_key=True),
        )
        reports_metadata.create_all(bind=reports_engine)

        # reflect on the allowed reporting bind works.
        assert "existing_report" not in db.metadatas["reports"].tables
        db.reflect(bind_key="reports")
        assert "existing_report" in db.metadatas["reports"].tables

        # create_all on the explicitly allowed default bind works.
        db.create_all(bind_key=None)
        assert _table_names(main_db) == {"main_table"}

        # An all-bind create still fails because reports cannot create, and the
        # already-created main table remains the only table in main.db.
        with pytest.raises(PermissionError):
            db.create_all()

        assert _table_names(main_db) == {"main_table"}
        assert _table_names(report_db) == {"existing_report"}


@pytest.mark.usefixtures("app_ctx")
def test_drop_batch_is_fully_authorized_first(app: Flask) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"reports": "sqlite://"}
    app.config["SQLALCHEMY_SCHEMA_PERMISSIONS"] = {
        None: {"create_all", "drop_all", "reflect"},
        "reports": {"reflect"},
    }
    db = SQLAlchemy(app)

    class MainTable(db.Model):
        id = sa.Column(sa.Integer, primary_key=True)

    db.create_all(bind_key=None)
    assert "main_table" in db.metadata.tables

    with pytest.raises(PermissionError):
        db.drop_all()

    # The default bind's table survives because the whole batch was rejected.
    inspect = sa.inspect(db.engine)
    assert "main_table" in inspect.get_table_names()


@pytest.mark.usefixtures("app_ctx")
def test_permission_values_accept_any_collection(app: Flask) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"a": "sqlite://"}
    app.config["SQLALCHEMY_SCHEMA_PERMISSIONS"] = {
        None: ["create_all", "drop_all", "reflect"],
        "a": ("reflect",),
    }
    db = SQLAlchemy(app)

    db.reflect(bind_key="a")

    with pytest.raises(PermissionError):
        db.create_all(bind_key="a")
