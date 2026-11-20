from __future__ import annotations

import os
import typing as t

import pytest
import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.record_queries import get_recorded_queries


@pytest.mark.usefixtures("app_ctx")
def test_query_info(app: Flask) -> None:
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True
    db = SQLAlchemy(app)

    # Copied and pasted from conftest.py
    if issubclass(db.Model, (sa_orm.MappedAsDataclass)):

        class Todo(db.Model):
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, init=False, primary_key=True
            )
            title: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String, nullable=True, default=None
            )

    elif issubclass(db.Model, (sa_orm.DeclarativeBase, sa_orm.DeclarativeBaseNoMeta)):

        class Todo(db.Model):  # type: ignore[no-redef]
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            title: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String, nullable=True)

    else:

        class Todo(db.Model):  # type: ignore[no-redef]
            id = sa.Column(sa.Integer, primary_key=True)
            title = sa.Column(sa.String)

    db.create_all()
    db.session.execute(sa.select(Todo).filter(Todo.id < 5)).scalars()
    info = get_recorded_queries()[-1]
    assert info.statement is not None
    assert "SELECT" in info.statement
    assert "FROM todo" in info.statement
    assert info.parameters[0][0] == 5
    assert info.duration == info.end_time - info.start_time
    assert os.path.join("tests", "test_record_queries.py:") in info.location
    assert "(test_query_info)" in info.location
    assert info.bind_key is None
    assert not info.parameters_restricted


def _make_app(parameter_policy: t.Any) -> Flask:
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["SQLALCHEMY_BINDS"] = {
        "audit": "sqlite://",
        "raw": "sqlite://",
    }
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True
    app.config["SQLALCHEMY_RECORD_QUERY_PARAMS"] = parameter_policy
    return app


def test_init_app_without_recording_does_not_install_policy(app: Flask) -> None:
    """An app that turns recording off keeps working, and a later app can enable it
    with a policy without affecting the first app.
    """
    db = SQLAlchemy()
    db.init_app(app)

    recorder = _make_app(["id"])
    db.init_app(recorder)

    with app.app_context():
        assert db.session.execute(sa.text("select 1")).scalar_one() == 1
        assert get_recorded_queries() == []

    with recorder.app_context():
        db.session.execute(
            sa.text("select :id as id, :token as token"), {"id": 1, "token": "x"}
        ).all()
        assert get_recorded_queries()[-1].parameters == [{"id": 1, "token": "***"}]


def test_two_apps_share_extension_and_keep_policies() -> None:
    """Each app records its own queries and applies its own parameter policy, even
    though both apps use the same extension instance.
    """
    db = SQLAlchemy()
    restricted = _make_app({"*": ["id"], "raw": True})
    permissive = _make_app(True)
    db.init_app(restricted)
    db.init_app(permissive)

    class RestrictedTodo(db.Model):
        __tablename__ = "restricted_todo"
        id = sa.Column(sa.Integer, primary_key=True)
        title = sa.Column(sa.String)
        token = sa.Column(sa.String)

    class AuditTodo(db.Model):
        __tablename__ = "audit_todo"
        __bind_key__ = "audit"
        id = sa.Column(sa.Integer, primary_key=True)
        token = sa.Column(sa.String)

    class RawTodo(db.Model):
        __tablename__ = "raw_todo"
        __bind_key__ = "raw"
        id = sa.Column(sa.Integer, primary_key=True)
        token = sa.Column(sa.String)

    for current in (restricted, permissive):
        with current.app_context():
            db.create_all()

    statement = sa.text("select :id as id, :title as title, :token as token")

    with restricted.app_context():
        result = db.session.execute(
            statement, {"id": 3, "title": "visible", "token": "secret"}
        )
        rows = [tuple(row) for row in result.all()]

        # The real query still ran and returned the actual values.
        assert rows == [(3, "visible", "secret")]

        info = get_recorded_queries()[-1]
        assert info.statement is not None
        assert "select" in info.statement
        assert "as title" in info.statement
        location = info.location
        assert location.endswith("(test_two_apps_share_extension_and_keep_policies)")
        assert info.parameters == [{"id": 3, "title": "***", "token": "***"}]
        assert info.parameters_restricted
        assert info.bind_key is None
        assert "secret" not in repr(info.parameters)

        # The default policy applies to other binds, while the "raw" bind overrides
        # it and records the values as-is.
        db.session.execute(
            sa.select(AuditTodo).where(AuditTodo.token == "audit-secret")
        ).scalars().all()
        audit_info = get_recorded_queries()[-1]
        assert audit_info.bind_key == "audit"
        assert audit_info.parameters == [{"token_1": "***"}]

        db.session.execute(
            sa.select(RawTodo).where(RawTodo.token == "raw-secret")
        ).scalars().all()
        raw_info = get_recorded_queries()[-1]
        assert raw_info.bind_key == "raw"
        assert raw_info.parameters == [("raw-secret",)]

        # A query that raises does not replace the recorded list, and the next query
        # is recorded normally.
        count = len(get_recorded_queries())

        with pytest.raises(sa.exc.OperationalError):
            db.session.execute(
                sa.text("select * from missing_table where token = :token"),
                {"token": "error-secret"},
            )

        db.session.rollback()
        assert len(get_recorded_queries()) == count

        db.session.execute(
            sa.text("select :id as id, :token as token"), {"id": 4, "token": "next"}
        ).all()
        assert len(get_recorded_queries()) == count + 1
        assert get_recorded_queries()[-1].parameters == [{"id": 4, "token": "***"}]

    with permissive.app_context():
        db.session.execute(
            statement, {"id": 7, "title": "visible", "token": "kept"}
        ).all()
        info = get_recorded_queries()[-1]
        assert info.parameters == [(7, "visible", "kept")]
        assert not info.parameters_restricted
        assert "kept" in repr(info.parameters)

    # The restricted app's list is not visible from the permissive app, and its
    # earlier records were not changed by the later app's queries.
    with restricted.app_context():
        assert get_recorded_queries() == []
        db.session.execute(
            sa.text("select :token as token"), {"token": "only-restricted"}
        ).all()
        assert get_recorded_queries()[-1].parameters == [{"token": "***"}]

    with permissive.app_context():
        assert get_recorded_queries() == []


def test_default_config_records_values() -> None:
    app = Flask("test_record_queries_default")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True
    db = SQLAlchemy(app)

    with app.app_context():
        db.session.execute(
            sa.text("select :token as token"), {"token": "visible"}
        ).all()

        info = get_recorded_queries()[-1]

    assert info.parameters == [("visible",)]
    assert not info.parameters_restricted


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        ({"missing": True}, "bind keys that are not configured"),
        ({"*": object()}, "must be a bool"),
        ({1: True}, "bind keys must be strings or None"),
        (["id", 1], "parameter names must be strings"),
    ],
)
def test_invalid_parameter_policy(policy: t.Any, message: str) -> None:
    app = Flask("invalid")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["SQLALCHEMY_RECORD_QUERIES"] = True
    app.config["SQLALCHEMY_RECORD_QUERY_PARAMS"] = policy

    with pytest.raises(RuntimeError, match=message):
        SQLAlchemy(app)


def test_parameter_policy_disabled_when_recording_disabled() -> None:
    app = Flask("disabled")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["SQLALCHEMY_RECORD_QUERIES"] = False
    app.config["SQLALCHEMY_RECORD_QUERY_PARAMS"] = {"missing": True}
    db = SQLAlchemy(app)

    with app.app_context():
        assert db.session.execute(sa.text("select 1")).scalar_one() == 1
        assert get_recorded_queries() == []


def test_redacted_parameters_copy_is_not_shared() -> None:
    app = _make_app(["id"])
    db = SQLAlchemy(app)
    values = {"id": 1, "token": "secret"}

    with app.app_context():
        db.session.execute(sa.text("select :id as id, :token as token"), values).all()
        info = get_recorded_queries()[-1]

    # Redaction builds a new list, it does not mutate the caller's values.
    assert values == {"id": 1, "token": "secret"}
    assert info.parameters == [{"id": 1, "token": "***"}]
    assert info.parameters is not values
