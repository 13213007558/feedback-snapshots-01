from __future__ import annotations

import typing as t

import pytest
import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
from flask import Flask
from flask import render_template_string

from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.session import BindAccessError


def _define_models(db: SQLAlchemy) -> tuple[t.Any, t.Any, t.Any]:
    if issubclass(db.Model, sa_orm.MappedAsDataclass):

        class Main(db.Model):
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, init=False, primary_key=True
            )
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(20), default="", init=False
            )

        class Reports(db.Model):
            __bind_key__ = "reports"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, init=False, primary_key=True
            )
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(20), default="", init=False
            )

        class Archive(db.Model):
            __bind_key__ = "archive"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, init=False, primary_key=True
            )
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(20), default="", init=False
            )

    elif issubclass(db.Model, (sa_orm.DeclarativeBase, sa_orm.DeclarativeBaseNoMeta)):

        class Main(db.Model):  # type: ignore[no-redef]
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String(20), default="")

        class Reports(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "reports"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String(20), default="")

        class Archive(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "archive"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String(20), default="")

    else:

        class Main(db.Model):  # type: ignore[no-redef]
            id = sa.Column(sa.Integer, primary_key=True)
            name = sa.Column(sa.String(20), default="")

        class Reports(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "reports"
            id = sa.Column(sa.Integer, primary_key=True)
            name = sa.Column(sa.String(20), default="")

        class Archive(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "archive"
            id = sa.Column(sa.Integer, primary_key=True)
            name = sa.Column(sa.String(20), default="")

    return Main, Reports, Archive


@pytest.fixture
def multi_db(app: Flask, model_class: t.Any) -> tuple[SQLAlchemy, t.Any, t.Any, t.Any]:
    app.config["SQLALCHEMY_BINDS"] = {
        "reports": "sqlite://",
        "archive": "sqlite://",
    }
    db = SQLAlchemy(app, model_class=model_class)

    with app.app_context():
        Main, Reports, Archive = _define_models(db)
        db.create_all(bind_key=[None, "reports", "archive"])
        main = Main()
        main.name = "main"
        reports = Reports()
        reports.name = "reports"
        archive = Archive()
        archive.name = "archive"
        db.session.add_all([main, reports, archive])
        db.session.commit()

    return db, Main, Reports, Archive


@pytest.mark.usefixtures("app_ctx")
def test_allowed_binds_default_none(app: Flask, model_class: t.Any) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"a": "sqlite://"}
    db = SQLAlchemy(app, model_class=model_class)
    assert db.allowed_binds is None


@pytest.mark.usefixtures("app_ctx")
def test_allowed_binds_validated(app: Flask, model_class: t.Any) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"a": "sqlite://"}
    app.config["SQLALCHEMY_ALLOWED_BINDS"] = {"a", "missing"}

    with pytest.raises(RuntimeError, match="not configured"):
        SQLAlchemy(app, model_class=model_class)


def test_allowed_binds_orm_and_core(
    app: Flask,
    multi_db: tuple[SQLAlchemy, t.Any, t.Any, t.Any],
) -> None:
    db, Main, Reports, Archive = multi_db
    app.config["SQLALCHEMY_ALLOWED_BINDS"] = [None, "reports"]
    db._app_allowed_binds[app] = frozenset({None, "reports"})

    with app.app_context():
        session = db.session()

        # Normal ORM reads on the default and allowed binds.
        assert session.execute(sa.select(Main)).scalar_one().name == "main"
        assert session.execute(sa.select(Reports)).scalar_one().name == "reports"

        # Core statements using table objects are checked the same way.
        assert (
            session.execute(sa.select(Reports.__table__)).one().name == "reports"
        )

        # A Core statement with no tables uses the default bind.
        assert session.execute(sa.text("select 1")).scalar_one() == 1

        # ORM and Core access to an unlisted bind is refused before execution.
        statement_events: list[str] = []

        def before_execute(
            conn: sa.engine.Connection,
            clauseelement: t.Any,
            multiparams: t.Any,
            params: t.Any,
            execution_options: t.Any,
        ) -> None:
            statement_events.append(str(clauseelement))

        sa.event.listen(db.engines["archive"], "before_execute", before_execute)

        try:
            with pytest.raises(BindAccessError):
                session.execute(sa.select(Archive)).all()

            with pytest.raises(BindAccessError):
                session.execute(sa.select(Archive.__table__)).all()

            with pytest.raises(BindAccessError):
                session.execute(
                    sa.select(Reports.__table__),
                    bind_arguments={"bind": db.engines["archive"]},
                )
        finally:
            sa.event.remove(db.engines["archive"], "before_execute", before_execute)

        assert statement_events == []

        # A statement joining an allowed and a disallowed bind is refused as a whole.
        with pytest.raises(BindAccessError):
            session.execute(
                sa.select(Main).select_from(
                    Main.__table__.join(
                        Archive.__table__, Main.id == Archive.id
                    )
                )
            ).all()

        # The same session still works for allowed binds afterwards.
        assert session.execute(sa.select(Main)).scalar_one().name == "main"

        # A fresh session in a new app context must apply the same restriction.
        with app.app_context():
            other = db.session()
            assert other.execute(sa.select(Reports)).scalar_one().name == "reports"

            with pytest.raises(BindAccessError):
                other.execute(sa.select(Archive)).all()


def test_allowed_binds_legacy_app_unrestricted(
    app: Flask,
    multi_db: tuple[SQLAlchemy, t.Any, t.Any, t.Any],
) -> None:
    db, Main, Reports, Archive = multi_db

    # Without the config, the old behavior is preserved for both binds.
    with app.app_context():
        assert db.session.execute(sa.select(Archive)).scalar_one().name == "archive"
        assert db.session.execute(sa.select(Reports)).scalar_one().name == "reports"


def test_allowed_binds_routes(
    app: Flask,
    multi_db: tuple[SQLAlchemy, t.Any, t.Any, t.Any],
) -> None:
    db, Main, Reports, Archive = multi_db

    @app.route("/reports")
    def reports_route() -> str:
        name = db.session.execute(sa.select(Reports)).scalar_one().name
        return render_template_string("{{ name }}", name=name)

    @app.route("/archive")
    def archive_route() -> str:
        return db.session.execute(sa.select(Archive)).scalar_one().name

    @app.route("/store")
    def store_route() -> str:
        db.session.add(Main())
        db.session.commit()
        return "stored"

    @app.route("/store-archive")
    def store_archive_route() -> str:
        db.session.add(Archive())
        db.session.commit()
        return "stored"

    app.config["SQLALCHEMY_ALLOWED_BINDS"] = [None, "reports"]
    db._app_allowed_binds[app] = frozenset({None, "reports"})

    app.testing = True
    client = app.test_client()
    assert client.get("/reports").data == b"reports"

    with pytest.raises(BindAccessError):
        client.get("/archive")

    with pytest.raises(BindAccessError):
        client.get("/store-archive")

    assert client.get("/store").data == b"stored"


@pytest.mark.parametrize("value", [None, ["reports"]])
def test_allowed_binds_per_app(
    app: Flask, model_class: t.Any, value: list[str] | None
) -> None:
    other_app = Flask("other", instance_path=app.instance_path + "/other")
    other_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    other_app.config["SQLALCHEMY_BINDS"] = {"reports": "sqlite://"}
    other_app.config["SQLALCHEMY_ALLOWED_BINDS"] = value

    db = SQLAlchemy(app, model_class=model_class)
    db.init_app(other_app)

    with app.app_context():
        assert db.allowed_binds is None

    with other_app.app_context():
        assert db.allowed_binds == (None if value is None else frozenset(value))

