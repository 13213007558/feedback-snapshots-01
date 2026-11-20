from __future__ import annotations

import typing as t

import pytest
import sqlalchemy as sa
import sqlalchemy.exc as sa_exc
import sqlalchemy.orm as sa_orm
from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.session import ReadOnlySession
from flask_sqlalchemy.session import Session


def test_scope(app: Flask, db: SQLAlchemy) -> None:
    with pytest.raises(RuntimeError):
        db.session()

    with app.app_context():
        first = db.session()
        second = db.session()
        assert first is second
        assert isinstance(first, Session)

    with app.app_context():
        third = db.session()
        assert first is not third


def test_custom_scope(app: Flask, model_class: t.Any) -> None:
    count = 0

    def scope() -> int:
        nonlocal count
        count += 1
        return count

    db = SQLAlchemy(app, model_class=model_class, session_options={"scopefunc": scope})

    with app.app_context():
        first = db.session()
        second = db.session()
        assert first is not second  # a new scope is generated on each call
        first.close()
        second.close()


@pytest.mark.usefixtures("app_ctx")
def test_session_class(app: Flask, model_class: t.Any) -> None:
    class CustomSession(Session):
        pass

    db = SQLAlchemy(
        app, model_class=model_class, session_options={"class_": CustomSession}
    )
    assert isinstance(db.session(), CustomSession)


@pytest.mark.usefixtures("app_ctx")
def test_session_uses_bind_key(app: Flask, model_class: t.Any) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"a": "sqlite://"}
    db = SQLAlchemy(app, model_class=model_class)

    if issubclass(db.Model, (sa_orm.DeclarativeBase, sa_orm.DeclarativeBaseNoMeta)):

        class User(db.Model):
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)

        class Post(db.Model):
            __bind_key__ = "a"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)

    else:

        class User(db.Model):  # type: ignore[no-redef]
            id = sa.Column(sa.Integer, primary_key=True)

        class Post(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "a"
            id = sa.Column(sa.Integer, primary_key=True)

    assert db.session.get_bind(mapper=User) is db.engine
    assert db.session.get_bind(mapper=Post) is db.engines["a"]


@pytest.mark.usefixtures("app_ctx")
def test_get_bind_inheritance(app: Flask, model_class: t.Any) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"a": "sqlite://"}
    db = SQLAlchemy(app, model_class=model_class)

    if issubclass(db.Model, (sa_orm.MappedAsDataclass)):

        class User(db.Model):
            __bind_key__ = "a"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, primary_key=True, init=False
            )
            type: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String, nullable=False, init=False
            )
            __mapper_args__ = {"polymorphic_on": type, "polymorphic_identity": "user"}

        class Admin(User):
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.ForeignKey(User.id), primary_key=True, init=False
            )
            org: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String, nullable=False)
            __mapper_args__ = {"polymorphic_identity": "admin"}

    elif issubclass(db.Model, (sa_orm.DeclarativeBase, sa_orm.DeclarativeBaseNoMeta)):

        class User(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "a"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            type: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String, nullable=False)
            __mapper_args__ = {"polymorphic_on": type, "polymorphic_identity": "user"}

        class Admin(User):  # type: ignore[no-redef]
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.ForeignKey(User.id), primary_key=True
            )
            org: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String, nullable=False)
            __mapper_args__ = {"polymorphic_identity": "admin"}

    else:

        class User(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "a"
            id = sa.Column(sa.Integer, primary_key=True)
            type = sa.Column(sa.String, nullable=False)
            __mapper_args__ = {"polymorphic_on": type, "polymorphic_identity": "user"}

        class Admin(User):  # type: ignore[no-redef]
            id = sa.Column(sa.ForeignKey(User.id), primary_key=True)  # type: ignore[assignment, var-annotated]
            org = sa.Column(sa.String, nullable=False)
            __mapper_args__ = {"polymorphic_identity": "admin"}

    db.create_all()
    db.session.add(Admin(org="pallets"))
    db.session.commit()
    admin = db.session.execute(db.select(Admin)).scalar_one()
    db.session.expire(admin)
    assert admin.org == "pallets"


@pytest.mark.usefixtures("app_ctx")
def test_session_multiple_dbs(app: Flask, model_class: t.Any) -> None:
    app.config["SQLALCHEMY_BINDS"] = {"db1": "sqlite:///"}
    db = SQLAlchemy(app, model_class=model_class)

    if issubclass(db.Model, (sa_orm.MappedAsDataclass)):

        class User(db.Model):
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, primary_key=True, init=False
            )
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(50), nullable=False, init=False
            )

        class Product(db.Model):
            __bind_key__ = "db1"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, primary_key=True, init=False
            )
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(50), nullable=False, init=False
            )

    elif issubclass(db.Model, (sa_orm.DeclarativeBase, sa_orm.DeclarativeBaseNoMeta)):

        class User(db.Model):  # type: ignore[no-redef]
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(50), nullable=False
            )

        class Product(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "db1"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(
                sa.String(50), nullable=False
            )

    else:

        class User(db.Model):  # type: ignore[no-redef]
            id = sa.Column(sa.Integer, primary_key=True)
            name = sa.Column(sa.String(50), nullable=False)

        class Product(db.Model):  # type: ignore[no-redef]
            __bind_key__ = "db1"
            id = sa.Column(sa.Integer, primary_key=True)
            name = sa.Column(sa.String(50), nullable=False)

    db.create_all()

    db.session.execute(User.__table__.insert(), [{"name": "User1"}, {"name": "User2"}])
    db.session.commit()
    users = db.session.execute(db.select(User)).scalars().all()
    assert len(users) == 2

    db.session.execute(
        Product.__table__.insert(), [{"name": "Product1"}, {"name": "Product2"}]
    )
    db.session.commit()
    products = db.session.execute(db.select(Product)).scalars().all()
    assert len(products) == 2


def test_read_only_session(app: Flask, tmp_path: t.Any) -> None:
    uri = f"sqlite:///{tmp_path / 'audit.db'}"
    app.config["SQLALCHEMY_DATABASE_URI"] = uri

    db_rw = SQLAlchemy(app)

    class Todo(db_rw.Model):
        id = sa.Column(sa.Integer, primary_key=True)
        title = sa.Column(sa.String)

    app_ro = Flask("audit_ro")
    app_ro.config["SQLALCHEMY_DATABASE_URI"] = uri
    db_ro = SQLAlchemy(app_ro, session_options={"class_": ReadOnlySession})

    class AuditTodo(db_ro.Model):
        __tablename__ = "todo"
        id = sa.Column(sa.Integer, primary_key=True)
        title = sa.Column(sa.String)

    with app.app_context():
        db_rw.create_all()
        db_rw.session.add(Todo(title="original"))
        db_rw.session.commit()

    with app_ro.app_context():
        # A business function mistakenly modifies the loaded instance.
        todo = db_ro.session.execute(db_ro.select(AuditTodo)).scalar_one()
        todo.title = "changed"
        # Another query in the same scope must not autoflush the change.
        todos = db_ro.session.execute(db_ro.select(AuditTodo)).scalars().all()
        assert len(todos) == 1
        # An explicit write with pending changes raises and writes nothing.
        with pytest.raises(sa_exc.InvalidRequestError):
            db_ro.session.commit()
    # Leaving the scope removes the session without saving anything.

    with app.app_context():
        # The read-only request left no changes in the database.
        todo = db_rw.session.execute(db_rw.select(Todo)).scalar_one()
        assert todo.title == "original"
        # A normal write transaction is unaffected by the previous request.
        db_rw.session.add(Todo(title="second"))
        db_rw.session.commit()
        titles = db_rw.session.execute(sa.select(Todo.title)).scalars().all()
        assert sorted(titles) == ["original", "second"]


@pytest.mark.usefixtures("app_ctx")
def test_read_only_session_clean_commit(app: Flask) -> None:
    db = SQLAlchemy(app, session_options={"class_": ReadOnlySession})

    class Todo(db.Model):
        id = sa.Column(sa.Integer, primary_key=True)
        title = sa.Column(sa.String)

    db.create_all()
    db.session.execute(db.select(Todo))
    # Committing with no pending changes is a harmless no-op.
    db.session.commit()

    db.session.add(Todo(title="x"))
    with pytest.raises(sa_exc.InvalidRequestError):
        db.session.flush()
