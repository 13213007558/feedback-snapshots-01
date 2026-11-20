from __future__ import annotations

import typing as t
from pathlib import Path

import pytest
import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
from flask import Flask

from flask_sqlalchemy import SQLAlchemy

BIND_KEY = "shared"


class _IsolationApps(t.NamedTuple):
    db: SQLAlchemy
    Item: t.Any
    one: Flask
    two: Flask
    queries: list[tuple[str, str]]
    engines: dict[str, sa.engine.Engine]


def _item_queries(apps: _IsolationApps) -> list[str]:
    """Return the app label for each query against the ``item`` table."""
    return [label for label, statement in apps.queries if "FROM item" in statement]


def _add_pending_item(apps: _IsolationApps) -> t.Any:
    item = apps.Item()
    item.id = 2
    item.name = "pending"
    apps.db.session.add(item)
    return item


@pytest.fixture
def apps(tmp_path: Path, model_class: t.Any) -> _IsolationApps:
    db = SQLAlchemy(model_class=model_class)

    if issubclass(db.Model, (sa_orm.MappedAsDataclass)):

        class Item(db.Model):
            __bind_key__ = BIND_KEY
            __tablename__ = "item"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(
                sa.Integer, primary_key=True, init=False
            )
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String, init=False)

    elif issubclass(db.Model, (sa_orm.DeclarativeBase, sa_orm.DeclarativeBaseNoMeta)):

        class Item(db.Model):  # type: ignore[no-redef]
            __bind_key__ = BIND_KEY
            __tablename__ = "item"
            id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
            name: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String)

    else:

        class Item(db.Model):  # type: ignore[no-redef]
            __bind_key__ = BIND_KEY
            __tablename__ = "item"
            id = sa.Column(sa.Integer, primary_key=True)
            name = sa.Column(sa.String, nullable=False)

    def make_app(label: str) -> Flask:
        app = Flask(f"isolation_{label}")
        app.config["SQLALCHEMY_BINDS"] = {
            BIND_KEY: f"sqlite:///{tmp_path / f'{label}.db'}"
        }
        app.testing = True
        db.init_app(app)
        return app

    one = make_app("one")
    two = make_app("two")

    # Both databases have a row with the same primary key but different data.
    for app, label in ((one, "one"), (two, "two")):
        with app.app_context():
            db.create_all(BIND_KEY)
            db.session.execute(Item.__table__.insert(), [{"id": 1, "name": label}])
            db.session.commit()

    queries: list[tuple[str, str]] = []
    engines: dict[str, sa.engine.Engine] = {}

    def listen(engine: sa.engine.Engine, label: str) -> None:
        def before_cursor_execute(
            conn: sa.engine.Connection,
            cursor: t.Any,
            statement: str,
            parameters: t.Any,
            context: sa.engine.ExecutionContext,
            executemany: bool,
        ) -> None:
            queries.append((label, statement))

        sa.event.listen(engine, "before_cursor_execute", before_cursor_execute)

    for app, label in ((one, "one"), (two, "two")):
        with app.app_context():
            engines[label] = db.engines[BIND_KEY]

        listen(engines[label], label)

    def read_item() -> str:
        item = db.session.get(Item, 1)
        assert item is not None
        return item.name

    def read_then_fail() -> str:
        read_item()
        raise RuntimeError("request failed")

    for app in (one, two):
        app.add_url_rule("/item", "item", read_item)
        app.add_url_rule("/boom", "boom", read_then_fail)

    return _IsolationApps(db, Item, one, two, queries, engines)


def test_nested_app_contexts_keep_sessions_separate(apps: _IsolationApps) -> None:
    db = apps.db

    # The same bind key resolves to a different engine for each app.
    assert apps.engines["one"] is not apps.engines["two"]
    assert apps.engines["one"].url.database != apps.engines["two"].url.database

    with apps.one.app_context():
        assert db.engines[BIND_KEY] is apps.engines["one"]
        outer_session = db.session()
        outer_item = outer_session.get(apps.Item, 1)
        assert outer_item is not None
        assert outer_item.name == "one"
        pending = _add_pending_item(apps)
        apps.queries.clear()

        with apps.two.app_context():
            # The inner app uses its own engine and its own session.
            assert db.engines[BIND_KEY] is apps.engines["two"]
            inner_session = db.session()
            assert inner_session is not outer_session

            inner_item = inner_session.get(apps.Item, 1)
            assert inner_item is not None
            assert inner_item.name == "two"
            assert _item_queries(apps) == ["two"]

        # The inner session was removed, but the outer one is still usable.
        assert sa.inspect(inner_item).detached
        assert sa.inspect(outer_item).persistent
        assert db.engines[BIND_KEY] is apps.engines["one"]
        assert db.session() is outer_session
        assert outer_item in outer_session
        assert pending in outer_session.new

        # Expiring forces a real ORM read from the outer app's database.
        outer_session.expire(outer_item)
        assert outer_item.name == "one"
        assert _item_queries(apps) == ["two", "one"]

        outer_session.rollback()
        assert pending not in outer_session.new


def test_request_exception_does_not_close_outer_session(
    apps: _IsolationApps,
) -> None:
    db = apps.db

    with apps.one.app_context():
        outer_session = db.session()
        outer_item = outer_session.get(apps.Item, 1)
        assert outer_item is not None
        assert outer_item.name == "one"
        pending = _add_pending_item(apps)
        apps.queries.clear()

        two_client = apps.two.test_client()
        response = two_client.get("/item")
        assert response.text == "two"
        assert _item_queries(apps) == ["two"]

        with pytest.raises(RuntimeError, match="request failed"):
            two_client.get("/boom")

        # Only the inner app's database was queried, even though the request
        # failed, and the outer session was not removed by its teardown.
        assert _item_queries(apps) == ["two", "two"]
        assert db.session() is outer_session
        assert outer_item in outer_session
        assert pending in outer_session.new

        response = apps.one.test_client().get("/item")
        assert response.text == "one"

        with pytest.raises(RuntimeError, match="request failed"):
            apps.one.test_client().get("/boom")

        # A request on the outer app reuses the outer context and session, so
        # it sees the outer identity map instead of the inner app's data.
        assert _item_queries(apps) == ["two", "two"]
        assert db.session() is outer_session
        assert pending in outer_session.new

        outer_session.expire(outer_item)
        assert outer_item.name == "one"

    # Fresh requests outside any manual context each read only their own data.
    apps.queries.clear()
    assert apps.one.test_client().get("/item").text == "one"
    assert apps.two.test_client().get("/item").text == "two"
    assert _item_queries(apps) == ["one", "two"]


def test_reenter_original_app_after_nested_context(
    apps: _IsolationApps,
) -> None:
    db = apps.db

    with apps.one.app_context():
        outer_session = db.session()
        outer_item = outer_session.get(apps.Item, 1)
        assert outer_item is not None
        assert outer_item.name == "one"
        apps.queries.clear()

        with apps.two.app_context():
            assert db.session().get(apps.Item, 1).name == "two"

        # Re-entering the original app creates a new context and session,
        # separate from the still-active outer session.
        with apps.one.app_context():
            assert db.engines[BIND_KEY] is apps.engines["one"]
            reentered_session = db.session()
            assert reentered_session is not outer_session
            assert reentered_session.get(apps.Item, 1).name == "one"
            assert _item_queries(apps) == ["two", "one"]

        assert db.session() is outer_session
        outer_session.expire(outer_item)
        assert outer_item.name == "one"
        assert _item_queries(apps) == ["two", "one", "one"]

    # After leaving every context, each app still reads its own database.
    apps.queries.clear()
    assert apps.one.test_client().get("/item").text == "one"
    assert apps.two.test_client().get("/item").text == "two"
    assert _item_queries(apps) == ["one", "two"]
