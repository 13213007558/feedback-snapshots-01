from __future__ import annotations

import typing as t

import pytest
import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
from flask import Flask

from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.track_modifications import AuditChange
from flask_sqlalchemy.track_modifications import models_committed
from flask_sqlalchemy.track_modifications import models_committed_audit
from flask_sqlalchemy.track_modifications import safe_models_committed

pytest.importorskip("blinker")


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[Flask, tuple[AuditChange, ...]]] = []

    def __call__(self, sender: Flask, changes: tuple[AuditChange, ...]) -> None:
        self.calls.append((sender, changes))

    @property
    def changes(self) -> list[AuditChange]:
        return [change for _, batch in self.calls for change in batch]


class LegacyRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[Flask, list[tuple[t.Any, str]]]] = []

    def __call__(self, sender: Flask, changes: list[tuple[t.Any, str]]) -> None:
        self.calls.append((sender, changes))

    @property
    def changes(self) -> list[tuple[t.Any, str]]:
        return [change for _, batch in self.calls for change in batch]


@pytest.fixture
def app(tmp_path: t.Any) -> Flask:
    app = Flask(__name__, instance_path=str(tmp_path / "instance"))
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'audit.sqlite'}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
    app.config["SQLALCHEMY_AUDIT_FIELDS"] = {
        "User": ("id", "name"),
        "Note": ("id", "user_id", "body"),
    }
    return app


@pytest.fixture
def db(app: Flask) -> SQLAlchemy:
    return SQLAlchemy(app)


@pytest.fixture
def models(app: Flask, db: SQLAlchemy) -> t.Any:
    class User(db.Model):
        id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
        name: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String)
        secret: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String)
        notes: sa_orm.Mapped[list[Note]] = sa_orm.relationship(
            back_populates="user", lazy="raise"
        )

    class Note(db.Model):
        id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
        user_id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.ForeignKey("user.id"))
        body: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String)
        draft: sa_orm.Mapped[str] = sa_orm.mapped_column(sa.String)
        user: sa_orm.Mapped[User] = sa_orm.relationship(
            back_populates="notes", lazy="raise"
        )

    with app.app_context():
        db.create_all()

    return User, Note


def test_commit_rollback_and_read_are_isolated(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    audit = Recorder()
    legacy = LegacyRecorder()

    with (
        app.app_context(),
        models_committed_audit.connected_to(audit, app),
        models_committed.connected_to(legacy, app),
    ):
        user = User(name="first", secret="never-disclosed")
        db.session.add(user)
        db.session.commit()

        assert len(audit.calls) == 1
        sender, changes = audit.calls[0]
        assert sender is app
        assert changes == (
            AuditChange(
                category="User",
                operation="insert",
                fields={"id": 1, "name": "first"},
            ),
        )
        record = changes[0]
        assert not hasattr(record, "instance")
        assert record.fields["name"] == "first"
        assert "secret" not in record.fields
        assert not isinstance(record, User)

        for change in changes:
            assert isinstance(change, AuditChange)
            assert set(change._fields) == {"category", "operation", "fields"}
            assert all(
                not isinstance(value, sa_orm.InstanceState)
                for value in change.fields.values()
            )

        # The legacy signal still receives the live ORM instance.
        assert len(legacy.changes) == 1
        legacy_instance, legacy_operation = legacy.changes[0]
        assert legacy_instance is user
        assert legacy_operation == "insert"

        # A rollback emits neither signal.
        audit.calls.clear()
        legacy.calls.clear()
        db.session.add(User(name="rolled-back", secret="nope"))
        db.session.rollback()
        assert audit.calls == []
        assert legacy.calls == []

        # Reading after the rollback does not produce audit records.
        assert db.session.scalar(sa.select(sa.func.count(User.id))) == 1
        assert audit.calls == []

        # Updating and committing reports the committed value, not a later edit.
        user = db.session.get(User, 1)
        assert user is not None
        user.name = "second"
        db.session.commit()
        assert len(audit.changes) == 1
        updated = audit.changes[0]
        assert updated.category == "User"
        assert updated.operation == "update"
        assert dict(updated.fields) == {"id": 1, "name": "second"}

        # A later edit does not change the record that was already sent.
        user.name = "not-yet-committed"
        assert dict(updated.fields)["name"] == "second"

        # Reading the object after the commit emits nothing.
        db.session.rollback()
        reloaded = db.session.get(User, 1)
        assert reloaded is not None
        assert reloaded.name == "second"
        assert len(audit.changes) == 1

        # The relationship is lazy="raise", so this also proves the audit path
        # never touched it, including while the approved fields were snapshotted.
        assert audit.changes[0].category == "User"


def test_delete_reports_loaded_approved_fields(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    audit = Recorder()

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        user = User(name="removed", secret="never-disclosed")
        db.session.add(user)
        db.session.commit()
        audit.calls.clear()

        user = db.session.get(User, 1)
        assert user is not None
        db.session.delete(user)
        db.session.commit()

        assert len(audit.changes) == 1
        change = audit.changes[0]
        assert change.operation == "delete"
        assert dict(change.fields) == {"id": 1, "name": "removed"}
        assert not db.session.scalar(sa.select(sa.func.count(User.id)))


def test_audit_payload_is_immutable_and_shared_safely(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    first = Recorder()
    second = Recorder()

    def mutate_instance(sender: Flask, changes: tuple[AuditChange, ...]) -> None:
        for change in changes:
            assert change.fields["name"] == "committed"

    with (
        app.app_context(),
        models_committed_audit.connected_to(first, app),
        models_committed_audit.connected_to(second, app),
        models_committed_audit.connected_to(mutate_instance, app),
    ):
        db.session.add(User(name="committed", secret="hidden"))
        db.session.commit()

        _, changes = first.calls[0]
        assert len(changes) == 1
        change = changes[0]

        with pytest.raises(TypeError):
            change.fields["name"] = "changed"  # type: ignore[index]

        _, second_changes = second.calls[0]
        assert second_changes is changes
        assert second_changes[0].fields["name"] == "committed"


def test_relationship_field_is_rejected_before_commit(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    app.config["SQLALCHEMY_AUDIT_FIELDS"] = {"User": ("id", "name", "notes")}
    audit = Recorder()

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        db.session.add(User(name="bad-config", secret="hidden"))

        with pytest.raises(ValueError, match="notes"):
            db.session.commit()

        db.session.rollback()
        assert audit.calls == []
        assert db.session.scalar(sa.select(sa.func.count(User.id))) == 0


def test_unapproved_models_are_omitted(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, Note = models
    audit = Recorder()

    def load_notes(user_id: int) -> list[t.Any]:
        return list(db.session.scalars(sa.select(Note).where(Note.user_id == user_id)))

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        db.session.add(User(name="owner", secret="hidden"))
        db.session.commit()
        audit.calls.clear()

        db.session.add(Note(user_id=1, body="visible", draft="hidden"))
        db.session.commit()

        assert [change.category for change in audit.changes] == ["Note"]
        assert dict(audit.changes[0].fields) == {
            "id": 1,
            "user_id": 1,
            "body": "visible",
        }
        assert "draft" not in audit.changes[0].fields

        notes = load_notes(1)
        assert [note.body for note in notes] == ["visible"]
        assert len(audit.changes) == 1


def test_savepoint_rollback_discards_only_its_records(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    audit = Recorder()

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        db.session.add(User(name="kept", secret="hidden"))
        db.session.commit()
        audit.calls.clear()

        db.session.add(User(name="outer", secret="hidden"))
        db.session.flush()

        savepoint = db.session.begin_nested()
        db.session.add(User(name="discarded", secret="hidden"))
        db.session.flush()
        savepoint.rollback()

        assert audit.calls == []
        db.session.commit()

        assert [change.fields["name"] for change in audit.changes] == ["outer"]
        assert db.session.scalar(sa.select(sa.func.count(User.id))) == 2


def test_signal_alias_points_to_same_signal() -> None:
    assert safe_models_committed is models_committed_audit


def test_audited_model_without_configured_fields_has_no_events(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    app.config["SQLALCHEMY_AUDIT_FIELDS"] = {}
    audit = Recorder()

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        db.session.add(User(name="ignored", secret="hidden"))
        db.session.commit()

    assert audit.calls == []


def test_savepoint_release_waits_for_outer_commit(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    audit = Recorder()

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        savepoint = db.session.begin_nested()
        db.session.add(User(name="savepoint", secret="hidden"))
        db.session.flush()
        savepoint.commit()

        assert audit.calls == []

        db.session.commit()

        assert [dict(change.fields) for change in audit.changes] == [
            {"id": 1, "name": "savepoint"}
        ]


def test_delete_after_savepoint_rollback_reports_once(
    app: Flask, db: SQLAlchemy, models: t.Any
) -> None:
    User, _Note = models
    audit = Recorder()

    with app.app_context(), models_committed_audit.connected_to(audit, app):
        db.session.add(User(name="kept", secret="hidden"))
        db.session.commit()
        audit.calls.clear()

        user = db.session.get(User, 1)
        assert user is not None
        savepoint = db.session.begin_nested()
        db.session.delete(user)
        db.session.flush()
        savepoint.rollback()

        db.session.delete(user)
        db.session.commit()

        assert len(audit.changes) == 1
        assert audit.changes[0].operation == "delete"
        assert dict(audit.changes[0].fields) == {"id": 1, "name": "kept"}


def test_mutable_column_value_is_copied_per_receiver(
    app: Flask, db: SQLAlchemy, tmp_path: t.Any
) -> None:
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'json.sqlite'}"
    app.config["SQLALCHEMY_AUDIT_FIELDS"] = {"Doc": ("id", "payload")}

    class Doc(db.Model):
        id: sa_orm.Mapped[int] = sa_orm.mapped_column(sa.Integer, primary_key=True)
        payload: sa_orm.Mapped[dict[str, t.Any]] = sa_orm.mapped_column(sa.JSON)

    received: list[dict[str, t.Any]] = []

    def tamper(sender: Flask, changes: tuple[AuditChange, ...]) -> None:
        for change in changes:
            value = change.fields["payload"]
            assert isinstance(value, dict)
            value["tampered"] = True

    def observe(sender: Flask, changes: tuple[AuditChange, ...]) -> None:
        received.append(dict(changes[0].fields["payload"]))

    with app.app_context():
        db.create_all()

        with (
            models_committed_audit.connected_to(tamper, app),
            models_committed_audit.connected_to(observe, app),
        ):
            doc = Doc(payload={"path": "report.pdf"})
            db.session.add(doc)
            db.session.commit()

            assert received == [{"path": "report.pdf"}]
            assert doc.payload == {"path": "report.pdf"}
