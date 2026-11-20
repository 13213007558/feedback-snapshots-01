from __future__ import annotations

import copy
import typing as t
import weakref

import sqlalchemy as sa
import sqlalchemy.event as sa_event
import sqlalchemy.orm as sa_orm
from flask import current_app
from flask import has_app_context
from flask.signals import Namespace  # type: ignore[attr-defined]

if t.TYPE_CHECKING:
    from .session import Session

_signals = Namespace()

models_committed = _signals.signal("models-committed")
"""This Blinker signal is sent after the session is committed if there were changed
models in the session.

The sender is the application that emitted the changes. The receiver is passed the
``changes`` argument with a list of tuples in the form ``(instance, operation)``.
The operations are ``"insert"``, ``"update"``, and ``"delete"``.

The instances are the live ORM objects, and accessing their attributes may load
relationships or otherwise run queries. Use :data:`models_committed_audit` instead
when the receiver is not allowed to see whole objects.
"""

before_models_committed = _signals.signal("before-models-committed")
"""This signal works exactly like :data:`models_committed` but is emitted before the
commit takes place.

Because the commit can still fail or be rolled back, this signal must not be used to
send information to an audit receiver.
"""


class _AuditFields(t.Mapping[str, t.Any]):
    """A read-only mapping that gives each reader its own copy of a value.

    A JSON or other mutable column would otherwise let the first receiver change the
    value that the next receiver sees.
    """

    __slots__ = ("_values",)

    def __init__(self, values: dict[str, t.Any]) -> None:
        self._values = values

    def __getitem__(self, key: str) -> t.Any:
        try:
            return copy.deepcopy(self._values[key])
        except Exception:
            return self._values[key]

    def __iter__(self) -> t.Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return repr(self._values)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _AuditFields):
            return self._values == other._values

        if isinstance(other, t.Mapping):
            return self._values == dict(other)

        return NotImplemented

    def __ne__(self, other: object) -> bool:
        return not self == other


class AuditChange(t.NamedTuple):
    """A post-commit description of a changed model that is safe to hand to an audit
    receiver.

    The record intentionally does not contain the model instance. ``category`` is the
    model class name, ``operation`` is ``"insert"``, ``"update"``, or ``"delete"``,
    and ``fields`` contains only the values approved in
    :data:`SQLALCHEMY_AUDIT_FIELDS`. ``fields`` is a read-only mapping.
    """

    category: str
    """The model class name, for example ``"User"``."""

    operation: str
    """``"insert"``, ``"update"``, or ``"delete"``."""

    fields: t.Mapping[str, t.Any]
    """Approved column values as they were committed."""


models_committed_audit = _signals.signal("models-committed-audit")
"""An opt-in Blinker signal that sends audit-safe descriptions after a commit.

Enable it by setting :data:`SQLALCHEMY_AUDIT_FIELDS` before calling
:meth:`.SQLAlchemy.init_app`. The sender is the application that emitted the changes.
The receiver is passed the ``changes`` argument with a tuple of
:class:`AuditChange` records, one for each changed model. The records contain the
model class name, the operation, and only the approved column values as they were
stored by the commit.

Models that are not listed in :data:`SQLALCHEMY_AUDIT_FIELDS` are omitted. Approved
fields must be column attributes; relationships cannot be approved, so receiving these
records never loads a relationship. No records are sent for a rollback or a failed
commit, and records are not sent for nested savepoint commits until the outermost
transaction commits.
"""

# A convenient explicit alias for applications that describe the signal by its
# security property rather than by its audit use case.
safe_models_committed = models_committed_audit


def _listen(session: sa_orm.scoped_session[Session]) -> None:
    sa_event.listen(session, "before_flush", _record_ops, named=True)
    sa_event.listen(session, "before_commit", _record_ops, named=True)
    sa_event.listen(session, "before_commit", _before_commit)
    sa_event.listen(session, "after_commit", _after_commit)
    sa_event.listen(session, "after_rollback", _after_rollback)


def _listen_audit(session: sa_orm.scoped_session[Session]) -> None:
    sa_event.listen(session, "before_flush", _prepare_audit_values)
    sa_event.listen(session, "after_flush", _record_audit_ops)
    sa_event.listen(session, "after_commit", _after_commit_audit)
    sa_event.listen(session, "after_rollback", _after_rollback_audit)
    sa_event.listen(session, "after_transaction_create", _create_audit_snapshot)
    sa_event.listen(session, "after_transaction_end", _end_audit_snapshot)


def _record_ops(session: Session, **kwargs: t.Any) -> None:
    if not has_app_context():
        return

    if not current_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]:
        return

    for targets, operation in (
        (session.new, "insert"),
        (session.dirty, "update"),
        (session.deleted, "delete"),
    ):
        for target in targets:
            state = sa.inspect(target)
            key = state.identity_key if state.has_identity else id(target)
            session._model_changes[key] = (target, operation)


def _before_commit(session: Session) -> None:
    if not has_app_context():
        return

    app = current_app._get_current_object()  # type: ignore[attr-defined]

    if not app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]:
        return

    if session._model_changes:
        changes = list(session._model_changes.values())
        before_models_committed.send(app, changes=changes)


def _after_commit(session: Session) -> None:
    if not has_app_context():
        return

    app = current_app._get_current_object()  # type: ignore[attr-defined]

    if not app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]:
        return

    if session._model_changes:
        changes = list(session._model_changes.values())
        models_committed.send(app, changes=changes)
        session._model_changes.clear()


def _after_rollback(session: Session) -> None:
    session._model_changes.clear()


def _audit_fields_for(target: t.Any) -> tuple[str, ...] | None:
    """Return the approved column names for an object, or ``None`` if the model is
    not approved for audit reporting.
    """
    app = current_app._get_current_object()  # type: ignore[attr-defined]
    config: t.Mapping[t.Any, t.Any] = app.config.get("SQLALCHEMY_AUDIT_FIELDS") or {}

    if not config:
        return None

    cls = type(target)
    configured = config.get(cls)

    if configured is None:
        configured = config.get(cls.__name__)

    if configured is None:
        for key, value in config.items():
            if isinstance(key, type) and isinstance(target, key):
                configured = value
                break

    if configured is None:
        return None

    if isinstance(configured, str):
        configured = (configured,)

    return tuple(configured)


def _audit_columns(target: t.Any, fields: tuple[str, ...]) -> None:
    """Validate that every approved name is a plain mapped column.

    A column property that wraps an arbitrary SQL expression is rejected too. It
    could query another table, which must not happen just because an audit receiver
    is subscribed.
    """
    state = sa.inspect(target)
    mapper = state.mapper
    props = {prop.key: prop for prop in mapper.column_attrs}
    invalid: list[str] = []

    for name in fields:
        prop = props.get(name)

        if prop is None:
            invalid.append(name)
            continue

        columns = getattr(prop, "columns", ())
        column = next(iter(columns), None)

        if not isinstance(column, sa.Column) or column.table not in mapper.tables:
            invalid.append(name)

    if invalid:
        category = type(target).__name__
        raise ValueError(
            f"SQLALCHEMY_AUDIT_FIELDS for {category!r} contains attributes that are"
            f" not plain columns: {invalid!r}. Only columns of the model's own tables"
            " can be disclosed by the audit signal; relationships and computed column"
            " properties are not allowed."
        )


def _audit_value(target: t.Any, name: str) -> t.Any:
    state = sa.inspect(target)

    if name in state.dict:
        value = state.dict[name]
    else:
        # The name was validated as a plain column, so loading it cannot load a
        # relationship. It may only issue a SELECT for that column.
        try:
            value = getattr(target, name)
        except sa_orm.exc.ObjectDeletedError:
            return None

    # Detach mutable values from the ORM object so a receiver cannot see later
    # edits. A value that cannot be copied is represented as text rather than
    # handing the live value to the receiver.
    try:
        return copy.deepcopy(value)
    except Exception:
        return repr(value)


def _prepare_audit_values(
    session: Session, flush_context: object, instances: object
) -> None:
    """Load approved columns before DML so deleted rows still have values.

    Validation also runs before anything is committed, so a bad configuration is
    rejected instead of silently leaking or skipping data.
    """
    if not has_app_context():
        return

    for targets in (session.new, session.dirty, session.deleted):
        for target in targets:
            fields = _audit_fields_for(target)

            if fields is None:
                continue

            _audit_columns(target, fields)
            state = sa.inspect(target)

            for name in fields:
                if name not in state.dict:
                    try:
                        getattr(target, name)
                    except sa_orm.exc.ObjectDeletedError:
                        # The row is gone but the object is still in the session,
                        # for example when a savepoint delete was rolled back. There
                        # is no committed value to disclose for this field.
                        continue


def _has_column_changes(target: t.Any) -> bool:
    """Return whether a dirty object changed a column, not only a relationship."""
    state = sa.inspect(target)

    for prop in state.mapper.column_attrs:
        if state.attrs[prop.key].history.has_changes():
            return True

    return False


def _audit_snapshot(target: t.Any) -> AuditChange | None:
    """Take a snapshot of approved column values without reading relationships."""
    fields = _audit_fields_for(target)

    if fields is None:
        return None

    _audit_columns(target, fields)

    return AuditChange(
        category=type(target).__name__,
        operation="",
        fields=_AuditFields({name: _audit_value(target, name) for name in fields}),
    )


def _record_audit_ops(session: Session, flush_context: object) -> None:
    if not has_app_context():
        return

    changes: list[tuple[object, str]] = []

    for targets, operation in (
        (session.new, "insert"),
        (session.dirty, "update"),
        (session.deleted, "delete"),
    ):
        for target in targets:
            if _audit_fields_for(target) is None:
                continue

            if operation == "update" and not _has_column_changes(target):
                continue

            changes.append((target, operation))

    for target, operation in changes:
        record = _audit_snapshot(target)

        if record is None:
            continue

        state = t.cast(sa_orm.InstanceState[t.Any], sa.inspect(target))
        object_key = id(target)
        key: object = state.identity_key if state.has_identity else object_key

        # A pending object was recorded under ``id(target)`` but gains an identity
        # after its INSERT. Follow that earlier key so one transaction produces one
        # record for the object. The weak reference makes sure a recycled object id
        # cannot merge two unrelated objects.
        previous_key: object = key
        tracked = session._audit_object_keys.get(object_key)

        if tracked is not None:
            tracked_ref, tracked_key = tracked

            if tracked_ref() is target:
                previous_key = tracked_key

        previous = session._audit_changes.get(previous_key)

        if operation == "delete" and previous is not None:
            if previous.operation == "insert":
                # An object inserted and deleted in the same transaction leaves no
                # row to disclose.
                session._audit_changes.pop(previous_key, None)
                session._audit_object_keys.pop(object_key, None)
                continue

        if previous_key != key:
            session._audit_changes.pop(previous_key, None)

        if operation == "update" and previous is not None:
            if previous.operation == "insert":
                operation = "insert"
            elif previous.operation == "delete":
                operation = "delete"

        session._audit_changes[key] = record._replace(operation=operation)
        session._audit_object_keys[object_key] = (weakref.ref(target), key)


def _after_commit_audit(session: Session) -> None:
    if not has_app_context():
        return

    # SQLAlchemy emits after_commit for savepoint releases too. Only the outermost
    # commit makes the records durable.
    if session.in_nested_transaction():
        return

    app = current_app._get_current_object()  # type: ignore[attr-defined]

    if not app.config.get("SQLALCHEMY_AUDIT_FIELDS"):
        session._audit_changes.clear()
        session._audit_object_keys.clear()
        return

    changes = tuple(session._audit_changes.values())

    # Clear before sending. A receiver that raises must not leave the records behind
    # to be sent again on the next commit.
    session._audit_changes.clear()
    session._audit_object_keys.clear()
    session._audit_savepoints.clear()

    if changes:
        models_committed_audit.send(app, changes=changes)


def _after_rollback_audit(session: Session) -> None:
    if session.in_nested_transaction():
        # Only discard records made inside the rolled back savepoint.
        transaction = session.get_nested_transaction()

        if transaction is not None:
            snapshot = session._audit_savepoints.pop(id(transaction), None)

            if snapshot is not None:
                session._audit_changes, session._audit_object_keys = snapshot

        return

    session._audit_changes.clear()
    session._audit_object_keys.clear()
    session._audit_savepoints.clear()


def _create_audit_snapshot(
    session: Session, transaction: sa_orm.SessionTransaction
) -> None:
    if transaction.nested:
        session._audit_savepoints[id(transaction)] = (
            session._audit_changes.copy(),
            session._audit_object_keys.copy(),
        )


def _end_audit_snapshot(
    session: Session, transaction: sa_orm.SessionTransaction
) -> None:
    if transaction.nested:
        # A saved snapshot means the savepoint was released and its changes stay
        # part of the outer transaction. A rolled back savepoint was already
        # restored by _after_rollback_audit.
        session._audit_savepoints.pop(id(transaction), None)
