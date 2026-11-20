from __future__ import annotations

import typing as t

import sqlalchemy as sa
import sqlalchemy.exc as sa_exc
import sqlalchemy.orm as sa_orm
from flask.globals import app_ctx

if t.TYPE_CHECKING:
    from .extension import SQLAlchemy


_MISSING = object()


class BindAccessError(sa_exc.UnboundExecutionError, PermissionError):
    """Raised when a session tries to use a bind that the current application is not
    allowed to access.

    This subclasses :class:`sqlalchemy.exc.UnboundExecutionError` so existing error
    handling continues to work, and :class:`PermissionError` to make the access
    denial explicit.

    .. versionadded:: 3.2
    """


class Session(sa_orm.Session):
    """A SQLAlchemy :class:`~sqlalchemy.orm.Session` class that chooses what engine to
    use based on the bind key associated with the metadata associated with the thing
    being queried.

    To customize ``db.session``, subclass this and pass it as the ``class_`` key in the
    ``session_options`` to :class:`.SQLAlchemy`.

    .. versionchanged:: 3.2
        If :data:`.SQLALCHEMY_ALLOWED_BINDS` is configured, the session refuses to use
        bind keys that are not in the allowlist. This applies to both ORM and Core
        statements.

    .. versionchanged:: 3.0
        Renamed from ``SignallingSession``.
    """

    def __init__(self, db: SQLAlchemy, **kwargs: t.Any) -> None:
        super().__init__(**kwargs)
        self._db = db
        self._model_changes: dict[object, tuple[t.Any, str]] = {}

    def get_bind(
        self,
        mapper: t.Any | None = None,
        clause: t.Any | None = None,
        bind: sa.engine.Engine | sa.engine.Connection | None = None,
        **kwargs: t.Any,
    ) -> sa.engine.Engine | sa.engine.Connection:
        """Select an engine based on the ``bind_key`` of the metadata associated with
        the model or table being queried. If no bind key is set, uses the default bind.

        If the current application has :data:`.SQLALCHEMY_ALLOWED_BINDS` configured,
        every bind key that the statement depends on must be allowed. The check runs
        before a connection is acquired, so a rejected statement is not sent to any
        engine.

        .. versionchanged:: 3.2
            Enforce the configured bind allowlist for ORM and Core statements.

        .. versionchanged:: 3.0.3
            Fix finding the bind for a joined inheritance model.

        .. versionchanged:: 3.0
            The implementation more closely matches the base SQLAlchemy implementation.

        .. versionchanged:: 2.1
            Support joining an external transaction.
        """
        allowed = self._db.allowed_binds
        engines = self._db.engines

        if allowed is None:
            return self._get_bind_unrestricted(mapper, clause, bind, **kwargs)

        mapper_keys: set[str | None] = set()

        if mapper is not None:
            try:
                mapper = sa.inspect(mapper)
            except sa_exc.NoInspectionAvailable as e:
                if isinstance(mapper, type):
                    raise sa_orm.exc.UnmappedClassError(mapper) from e

                raise

            mapper_keys = _mapper_bind_keys(mapper)

        clause_keys = _clause_bind_keys(clause)
        statement_keys = mapper_keys | clause_keys

        if bind is not None:
            # An explicit bind bypasses statement routing in SQLAlchemy. Check both
            # the engine and any statement tables so a disallowed bind cannot be
            # reached through an override.
            forbidden = statement_keys - allowed

            if forbidden:
                raise _access_error(forbidden, allowed)

            _check_engine_allowed(bind, engines, allowed)
            return bind

        forbidden = statement_keys - allowed

        if forbidden:
            raise _access_error(forbidden, allowed)

        engine = _keys_to_engine(mapper_keys, engines)

        if engine is not None:
            return engine

        engine = _keys_to_engine(clause_keys, engines)

        if engine is not None:
            return engine

        if None in engines:
            return engines[None]

        result = super().get_bind(mapper=mapper, clause=clause, bind=bind, **kwargs)
        _check_engine_allowed(result, engines, allowed)
        return result

    def _get_bind_unrestricted(
        self,
        mapper: t.Any | None,
        clause: t.Any | None,
        bind: sa.engine.Engine | sa.engine.Connection | None,
        /,
        **kwargs: t.Any,
    ) -> sa.engine.Engine | sa.engine.Connection:
        """The original bind selection, used when no allowlist is configured."""
        if bind is not None:
            return bind

        engines = self._db.engines

        if mapper is not None:
            try:
                mapper = sa.inspect(mapper)
            except sa_exc.NoInspectionAvailable as e:
                if isinstance(mapper, type):
                    raise sa_orm.exc.UnmappedClassError(mapper) from e

                raise

            engine = _clause_to_engine(mapper.local_table, engines)

            if engine is not None:
                return engine

        if clause is not None:
            engine = _clause_to_engine(clause, engines)

            if engine is not None:
                return engine

        if None in engines:
            return engines[None]

        return super().get_bind(mapper=mapper, clause=clause, bind=bind, **kwargs)


def _check_engine_allowed(
    bind: sa.engine.Engine | sa.engine.Connection,
    engines: t.Mapping[str | None, sa.engine.Engine],
    allowed: t.Collection[str | None],
) -> None:
    key = _bind_key(bind, engines)

    if key is _MISSING or key not in allowed:
        keys: set[str | None] = {None} if key is _MISSING else {key}
        raise _access_error(keys, allowed)


def _bind_key(
    bind: sa.engine.Engine | sa.engine.Connection,
    engines: t.Mapping[str | None, sa.engine.Engine],
) -> str | None | object:
    """Return the bind key of an engine or connection managed by the extension."""
    engine = bind.engine if isinstance(bind, sa.engine.Connection) else bind

    for key, candidate in engines.items():
        if candidate is engine:
            return key

    return _MISSING


def _access_error(
    keys: t.Collection[str | None], allowed: t.Collection[str | None]
) -> BindAccessError:
    ordered = sorted(keys, key=lambda key: "" if key is None else key)
    requested = ", ".join(
        "the default bind (None)" if key is None else f"bind key {key!r}"
        for key in ordered
    )
    permitted = ", ".join(
        "None" if key is None else repr(key)
        for key in sorted(allowed, key=lambda key: "" if key is None else key)
    )
    return BindAccessError(
        f"Session is not allowed to access {requested}."
        f" Allowed bind keys: {permitted or '(none)'}."
    )


def _mapper_bind_keys(mapper: sa_orm.Mapper[t.Any]) -> set[str | None]:
    """Get all bind keys referenced by the tables of a mapper."""
    keys: set[str | None] = set()

    for table in mapper.tables:
        if isinstance(table, sa.Table):
            keys.update(_table_bind_keys(table))

    return keys


def _clause_bind_keys(clause: sa.ClauseElement | None) -> set[str | None]:
    """Get all bind keys referenced by tables in a Core or ORM expression."""
    if clause is None:
        return set()

    keys: set[str | None] = set()

    for element in sa.sql.visitors.iterate(clause):
        if isinstance(element, sa.Table):
            keys.update(_table_bind_keys(element))

    return keys


def _table_bind_keys(table: sa.Table) -> set[str | None]:
    if "bind_key" in table.metadata.info:
        return {table.metadata.info["bind_key"]}

    return set()


def _keys_to_engine(
    keys: set[str | None],
    engines: t.Mapping[str | None, sa.engine.Engine],
) -> sa.engine.Engine | None:
    """If all keys refer to one bind, return its engine."""
    if len(keys) != 1:
        return None

    key = next(iter(keys))

    if key not in engines:
        raise sa_exc.UnboundExecutionError(
            f"Bind key '{key}' is not in 'SQLALCHEMY_BINDS' config."
        )

    return engines[key]


def _clause_to_engine(
    clause: sa.ClauseElement | None,
    engines: t.Mapping[str | None, sa.engine.Engine],
) -> sa.engine.Engine | None:
    """If the clause is a table, return the engine associated with the table's
    metadata's bind key.
    """
    table = None

    if clause is not None:
        if isinstance(clause, sa.Table):
            table = clause
        elif isinstance(clause, sa.UpdateBase) and isinstance(clause.table, sa.Table):
            table = clause.table

    if table is not None and "bind_key" in table.metadata.info:
        key = table.metadata.info["bind_key"]

        if key not in engines:
            raise sa_exc.UnboundExecutionError(
                f"Bind key '{key}' is not in 'SQLALCHEMY_BINDS' config."
            )

        return engines[key]

    return None


def _app_ctx_id() -> int:
    """Get the id of the current Flask application context for the session scope."""
    return id(app_ctx._get_current_object())  # type: ignore[attr-defined]
