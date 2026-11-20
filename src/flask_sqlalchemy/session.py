from __future__ import annotations

import typing as t

import sqlalchemy as sa
import sqlalchemy.exc as sa_exc
import sqlalchemy.orm as sa_orm
from flask.globals import app_ctx

if t.TYPE_CHECKING:
    from .extension import SQLAlchemy


class Session(sa_orm.Session):
    """A SQLAlchemy :class:`~sqlalchemy.orm.Session` class that chooses what engine to
    use based on the bind key associated with the metadata associated with the thing
    being queried.

    To customize ``db.session``, subclass this and pass it as the ``class_`` key in the
    ``session_options`` to :class:`.SQLAlchemy`.

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

        .. versionchanged:: 3.0.3
            Fix finding the bind for a joined inheritance model.

        .. versionchanged:: 3.0
            The implementation more closely matches the base SQLAlchemy implementation.

        .. versionchanged:: 2.1
            Support joining an external transaction.
        """
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


class ReadOnlySession(Session):
    """A SQLAlchemy session that never writes to the database, for serving
    read-only requests such as internal audit APIs.

    Queries work exactly as with :class:`.Session`, and existing models are read
    as usual. Autoflush is disabled, so a query never triggers an automatic
    flush, even if a business function has mistakenly modified a model
    instance's attributes. Such modifications only exist in memory and are
    discarded when the session is removed at the end of the request.

    An explicit write operation --- calling :meth:`~sqlalchemy.orm.Session.flush`
    or :meth:`~sqlalchemy.orm.Session.commit` while there are pending new, dirty,
    or deleted objects --- raises :class:`sqlalchemy.exc.InvalidRequestError` and
    nothing is sent to the database. Committing with no pending changes is a
    harmless no-op.

    To use it, pass it as the ``class_`` key in the ``session_options`` to
    :class:`.SQLAlchemy`:

    .. code-block:: python

        from flask_sqlalchemy.session import ReadOnlySession

        db = SQLAlchemy(session_options={"class_": ReadOnlySession})

    .. versionadded:: 3.1.2
    """

    def __init__(self, db: SQLAlchemy, **kwargs: t.Any) -> None:
        kwargs["autoflush"] = False
        super().__init__(db, **kwargs)

    def flush(self, objects: t.Sequence[t.Any] | None = None) -> None:
        if self.new or self.dirty or self.deleted:
            raise sa_exc.InvalidRequestError(
                "This session is read-only and does not write to the database."
                " Discarding pending changes; use a regular session to modify"
                " data."
            )

        super().flush(objects=objects)


def _app_ctx_id() -> int:
    """Get the id of the current Flask application context for the session scope."""
    return id(app_ctx._get_current_object())  # type: ignore[attr-defined]
