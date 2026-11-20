Tracking Modifications
======================

.. warning::
    Tracking changes adds significant overhead. In most cases, you'll be better served by
    using `SQLAlchemy events`_ directly.

.. _SQLAlchemy events: https://docs.sqlalchemy.org/core/event.html

Flask-SQLAlchemy can set up its session to track inserts, updates, and deletes for
models, then send a Blinker signal with a list of these changes either before or during
calls to ``session.flush()`` and ``session.commit()``.

To enable this feature, set :data:`.SQLALCHEMY_TRACK_MODIFICATIONS` in the Flask app
config. Then add a listener to :data:`.models_committed` (emitted after the commit) or
:data:`.before_models_committed` (emitted before the commit).

.. code-block:: python

    from flask_sqlalchemy.track_modifications import models_committed

    def get_modifications(sender: Flask, changes: list[tuple[t.Any, str]]) -> None:
        ...

    models_committed.connect(get_modifications)

Safe audit events
-----------------

The ``changes`` from the signals above contain live ORM instances. A receiver can read
any attribute from them, which may disclose unapproved fields or load a relationship
that the receiver is not allowed to read. For an audit receiver, enable
:data:`.SQLALCHEMY_AUDIT_FIELDS` and subscribe to :data:`.models_committed_audit`.

.. code-block:: python

    from flask_sqlalchemy.track_modifications import AuditChange
    from flask_sqlalchemy.track_modifications import models_committed_audit

    app.config["SQLALCHEMY_AUDIT_FIELDS"] = {
        "User": ("id", "email"),
        "Order": ("id", "status", "total"),
    }

    def record_audit(sender: Flask, changes: tuple[AuditChange, ...]) -> None:
        for change in changes:
            print(change.category, change.operation, dict(change.fields))

    models_committed_audit.connect(record_audit)

``safe_models_committed`` is an alias for applications that name the signal by its
security property instead of its audit use.

The records contain only the model class name, the operation, and the approved column
values. Approved names must be plain columns defined by the model. A relationship or a
computed column property is rejected with a ``ValueError`` before the commit, instead of
being read. Models that are not listed in the configuration are omitted.

Each record is a copy taken while the data is being flushed, and it is deep-copied away
from the ORM object. Editing the instance afterwards does not change an already sent
record. The ``fields`` mapping is read-only, and reading a value such as a JSON column
gives the receiver its own copy, so one receiver cannot modify what another sees.

Records are only sent from the outermost ``after_commit``. A rollback sends nothing, and
a savepoint that is rolled back discards only the records made inside it. These events
are independent of ``SQLALCHEMY_TRACK_MODIFICATIONS``; the original signals keep
working with their existing behavior for application code.
