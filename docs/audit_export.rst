Minimal audit exports
=====================

External and annual reviews often need only a narrow projection of history
data: the time of each change, the kind of change and the internal
reference of the object it happened to. Raw model fields and historical
snapshots must not leave the system.

The ``simple_history.audit`` package provides a batched export that
guarantees those boundaries. Every emitted row contains exactly three
keys:

``event_time``
    The timezone-aware ``history_date`` rendered as UTC ISO-8601.
``change_type``
    One of ``created``, ``changed`` or ``deleted`` (from ``history_type``
    ``+``, ``~`` and ``-``).
``object_ref``
    The primary key of the tracked object — the internal association
    number used to correlate events. It is rendered as a string, so
    integer and UUID primary keys serialise identically.

Only those columns are selected from the history table, so original field
values cannot appear in an export even by accident.

.. note::

   Exports require a boolean ``approved`` field on the historical model
   (typically a plain ``BooleanField`` on the tracked model, which is
   copied onto every historical row). Rows whose snapshot has
   ``approved=False`` are excluded unless ``approved_only=False`` is
   passed.

Filtering by time and approval
------------------------------

``start_time`` and ``end_time`` form a half-open interval
``[start_time, end_time)``. Both must be timezone-aware datetimes.

.. code-block:: python

    from datetime import datetime, timezone
    from simple_history.audit import iter_audit_pages

    for rows, next_cursor, has_next in iter_audit_pages(
        MyModel.history.model,
        page_size=500,
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_time=datetime(2027, 1, 1, tzinfo=timezone.utc),
    ):
        for event in rows:
            ...  # event has only event_time, change_type and object_ref

Enforcing row-level access
--------------------------

Pass an ``access_q`` :class:`~django.db.models.Q` object expressed against
*history* columns. Filtering on the historical snapshot — rather than on
the live table — matters for ``deleted`` events, whose live object no
longer exists:

.. code-block:: python

    from django.db.models import Q

    for rows, _, _ in iter_audit_pages(
        CaseFile.history.model,
        page_size=500,
        access_q=Q(department="LEGAL"),
    ):
        ...

Stable, re-runnable pagination
------------------------------

Ordering is the total, deterministic pair
``(history_date, history_id)``. Rows that share a ``history_date`` are
therefore never reordered. The opaque cursor encodes the last
``(history_date, history_id)`` pair of a page; resuming from it uses a
strict keyset predicate, so no row is skipped or duplicated:

.. code-block:: python

    from simple_history.audit import fetch_audit_page

    rows, next_cursor, has_next = fetch_audit_page(
        MyModel.history.model, page_size=500
    )
    # Store next_cursor, then later:
    rows, next_cursor, has_next = fetch_audit_page(
        MyModel.history.model, page_size=500, cursor=next_cursor
    )

Because ordering is total and only immutable history columns are read,
re-running an export against unchanged history produces byte-identical
pages.

Writing JSON Lines files
------------------------

``write_audit_page`` serialises one page as JSON Lines, one event per line:

.. code-block:: python

    from simple_history.audit import write_audit_page

    with open("audit-page-0001.jsonl", "w", encoding="utf-8") as handle:
        write_audit_page(rows, handle)

The ``export_audit`` management command wraps the same API:

.. code-block:: console

    python manage.py export_audit myapp.casefile \
        --page-size 500 --max-pages 10 \
        --start-time 2026-01-01T00:00:00Z \
        --end-time 2027-01-01T00:00:00Z \
        --access-callback myapp.access.legal_department_access \
        --out-dir audit_pages/

Data rows go to the page files (or stdout); the resume cursor and paging
metadata are emitted on stderr as a JSON trailer.

A runnable SQLite project demonstrating same-timestamp changes, a deleted
history author and inaccessible records lives in
``examples/audit_export/`` in the repository.
