"""Local, broker-free experiments for reconciling task cancellation.

This package models the three evidence channels that Flower / Celery expose
when a task is revoked, and shows why none of them alone can answer the
on-call question "was *this* attempt actually interrupted?".

Channels (the evidence boundary of each is intentionally preserved):

* ``api``      - the synchronous ``POST /api/task/revoke/<id>`` HTTP reply.
                 Flower currently calls ``control.revoke(...)`` without
                 ``reply=True`` and always answers 200, so this only proves
                 the request was *accepted locally*.
* ``control``  - the worker control-bus reply to the ``revoke`` command
                 (only exists when ``reply=True`` is used). It proves a
                 worker *processed the control command*, not that the task
                 was stopped.
* ``event``    - the ``task-*`` events Flower merges into ``EventsState``.
                 ``task-revoked`` / ``task-succeeded`` describe the task's
                 own final state but are delivered asynchronously and can be
                 reordered, retried or duplicated under the same task id.
"""

from .model import (
    Attempt,
    Channel,
    EvidenceRecord,
    Ledger,
    Reconciler,
    Verdict,
)

__all__ = [
    'Attempt',
    'Channel',
    'EvidenceRecord',
    'Ledger',
    'Reconciler',
    'Verdict',
]
