"""Task-scoped attribution helpers for historical records.

``HistoryRequestMiddleware`` answers "which web request is this?".  The helpers
in this module answer a different question: "which author should this
background task or import attribute its history to?".  Keeping the two
contexts separate means a task never has to pretend to be a request, and a
request never inherits a task's author by accident.
"""

from contextlib import contextmanager

try:
    from asgiref.local import Local as LocalContext
except ImportError:
    from threading import local as LocalContext

_context = LocalContext()
_UNSET = object()


def get_context_history_user():
    """Return the author declared for the current task, if any."""
    return getattr(_context, "user", None)


@contextmanager
def history_user_context(user=None, *, approver=None):
    """Attribute history records created in this block to a task author.

    Use this for management commands, imports, and other background work that
    runs outside a web request.  ``user`` is normally the service identity
    executing the task.  When ``approver`` is given, the approver is recorded
    as the author instead.

    Inside the block, a historical record's author is resolved in this order:

    1. an explicit ``instance._history_user``
    2. the author declared by this context
    3. the authenticated user from ``HistoryRequestMiddleware``
    4. the model's ``get_user`` callable

    The context is scoped to the current thread or async task and is removed on
    exit, even when the block raises, so it cannot leak into a later request.

    .. code-block:: python

        from simple_history.attribution import history_user_context

        author = approval.approved_by if approval else service_account
        with history_user_context(user=service_account, approver=author):
            import_rows()

    Yields the effective author: ``approver`` when supplied, otherwise ``user``.
    """
    author = approver if approver is not None else user
    previous = getattr(_context, "user", _UNSET)
    _context.user = author
    try:
        yield author
    finally:
        if previous is _UNSET:
            try:
                del _context.user
            except AttributeError:
                pass
        else:
            _context.user = previous
