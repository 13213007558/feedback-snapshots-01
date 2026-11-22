"""Minimal, re-runnable audit exports of historical records.

The functions in this package intentionally project only the three pieces of
information an annual review needs:

* the time of the change (``history_date``),
* the kind of change (``history_type``), and
* the internal reference of the changed object (the tracked model's primary
  key).

Model fields and historical snapshots are never selected or serialised, so
raw records cannot leave the system through an export file.
"""

from .exporter import (
    AuditCursorError,
    AuditExportError,
    iter_audit_pages,
    serialize_audit_event,
    write_audit_page,
)

__all__ = [
    "AuditCursorError",
    "AuditExportError",
    "iter_audit_pages",
    "serialize_audit_event",
    "write_audit_page",
]
