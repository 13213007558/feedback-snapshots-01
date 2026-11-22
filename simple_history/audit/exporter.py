"""Batch export of approved historical changes for external audits.

Only three values are ever projected from the history table:

``event_time``
    The timezone-aware ``history_date`` rendered in UTC ISO-8601 form.
``change_type``
    A stable word derived from ``history_type`` (``created``, ``changed``
    or ``deleted``).
``object_ref``
    The primary key of the tracked object, i.e. the internal association
    number auditors use to correlate events. The value is never a model
    instance and no other model field is read.

Pagination is keyset-based on ``(history_date, history_id)``. The cursor is
opaque and the ordering is total, so a dataset can be exported repeatedly
with byte-identical rows as long as the underlying history is unchanged.
"""

import datetime
import json

from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q
from django.utils import timezone

from .cursor import AuditCursorError, decode_cursor, encode_cursor

UTC = datetime.timezone.utc

CHANGE_TYPE_LABELS = {
    "+": "created",
    "~": "changed",
    "-": "deleted",
}

PROJECTED_FIELDS = ("history_date", "history_type", "history_id")


class AuditExportError(ValueError):
    """Raised when the export request is invalid."""


def _normalise_bound(value, name):
    if value is None:
        return None
    if not isinstance(value, datetime.datetime):
        raise AuditExportError(f"{name} must be a datetime.datetime instance.")
    if timezone.is_naive(value):
        raise AuditExportError(f"{name} must be timezone-aware.")
    return value


def build_audit_queryset(
    history_model,
    *,
    start_time=None,
    end_time=None,
    approved_only=True,
    access_q=None,
    cursor=None,
):
    """Build the filtered, deterministically ordered audit queryset.

    ``start_time`` and ``end_time`` are interpreted as a half-open interval
    ``[start_time, end_time)``. ``access_q`` is a :class:`~django.db.models.Q`
    expressed against *history* columns (including snapshot copies of the
    tracked model's fields). Filtering on history columns matters for
    ``deleted`` rows, whose live object no longer exists.
    """
    start_time = _normalise_bound(start_time, "start_time")
    end_time = _normalise_bound(end_time, "end_time")
    if start_time and end_time and end_time <= start_time:
        raise AuditExportError("end_time must be later than start_time.")

    queryset = history_model.objects.all()
    if approved_only:
        try:
            approved_field = history_model._meta.get_field("approved")
        except FieldDoesNotExist as exc:
            raise AuditExportError(
                f"{history_model.__name__} has no 'approved' field; "
                "export approved-only datasets from models that track one."
            ) from exc
        if approved_field.get_internal_type() != "BooleanField":
            raise AuditExportError(
                f"{history_model.__name__}.approved must be a BooleanField."
            )
        queryset = queryset.filter(approved=True)

    if start_time is not None:
        queryset = queryset.filter(history_date__gte=start_time)
    if end_time is not None:
        queryset = queryset.filter(history_date__lt=end_time)
    if access_q is not None:
        queryset = queryset.filter(access_q)
    if cursor is not None:
        cursor_date, cursor_id = decode_cursor(cursor)
        queryset = queryset.filter(
            Q(history_date__gt=cursor_date)
            | Q(history_date=cursor_date, history_id__gt=cursor_id)
        )
    return queryset.order_by("history_date", "history_id")


def _object_ref_field(history_model):
    return history_model.instance_type._meta.pk.attname


def fetch_audit_page(
    history_model,
    *,
    page_size,
    start_time=None,
    end_time=None,
    approved_only=True,
    access_q=None,
    cursor=None,
):
    """Return ``(rows, next_cursor, has_next)`` for one batch.

    ``rows`` are plain dictionaries containing only the three audit fields.
    One extra row is fetched internally to decide whether another page
    exists; it is never returned to the caller.
    """
    if not isinstance(page_size, int) or page_size <= 0:
        raise AuditExportError("page_size must be a positive integer.")

    queryset = build_audit_queryset(
        history_model,
        start_time=start_time,
        end_time=end_time,
        approved_only=approved_only,
        access_q=access_q,
        cursor=cursor,
    )
    object_ref_field = _object_ref_field(history_model)
    values = queryset.values(*PROJECTED_FIELDS, object_ref_field)[: page_size + 1]

    fetched = list(values)
    has_next = len(fetched) > page_size
    page_rows = fetched[:page_size]
    next_cursor = None
    if has_next:
        last = page_rows[-1]
        next_cursor = encode_cursor(last["history_date"], last["history_id"])
    return (
        [serialize_audit_event(row, object_ref_field) for row in page_rows],
        next_cursor,
        has_next,
    )


def serialize_audit_event(row, object_ref_field):
    """Project a values() row down to the three permitted audit columns."""
    return {
        "event_time": timezone.localtime(row["history_date"], UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "change_type": CHANGE_TYPE_LABELS[row["history_type"]],
        "object_ref": str(row[object_ref_field]),
    }


def iter_audit_pages(
    history_model,
    *,
    page_size,
    start_time=None,
    end_time=None,
    approved_only=True,
    access_q=None,
    cursor=None,
    max_pages=None,
):
    """Yield ``(rows, next_cursor, has_next)`` batches until exhausted.

    Passing the last ``next_cursor`` back into a fresh run resumes the
    export without skipping or duplicating any event.
    """
    if max_pages is not None and (not isinstance(max_pages, int) or max_pages <= 0):
        raise AuditExportError("max_pages must be a positive integer or None.")
    pages_seen = 0
    while True:
        rows, next_cursor, has_next = fetch_audit_page(
            history_model,
            page_size=page_size,
            start_time=start_time,
            end_time=end_time,
            approved_only=approved_only,
            access_q=access_q,
            cursor=cursor,
        )
        yield rows, next_cursor, has_next
        pages_seen += 1
        if not has_next or next_cursor is None:
            return
        if max_pages is not None and pages_seen >= max_pages:
            return
        cursor = next_cursor


def write_audit_page(rows, file_obj):
    """Write one page as JSON Lines and return the number of rows written."""
    for row in rows:
        file_obj.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
        file_obj.write("\n")
    return len(rows)
