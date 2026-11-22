"""Opaque keyset pagination cursors for audit exports.

Ordering is the fully deterministic pair ``(history_date, history_id)``.
Rows sharing the same ``history_date`` are therefore never reordered or
dropped between pages, which keeps every export stable when it is re-run.
"""

import base64
import json

from django.utils import timezone
from django.utils.dateparse import parse_datetime

CURSOR_VERSION = 1


class AuditCursorError(ValueError):
    """Raised when a pagination cursor cannot be decoded."""


def encode_cursor(history_date, history_id):
    """Return an opaque token for the last row of a page."""
    payload = {
        "v": CURSOR_VERSION,
        "d": history_date.isoformat(),
        "i": str(history_id),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor):
    """Decode an opaque cursor back to ``(history_date, history_id)``.

    ``history_id`` is always returned as a string: the caller compares it
    against the database value, which works for integer, UUID and other
    primary key types.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        payload = json.loads(raw.decode("ascii"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditCursorError("Cursor is not valid base64-encoded JSON.") from exc
    if not isinstance(payload, dict) or payload.get("v") != CURSOR_VERSION:
        raise AuditCursorError("Cursor uses an unsupported version.")
    history_date = parse_datetime(payload.get("d", ""))
    history_id = payload.get("i")
    if history_date is None or timezone.is_naive(history_date) or not history_id:
        raise AuditCursorError("Cursor is missing a valid timestamp or id.")
    return history_date, str(history_id)
