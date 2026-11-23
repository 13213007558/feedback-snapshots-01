"""
Optional audit integration for ``SimpleHistoryAdmin``.

When a collector is configured (see ``SIMPLE_HISTORY_AUDIT_COLLECTOR``), the
admin emits an :class:`AuditEvent` for each disclosure of historical data and
for each committed revert. Events only carry minimal identifiers (operator,
object, history version ids) - never historical field values. Denied or failed
operations record the event category only.

With ``SIMPLE_HISTORY_AUDIT_ATOMIC_REVERT`` enabled, the revert event is stored
as a :class:`PendingAuditEvent` in the same database transaction as the revert
itself, and is handed to the collector only after the transaction commits. If
the collector is unavailable, the pending record can be re-delivered later with
the same event id via :func:`flush_pending_audit_events`.
"""

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from functools import lru_cache

from django.conf import settings
from django.db import models
from django.dispatch import receiver
from django.test.signals import setting_changed
from django.utils import timezone
from django.utils.module_loading import import_string

logger = logging.getLogger(__name__)


class AuditCategory:
    """Categories used to distinguish audited admin operations."""

    HISTORY_LIST = "history_list"
    HISTORY_LIST_DENIED = "history_list_denied"
    HISTORY_VERSION_VIEW = "history_version_view"
    HISTORY_VERSION_DENIED = "history_version_denied"
    HISTORY_REVERT = "history_revert"
    HISTORY_REVERT_FAILED = "history_revert_failed"


@dataclass
class AuditEvent:
    """
    A single audit record. Only identifiers are carried - never field values.

    ``history_ids`` lists the versions disclosed on a successfully rendered
    history list page. ``source_history_id`` identifies the version a revert
    (or version form view) was based on, and ``result_history_id`` identifies
    the historical record created by a committed revert.
    """

    category: str
    actor: str | None = None
    object_label: str | None = None
    object_id: str | None = None
    page: int | None = None
    history_ids: tuple[str, ...] = ()
    source_history_id: str | None = None
    result_history_id: str | None = None
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=timezone.now)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["history_ids"] = list(self.history_ids)
        data["created_at"] = self.created_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEvent":
        data = dict(data)
        data["history_ids"] = tuple(data.get("history_ids") or ())
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            data["created_at"] = datetime.fromisoformat(created_at)
        return cls(**data)


class AuditCollector:
    """
    Base class for audit collectors. Subclasses must implement ``record()``.

    ``record()`` should raise (or return ``False``) when the event could not
    be accepted, so that pending events are kept for a later retry.
    """

    def record(self, event: AuditEvent):  # pragma: no cover
        raise NotImplementedError


@lru_cache(maxsize=None)
def _resolve_collector(configured):
    if configured is None:
        return None
    if isinstance(configured, str):
        resolved = import_string(configured)
        return resolved() if isinstance(resolved, type) else resolved
    return configured


def get_audit_collector():
    """
    Return the collector configured via ``SIMPLE_HISTORY_AUDIT_COLLECTOR``
    (a dotted path to a collector instance or class, or a collector directly),
    or ``None`` when auditing is not configured.
    """
    configured = getattr(settings, "SIMPLE_HISTORY_AUDIT_COLLECTOR", None)
    try:
        return _resolve_collector(configured)
    except Exception:
        logger.exception("Could not resolve SIMPLE_HISTORY_AUDIT_COLLECTOR")
        return None


@receiver(setting_changed)
def _reset_cached_collector(*, setting, **kwargs):
    if setting == "SIMPLE_HISTORY_AUDIT_COLLECTOR":
        _resolve_collector.cache_clear()


def emit_audit_event(event: AuditEvent, collector=None) -> bool:
    """
    Deliver ``event`` directly to the collector, best-effort: collector
    failures are logged and never break the admin request.
    """
    if collector is None:
        collector = get_audit_collector()
    if collector is None:
        return False
    try:
        result = collector.record(event)
    except Exception:
        logger.exception("Failed to deliver audit event %s", event.event_id)
        return False
    return result is not False


class PendingAuditEvent(models.Model):
    """
    Outbox record for an audit event that must be delivered to the collector.

    Created in the same database (and transaction) as the revert it audits;
    deleted once the collector has accepted the event.
    """

    event_id = models.CharField(max_length=64, unique=True)
    category = models.CharField(max_length=64)
    payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.PositiveIntegerField(default=0)
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("created_at", "pk")

    def __str__(self):
        return f"{self.category} ({self.event_id})"

    def build_event(self) -> AuditEvent:
        return AuditEvent.from_dict(self.payload)


def dispatch_pending_audit_event(event_id: str, using=None, collector=None) -> bool:
    """
    Try to deliver the pending event ``event_id`` to the collector.

    Returns ``True`` when the event was accepted (and the pending record was
    removed). Returns ``False`` when the collector is unavailable, keeping the
    pending record so it can be retried later with the same event id.
    """
    if collector is None:
        collector = get_audit_collector()
    if collector is None:
        return False
    manager = PendingAuditEvent.objects
    if using:
        manager = manager.using(using)
    try:
        pending = manager.get(event_id=event_id)
    except PendingAuditEvent.DoesNotExist:
        return True
    try:
        accepted = emit_audit_event(pending.build_event(), collector=collector)
    except Exception:  # pragma: no cover - emit_audit_event already swallows
        accepted = False
    if not accepted:
        manager.filter(pk=pending.pk).update(
            attempts=models.F("attempts") + 1, last_attempt_at=timezone.now()
        )
        return False
    pending.delete()
    return True


def flush_pending_audit_events(using=None, collector=None) -> int:
    """
    Try to deliver all pending audit events (oldest first), e.g. after the
    collector has recovered from an outage. Events are re-sent with the same
    event id they were originally recorded with. Returns the number of events
    that were accepted by the collector.
    """
    if collector is None:
        collector = get_audit_collector()
    if collector is None:
        return 0
    manager = PendingAuditEvent.objects
    if using:
        manager = manager.using(using)
    delivered = 0
    for pending in manager.iterator():
        if dispatch_pending_audit_event(
            pending.event_id, using=pending._state.db, collector=collector
        ):
            delivered += 1
    return delivered
