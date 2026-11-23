import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.admin.utils import quote
from django.contrib.admin.views.main import PAGE_VAR
from django.contrib.auth import get_user_model
from django.forms.models import BaseModelForm
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from simple_history.audit import (
    AuditCategory,
    PendingAuditEvent,
    flush_pending_audit_events,
)
from simple_history.tests.external.models import AuditedArchive

User = get_user_model()

OTHER_DB = "other"


class ListAuditCollector:
    """Test collector: records events in memory, can simulate an outage."""

    def __init__(self):
        self.events = []
        self.available = True

    def record(self, event):
        if not self.available:
            raise ConnectionError("audit collector unavailable")
        self.events.append(event)

    def reset(self):
        self.events = []
        self.available = True


collector = ListAuditCollector()


class AuditTestRouter:
    """Routes the audited model, its history and the audit outbox to 'other'."""

    def _db_for(self, model, **hints):
        if (
            model._meta.app_label == "external"
            or model._meta.label == "simple_history.PendingAuditEvent"
        ):
            return OTHER_DB
        return None

    def db_for_read(self, model, **hints):
        return self._db_for(model, **hints)

    def db_for_write(self, model, **hints):
        return self._db_for(model, **hints)

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label == "external" and obj2._meta.app_label == "external":
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == "external":
            return db == OTHER_DB
        if app_label == "simple_history" and model_name == "pendingauditevent":
            return None
        if db == OTHER_DB:
            return False
        return None


audit_override_settings = {
    "DATABASE_ROUTERS": ["simple_history.tests.tests.test_admin_audit.AuditTestRouter"],
    "SIMPLE_HISTORY_AUDIT_COLLECTOR": (
        "simple_history.tests.tests.test_admin_audit.collector"
    ),
}


def history_list_url(obj):
    app, model = obj._meta.app_label, obj._meta.model_name
    return reverse(f"admin:{app}_{model}_history", args=[quote(obj.pk)])


def history_version_url(obj, history_id):
    app, model = obj._meta.app_label, obj._meta.model_name
    return reverse(
        f"admin:{app}_{model}_simple_history",
        args=[quote(obj.pk), quote(history_id)],
    )


def make_archive(versions):
    """Create an AuditedArchive (on the routed DB) with one version per title."""
    archive = AuditedArchive.objects.create(title=versions[0])
    for title in versions[1:]:
        archive.title = title
        archive.save()
    return archive


def spread_history_dates(archive):
    """Give the historical records distinct, ordered dates for stable paging."""
    base = timezone.now() - timedelta(days=1)
    history_model = archive.history.model
    for index, record in enumerate(archive.history.order_by("history_id")):
        history_model.objects.filter(pk=record.pk).update(
            history_date=base + timedelta(minutes=index)
        )


@override_settings(**audit_override_settings)
class AdminAuditDisclosureTest(TestCase):
    databases = {"default", OTHER_DB}

    def setUp(self):
        collector.reset()
        self.user = User.objects.create_superuser("audit_admin", "a@example.com", "pw")
        self.client.force_login(self.user)

    def test_history_list_audits_only_the_rendered_page(self):
        archive = make_archive(["v1", "v2", "v3", "v4"])
        spread_history_dates(archive)
        ordered_records = list(archive.history.order_by("-history_date"))
        self.assertEqual(len(ordered_records), 4)  # two pages of two

        response = self.client.get(history_list_url(archive), {PAGE_VAR: 2})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(collector.events), 1)
        event = collector.events[0]
        self.assertEqual(event.category, AuditCategory.HISTORY_LIST)
        self.assertEqual(event.actor, "audit_admin")
        self.assertEqual(event.object_label, "external.AuditedArchive")
        self.assertEqual(event.object_id, str(archive.pk))
        self.assertEqual(event.page, 2)
        # Only the versions on the rendered page are disclosed
        self.assertEqual(
            event.history_ids,
            tuple(str(record.history_id) for record in ordered_records[2:4]),
        )
        # No historical field values leak into the audit output
        self.assertNotIn("v3", json.dumps(event.as_dict()))
        self.assertNotIn("title", event.as_dict())

    def test_history_list_first_page_is_a_separate_event(self):
        archive = make_archive(["v1", "v2", "v3", "v4"])
        spread_history_dates(archive)
        ordered_records = list(archive.history.order_by("-history_date"))

        response = self.client.get(history_list_url(archive))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(collector.events), 1)
        event = collector.events[0]
        self.assertEqual(event.page, 1)
        self.assertEqual(
            event.history_ids,
            tuple(str(record.history_id) for record in ordered_records[0:2]),
        )

    def test_history_list_permission_denied_records_category_only(self):
        staff = User.objects.create_user("staff", "s@example.com", "pw")
        staff.is_staff = True
        staff.save()
        self.client.force_login(staff)
        archive = make_archive(["v1", "v2"])

        response = self.client.get(history_list_url(archive))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(collector.events), 1)
        event = collector.events[0]
        self.assertEqual(event.category, AuditCategory.HISTORY_LIST_DENIED)
        self.assertIsNone(event.actor)
        self.assertIsNone(event.object_label)
        self.assertIsNone(event.object_id)
        self.assertEqual(event.history_ids, ())

    def test_version_form_get_and_revert_post_are_recorded_separately(self):
        archive = make_archive(["v1", "v2"])
        first_record = archive.history.order_by("history_id").first()
        url = history_version_url(archive, first_record.history_id)

        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(collector.events), 1)
        view_event = collector.events[0]
        self.assertEqual(view_event.category, AuditCategory.HISTORY_VERSION_VIEW)
        self.assertEqual(view_event.actor, "audit_admin")
        self.assertEqual(view_event.object_id, str(archive.pk))
        self.assertEqual(view_event.source_history_id, str(first_record.history_id))
        self.assertIsNone(view_event.result_history_id)

        response = self.client.post(url, {"title": "v1"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(collector.events), 2)
        revert_event = collector.events[1]
        self.assertEqual(revert_event.category, AuditCategory.HISTORY_REVERT)
        self.assertEqual(revert_event.actor, "audit_admin")
        self.assertEqual(revert_event.object_id, str(archive.pk))
        self.assertEqual(revert_event.source_history_id, str(first_record.history_id))
        latest_record = archive.history.order_by("-history_id").first()
        self.assertEqual(revert_event.result_history_id, str(latest_record.history_id))
        archive.refresh_from_db()
        self.assertEqual(archive.title, "v1")

    def test_version_form_permission_denied_records_category_only(self):
        staff = User.objects.create_user("staff2", "s2@example.com", "pw")
        staff.is_staff = True
        staff.save()
        self.client.force_login(staff)
        archive = make_archive(["v1", "v2"])
        first_record = archive.history.order_by("history_id").first()

        response = self.client.get(
            history_version_url(archive, first_record.history_id)
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(collector.events), 1)
        event = collector.events[0]
        self.assertEqual(event.category, AuditCategory.HISTORY_VERSION_DENIED)
        self.assertIsNone(event.actor)
        self.assertIsNone(event.source_history_id)


@override_settings(SIMPLE_HISTORY_AUDIT_ATOMIC_REVERT=True, **audit_override_settings)
class AdminAtomicRevertAuditTest(TransactionTestCase):
    databases = {"default", OTHER_DB}

    def setUp(self):
        collector.reset()
        self.user = User.objects.create_superuser("audit_admin", "a@example.com", "pw")
        self.client.force_login(self.user)
        self.archive = make_archive(["alpha-secret", "v2", "v3"])
        self.first_record = self.archive.history.order_by("history_id").first()
        self.revert_url = history_version_url(
            self.archive, self.first_record.history_id
        )

    def test_failed_revert_commits_no_audit_event(self):
        with patch.object(
            BaseModelForm,
            "_save_m2m",
            side_effect=RuntimeError("related data write failed"),
        ):
            with self.assertRaises(RuntimeError):
                self.client.post(self.revert_url, {"title": "alpha-secret"})

        # The whole transaction was rolled back: object, history and outbox
        self.archive.refresh_from_db()
        self.assertEqual(self.archive.title, "v3")
        self.assertEqual(self.archive.history.count(), 3)
        self.assertEqual(PendingAuditEvent.objects.using(OTHER_DB).count(), 0)
        self.assertEqual(PendingAuditEvent.objects.using("default").count(), 0)
        # No revert commit event was recorded - only the failure category
        categories = [event.category for event in collector.events]
        self.assertNotIn(AuditCategory.HISTORY_REVERT, categories)
        self.assertEqual(categories, [AuditCategory.HISTORY_REVERT_FAILED])
        failure_event = collector.events[0]
        self.assertIsNone(failure_event.actor)
        self.assertIsNone(failure_event.object_id)
        self.assertIsNone(failure_event.source_history_id)

    def test_successful_revert_leaves_one_retryable_pending_event(self):
        collector.available = False

        response = self.client.post(self.revert_url, {"title": "alpha-secret"})

        self.assertEqual(response.status_code, 302)
        self.archive.refresh_from_db()
        self.assertEqual(self.archive.title, "alpha-secret")
        self.assertEqual(self.archive.history.count(), 4)
        # The collector was down: nothing delivered, but exactly one pending
        # record was committed - on the same database as the object/history
        self.assertEqual(collector.events, [])
        self.assertEqual(PendingAuditEvent.objects.using("default").count(), 0)
        pending = PendingAuditEvent.objects.using(OTHER_DB).get()
        self.assertEqual(pending.category, AuditCategory.HISTORY_REVERT)
        payload = pending.payload
        self.assertEqual(payload["event_id"], pending.event_id)
        self.assertEqual(payload["actor"], "audit_admin")
        self.assertEqual(payload["object_label"], "external.AuditedArchive")
        self.assertEqual(payload["object_id"], str(self.archive.pk))
        self.assertEqual(
            payload["source_history_id"], str(self.first_record.history_id)
        )
        latest_record = self.archive.history.order_by("-history_id").first()
        self.assertEqual(payload["result_history_id"], str(latest_record.history_id))
        # No historical field values in the persisted audit payload
        self.assertNotIn("alpha-secret", json.dumps(payload))
        self.assertNotIn("title", payload)

        # The collector recovers: the same event id is re-sent exactly once
        collector.available = True
        delivered = flush_pending_audit_events(using=OTHER_DB)
        self.assertEqual(delivered, 1)
        self.assertEqual(len(collector.events), 1)
        event = collector.events[0]
        self.assertEqual(event.event_id, pending.event_id)
        self.assertEqual(event.category, AuditCategory.HISTORY_REVERT)
        self.assertEqual(event.source_history_id, str(self.first_record.history_id))
        self.assertEqual(event.result_history_id, str(latest_record.history_id))
        self.assertEqual(PendingAuditEvent.objects.using(OTHER_DB).count(), 0)

        # Nothing left to retry - no duplicate delivery
        self.assertEqual(flush_pending_audit_events(using=OTHER_DB), 0)
        self.assertEqual(len(collector.events), 1)
