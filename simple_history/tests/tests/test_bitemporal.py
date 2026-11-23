import datetime

from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from simple_history.tests.models import Approval, Poll
from simple_history.utils import bulk_create_with_history


class BitemporalTestCase(TestCase):
    """
    Normal saves, a legal backfill batch and a rolled-back import are
    interleaved on SQLite. Business queries read history by effective time
    (`history_date`); audit queries reconstruct what the system actually knew
    at a moment via `history_recorded_at`.
    """

    def setUp(self):
        self.t_created = datetime.datetime(2026, 1, 5, 9, 0, 0)
        self.t_approved = datetime.datetime(2026, 1, 6, 9, 0, 0)
        self.t_revoked = datetime.datetime(2026, 1, 6, 10, 0, 0)
        self.t_old_import = datetime.datetime(2025, 12, 20, 9, 0, 0)
        self.t_legacy = datetime.datetime(2026, 1, 1, 9, 0, 0)

        # --- normal saves: effective time declared by the business,
        #     entry time assigned by the trusted recorder ---
        self.approval = Approval(name="A-1", status="draft")
        self.approval._history_date = self.t_created
        self.approval.save()

        self.approval.status = "approved"
        self.approval._history_date = self.t_approved
        self.approval.save()

        # --- legacy row: predates bitemporal tracking, entry time unknown ---
        self.legacy_row = Approval.history.model.objects.create(
            id=self.approval.pk,
            name="A-1",
            status="filed",
            history_date=self.t_legacy,
            history_type="+",
        )

        # moment 1: the audit store does not contain the backfill yet
        self.audit_point_before_backfill = timezone.now()

        # --- legal backfill batch: old objects plus a late-arriving action
        #     for A-1, entering the audit store in one controlled import ---
        backfill_objs = [
            Approval(name="A-2", status="approved"),
            Approval(name="A-3", status="rejected"),
        ]
        with transaction.atomic():
            bulk_create_with_history(
                backfill_objs, Approval, default_date=self.t_old_import
            )
            revoked = Approval(pk=self.approval.pk, name="A-1", status="revoked")
            revoked._history_date = self.t_revoked
            Approval.history.bulk_history_create([revoked], update=True)

        # moment 2: the audit store now also holds the backfilled rows
        self.audit_point_after_backfill = timezone.now()

        # --- a failed import: rolled back, must never be queryable ---
        self.history_count_before_failure = Approval.history.count()
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                bulk_create_with_history(
                    [Approval(name="A-4", status="draft")],
                    Approval,
                    default_date=self.t_old_import,
                )
                raise RuntimeError("backfill batch aborted")

    def history_of(self, approval):
        return Approval.history.filter(id=approval.pk)

    def test_normal_saves_have_trusted_entry_time(self):
        rows = self.history_of(self.approval).exclude(pk=self.legacy_row.pk)
        self.assertEqual(rows.count(), 3)
        for row in rows:
            self.assertIsNotNone(row.history_recorded_at)
        normal_rows = rows.filter(history_date__in=[self.t_created, self.t_approved])
        for row in normal_rows:
            self.assertLessEqual(
                row.history_recorded_at, self.audit_point_before_backfill
            )

    def test_backfill_batch_shares_one_recorded_boundary(self):
        backfilled = Approval.history.filter(name__in=["A-2", "A-3"])
        self.assertEqual(backfilled.count(), 2)
        # one shared entry timestamp for the whole controlled import
        self.assertEqual(
            {row.history_recorded_at for row in backfilled},
            {backfilled[0].history_recorded_at},
        )
        for row in backfilled:
            # business-effective time stays the old, declared one ...
            self.assertEqual(row.history_date, self.t_old_import)
            # ... while the entry time falls inside the import window
            self.assertGreater(
                row.history_recorded_at, self.audit_point_before_backfill
            )
            self.assertLessEqual(
                row.history_recorded_at, self.audit_point_after_backfill
            )

    def test_failed_import_is_never_recorded(self):
        self.assertEqual(Approval.history.count(), self.history_count_before_failure)
        self.assertFalse(Approval.objects.filter(name="A-4").exists())
        self.assertFalse(Approval.history.filter(name="A-4").exists())
        audit_view = Approval.history.as_of_recorded(timezone.now())
        self.assertFalse(audit_view.filter(name="A-4").exists())

    def test_current_business_history_uses_effective_time(self):
        current = Approval.objects.get(pk=self.approval.pk)
        self.assertEqual(current.history.as_of(timezone.now()).status, "revoked")
        timeline = list(
            self.history_of(self.approval).values_list("status", "history_date")
        )
        self.assertEqual(
            timeline,
            [
                ("revoked", self.t_revoked),
                ("approved", self.t_approved),
                ("draft", self.t_created),
                ("filed", self.t_legacy),
            ],
        )

    def test_audit_views_before_and_after_backfill_differ(self):
        current = Approval.objects.get(pk=self.approval.pk)
        # Same object, reconstructed as the system knew it at two moments:
        # the revocation took effect in the past but only entered the audit
        # store with the backfill batch.
        self.assertEqual(
            current.history.audit_as_of(self.audit_point_before_backfill).status,
            "approved",
        )
        self.assertEqual(
            current.history.audit_as_of(self.audit_point_after_backfill).status,
            "revoked",
        )

        names_before = {
            obj.name
            for obj in Approval.history.audit_as_of(self.audit_point_before_backfill)
        }
        names_after = {
            obj.name
            for obj in Approval.history.audit_as_of(self.audit_point_after_backfill)
        }
        self.assertEqual(names_before, {"A-1"})
        self.assertEqual(names_after, {"A-1", "A-2", "A-3"})

    def test_legacy_rows_have_queryable_unknown_entry_time(self):
        self.assertIsNone(self.legacy_row.history_recorded_at)
        unknown = Approval.history.filter(history_recorded_at__isnull=True)
        self.assertEqual(list(unknown), [self.legacy_row])

        # explicit rule: unknown-entry rows are part of every audit view ...
        for point in (
            self.audit_point_before_backfill,
            self.audit_point_after_backfill,
        ):
            self.assertIn(
                self.legacy_row.pk,
                Approval.history.as_of_recorded(point).values_list("pk", flat=True),
            )
        # ... unless the caller explicitly restricts to known entry times
        known_only = Approval.history.as_of_recorded(
            timezone.now(), include_unknown=False
        )
        self.assertNotIn(
            self.legacy_row.pk, known_only.values_list("pk", flat=True)
        )
        # no entry time was ever fabricated for the legacy row
        self.legacy_row.refresh_from_db()
        self.assertIsNone(self.legacy_row.history_recorded_at)


class BitemporalOrderingTest(TestCase):
    def test_equal_effective_times_have_deterministic_order(self):
        effective = datetime.datetime(2026, 2, 1, 9, 0, 0)
        approval = Approval(name="A-9", status="draft")
        approval._history_date = effective
        approval.save()

        # legacy row with the same effective time but unknown entry time
        Approval.history.model.objects.create(
            id=approval.pk,
            name="A-9",
            status="legacy-draft",
            history_date=effective,
            history_type="+",
        )
        # later-recorded correction with the same effective time
        correction = Approval(pk=approval.pk, name="A-9", status="draft-corrected")
        correction._history_date = effective
        Approval.history.bulk_history_create([correction], update=True)

        # the later-recorded row wins; the unknown-entry row loses
        self.assertEqual(approval.history.as_of(effective).status, "draft-corrected")
        latest = Approval.history.filter(id=approval.pk).latest_of_each()
        self.assertEqual(latest.get().status, "draft-corrected")
        ordered = list(
            Approval.history.filter(id=approval.pk).values_list("status", flat=True)
        )
        self.assertEqual(ordered, ["draft-corrected", "draft", "legacy-draft"])


class BitemporalRecorderTest(TestCase):
    def test_caller_cannot_supply_entry_time_on_save(self):
        approval = Approval(name="A-7", status="draft")
        approval._history_recorded_at = datetime.datetime(2000, 1, 1)
        approval.save()
        row = Approval.history.get(id=approval.pk)
        self.assertNotEqual(row.history_recorded_at, datetime.datetime(2000, 1, 1))
        self.assertGreater(
            row.history_recorded_at, timezone.now() - datetime.timedelta(minutes=1)
        )

    def test_caller_cannot_supply_entry_time_on_bulk_import(self):
        fake = datetime.datetime(2000, 1, 1)
        obj = Approval.objects.create(name="A-8", status="draft")
        Approval.history.bulk_history_create(
            [obj], update=True, custom_historical_attrs={"history_recorded_at": fake}
        )
        row = Approval.history.get(name="A-8", history_type="~")
        self.assertNotEqual(row.history_recorded_at, fake)
        self.assertGreater(
            row.history_recorded_at, timezone.now() - datetime.timedelta(minutes=1)
        )

    def test_failed_bulk_import_rolls_back_atomically(self):
        existing = Approval.objects.create(name="A-5", status="draft")
        duplicate = Approval(pk=existing.pk, name="A-5-dupe", status="draft")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                bulk_create_with_history([Approval(name="A-6"), duplicate], Approval)
        self.assertFalse(Approval.objects.filter(name="A-6").exists())
        self.assertFalse(Approval.history.filter(name="A-6").exists())
        self.assertFalse(Approval.history.filter(name="A-5-dupe").exists())

    def test_audit_queries_require_bitemporal_history(self):
        with self.assertRaises(ImproperlyConfigured):
            Poll.history.as_of_recorded(timezone.now())
        with self.assertRaises(ImproperlyConfigured):
            Poll.history.audit_as_of(timezone.now())
