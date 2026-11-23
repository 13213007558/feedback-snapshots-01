from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import management
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.utils import timezone

from simple_history.exceptions import (
    InvalidPseudonymizationIdentity,
    PseudonymizationConflict,
)
from simple_history.pseudonym import (
    PSEUDONYM_FIELD_NAME,
    pseudonym_for,
    pseudonym_label,
)

from ..models import (
    PseudonymAuditRecord,
    PseudonymExternalAuditRecord,
)

User = get_user_model()

SECRET = "audit-secret-used-only-by-these-tests"

pseudonym_settings = override_settings(SIMPLE_HISTORY_PSEUDONYM_SECRET=SECRET)


class PseudonymHelperTest(TestCase):
    def test_pseudonym_is_stable_and_keyed(self):
        first = pseudonym_for("42", secret=SECRET)
        second = pseudonym_for("42", secret=SECRET)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertNotIn("42", first)
        self.assertNotEqual(first, pseudonym_for("42", secret=SECRET + "x"))
        self.assertNotEqual(first, pseudonym_for("43", secret=SECRET))
        self.assertNotEqual(
            first, pseudonym_for("42", secret=SECRET, namespace="other")
        )

    def test_configured_secret_is_used(self):
        with pseudonym_settings:
            self.assertEqual(pseudonym_for("42"), pseudonym_for("42", secret=SECRET))

    def test_missing_secret_is_refused(self):
        from django.test import override_settings

        with override_settings():
            from django.conf import settings

            # ``settings`` does not define this by default in the test project.
            if hasattr(settings, "SIMPLE_HISTORY_PSEUDONYM_SECRET"):
                del settings.SIMPLE_HISTORY_PSEUDONYM_SECRET
            with self.assertRaises(ImproperlyConfigured):
                pseudonym_for("42")

    def test_empty_identity_is_refused(self):
        for value in (None, "", "   ", b""):
            with self.subTest(value=value):
                with self.assertRaises(InvalidPseudonymizationIdentity):
                    pseudonym_for(value, secret=SECRET)

    def test_label_does_not_reveal_digest(self):
        digest = pseudonym_for("42", secret=SECRET)
        label = pseudonym_label(digest)
        self.assertEqual(label, f"pseudonym:{digest[:12]}")
        self.assertNotIn(digest, label)
        self.assertIsNone(pseudonym_label(None))


@pseudonym_settings
class ForeignKeyPseudonymizationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("departed", "departed@example.com")
        self.other = User.objects.create_user("remaining", "remaining@example.com")

    def _make_history(self):
        record = PseudonymAuditRecord(subject="first")
        record._history_user = self.user
        record.save()
        record.subject = "second"
        record._history_user = self.user
        record.save()
        record.subject = "third"
        record._history_user = self.other
        record.save()
        return record

    def test_severs_identity_and_keeps_audit_fields(self):
        record = self._make_history()
        before = list(
            PseudonymAuditRecord.history.order_by("history_id").values_list(
                "history_id", "history_date", "history_type", "history_user_id"
            )
        )

        result = PseudonymAuditRecord.history.anonymize_user(user=self.user)

        rows = list(
            PseudonymAuditRecord.history.order_by("history_id").values(
                "history_id",
                "history_date",
                "history_type",
                "history_user_id",
                PSEUDONYM_FIELD_NAME,
            )
        )
        self.assertEqual(result.pseudonymized, 2)
        self.assertEqual(result.already_pseudonymized, 0)
        self.assertEqual([r["history_id"] for r in rows], [r[0] for r in before])
        self.assertEqual([r["history_date"] for r in rows], [r[1] for r in before])
        self.assertEqual([r["history_type"] for r in rows], [r[2] for r in before])
        self.assertEqual(
            [r["history_user_id"] for r in rows], [None, None, self.other.pk]
        )
        self.assertEqual(
            [r[PSEUDONYM_FIELD_NAME] for r in rows],
            [result.pseudonym, result.pseudonym, None],
        )
        self.assertEqual(record.subject, "third")

    def test_reads_do_not_resolve_severed_account(self):
        record = self._make_history()
        PseudonymAuditRecord.history.anonymize_user(user=self.user)

        for history_row in PseudonymAuditRecord.history.filter(
            history_user_id__isnull=True
        ):
            self.assertIsNone(history_row.history_user)
            self.assertTrue(history_row.is_pseudonymized)
            label = history_row.get_history_user_label()
            self.assertTrue(label.startswith("pseudonym:"))

        # The live association is untouched and still resolves.
        live = PseudonymAuditRecord.history.get(history_user_id=self.other.pk)
        self.assertEqual(live.history_user, self.other)
        self.assertFalse(live.is_pseudonymized)

    def test_severed_association_is_not_reversible_by_filtering(self):
        self._make_history()
        PseudonymAuditRecord.history.anonymize_user(user=self.user)
        self.assertFalse(
            PseudonymAuditRecord.history.filter(history_user=self.user).exists()
        )
        self.assertFalse(
            PseudonymAuditRecord.history.filter(history_user_id=self.user.pk).exists()
        )

    def test_as_of_keeps_operations_and_time(self):
        record = self._make_history()
        timestamps = list(
            PseudonymAuditRecord.history.order_by("history_id").values_list(
                "history_date", flat=True
            )
        )
        PseudonymAuditRecord.history.anonymize_user(user=self.user)

        for point in timestamps:
            snapshot = record.history.as_of(point)
            self.assertIsNotNone(snapshot)
            self.assertIn(snapshot.subject, {"first", "second", "third"})

        as_of_rows = PseudonymAuditRecord.history.as_of(
            timezone.now() + timedelta(days=1)
        )
        self.assertEqual(as_of_rows.count(), 1)
        self.assertEqual(as_of_rows[0].subject, "third")

    def test_new_row_between_batches_is_out_of_scope(self):
        record = self._make_history()
        first = PseudonymAuditRecord.history.anonymize_user(user=self.user)

        record.subject = "between"
        record._history_user = self.user
        record.save()
        new_row = PseudonymAuditRecord.history.order_by("-history_id").first()
        self.assertEqual(new_row.history_user_id, self.user.pk)
        self.assertEqual(new_row.history_user, self.user)

        second = PseudonymAuditRecord.history.anonymize_user(
            user=self.user, watermark=new_row.history_id
        )
        self.assertEqual(second.pseudonymized, 0)
        self.assertEqual(second.already_pseudonymized, first.pseudonymized)
        new_row.refresh_from_db()
        self.assertEqual(new_row.history_user_id, self.user.pk)

    def test_repeating_first_batch_is_idempotent(self):
        self._make_history()
        first = PseudonymAuditRecord.history.anonymize_user(user=self.user)
        second = PseudonymAuditRecord.history.anonymize_user(user=self.user)
        self.assertEqual(second.pseudonymized, 0)
        self.assertEqual(second.already_pseudonymized, first.pseudonymized)
        self.assertEqual(first.pseudonym, second.pseudonym)

    def test_dry_run_does_not_write(self):
        self._make_history()
        result = PseudonymAuditRecord.history.anonymize_user(
            user=self.user, dry_run=True
        )
        self.assertEqual(result.pseudonymized, 2)
        self.assertEqual(
            PseudonymAuditRecord.history.filter(history_user_id=self.user.pk).count(),
            2,
        )
        self.assertFalse(
            PseudonymAuditRecord.history.exclude(
                **{PSEUDONYM_FIELD_NAME: None}
            ).exists()
        )

    def test_conflicting_pseudonym_is_refused(self):
        self._make_history()
        model = PseudonymAuditRecord.history.model
        model.objects.filter(history_user_id=self.user.pk).update(
            **{PSEUDONYM_FIELD_NAME: "some-other-subject"}
        )

        with self.assertRaises(PseudonymizationConflict):
            PseudonymAuditRecord.history.anonymize_user(user=self.user)

    def test_later_identity_rows_share_the_same_pseudonym(self):
        self._make_history()
        first = PseudonymAuditRecord.history.anonymize_user(user=self.user)

        record = PseudonymAuditRecord.objects.create(subject="later")
        record._history_user = self.user
        record.save()
        second = PseudonymAuditRecord.history.anonymize_user(user=self.user)

        self.assertEqual(first.pseudonym, second.pseudonym)
        self.assertEqual(second.pseudonymized, 1)
        self.assertEqual(second.already_pseudonymized, 2)

    def test_explicit_subject_links_multiple_accounts(self):
        self._make_history()
        result = PseudonymAuditRecord.history.anonymize_user(
            users=[self.user, self.other], subject="person-42"
        )
        self.assertEqual(result.pseudonymized, 3)
        self.assertEqual(
            set(
                PseudonymAuditRecord.history.values_list(
                    PSEUDONYM_FIELD_NAME, flat=True
                )
            ),
            {result.pseudonym},
        )
        self.assertFalse(
            PseudonymAuditRecord.history.exclude(history_user_id=None).exists()
        )

    def test_instance_manager_scope(self):
        record = self._make_history()
        other_record = PseudonymAuditRecord(subject="unrelated")
        other_record._history_user = self.user
        other_record.save()

        result = record.history.anonymize_user(user=self.user)
        self.assertEqual(result.pseudonymized, 2)
        self.assertEqual(
            PseudonymAuditRecord.history.filter(history_user_id=self.user.pk).count(),
            1,
        )


@pseudonym_settings
class ExternalIdentityPseudonymizationTest(TestCase):
    def test_external_identity_is_severed_and_kept_together(self):
        record = PseudonymExternalAuditRecord(subject="external")
        for identity in ("ext-1", "ext-1", "ext-2"):
            record.subject = identity
            record._history_user = _ExternalIdentity(identity)
            record.save()

        result = PseudonymExternalAuditRecord.history.anonymize_user(identity="ext-1")
        self.assertEqual(result.pseudonymized, 2)

        rows = list(
            PseudonymExternalAuditRecord.history.order_by("history_id").values(
                "history_user_id", PSEUDONYM_FIELD_NAME
            )
        )
        self.assertEqual(rows[0]["history_user_id"], None)
        self.assertEqual(rows[1]["history_user_id"], None)
        self.assertEqual(rows[0][PSEUDONYM_FIELD_NAME], result.pseudonym)
        self.assertEqual(rows[1][PSEUDONYM_FIELD_NAME], result.pseudonym)
        self.assertEqual(rows[2]["history_user_id"], "ext-2")
        self.assertIsNone(rows[2][PSEUDONYM_FIELD_NAME])

    def test_custom_getter_is_not_called_for_severed_rows(self):
        from ..models import (
            PseudonymExternalGetterRecord,
            pseudonym_external_getter_calls,
        )

        pseudonym_external_getter_calls.clear()
        record = PseudonymExternalGetterRecord(subject="external")
        record._history_user = _ExternalIdentity("ext-1")
        record.save()
        PseudonymExternalGetterRecord.history.anonymize_user(identity="ext-1")

        row = PseudonymExternalGetterRecord.history.get()
        self.assertIsNone(row.history_user)
        self.assertEqual(pseudonym_external_getter_calls, [])

    def test_unknown_identity_does_not_resolve_to_someone(self):
        record = PseudonymExternalAuditRecord(subject="external")
        record._history_user = _ExternalIdentity("ext-1")
        record.save()

        result = PseudonymExternalAuditRecord.history.anonymize_user(
            identity="ext-unknown"
        )
        self.assertEqual(result.pseudonymized, 0)
        row = PseudonymExternalAuditRecord.history.get()
        self.assertEqual(row.history_user_id, "ext-1")
        self.assertIsNone(row.history_user_pseudonym)

    def test_lookup_by_unknown_identity_is_untouched(self):
        record = PseudonymExternalAuditRecord(subject="external")
        record._history_user = _ExternalIdentity("ext-1")
        record.save()

        result = PseudonymExternalAuditRecord.history.anonymize_user(
            identity="ext-unknown", dry_run=True
        )
        self.assertEqual(result.pseudonymized, 0)
        self.assertEqual(
            PseudonymExternalAuditRecord.history.get().history_user_id, "ext-1"
        )


class _ExternalIdentity:
    """Minimal stand-in for an identity managed outside Django's user tables."""

    def __init__(self, pk):
        self.pk = pk


@pseudonym_settings
class PseudonymAdminViewTest(TestCase):
    """The ordinary admin history view must not restore severed accounts."""

    def setUp(self):
        from django.contrib.admin import AdminSite
        from django.test.client import RequestFactory

        from simple_history.admin import SimpleHistoryAdmin

        self.user = User.objects.create_superuser(
            "admin-user", "admin@example.com", "pass"
        )
        self.departed = User.objects.create_user(
            "departed-admin", "departed@example.com"
        )
        self.record = PseudonymAuditRecord.objects.create(subject="initial")
        self.record.subject = "updated"
        self.record._history_user = self.departed
        self.record.save()

        self.admin = SimpleHistoryAdmin(PseudonymAuditRecord, AdminSite())
        self.factory = RequestFactory()

    def _render_pages(self, request):
        from unittest.mock import patch

        pages = []
        with patch("simple_history.admin.render") as mock_render:
            self.admin.history_view(request, str(self.record.pk))
            pages.append(mock_render.call_args[0][2])
            if request.GET.get("p") == "2":
                # The first render call is for pagination validation only; the
                # request-scoped page is what an operator actually sees.
                pass
        return pages

    def test_admin_shows_pseudonym_and_no_user_link(self):
        PseudonymAuditRecord.history.anonymize_user(user=self.departed)

        request = self.factory.get("/")
        request.user = self.user
        page = self._render_pages(request)[0]

        row = page["page_obj"].object_list[0]
        self.assertTrue(row.is_pseudonymized)
        self.assertIsNone(row.history_user)
        self.assertIsNone(row.history_user_id)
        self.assertEqual(
            row.get_history_user_label(),
            f"pseudonym:{row.history_user_pseudonym[:12]}",
        )

    def test_paginated_old_rows_stay_pseudonymized(self):
        record = PseudonymAuditRecord(subject="many")
        for index in range(105):
            record.subject = f"change-{index}"
            record._history_user = self.departed
            record.save()
        self.record = record

        PseudonymAuditRecord.history.anonymize_user(user=self.departed)

        request = self.factory.get("/", {"p": "2"})
        request.user = self.user
        from unittest.mock import patch

        with patch("simple_history.admin.render") as mock_render:
            self.admin.history_view(request, str(self.record.pk))
            page = mock_render.call_args[0][2]
        rows = list(page["page_obj"].object_list)
        self.assertEqual(page["page_obj"].paginator.count, 105)
        self.assertEqual(len(rows), 5)
        for row in rows:
            self.assertTrue(row.is_pseudonymized)
            self.assertIsNone(row.history_user)
            self.assertIsNone(row.history_user_id)


class PseudonymCommandTest(TestCase):
    @pseudonym_settings
    def test_command_severs_and_reports(self):
        from io import StringIO

        user = User.objects.create_user("cmd-user", "cmd@example.com")
        record = PseudonymAuditRecord(subject="command")
        record._history_user = user
        record.save()

        out = StringIO()
        management.call_command(
            "anonymize_history",
            "tests.pseudonymauditrecord",
            "--user-id",
            str(user.pk),
            stdout=out,
            stderr=StringIO(),
        )
        self.assertIn("Pseudonymized 1", out.getvalue())
        row = PseudonymAuditRecord.history.get()
        self.assertIsNone(row.history_user_id)
        self.assertTrue(row.history_user_pseudonym)

    @pseudonym_settings
    def test_command_requires_subject(self):
        from io import StringIO

        with self.assertRaises(management.CommandError):
            management.call_command(
                "anonymize_history",
                "tests.pseudonymauditrecord",
                stdout=StringIO(),
                stderr=StringIO(),
            )

    @pseudonym_settings
    def test_command_rejects_unknown_user(self):
        from io import StringIO

        with self.assertRaises(management.CommandError):
            management.call_command(
                "anonymize_history",
                "tests.pseudonymauditrecord",
                "--user-id",
                "999999",
                stdout=StringIO(),
                stderr=StringIO(),
            )


@pseudonym_settings
class PseudonymTransactionTest(TestCase):
    """A failed batch must leave both the history rows and the accounts alone."""

    def setUp(self):
        self.user = User.objects.create_user("tx-user", "tx@example.com")
        self.record = PseudonymAuditRecord.objects.create(subject="tx")
        self.record.subject = "tx-updated"
        self.record._history_user = self.user
        self.record.save()

    def test_failed_batch_keeps_original_rows_and_objects(self):
        from django.db import transaction

        original = list(
            PseudonymAuditRecord.history.order_by("history_id").values_list(
                "history_id", "history_date", "history_type", "history_user_id"
            )
        )
        original_count = PseudonymAuditRecord.objects.count()

        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                PseudonymAuditRecord.history.anonymize_user(user=self.user)
                raise RuntimeError("simulated failure after update")

        after = list(
            PseudonymAuditRecord.history.order_by("history_id").values_list(
                "history_id", "history_date", "history_type", "history_user_id"
            )
        )
        self.assertEqual(after, original)
        self.assertEqual(PseudonymAuditRecord.objects.count(), original_count)

        # A retry after the rollback still severs exactly the same rows.
        result = PseudonymAuditRecord.history.anonymize_user(user=self.user)
        self.assertEqual(result.pseudonymized, 1)
        severed = PseudonymAuditRecord.history.get(
            history_user_pseudonym__isnull=False
        )
        self.assertIsNone(severed.history_user_id)
        untouched = PseudonymAuditRecord.history.get(
            history_user_pseudonym__isnull=True
        )
        self.assertIsNone(untouched.history_user_id)


@pseudonym_settings
class CustomGetterAssociationTest(TestCase):
    def test_mismatched_getter_result_is_not_exposed(self):
        from .. import models as test_models

        record = test_models.PseudonymExternalResolvingRecord(subject="resolved")
        record._history_user = _ExternalIdentity("ext-1")
        record.save()

        row = test_models.PseudonymExternalResolvingRecord.history.get()
        self.assertEqual(row.history_user.pk, "ext-1")

        test_models.pseudonym_external_resolution_override = "someone-else"
        try:
            row = test_models.PseudonymExternalResolvingRecord.history.get()
            self.assertIsNone(row.history_user)
        finally:
            test_models.pseudonym_external_resolution_override = None

    def test_severed_row_never_calls_getter(self):
        from .. import models as test_models

        record = test_models.PseudonymExternalResolvingRecord(subject="resolved")
        record._history_user = _ExternalIdentity("ext-1")
        record.save()
        test_models.PseudonymExternalResolvingRecord.history.anonymize_user(
            identity="ext-1"
        )

        row = test_models.PseudonymExternalResolvingRecord.history.get()
        self.assertTrue(row.is_pseudonymized)
        self.assertIsNone(row.history_user)


@pseudonym_settings
class IdentityKindGuardTest(TestCase):
    def test_raw_identity_rejected_for_foreign_key_models(self):
        from simple_history.pseudonym import identity_kind

        user = User.objects.create_user("fk-guard", "guard@example.com")
        record = PseudonymAuditRecord.objects.create(subject="guard")
        record._history_user = user
        record.save()

        self.assertEqual(
            identity_kind(PseudonymAuditRecord.history.model), "foreign_key"
        )
        with self.assertRaises(InvalidPseudonymizationIdentity):
            PseudonymAuditRecord.history.anonymize_user(identity=user.pk)

    def test_external_identity_on_external_model(self):
        from simple_history.pseudonym import identity_kind

        self.assertEqual(
            identity_kind(PseudonymExternalAuditRecord.history.model), "external"
        )
