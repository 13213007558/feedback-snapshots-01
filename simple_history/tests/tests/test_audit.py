import datetime as dt
import json
from io import StringIO

from django.contrib.auth import get_user_model
from django.core import management
from django.db.models import Q
from django.test import TestCase, override_settings

from simple_history.audit import (
    AuditCursorError,
    AuditExportError,
    iter_audit_pages,
    write_audit_page,
)
from simple_history.audit.cursor import decode_cursor, encode_cursor
from simple_history.audit.exporter import fetch_audit_page

from ..models import AuditCaseFile

USER_MODEL = get_user_model()


def utc(year, month, day, hour=0, minute=0, second=0):
    return dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)


@override_settings(USE_TZ=True)
class AuditExportTestBase(TestCase):
    def setUp(self):
        self.author = USER_MODEL.objects.create(username="auditor-author")
        self.removed_author = USER_MODEL.objects.create(username="since-deleted-author")
        self.created_at = utc(2026, 1, 15, 8, 0, 0)
        self.legal = AuditCaseFile(
            case_secret="legal-secret", department="LEGAL", approved=True
        )
        self.legal._history_date = self.created_at
        self.legal.save()
        self.exec_file = AuditCaseFile(
            case_secret="exec-secret", department="EXEC", approved=True
        )
        self.exec_file._history_date = self.created_at
        self.exec_file.save()
        self.draft = AuditCaseFile(
            case_secret="draft-secret", department="LEGAL", approved=False
        )
        self.draft._history_date = self.created_at
        self.draft.save()
        self.legal_pk = self.legal.pk
        self.tie = utc(2026, 3, 1, 9, 0, 0)

    def _record(self, instance, *, at, user=None, **changes):
        for field, value in changes.items():
            setattr(instance, field, value)
        instance._history_date = at
        if user is not None:
            instance._history_user = user
        elif hasattr(instance, "_history_user"):
            del instance._history_user
        instance.save()

    def _delete(self, instance, *, at, user=None):
        instance._history_date = at
        if user is not None:
            instance._history_user = user
        elif hasattr(instance, "_history_user"):
            del instance._history_user
        instance.delete()

    @property
    def legal_access(self):
        return Q(department="LEGAL")

    @property
    def history_model(self):
        return AuditCaseFile.history.model


class CursorTests(TestCase):
    def test_round_trip(self):
        when = utc(2026, 3, 1, 9, 0, 0)
        decoded_date, decoded_id = decode_cursor(encode_cursor(when, 7))
        self.assertEqual(decoded_date, when)
        self.assertEqual(decoded_id, "7")

    def test_rejects_garbage(self):
        with self.assertRaises(AuditCursorError):
            decode_cursor("not-a-cursor")

    def test_rejects_tampered_payload(self):
        import base64

        tampered = base64.urlsafe_b64encode(b'{"v":99,"d":"x","i":"1"}').decode()
        with self.assertRaises(AuditCursorError):
            decode_cursor(tampered)


class AuditQuerysetTests(AuditExportTestBase):
    def test_naive_datetime_rejected(self):
        with self.assertRaises(AuditExportError):
            fetch_audit_page(
                self.history_model,
                page_size=10,
                start_time=dt.datetime(2026, 1, 1),
            )

    def test_inverted_window_rejected(self):
        with self.assertRaises(AuditExportError):
            fetch_audit_page(
                self.history_model,
                page_size=10,
                start_time=utc(2026, 2, 1),
                end_time=utc(2026, 1, 1),
            )

    def test_invalid_page_size_rejected(self):
        with self.assertRaises(AuditExportError):
            fetch_audit_page(self.history_model, page_size=0)


class AuditExportContentTests(AuditExportTestBase):
    def setUp(self):
        super().setUp()
        # Two approved LEGAL changes share one timestamp; ids break the tie.
        self._record(self.legal, at=self.tie, user=self.author, case_secret="v2")
        self._record(self.draft, at=self.tie, user=self.author, approved=True)
        later = utc(2026, 3, 2, 10, 30, 0)
        self._record(
            self.legal,
            at=later,
            user=self.removed_author,
            case_secret="v3",
        )
        # An EXEC change the auditor may not see.
        self._record(self.exec_file, at=utc(2026, 3, 3, 8, 0, 0), user=self.author)
        # An unapproved LEGAL change that must stay out of the export.
        self._record(
            self.draft,
            at=utc(2026, 3, 4, 8, 0, 0),
            user=self.author,
            approved=False,
            case_secret="still-draft",
        )
        # Deleting the author leaves history_user_id NULL (SET_NULL); the
        # export never reads the user relation.
        self.removed_author.delete()
        # Deleting a live object still produces an exportable deletion event.
        self._delete(self.legal, at=utc(2026, 3, 5, 12, 0, 0))

    def test_rows_contain_only_three_fields(self):
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=50, access_q=self.legal_access
        )
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(set(row), {"event_time", "change_type", "object_ref"})
            serialized = json.dumps(row)
            self.assertNotIn("secret", serialized)
            self.assertNotIn("case_secret", serialized)
            self.assertNotIn("v2", serialized)
            self.assertNotIn("v3", serialized)

    def test_access_rule_excludes_exec_records(self):
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=50, access_q=self.legal_access
        )
        exec_ref = str(self.exec_file.pk)
        self.assertFalse(any(row["object_ref"] == exec_ref for row in rows))

    def test_approved_filter_excludes_unapproved_rows(self):
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=50, access_q=self.legal_access
        )
        # draft's create row is unapproved and excluded; only the later
        # approved flip (the tie row) may appear.
        draft_rows = [row for row in rows if row["object_ref"] == str(self.draft.pk)]
        self.assertEqual(len(draft_rows), 1)
        self.assertEqual(draft_rows[0]["change_type"], "changed")

    def test_same_timestamp_keeps_total_order(self):
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=50, access_q=self.legal_access
        )
        tie_rows = [
            row for row in rows if row["event_time"].startswith("2026-03-01T09:00:00")
        ]
        self.assertEqual(len(tie_rows), 2)
        # Deterministic: object refs appear in ascending history_id order.
        history_ids = list(
            self.history_model.objects.filter(history_date=self.tie)
            .order_by("history_id")
            .values_list("id", flat=True)
        )
        self.assertEqual(
            [row["object_ref"] for row in tie_rows],
            [str(pk) for pk in history_ids],
        )

    def test_deletion_event_survives_missing_live_object(self):
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=50, access_q=self.legal_access
        )
        deletion = [
            row
            for row in rows
            if row["object_ref"] == str(self.legal_pk)
            and row["change_type"] == "deleted"
        ]
        self.assertEqual(len(deletion), 1)

    def test_deleted_history_author_does_not_break_export(self):
        # removed_author was deleted in setUp; its rows now have
        # history_user_id == NULL and must still export cleanly.
        null_author_rows = self.history_model.objects.filter(
            history_user_id__isnull=True
        ).count()
        self.assertGreater(null_author_rows, 0)
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=50, access_q=self.legal_access
        )
        self.assertTrue(rows)

    def test_half_open_time_window(self):
        rows, _, _ = fetch_audit_page(
            self.history_model,
            page_size=50,
            access_q=self.legal_access,
            start_time=self.tie,
            end_time=utc(2026, 3, 2, 10, 30, 0),
        )
        # Includes the tie rows, excludes the 10:30 row at end_time.
        self.assertTrue(all(row["event_time"] >= "2026-03-01T09:00:00" for row in rows))
        self.assertTrue(all(row["event_time"] < "2026-03-02T10:30:00" for row in rows))
        self.assertEqual(len(rows), 2)

    def test_rerun_produces_identical_pages(self):
        first = list(
            iter_audit_pages(
                self.history_model,
                page_size=2,
                access_q=self.legal_access,
            )
        )
        second = list(
            iter_audit_pages(
                self.history_model,
                page_size=2,
                access_q=self.legal_access,
            )
        )
        self.assertEqual(first, second)

    def test_resume_with_cursor_never_skips_or_duplicates(self):
        pages = list(
            iter_audit_pages(
                self.history_model,
                page_size=2,
                access_q=self.legal_access,
            )
        )
        full_rows, _, _ = fetch_audit_page(
            self.history_model, page_size=100, access_q=self.legal_access
        )
        paged_rows = [row for page in pages for row in page[0]]
        self.assertEqual(paged_rows, full_rows)

        # Resume from the first page's cursor and compare against the tail.
        first_cursor = pages[0][1]
        resumed_rows, _, _ = fetch_audit_page(
            self.history_model,
            page_size=100,
            access_q=self.legal_access,
            cursor=first_cursor,
        )
        self.assertEqual(resumed_rows, full_rows[2:])

    def test_tie_group_can_straddle_a_page_boundary(self):
        pages = list(
            iter_audit_pages(
                self.history_model,
                page_size=1,
                access_q=self.legal_access,
            )
        )
        paged_rows = [row for page in pages for row in page[0]]
        full_rows, _, _ = fetch_audit_page(
            self.history_model, page_size=100, access_q=self.legal_access
        )
        self.assertEqual(paged_rows, full_rows)

    def test_json_lines_output_shape(self):
        rows, _, _ = fetch_audit_page(
            self.history_model, page_size=5, access_q=self.legal_access
        )
        handle = StringIO()
        written = write_audit_page(rows[:3], handle)
        lines = handle.getvalue().strip().split("\n")
        self.assertEqual(written, 3)
        self.assertEqual(len(lines), 3)
        for line in lines:
            parsed = json.loads(line)
            self.assertEqual(
                sorted(parsed), ["change_type", "event_time", "object_ref"]
            )

    def test_management_command_stdout_and_stderr_trailer(self):
        out, err = StringIO(), StringIO()
        management.call_command(
            "export_audit",
            "tests.auditcasefile",
            page_size=2,
            max_pages=10,
            access_callback="simple_history.tests.tests.test_audit.legal_access_q",
            stdout=out,
            stderr=err,
        )
        lines = [line for line in out.getvalue().splitlines() if line]
        full_rows, _, _ = fetch_audit_page(
            self.history_model, page_size=100, access_q=self.legal_access
        )
        self.assertEqual(len(lines), len(full_rows))
        trailer = json.loads(err.getvalue().strip().splitlines()[-1])
        self.assertFalse(trailer["has_next"])
        self.assertIsNone(trailer["next_cursor"])

    def test_management_command_rejects_bad_cursor(self):
        with self.assertRaises(management.CommandError):
            management.call_command(
                "export_audit",
                "tests.auditcasefile",
                cursor="garbage",
                stdout=StringIO(),
                stderr=StringIO(),
            )


def legal_access_q():
    """Module-level callback used by the management command test."""
    return Q(department="LEGAL")
