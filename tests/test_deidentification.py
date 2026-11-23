from datetime import timedelta
from io import StringIO
from unittest.mock import Mock

from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone

from axes.admin import (
    AccessAttemptAdmin,
    EXPORT_PERMISSION,
    VIEW_MARKER_PERMISSION,
)
from axes.deidentification import REDACTED, hash_identifier
from axes.handlers.database import AxesDatabaseHandler
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_client_str
from axes.models import AccessAttempt, AccessFailureLog, AccessLog
from tests.base import AxesTestCase


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_DEIDENTIFY_ENABLED=True,
    AXES_DEIDENTIFY_RETENTION_DAYS=30,
    AXES_ENABLE_ACCESS_FAILURE_LOG=True,
)
class DeidentifiedFailureTestCase(AxesTestCase):
    def _record_failure(self):
        AxesProxyHandler.user_login_failed(
            sender=None, request=self.request, credentials=self.credentials
        )

    def test_failure_stores_hashes_without_cleartext(self):
        self._record_failure()

        attempt = AccessAttempt.objects.get()
        self.assertIsNone(attempt.username)
        self.assertIsNone(attempt.ip_address)
        self.assertIsNone(attempt.user_agent)
        self.assertEqual(
            attempt.username_hash, hash_identifier(self.username, "username")
        )
        self.assertEqual(
            attempt.ip_address_hash,
            hash_identifier(self.ip_address, "ip_address"),
        )
        self.assertEqual(
            attempt.user_agent_hash,
            hash_identifier(self.user_agent, "user_agent"),
        )
        self.assertIsNotNone(attempt.deidentified_at)

        failure = AccessFailureLog.objects.get()
        self.assertIsNone(failure.username)
        self.assertIsNone(failure.ip_address)
        self.assertEqual(
            failure.username_hash, hash_identifier(self.username, "username")
        )

    def test_repeated_failures_correlate_on_hash_and_increment(self):
        for _ in range(3):
            self._record_failure()

        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertEqual(3, AccessAttempt.objects.get().failures_since_start)
        self.assertEqual(
            3, AxesProxyHandler.get_failures(self.request, self.credentials)
        )

    def test_lockout_window_still_uses_real_failures(self):
        for _ in range(3):
            self._record_failure()

        with override_settings(AXES_FAILURE_LIMIT=3):
            self.assertFalse(
                AxesProxyHandler.is_allowed(self.request, self.credentials)
            )

    def test_successful_login_writes_deidentified_access_log(self):
        AxesProxyHandler.user_logged_in(
            sender=None, request=self.request, user=self.user
        )
        log = AccessLog.objects.get()
        self.assertIsNone(log.username)
        self.assertEqual(
            log.username_hash, hash_identifier(self.username, "username")
        )
        self.assertIsNotNone(log.deidentified_at)

    def test_client_string_never_contains_identifier_or_digest(self):
        digest = hash_identifier(self.username, "username")
        for verbose in (True, False):
            with override_settings(AXES_VERBOSE=verbose):
                client_str = get_client_str(
                    self.username,
                    self.ip_address,
                    self.user_agent,
                    self.path_info,
                    self.request,
                )
            self.assertNotIn(self.username, client_str)
            self.assertNotIn(self.ip_address, client_str)
            self.assertNotIn(digest, client_str)
            self.assertIn(REDACTED, client_str)

    def _legacy_attempt(self, failures):
        return AccessAttempt.objects.create(
            username=self.username,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            http_accept="accept",
            path_info=self.path_info,
            get_data="",
            post_data="",
            failures_since_start=failures,
        )

    @staticmethod
    def _backdate(instance, days):
        # attempt_time is auto_now_add, so it can only be changed after insert.
        instance.attempt_time = timezone.now() - timedelta(days=days)
        instance.save(update_fields=["attempt_time"])

    def test_conversion_in_place_preserves_failure_count(self):
        legacy = self._legacy_attempt(failures=4)

        processed = AxesProxyHandler.convert_legacy_records()

        self.assertEqual(1, processed)
        attempt = AccessAttempt.objects.get(pk=legacy.pk)
        self.assertEqual(4, attempt.failures_since_start)
        self.assertIsNone(attempt.username)
        self.assertEqual(
            attempt.username_hash, hash_identifier(self.username, "username")
        )
        self.assertIsNotNone(attempt.deidentified_at)

    def test_conversion_merges_interleaved_live_failure_without_reset_or_inflation(self):
        # Old record written before the switch, holding 3 cleartext failures.
        legacy = self._legacy_attempt(failures=3)
        # A new failure arrives while the migration batch has not run yet.
        self._record_failure()

        self.assertEqual(2, AccessAttempt.objects.count())

        AxesProxyHandler.convert_legacy_records()

        # One correlated row whose count is the true cumulative total (3 + 1),
        # never reset to 1 and never inflated to 5.
        self.assertEqual(1, AccessAttempt.objects.count())
        attempt = AccessAttempt.objects.get()
        self.assertEqual(4, attempt.failures_since_start)
        self.assertEqual(attempt.pk != legacy.pk, True)
        self.assertIsNone(attempt.username)
        self.assertEqual(
            attempt.username_hash, hash_identifier(self.username, "username")
        )
        self.assertEqual(
            4, AxesProxyHandler.get_failures(self.request, self.credentials)
        )

    def test_conversion_is_idempotent(self):
        self._legacy_attempt(failures=2)
        self.assertEqual(1, AxesProxyHandler.convert_legacy_records())
        # Re-running finds no cleartext records and leaves state untouched.
        self.assertEqual(0, AxesProxyHandler.convert_legacy_records())
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertEqual(2, AccessAttempt.objects.get().failures_since_start)

    def test_failures_interleaved_across_migration_keep_true_threshold(self):
        # Two failures recorded before the switch.
        self._legacy_attempt(failures=2)
        # Two failures arrive while the migration has not run yet.
        for _ in range(2):
            self._record_failure()
        # The migration merges the legacy row into the live de-identified row.
        AxesProxyHandler.convert_legacy_records()
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertEqual(
            4, AccessAttempt.objects.get().failures_since_start
        )
        # Failures after the migration keep incrementing the same window.
        self._record_failure()
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertEqual(
            5, AccessAttempt.objects.get().failures_since_start
        )
        # A repeated migration neither resets nor inflates the count.
        self.assertEqual(0, AxesProxyHandler.convert_legacy_records())
        self.assertEqual(
            5, AccessAttempt.objects.get().failures_since_start
        )

    def test_conversion_handles_failure_and_access_logs(self):
        self.create_failure_log()
        self.create_log()

        AxesProxyHandler.convert_legacy_records()

        for model in (AccessFailureLog, AccessLog):
            instance = model.objects.get()
            self.assertIsNone(instance.username)
            self.assertIsNone(instance.ip_address)
            self.assertIsNone(instance.user_agent)
            self.assertEqual(
                instance.username_hash, hash_identifier(self.username, "username")
            )
            self.assertIsNotNone(instance.deidentified_at)

    def test_retention_cleanup_deletes_only_expired_records(self):
        self._record_failure()
        recent = AccessAttempt.objects.get()

        old = self._legacy_attempt(failures=1)
        # Distinct account so the migration keeps it as a separate row.
        old.username = "legacy-other-user"
        old.save(update_fields=["username"])
        self._backdate(old, 90)
        AxesProxyHandler.convert_legacy_records()

        self.assertEqual(2, AccessAttempt.objects.count())

        removed = AxesProxyHandler.clean_expired_deidentified_records()

        remaining = AccessAttempt.objects.values_list("pk", flat=True)
        self.assertEqual(list(remaining), [recent.pk])
        self.assertNotIn(old.pk, remaining)
        self.assertGreaterEqual(removed, 1)

    def test_retention_cleanup_is_idempotent(self):
        old = self._legacy_attempt(failures=1)
        old.username = "legacy-other-user"
        old.save(update_fields=["username"])
        self._backdate(old, 90)
        AxesProxyHandler.convert_legacy_records()

        first = AxesProxyHandler.clean_expired_deidentified_records()
        second = AxesProxyHandler.clean_expired_deidentified_records()

        self.assertGreaterEqual(first, 1)
        self.assertEqual(0, second)
        self.assertEqual(0, AccessAttempt.objects.count())

    def test_reset_attempts_matches_on_hash(self):
        self._record_failure()
        count = AxesProxyHandler.reset_attempts(username=self.username)
        self.assertEqual(1, count)
        self.assertEqual(0, AccessAttempt.objects.count())

    @override_settings(AXES_LOCKOUT_PARAMETERS=["username"])
    def test_none_username_skips_record_creation(self):
        # Mirrors the legacy behaviour: username-only lockouts with an unknown
        # username never create a record, even under de-identification.
        from unittest.mock import MagicMock

        AxesProxyHandler.user_login_failed(
            MagicMock(), {"username": None, "password": "x"}, self.request
        )
        self.assertEqual(0, AccessAttempt.objects.count())

    @override_settings(
        AXES_LOCKOUT_PARAMETERS=[["username", "ip_address"]],
        AXES_COOLOFF_TIME=timedelta(seconds=10),
    )
    def test_combined_lockout_params_correlate_on_hashes(self):
        for _ in range(2):
            self._record_failure()
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertEqual(
            2, AxesProxyHandler.get_failures(self.request, self.credentials)
        )

    def test_deidentify_command_is_re_runnable(self):
        self._legacy_attempt(failures=1)
        out = StringIO()
        call_command("axes_deidentify", stdout=out)
        self.assertIn("1 records de-identified.", out.getvalue())

        out = StringIO()
        call_command("axes_deidentify", stdout=out)
        self.assertIn("No cleartext records left to convert.", out.getvalue())

    def test_cleanup_command_reports_and_repeats(self):
        old = self._legacy_attempt(failures=1)
        old.username = "legacy-other-user"
        old.save(update_fields=["username"])
        self._backdate(old, 90)
        AxesProxyHandler.convert_legacy_records()

        out = StringIO()
        call_command("axes_cleanup_deidentified", stdout=out)
        self.assertIn("expired records removed.", out.getvalue())

        out = StringIO()
        call_command("axes_cleanup_deidentified", stdout=out)
        self.assertIn("No expired records found.", out.getvalue())


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_DEIDENTIFY_ENABLED=True,
)
class DeidentifiedAdminTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        self.attempt = AccessAttempt.objects.create(
            username=None,
            ip_address=None,
            user_agent=None,
            username_hash=hash_identifier(self.username, "username"),
            ip_address_hash=hash_identifier(self.ip_address, "ip_address"),
            user_agent_hash=hash_identifier(self.user_agent, "user_agent"),
            http_accept="accept",
            path_info=self.path_info,
            get_data="",
            post_data="",
            failures_since_start=1,
            deidentified_at=timezone.now(),
        )
        self.admin = AccessAttemptAdmin(AccessAttempt, admin_site=None)

    def _request(self, permitted):
        request = Mock()
        request.user = Mock()

        def has_perm(perm):
            return permitted if perm == VIEW_MARKER_PERMISSION else False

        request.user.has_perm = has_perm
        return request

    def test_marker_hidden_without_permission(self):
        self.admin.get_queryset(self._request(False))
        self.assertEqual(
            REDACTED, self.admin.username_display(self.attempt)
        )
        self.assertEqual(
            REDACTED, self.admin.ip_address_display(self.attempt)
        )

    def test_marker_visible_with_permission(self):
        self.admin.get_queryset(self._request(True))
        self.assertEqual(
            hash_identifier(self.username, "username"),
            self.admin.username_display(self.attempt),
        )

    def test_list_display_uses_redacting_columns(self):
        request = self._request(False)
        columns = self.admin.get_list_display(request)
        self.assertIn("username_display", columns)
        self.assertNotIn("username", columns)

    def test_search_resolves_cleartext_to_digest(self):
        request = self._request(False)
        queryset, _ = self.admin.get_search_results(
            request, AccessAttempt.objects.all(), self.username
        )
        self.assertIn(self.attempt, list(queryset))

    def test_search_matches_marker_digest_directly(self):
        request = self._request(False)
        digest = hash_identifier(self.username, "username")
        queryset, _ = self.admin.get_search_results(
            request, AccessAttempt.objects.all(), digest
        )
        self.assertIn(self.attempt, list(queryset))

    def test_export_only_contains_approved_records(self):
        unapproved = AccessAttempt.objects.create(
            username=None,
            ip_address=None,
            user_agent=None,
            username_hash="username:other",
            ip_address_hash="ip:other",
            user_agent_hash="ua:other",
            http_accept="accept",
            path_info=self.path_info,
            get_data="",
            post_data="",
            failures_since_start=1,
            deidentified_at=timezone.now(),
            export_approved=False,
        )
        self.attempt.export_approved = True
        self.attempt.save()

        request = self._request(True)
        request.user.has_perm = lambda perm: perm in (
            VIEW_MARKER_PERMISSION,
            EXPORT_PERMISSION,
        )
        queryset = AccessAttempt.objects.all()
        response = self.admin.export_approved_csv(request, queryset)

        body = response.content.decode()
        self.assertIn(hash_identifier(self.username, "username"), body)
        self.assertNotIn("username:other", body)
        self.assertNotIn(unapproved.username_hash or "", body)

    def test_export_redacts_markers_without_view_permission(self):
        self.attempt.export_approved = True
        self.attempt.save()

        request = self._request(False)
        request.user.has_perm = lambda perm: perm == EXPORT_PERMISSION
        response = self.admin.export_approved_csv(
            request, AccessAttempt.objects.all()
        )

        body = response.content.decode()
        self.assertIn(REDACTED, body)
        self.assertNotIn(
            hash_identifier(self.username, "username"), body
        )


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_DEIDENTIFY_ENABLED=False,
)
class DeidentificationDisabledTestCase(AxesTestCase):
    def test_default_behaviour_keeps_cleartext(self):
        AxesProxyHandler.user_login_failed(
            sender=None, request=self.request, credentials=self.credentials
        )
        attempt = AccessAttempt.objects.get()
        self.assertEqual(self.username, attempt.username)
        self.assertIsNone(attempt.username_hash)
        self.assertIsNone(attempt.deidentified_at)

    def test_conversion_is_noop_when_disabled(self):
        self.create_attempt()
        self.assertEqual(0, AxesProxyHandler.convert_legacy_records())
        self.assertEqual(
            self.username, AccessAttempt.objects.get().username
        )

    def test_cleanup_is_noop_without_retention(self):
        handler = AxesDatabaseHandler()
        self.assertEqual(0, handler.clean_expired_deidentified_records())
