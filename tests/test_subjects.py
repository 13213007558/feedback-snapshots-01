from datetime import timedelta

from django.db.models import Sum
from django.test import override_settings
from django.utils.timezone import now

from axes.handlers.database import AxesDatabaseHandler
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_client_parameters
from axes.models import AccessAttempt, AccessFailureEvent
from axes.subjects import backfill_subject_attempts, filter_subject_scope
from axes.utils import reset
from tests.base import AxesTestCase

SUBJECT_A = "institution-a"
SUBJECT_B = "institution-b"

LEGACY_IDENTITIES = {
    SUBJECT_A: [
        {"username": "alice", "ip_address": "10.0.0.1"},
        {"username": "alice", "ip_address": "10.0.0.2"},
    ],
    SUBJECT_B: [
        {"username": "alice", "ip_address": "10.9.9.9"},
    ],
}


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_SUBJECT_LEGACY_IDENTITIES=LEGACY_IDENTITIES,
    AXES_SUBJECT_CALLABLE=None,
    AXES_COOLOFF_TIME=None,
)
class SubjectLockoutTestCase(AxesTestCase):
    """End-to-end checks for the username/network-group to subject migration."""

    IP_A = "10.0.0.1"
    IP_A2 = "10.0.0.2"
    IP_B = "10.9.9.9"

    def setUp(self):
        super().setUp()
        self.handler = AxesDatabaseHandler()

    def failure(self, username, subject, ip_address, event_id=None):
        """Simulate one failed login observed by a subject-aware worker."""

        request = self._request(username, ip_address)
        credentials = {"username": username, "subject": subject}
        if event_id is not None:
            credentials["failure_id"] = event_id
        AxesProxyHandler.user_login_failed(
            sender=None, credentials=credentials, request=request
        )
        return request

    def legacy_failure(self, username, ip_address):
        """Simulate a failed login written by a pre-subject worker.

        The pre-subject code knows only the username, IP address and user
        agent, so it writes the legacy row directly with an empty subject.
        """

        return self.create_attempt(
            username=username,
            ip_address=ip_address,
            user_agent=self.user_agent,
            failures_since_start=1,
        )

    def _request(self, username, ip_address):
        request = self.make_request(username=username, ip_address=ip_address)
        request.axes_attempt_time = now()
        return request

    def make_request(self, username, ip_address):
        from django.http import HttpRequest

        request = HttpRequest()
        request.method = "POST"
        request.META["REMOTE_ADDR"] = ip_address
        request.META["HTTP_USER_AGENT"] = self.user_agent
        request.META["PATH_INFO"] = self.path_info
        request.axes_attempt_time = now()
        request.axes_ip_address = ip_address
        request.axes_user_agent = self.user_agent
        request.axes_path_info = self.path_info
        request.axes_http_accept = "<unknown>"
        request.axes_failures_since_start = None
        request.axes_locked_out = False
        request.axes_credentials = None
        return request

    def failures_for(self, subject, username, ip_address):
        request = self.make_request(username, ip_address)
        credentials = {"username": username, "subject": subject}
        return AxesProxyHandler.get_failures(request, credentials)

    def test_mixed_worker_requests_keep_one_count_per_failure(self):
        self.legacy_failure("alice", self.IP_A)
        self.failure("alice", SUBJECT_A, self.IP_A)
        self.legacy_failure("alice", self.IP_A2)

        self.assertEqual(3, self.failures_for(SUBJECT_A, "alice", self.IP_A))

        # The pre-migration row for 10.0.0.1 was adopted, and the new failure
        # incremented it, so one real failure is stored once.
        subject_window = AccessAttempt.objects.filter(subject=SUBJECT_A)
        self.assertEqual(1, subject_window.count())
        self.assertEqual(2, subject_window.get().failures_since_start)
        self.assertEqual(
            0, AccessAttempt.objects.filter(subject="", ip_address=self.IP_A).count()
        )
        self.assertEqual(
            1, AccessAttempt.objects.filter(subject="", ip_address=self.IP_A2).count()
        )

    def test_same_name_other_subject_keeps_own_counter(self):
        for _ in range(2):
            self.failure("alice", SUBJECT_A, self.IP_A)
        self.failure("alice", SUBJECT_B, self.IP_B)

        self.assertEqual(2, self.failures_for(SUBJECT_A, "alice", self.IP_A))
        self.assertEqual(1, self.failures_for(SUBJECT_B, "alice", self.IP_B))

        # Unlocking subject A leaves subject B's coincidental namesake alone.
        reset(subject=SUBJECT_A)
        self.assertEqual(0, self.failures_for(SUBJECT_A, "alice", self.IP_A))
        self.assertEqual(1, self.failures_for(SUBJECT_B, "alice", self.IP_B))

    def test_duplicate_failure_event_counts_once(self):
        for _ in range(2):
            self.failure("alice", SUBJECT_A, self.IP_A, event_id="event-1")

        self.assertEqual(1, AccessFailureEvent.objects.count())
        self.assertEqual(1, self.failures_for(SUBJECT_A, "alice", self.IP_A))
        self.assertEqual(
            1, AccessAttempt.objects.get(subject=SUBJECT_A).failures_since_start
        )

    def test_unlock_subject_clears_complete_subject_scope(self):
        self.legacy_failure("alice", self.IP_A)
        self.legacy_failure("alice", self.IP_A2)
        self.failure("alice", SUBJECT_A, self.IP_A)
        self.failure("alice", SUBJECT_B, self.IP_B)

        self.assertGreater(filter_subject_scope(SUBJECT_A).count(), 0)
        self.assertEqual(3, AccessAttempt.objects.count())

        removed = reset(subject=SUBJECT_A)
        self.assertEqual(2, removed)
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertTrue(AccessAttempt.objects.filter(subject=SUBJECT_B).exists())

    def test_reset_by_legacy_window_maps_to_subject_scope(self):
        self.legacy_failure("alice", self.IP_A)
        self.legacy_failure("alice", self.IP_A2)
        self.failure("alice", SUBJECT_A, self.IP_A)

        removed = reset(ip=self.IP_A, username="alice")
        # The mapped subject scope is cleared together with the exact legacy
        # window, so the remaining window cannot re-lock the subject.
        self.assertEqual(2, removed)
        self.assertFalse(AccessAttempt.objects.exists())

    def test_backfill_preserves_threshold_and_deadline(self):
        locked = self.create_attempt(
            username="alice",
            ip_address=self.IP_A,
            failures_since_start=10,
        )
        AccessAttempt.objects.filter(pk=locked.pk).update(
            attempt_time=now() - timedelta(hours=1)
        )

        backfill_subject_attempts(SUBJECT_A)

        subject_attempt = AccessAttempt.objects.get(
            subject=SUBJECT_A, username="alice", ip_address=self.IP_A
        )
        self.assertEqual(10, subject_attempt.failures_since_start)
        self.assertEqual(
            AccessAttempt.objects.get(pk=locked.pk).attempt_time,
            subject_attempt.attempt_time,
        )

        # Running the migration again neither resets nor inflates the count.
        # The adopted row is the same row the old worker used, so its
        # username/network-group lookups still find it.
        self.assertEqual(0, backfill_subject_attempts(SUBJECT_A))
        subject_attempt.refresh_from_db()
        self.assertEqual(10, subject_attempt.failures_since_start)
        self.assertEqual(
            10,
            AccessAttempt.objects.filter(
                username="alice", ip_address=self.IP_A
            ).aggregate(Sum("failures_since_start"))["failures_since_start__sum"],
        )
        self.assertEqual(10, self.failures_for(SUBJECT_A, "alice", self.IP_A))

    @override_settings(AXES_FAILURE_LIMIT=3)
    def test_legacy_attempt_at_threshold_still_locks_subject(self):
        self.create_attempt(
            username="alice",
            ip_address=self.IP_A,
            failures_since_start=3,
        )
        request = self.make_request("alice", self.IP_A)
        credentials = {"username": "alice", "subject": SUBJECT_A}

        self.assertFalse(AxesProxyHandler.is_allowed(request, credentials))

    def test_client_parameters_use_subject_window_for_subject_request(self):
        request = self.make_request("alice", self.IP_A)
        credentials = {"username": "alice", "subject": SUBJECT_A}
        self.assertEqual(
            [{"subject": SUBJECT_A}],
            get_client_parameters(
                "alice", self.IP_A, self.user_agent, request, credentials
            ),
        )

    def test_client_parameters_keep_legacy_window_without_subject(self):
        request = self.make_request("alice", self.IP_A)
        # A pre-subject request does not know its registered subject, so the
        # old username/network-group configuration stays in effect for it.
        self.assertEqual(
            [{"ip_address": self.IP_A}],
            get_client_parameters(
                "alice", self.IP_A, self.user_agent, request, {"username": "alice"}
            ),
        )


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_SUBJECT_LEGACY_IDENTITIES=LEGACY_IDENTITIES,
    AXES_COOLOFF_TIME=None,
)
class SubjectResetRequestTestCase(AxesTestCase):
    def test_reset_request_by_subject_clears_complete_scope(self):
        from axes.utils import reset_request

        self.create_attempt(username="alice", ip_address="10.0.0.1")
        self.create_attempt(username="alice", ip_address="10.0.0.2")
        self.create_attempt(username="alice", ip_address="10.9.9.9")

        request = self.request
        request.GET["subject"] = SUBJECT_A
        removed = reset_request(request)

        self.assertEqual(2, removed)
        self.assertEqual(1, AccessAttempt.objects.count())
        self.assertTrue(AccessAttempt.objects.filter(ip_address="10.9.9.9").exists())


@override_settings(
    AXES_HANDLER="axes.handlers.cache.AxesCacheHandler",
    AXES_SUBJECT_LEGACY_IDENTITIES=LEGACY_IDENTITIES,
    AXES_COOLOFF_TIME=timedelta(minutes=10),
)
class SubjectCacheHandlerTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        from axes.helpers import get_cache

        get_cache().clear()

    def _request(self, ip_address):
        from django.http import HttpRequest

        request = HttpRequest()
        request.method = "POST"
        request.META["REMOTE_ADDR"] = ip_address
        request.META["HTTP_USER_AGENT"] = self.user_agent
        request.META["PATH_INFO"] = self.path_info
        from django.utils.timezone import now

        request.axes_attempt_time = now()
        request.axes_ip_address = ip_address
        request.axes_user_agent = self.user_agent
        request.axes_path_info = self.path_info
        request.axes_http_accept = "<unknown>"
        request.axes_failures_since_start = None
        request.axes_locked_out = False
        request.axes_credentials = None
        return request

    def _failure(self, username, subject, ip_address, event_id=None):
        request = self._request(ip_address)
        credentials = {"username": username, "subject": subject}
        if event_id:
            credentials["failure_id"] = event_id
        AxesProxyHandler.user_login_failed(
            sender=None, credentials=credentials, request=request
        )
        return request

    def test_same_name_subjects_keep_separate_counts(self):
        self._failure("alice", SUBJECT_A, "10.0.0.1")
        self._failure("alice", SUBJECT_A, "10.0.0.1")

        self.assertEqual(
            2,
            AxesProxyHandler.get_failures(
                self._request("10.0.0.1"),
                {"username": "alice", "subject": SUBJECT_A},
            ),
        )
        self.assertEqual(
            0,
            AxesProxyHandler.get_failures(
                self._request("10.9.9.9"),
                {"username": "alice", "subject": SUBJECT_B},
            ),
        )

    def test_cache_reads_seeded_legacy_window(self):
        from axes.helpers import get_cache
        from axes.helpers import make_cache_key_list

        # Seed the legacy username+IP key the way a pre-subject worker would.
        legacy_key = make_cache_key_list(
            [{"username": "alice", "ip_address": "10.0.0.1"}]
        )[0]
        get_cache().set(legacy_key, 5, timeout=600)

        self.assertEqual(
            5,
            AxesProxyHandler.get_failures(
                self._request("10.0.0.1"),
                {"username": "alice", "subject": SUBJECT_A},
            ),
        )

    def test_cache_unlock_keeps_same_name_other_subject_window(self):
        from axes.helpers import get_cache
        from axes.helpers import make_cache_key_list

        other_key = make_cache_key_list(
            [{"username": "alice", "ip_address": "10.9.9.9"}]
        )[0]
        get_cache().set(other_key, 4, timeout=600)

        AxesProxyHandler.reset_attempts(subject=SUBJECT_A)
        self.assertEqual(4, get_cache().get(other_key, default=0))

    def test_cache_unlock_keeps_other_subject(self):
        self._failure("alice", SUBJECT_A, "10.0.0.1")
        self._failure("alice", SUBJECT_B, "10.9.9.9")

        AxesProxyHandler.reset_attempts(subject=SUBJECT_A)

        self.assertEqual(
            0,
            AxesProxyHandler.get_failures(
                self._request("10.0.0.1"),
                {"username": "alice", "subject": SUBJECT_A},
            ),
        )
        self.assertEqual(
            1,
            AxesProxyHandler.get_failures(
                self._request("10.9.9.9"),
                {"username": "alice", "subject": SUBJECT_B},
            ),
        )

    def test_cache_unlock_by_legacy_window_clears_mapped_subject(self):
        self._failure("alice", SUBJECT_A, "10.0.0.1")
        self._failure("alice", SUBJECT_A, "10.0.0.2")

        # An operator unlocks the old username/network-group window.
        AxesProxyHandler.reset_attempts(ip_address="10.0.0.1", username="alice")

        # The mapped subject's legacy cache keys are cleared as well, so the
        # subject count drops even for the second registered window.
        self.assertEqual(
            0,
            AxesProxyHandler.get_failures(
                self._request("10.0.0.2"),
                {"username": "alice", "subject": SUBJECT_A},
            ),
        )

    def test_duplicate_event_counts_once_in_cache(self):
        self._failure("alice", SUBJECT_A, "10.0.0.1", event_id="evt-1")
        self._failure("alice", SUBJECT_A, "10.0.0.1", event_id="evt-1")

        self.assertEqual(
            1,
            AxesProxyHandler.get_failures(
                self._request("10.0.0.1"),
                {"username": "alice", "subject": SUBJECT_A},
            ),
        )


@override_settings(
    AXES_HANDLER="axes.handlers.database.AxesDatabaseHandler",
    AXES_SUBJECT_LEGACY_IDENTITIES=LEGACY_IDENTITIES,
    AXES_COOLOFF_TIME=timedelta(minutes=30),
    AXES_FAILURE_LIMIT=3,
)
class SubjectMigrationAcceptanceTestCase(AxesTestCase):
    """Rolling-deployment acceptance for one locked account and a namesake."""

    def setUp(self):
        super().setUp()
        self.now = now()

    def request_for(self, username, ip_address, subject=None, event_id=None):
        from django.http import HttpRequest

        request = HttpRequest()
        request.method = "POST"
        request.META["REMOTE_ADDR"] = ip_address
        request.META["HTTP_USER_AGENT"] = self.user_agent
        request.META["PATH_INFO"] = self.path_info
        request.axes_attempt_time = self.now
        request.axes_ip_address = ip_address
        request.axes_user_agent = self.user_agent
        request.axes_path_info = self.path_info
        request.axes_http_accept = "<unknown>"
        request.axes_failures_since_start = None
        request.axes_locked_out = False
        request.axes_credentials = None
        if subject is not None:
            request.META["HTTP_X_AXES_SUBJECT"] = subject
        if event_id is not None:
            request.META["HTTP_X_AXES_FAILURE_ID"] = event_id
        return request

    def legacy_write(self, username, ip_address, failures=1):
        """Write the row a pre-migration worker produces, without subjects."""

        attempt, created = AccessAttempt.objects.get_or_create(
            subject="",
            username=username,
            ip_address=ip_address,
            user_agent=self.user_agent,
            defaults={
                "get_data": "",
                "post_data": "",
                "http_accept": "<unknown>",
                "path_info": self.path_info,
                "failures_since_start": failures,
            },
        )
        if not created:
            attempt.failures_since_start += failures
            attempt.save(update_fields=["failures_since_start"])
        return attempt

    def new_write(self, username, ip_address, subject, event_id=None):
        request = self.request_for(username, ip_address, subject, event_id)
        AxesProxyHandler.user_login_failed(
            sender=None,
            credentials=(
                {
                    "username": username,
                    "subject": subject,
                    "failure_id": event_id,
                }
                if event_id
                else {"username": username, "subject": subject}
            ),
            request=request,
        )
        return request

    def count(self, request, username, subject=None):
        credentials = {"username": username}
        if subject is not None:
            credentials["subject"] = subject
        return AxesProxyHandler.get_failures(request, credentials)

    def is_allowed(self, request, username, subject):
        return AxesProxyHandler.is_allowed(
            request, {"username": username, "subject": subject}
        )

    def test_switch_before_and_after_agree(self):
        # Pre-switch: a legacy worker locked alice on 10.0.0.1, and another
        # namesake on 10.9.9.9 already has one failure of its own.
        self.legacy_write("alice", "10.0.0.1", failures=3)
        self.legacy_write("alice", "10.9.9.9", failures=1)

        self.assertEqual(3, self.count(self.request_for("alice", "10.0.0.1"), "alice"))
        self.assertFalse(
            self.is_allowed(self.request_for("alice", "10.0.0.1"), "alice", SUBJECT_A)
        )

        # Switch: the migration keeps the count, the lockout and its deadline.
        from axes.subjects import backfill_subject_attempts

        backfill_subject_attempts(SUBJECT_A)

        request_a = self.request_for("alice", "10.0.0.1", SUBJECT_A)
        self.assertEqual(3, self.count(request_a, "alice", SUBJECT_A))
        self.assertFalse(self.is_allowed(request_a, "alice", SUBJECT_A))

        request_b = self.request_for("alice", "10.9.9.9", SUBJECT_B)
        self.assertEqual(1, self.count(request_b, "alice", SUBJECT_B))
        self.assertTrue(self.is_allowed(request_b, "alice", SUBJECT_B))

        # Authorised unlock of subject A clears its complete scope and
        # leaves the coincidental namesake's count intact.
        removed = AxesProxyHandler.reset_attempts(subject=SUBJECT_A)
        self.assertEqual(1, removed)
        self.assertTrue(
            self.is_allowed(
                self.request_for("alice", "10.0.0.1", SUBJECT_A),
                "alice",
                SUBJECT_A,
            )
        )
        self.assertEqual(
            1,
            self.count(
                self.request_for("alice", "10.9.9.9", SUBJECT_B),
                "alice",
                SUBJECT_B,
            ),
        )

    def test_dual_write_of_same_failure_counts_once(self):
        event = "login-event-42"
        # One failed login reaches two workers.  The first write is the legacy
        # shape (username only), the second carries the registered subject.
        legacy_request = self.request_for("alice", "10.0.0.1")
        AxesProxyHandler.user_login_failed(
            sender=None,
            credentials={"username": "alice", "failure_id": event},
            request=legacy_request,
        )
        self.new_write("alice", "10.0.0.1", SUBJECT_A, event_id=event)
        # A third delivery of the same event is also ignored.
        self.new_write("alice", "10.0.0.1", SUBJECT_A, event_id=event)

        self.assertEqual(
            1,
            self.count(
                self.request_for("alice", "10.0.0.1", SUBJECT_A),
                "alice",
                SUBJECT_A,
            ),
        )
        self.assertEqual(1, AccessAttempt.objects.count())

    def test_backfill_and_new_failure_neither_reset_nor_inflate(self):
        from axes.subjects import backfill_subject_attempts

        self.legacy_write("alice", "10.0.0.1", failures=2)
        backfill_subject_attempts(SUBJECT_A)
        self.new_write("alice", "10.0.0.1", SUBJECT_A)

        request = self.request_for("alice", "10.0.0.1", SUBJECT_A)
        self.assertEqual(3, self.count(request, "alice", SUBJECT_A))
        self.assertFalse(self.is_allowed(request, "alice", SUBJECT_A))
