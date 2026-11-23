"""
Tests for the stable identity of real authentication attempts.

Two observable scenarios are covered:

1. The same password check is reported through two login entry points
   (a form layer and a direct ``authenticate`` style report). The duplicate
   report shares one attempt identity and consumes a single lockout score
   point, while the user still sees one concrete rejection reason.

2. One request performs two genuinely independent authentication attempts.
   Each attempt gets its own identity and therefore its own lockout score
   point.
"""

from unittest.mock import patch

from django.contrib.auth import authenticate
from django.contrib.auth.signals import user_login_failed
from django.http import HttpRequest
from django.test import override_settings
from django.utils.timezone import now

from axes.attempt_identity import (
    REQUEST_ATTRIBUTE,
    begin_attempt_identifier,
    get_attempt_identifier,
    mark_attempt_non_countable,
    reset_attempt_identifier,
    set_attempt_identifier,
)
from axes.backends import AxesStandaloneBackend
from axes.exceptions import AxesBusinessRuleDenied
from axes.helpers import (
    get_client_http_accept,
    get_client_ip_address,
    get_client_path_info,
    get_client_user_agent,
    get_credentials,
)
from axes.models import AccessAttempt
from axes.signals import handle_user_login_failed
from tests.base import AxesTestCase


def build_axes_request(case):
    request = HttpRequest()
    request.method = "POST"
    request.META["REMOTE_ADDR"] = case.ip_address
    request.META["HTTP_USER_AGENT"] = case.user_agent
    request.META["PATH_INFO"] = case.path_info
    request.axes_attempt_time = now()
    request.axes_ip_address = get_client_ip_address(request)
    request.axes_user_agent = get_client_user_agent(request)
    request.axes_path_info = get_client_path_info(request)
    request.axes_http_accept = get_client_http_accept(request)
    request.axes_failures_since_start = None
    request.axes_locked_out = False
    return request


class AttemptIdentityTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        reset_attempt_identifier()

    def tearDown(self):
        reset_attempt_identifier()
        super().tearDown()

    def test_each_begin_call_produces_a_distinct_identity(self):
        first = begin_attempt_identifier()
        second = begin_attempt_identifier()
        self.assertNotEqual(first, second)
        self.assertEqual(get_attempt_identifier(), second)

    def test_identity_is_mirrored_on_the_request(self):
        identifier = begin_attempt_identifier()
        set_attempt_identifier(identifier, self.request)
        self.assertEqual(getattr(self.request, REQUEST_ATTRIBUTE), identifier)
        self.assertEqual(get_attempt_identifier(self.request), identifier)

    def test_request_attribute_is_the_legacy_fallback(self):
        reset_attempt_identifier()
        self.request.axes_attempt_identifier = "legacy-identity"
        self.assertEqual(
            get_attempt_identifier(self.request), "legacy-identity"
        )

    def test_backend_starts_a_new_identity_on_every_authenticate_call(self):
        backend = AxesStandaloneBackend()
        backend.authenticate(self.request, self.username, self.INVALID_PASSWORD)
        first = get_attempt_identifier(self.request)

        backend.authenticate(self.request, self.username, self.INVALID_PASSWORD)
        second = get_attempt_identifier(self.request)

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertNotEqual(first, second)


class DuplicateReportTestCase(AxesTestCase):
    """
    Scenario 1: two entry points report the very same password check.
    """

    def setUp(self):
        super().setUp()
        reset_attempt_identifier()

    def tearDown(self):
        reset_attempt_identifier()
        super().tearDown()

    def test_duplicate_report_is_scored_once(self):
        identifier = begin_attempt_identifier()
        setattr(self.request, REQUEST_ATTRIBUTE, identifier)
        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)

        # The form layer reports the failed password check first.
        user_login_failed.send(
            sender="form-layer",
            credentials=credentials,
            request=self.request,
        )
        # A second entry point observes the same check and reports it again
        # with the same attempt identity.
        user_login_failed.send(
            sender="authenticate-layer",
            credentials=credentials,
            request=self.request,
        )

        self.assertEqual(AccessAttempt.objects.count(), 1)
        self.assertEqual(
            AccessAttempt.objects.get().failures_since_start, 1
        )
        self.assertEqual(
            self.request.axes_failures_since_start, 1
        )

    def test_duplicate_report_through_signal_receiver_is_forwarded_once(self):
        identifier = begin_attempt_identifier()
        setattr(self.request, REQUEST_ATTRIBUTE, identifier)
        credentials = get_credentials(self.username)

        with patch(
            "axes.signals.AxesProxyHandler.user_login_failed"
        ) as handler:
            handle_user_login_failed(
                sender="form-layer",
                credentials=credentials,
                request=self.request,
            )
            handle_user_login_failed(
                sender="authenticate-layer",
                credentials=credentials,
                request=self.request,
            )

        self.assertEqual(handler.call_count, 1)

    def test_report_without_identity_keeps_legacy_behaviour(self):
        reset_attempt_identifier()
        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)

        with patch(
            "axes.signals.AxesProxyHandler.user_login_failed"
        ) as handler:
            handle_user_login_failed(
                sender="legacy-entry",
                credentials=credentials,
                request=self.request,
            )

        self.assertEqual(handler.call_count, 1)

    def test_full_stack_duplicate_report_locks_out_at_failure_limit(self):
        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)

        # Every reported pair shares one identity, simulating two entry points
        # observing the same authenticate() call on each HTTP request.
        for _ in range(9):
            identifier = begin_attempt_identifier()
            setattr(self.request, REQUEST_ATTRIBUTE, identifier)
            user_login_failed.send(
                sender="form-layer",
                credentials=credentials,
                request=self.request,
            )
            user_login_failed.send(
                sender="authenticate-layer",
                credentials=credentials,
                request=self.request,
            )

        self.assertEqual(
            AccessAttempt.objects.get().failures_since_start, 9
        )
        self.assertFalse(self.request.axes_locked_out)

        # The tenth real attempt crosses the default limit of 10 even though
        # it is reported twice.
        identifier = begin_attempt_identifier()
        setattr(self.request, REQUEST_ATTRIBUTE, identifier)
        user_login_failed.send(
            sender="form-layer",
            credentials=credentials,
            request=self.request,
        )
        user_login_failed.send(
            sender="authenticate-layer",
            credentials=credentials,
            request=self.request,
        )

        self.assertEqual(
            AccessAttempt.objects.get().failures_since_start, 10
        )
        self.assertTrue(self.request.axes_locked_out)


class TwoIndependentAttemptsTestCase(AxesTestCase):
    """
    Scenario 2: two independent authentication attempts on one request.
    """

    def setUp(self):
        super().setUp()
        reset_attempt_identifier()

    def tearDown(self):
        reset_attempt_identifier()
        super().tearDown()

    def test_two_attempts_are_scored_separately(self):
        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)

        first_identifier = begin_attempt_identifier()
        setattr(self.request, REQUEST_ATTRIBUTE, first_identifier)
        user_login_failed.send(
            sender="attempt-1",
            credentials=credentials,
            request=self.request,
        )

        second_identifier = begin_attempt_identifier()
        self.assertNotEqual(first_identifier, second_identifier)
        setattr(self.request, REQUEST_ATTRIBUTE, second_identifier)
        user_login_failed.send(
            sender="attempt-2",
            credentials=credentials,
            request=self.request,
        )

        self.assertEqual(AccessAttempt.objects.count(), 1)
        self.assertEqual(
            AccessAttempt.objects.get().failures_since_start, 2
        )
        self.assertEqual(self.request.axes_failures_since_start, 2)

    def test_authenticate_calls_on_one_request_get_two_scores(self):
        # The standalone backend is first in AUTHENTICATION_BACKENDS, so a
        # locked out / wrong password run still goes through it and assigns an
        # identity per call.
        request = build_axes_request(self)

        authenticate(
            request=request,
            username=self.username,
            password=self.INVALID_PASSWORD,
        )
        first_identifier = getattr(request, REQUEST_ATTRIBUTE)
        authenticate(
            request=request,
            username=self.username,
            password=self.INVALID_PASSWORD,
        )
        second_identifier = getattr(request, REQUEST_ATTRIBUTE)

        self.assertNotEqual(first_identifier, second_identifier)
        self.assertEqual(
            AccessAttempt.objects.get().failures_since_start, 2
        )


@override_settings(AXES_HANDLER="axes.handlers.cache.AxesCacheHandler")
class CacheHandlerIdentityTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        reset_attempt_identifier()

    def tearDown(self):
        reset_attempt_identifier()
        super().tearDown()

    def test_two_attempts_are_scored_separately_in_cache(self):
        from axes.helpers import get_cache, get_client_cache_keys

        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)

        for sender in ("attempt-1", "attempt-2"):
            identifier = begin_attempt_identifier()
            setattr(self.request, REQUEST_ATTRIBUTE, identifier)
            user_login_failed.send(
                sender=sender,
                credentials=credentials,
                request=self.request,
            )

        cache_key = get_client_cache_keys(self.request, credentials)[0]
        self.assertEqual(get_cache().get(cache_key), 2)

    def test_duplicate_report_is_scored_once_in_cache(self):
        from axes.helpers import get_cache, get_client_cache_keys

        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)
        identifier = begin_attempt_identifier()
        setattr(self.request, REQUEST_ATTRIBUTE, identifier)

        for sender in ("form-layer", "authenticate-layer"):
            user_login_failed.send(
                sender=sender,
                credentials=credentials,
                request=self.request,
            )

        cache_key = get_client_cache_keys(self.request, credentials)[0]
        self.assertEqual(get_cache().get(cache_key), 1)


class BusinessRuleBackend(AxesStandaloneBackend):
    def check_business_rules(self, request, credentials):
        return "Account is not verified."


class BusinessRuleRejectionTestCase(AxesTestCase):
    def setUp(self):
        super().setUp()
        reset_attempt_identifier()

    def tearDown(self):
        reset_attempt_identifier()
        super().tearDown()

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "tests.test_attempt_identity.BusinessRuleBackend",
            "django.contrib.auth.backends.ModelBackend",
        ]
    )
    def test_business_rule_rejection_does_not_consume_lockout_score(self):
        request = build_axes_request(self)

        with patch(
            "axes.signals.AxesProxyHandler.user_login_failed"
        ) as handler:
            user = authenticate(
                request=request,
                username=self.username,
                password=self.VALID_PASSWORD,
            )

        self.assertIsNone(user)
        self.assertEqual(handler.call_count, 1)
        self.assertEqual(AccessAttempt.objects.count(), 0)
        self.assertEqual(
            request.axes_non_countable_reason, "Account is not verified."
        )
        self.assertFalse(request.axes_locked_out)

    @override_settings(
        AUTHENTICATION_BACKENDS=[
            "tests.test_attempt_identity.BusinessRuleBackend",
            "django.contrib.auth.backends.ModelBackend",
        ]
    )
    def test_repeated_business_rule_rejections_never_lock_out(self):
        for _ in range(20):
            request = build_axes_request(self)
            self.assertIsNone(
                authenticate(
                    request=request,
                    username=self.username,
                    password=self.VALID_PASSWORD,
                )
            )

        self.assertEqual(AccessAttempt.objects.count(), 0)

    def test_mark_attempt_non_countable_skips_database_scoring(self):
        mark_attempt_non_countable(self.request, "Account is disabled.")
        credentials = get_credentials(self.username, password=self.INVALID_PASSWORD)

        user_login_failed.send(
            sender="business-rule",
            credentials=credentials,
            request=self.request,
        )

        self.assertEqual(AccessAttempt.objects.count(), 0)
        self.assertFalse(self.request.axes_locked_out)

    def test_business_rule_exception_carries_the_reason(self):
        with self.assertRaises(AxesBusinessRuleDenied) as context:
            raise AxesBusinessRuleDenied("Account is not verified.")
        self.assertEqual(context.exception.reason, "Account is not verified.")
