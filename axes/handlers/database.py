from datetime import timedelta
from logging import getLogger
from typing import List, Optional

from django.db import IntegrityError, router, transaction
from django.db.models import F, Q, QuerySet, Sum, Value
from django.db.models.functions import Concat
from django.http import HttpRequest
from django.http.multipartparser import MultiPartParserError
from django.utils import timezone

from axes.attempts import get_cool_off_threshold
from axes.conf import settings
from axes.handlers.base import AbstractAxesHandler, AxesBaseHandler
from axes.helpers import (
    get_client_parameters,
    get_client_session_hash,
    get_client_str,
    get_client_username,
    get_credentials,
    get_failure_limit,
    get_lockout_parameters,
    get_query_str,
    get_attempt_expiration,
)
from axes.models import (
    AccessAttempt,
    AccessAttemptExpiration,
    AccessFailureEvent,
    AccessFailureLog,
    AccessLog,
)
from axes.signals import user_locked_out
from axes.subjects import (
    filter_subject_scope,
    get_client_subject,
    get_failure_event_key,
    get_subject_for_legacy,
    subject_attempt_querysets,
)

log = getLogger(__name__)


class AxesDatabaseHandler(AbstractAxesHandler, AxesBaseHandler):
    """
    Signal handler implementation that records user login attempts to database and locks users out if necessary.

    .. note:: The get_user_attempts function is called several time during the authentication and lockout
              process, caching its output can be dangerous.
    """

    def reset_attempts(
        self,
        *,
        ip_address: Optional[str] = None,
        username: Optional[str] = None,
        subject: Optional[str] = None,
        ip_or_username: bool = False,
    ) -> int:
        if subject:
            # An authorised unlock applies to the complete subject scope: the
            # subject window and every legacy window registered to it.
            attempts = filter_subject_scope(subject)
        else:
            attempts = AccessAttempt.objects.all()
            mapped_subject = (
                get_subject_for_legacy(username, ip_address)
                if username or ip_address
                else None
            )

            if ip_or_username:
                attempts = attempts.filter(
                    Q(ip_address=ip_address) | Q(username=username)
                )
            else:
                if ip_address:
                    attempts = attempts.filter(ip_address=ip_address)
                if username:
                    attempts = attempts.filter(username=username)

            if mapped_subject:
                attempts = attempts | filter_subject_scope(mapped_subject)

        count = 0
        deleted_attempts, _ = attempts.delete()
        count += deleted_attempts
        log.info("AXES: Reset %d access attempts from database.", count)

        return count

    def reset_logs(self, *, age_days: Optional[int] = None) -> int:
        if age_days is None:
            count, _ = AccessLog.objects.all().delete()
            log.info("AXES: Reset all %d access logs from database.", count)
        else:
            limit = timezone.now() - timedelta(days=age_days)
            count, _ = AccessLog.objects.filter(attempt_time__lte=limit).delete()
            log.info(
                "AXES: Reset %d access logs older than %d days from database.",
                count,
                age_days,
            )

        return count

    def reset_failure_logs(self, *, age_days: Optional[int] = None) -> int:
        if age_days is None:
            count, _ = AccessFailureLog.objects.all().delete()
            AccessFailureEvent.objects.all().delete()
            log.info("AXES: Reset all %d access failure logs from database.", count)
        else:
            limit = timezone.now() - timedelta(days=age_days)
            count, _ = AccessFailureLog.objects.filter(attempt_time__lte=limit).delete()
            AccessFailureEvent.objects.filter(attempt_time__lte=limit).delete()
            log.info(
                "AXES: Reset %d access failure logs older than %d days from database.",
                count,
                age_days,
            )

        return count

    def remove_out_of_limit_failure_logs(
        self,
        *,
        username: str,
        limit: Optional[int] = settings.AXES_ACCESS_FAILURE_LOG_PER_USER_LIMIT,
    ) -> int:
        count = 0
        failures = AccessFailureLog.objects.filter(username=username)
        out_of_limit_failures_logs = failures.count() - limit
        if out_of_limit_failures_logs > 0:
            for failure in failures[:out_of_limit_failures_logs]:
                failure.delete()
                count += 1
        return count

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        attempts_list = self.get_user_attempts(request, credentials)
        if not attempts_list:
            return 0
        attempt_count = max(
            (
                attempts.aggregate(Sum("failures_since_start"))[
                    "failures_since_start__sum"
                ]
                or 0
            )
            for attempts in attempts_list
        )
        return attempt_count

    def user_login_failed(self, sender, credentials: dict, request=None, **kwargs):
        """
        When user login fails, save AccessFailureLog record in database,
        save AccessAttempt record in database, mark request with
        lockout attribute and emit lockout signal.
        """

        log.info("AXES: User login failed, running database handler for failure.")

        if request is None:
            log.error(
                "AXES: AxesDatabaseHandler.user_login_failed does not function without a request."
            )
            return

        # 1. database query: Clean up expired user attempts from the database before logging new attempts
        self.clean_expired_user_attempts(request, credentials)

        username = get_client_username(request, credentials)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        # If axes denied access, don't record the failed attempt as that would reset the lockout time.
        if (
            not settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT
            and request.axes_locked_out
        ):
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )
            return

        # This replaces null byte chars that crash saving failures.
        get_data = get_query_str(request.GET).replace("\0", "0x00")
        try:
            post_data = get_query_str(request.POST).replace("\0", "0x00")
        except MultiPartParserError as ex:
            post_data = (
                f'Could not access "request.POST": {ex.__class__.__name__}: {ex}'
            )

        if self.is_whitelisted(request, credentials):
            log.info("AXES: Login failed from whitelisted client %s.", client_str)
            return

        subject = get_client_subject(request, credentials)
        if subject is None:
            subject = get_subject_for_legacy(username, request.axes_ip_address)

        # 2. database query: Get or create access record with the new failure data.
        #
        # During a rolling deployment one failed login can be observed by both a
        # pre-migration worker and a subject-aware worker.  The failure event key
        # makes the second observation a no-op so the failure is counted once.
        lockout_parameters = get_lockout_parameters(request, credentials)
        event_key = get_failure_event_key(request, credentials)
        already_recorded = False
        if lockout_parameters == ["username"] and username is None:
            log.warning(
                "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
            )
        else:
            if event_key is not None:
                try:
                    with transaction.atomic(
                        using=router.db_for_write(AccessFailureEvent)
                    ):
                        AccessFailureEvent.objects.create(
                            key=event_key,
                            subject=subject or "",
                            username=username,
                            ip_address=request.axes_ip_address,
                            user_agent=request.axes_user_agent or "",
                        )
                except IntegrityError:
                    already_recorded = True

            if already_recorded:
                log.info(
                    "AXES: Failure event %s was already recorded by another worker; "
                    "not counting it again.",
                    event_key,
                )
            else:
                self.record_attempt(
                    request=request,
                    username=username,
                    subject=subject,
                    get_data=get_data,
                    post_data=post_data,
                    client_str=client_str,
                )

        # 3. or 4. database query: Calculate the current maximum failure number from the existing attempts
        failures_since_start = self.get_failures(request, credentials)
        request.axes_failures_since_start = failures_since_start

        if (
            settings.AXES_LOCK_OUT_AT_FAILURE
            and failures_since_start >= get_failure_limit(request, credentials)
        ):
            log.warning(
                "AXES: Locking out %s after repeated login failures.", client_str
            )

            request.axes_locked_out = True
            request.axes_credentials = credentials
            user_locked_out.send(
                "axes",
                request=request,
                username=username,
                ip_address=request.axes_ip_address,
            )

        # 5. database entry: Log for ever the attempt in the AccessFailureLog
        if settings.AXES_ENABLE_ACCESS_FAILURE_LOG and not already_recorded:
            try:
                with transaction.atomic(using=router.db_for_write(AccessFailureLog)):
                    AccessFailureLog.objects.create(
                        username=username,
                        subject=subject or "",
                        ip_address=request.axes_ip_address,
                        user_agent=request.axes_user_agent,
                        http_accept=request.axes_http_accept,
                        path_info=request.axes_path_info,
                        attempt_time=request.axes_attempt_time,
                        locked_out=request.axes_locked_out,
                        event_key=event_key,
                    )
            except IntegrityError:
                log.info(
                    "AXES: Failure log for event %s already exists; "
                    "not writing a duplicate.",
                    event_key,
                )
            self.remove_out_of_limit_failure_logs(username=username)

    def record_attempt(
        self,
        *,
        request,
        username,
        subject,
        get_data: str,
        post_data: str,
        client_str: str,
    ):
        """Record one failed login in the window that owns its subject.

        A subject-aware request reuses an existing row for the same real
        subject, adopting a pre-migration row when needed, and increments it.
        Otherwise it creates the subject row.  A request without a subject keeps
        updating its username/network-group window.  Rows stay single-homed, so
        a subject-scoped read counts each real failure exactly once.
        """

        with transaction.atomic(using=router.db_for_write(AccessAttempt)):
            self._record_attempt_window(
                request=request,
                username=username,
                subject=subject or "",
                get_data=get_data,
                post_data=post_data,
                client_str=client_str,
            )

    def _record_attempt_window(
        self,
        *,
        request,
        username,
        subject,
        get_data: str,
        post_data: str,
        client_str: str,
    ):
        base = AccessAttempt.objects.select_for_update().filter(
            username=username,
            ip_address=request.axes_ip_address,
            user_agent=request.axes_user_agent,
        )

        attempt = base.filter(subject=subject).first()
        if attempt is None and subject:
            # A pre-migration worker already recorded this same real subject.
            # Adopt that row instead of creating a second copy, so the union
            # read does not count the same failure twice.
            attempt = base.filter(subject="").first()
            if attempt is not None:
                attempt.subject = subject
                attempt.save(update_fields=["subject"])
                log.info(
                    "AXES: Adopted legacy attempt window for %s into subject %s.",
                    client_str,
                    subject,
                )

        if attempt is None:
            attempt, created = AccessAttempt.objects.get_or_create(
                subject=subject,
                username=username,
                ip_address=request.axes_ip_address,
                user_agent=request.axes_user_agent,
                defaults={
                    "get_data": get_data,
                    "post_data": post_data,
                    "http_accept": request.axes_http_accept,
                    "path_info": request.axes_path_info,
                    "failures_since_start": 1,
                },
            )
        else:
            created = False

        if created:
            log.warning(
                "AXES: New login failure by %s. Created new record in the database.",
                client_str,
            )
        else:
            separator = "\n---------\n"

            attempt.get_data = Concat("get_data", Value(separator + get_data))
            attempt.post_data = Concat("post_data", Value(separator + post_data))
            attempt.http_accept = request.axes_http_accept
            attempt.path_info = request.axes_path_info
            attempt.failures_since_start = F("failures_since_start") + 1
            attempt.attempt_time = request.axes_attempt_time
            attempt.save()

            log.warning(
                "AXES: Repeated login failure by %s. Updated existing record in the database.",
                client_str,
            )

        if settings.AXES_USE_ATTEMPT_EXPIRATION:
            if not hasattr(attempt, "expiration") or attempt.expiration is None:
                log.debug(
                    "AXES: Creating new AccessAttemptExpiration for %s",
                    client_str,
                )
                attempt.expiration = AccessAttemptExpiration.objects.create(
                    access_attempt=attempt,
                    expires_at=get_attempt_expiration(request),
                )
            else:
                attempt.expiration.expires_at = max(
                    get_attempt_expiration(request),
                    attempt.expiration.expires_at,
                )
                attempt.expiration.save()

    def user_logged_in(self, sender, request, user, **kwargs):
        """
        When user logs in, update the AccessLog related to the user.
        """

        username = user.get_username()
        credentials = get_credentials(username)
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        log.info("AXES: Successful login by %s.", client_str)

        # 1. database query: Clean up expired user attempts from the database
        self.clean_expired_user_attempts(request, credentials)

        if not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Insert new access logs with login time
            AccessLog.objects.create(
                username=username,
                ip_address=request.axes_ip_address,
                user_agent=request.axes_user_agent,
                http_accept=request.axes_http_accept,
                path_info=request.axes_path_info,
                attempt_time=request.axes_attempt_time,
                # evaluate session hash here to ensure having the correct
                # value which is stored on the backend
                session_hash=get_client_session_hash(request),
            )

        if settings.AXES_RESET_ON_SUCCESS:
            # 3. database query: Reset failed attempts for the logging in user
            count = self.reset_user_attempts(request, credentials)
            log.info(
                "AXES: Deleted %d failed login attempts by %s from database.",
                count,
                client_str,
            )

    def user_logged_out(self, sender, request, user, **kwargs):
        """
        When user logs out, update the AccessLog related to the user.
        """

        username = user.get_username() if user else None
        credentials = get_credentials(username) if username else None
        client_str = get_client_str(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request.axes_path_info,
            request,
        )

        # 1. database query: Clean up expired user attempts from the database
        self.clean_expired_user_attempts(request, credentials)

        log.info("AXES: Successful logout by %s.", client_str)

        if username and not settings.AXES_DISABLE_ACCESS_LOG:
            # 2. database query: Update existing attempt logs with logout time
            AccessLog.objects.filter(
                username=username,
                logout_time__isnull=True,
                # update only access log for given session
                session_hash=get_client_session_hash(request),
            ).update(logout_time=request.axes_attempt_time)

    def filter_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None
    ) -> List[QuerySet]:
        """
        Return a list querysets of AccessAttempts that match the given request and credentials.

        A request that resolved a registered subject is evaluated across the
        complete subject scope: the subject window plus the legacy windows
        registered to the subject.  Each window stays a separate queryset so
        callers combine them with ``max`` semantics instead of double counting.
        """

        subject = get_client_subject(request, credentials)
        if subject is None:
            username = get_client_username(request, credentials)
            ip_address = request.axes_ip_address
            subject = get_subject_for_legacy(username, ip_address)

        if subject:
            return subject_attempt_querysets(subject)

        # A pre-migration request does not send a subject.  When its
        # username/network-group window is registered to a subject, evaluate the
        # complete subject scope so the old worker and the new worker agree on
        # the lockout state and on administrative unlocks.
        username = get_client_username(request, credentials)
        ip_address = request.axes_ip_address
        mapped_subject = get_subject_for_legacy(username, ip_address)
        if mapped_subject:
            return subject_attempt_querysets(mapped_subject)

        filter_kwargs_list = get_client_parameters(
            username,
            ip_address,
            request.axes_user_agent,
            request,
            credentials,
        )
        return [
            AccessAttempt.objects.filter(**filter_kwargs)
            for filter_kwargs in filter_kwargs_list
        ]

    def get_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None  # noqa
    ) -> List[QuerySet]:
        """
        Get list of querysets with valid user attempts that match the given request and credentials.
        """

        attempts_list = self.filter_user_attempts(request, credentials)

        if settings.AXES_COOLOFF_TIME is None:
            log.debug(
                "AXES: Getting all access attempts from database because no AXES_COOLOFF_TIME is configured"
            )
            return attempts_list

        threshold = get_cool_off_threshold(request)
        log.debug("AXES: Getting access attempts that are newer than %s", threshold)
        return [
            attempts.filter(attempt_time__gte=threshold) for attempts in attempts_list
        ]

    def clean_expired_user_attempts(
        self,
        request: Optional[HttpRequest] = None,
        credentials: Optional[dict] = None,  # noqa
    ) -> int:
        """
        Clean expired user attempts from the database.
        """

        if settings.AXES_COOLOFF_TIME is None:
            log.debug(
                "AXES: Skipping clean for expired access attempts because no AXES_COOLOFF_TIME is configured"
            )
            return 0

        if settings.AXES_USE_ATTEMPT_EXPIRATION:
            threshold = timezone.now()
            count, _ = AccessAttempt.objects.filter(
                expiration__expires_at__lte=threshold
            ).delete()
            log.info(
                "AXES: Cleaned up %s expired access attempts from database that expiry were older than %s",
                count,
                threshold,
            )
        else:
            threshold = get_cool_off_threshold(request)
            count, _ = AccessAttempt.objects.filter(
                attempt_time__lte=threshold
            ).delete()
            log.info(
                "AXES: Cleaned up %s expired access attempts from database that were older than %s",
                count,
                threshold,
            )
        return count

    def reset_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None
    ) -> int:
        """
        Reset all user attempts that match the given request and credentials.
        """

        attempts_list = self.filter_user_attempts(request, credentials)

        count = 0
        for attempts in attempts_list:
            _count, _ = attempts.delete()
            count += _count
        log.info("AXES: Reset %s access attempts from database.", count)

        return count

    def post_save_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post save signal.

        When needed, all post_save actions for this backend should be located
        here.
        """

    def post_delete_access_attempt(self, instance, **kwargs):
        """
        Handles the ``axes.models.AccessAttempt`` object post delete signal.

        When needed, all post_delete actions for this backend should be located
        here.
        """
