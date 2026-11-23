from datetime import timedelta
from logging import getLogger
from typing import List, Optional

from django.db import router, transaction
from django.db.models import F, Q, QuerySet, Sum, Value
from django.db.models.functions import Concat
from django.http import HttpRequest
from django.http.multipartparser import MultiPartParserError
from django.utils import timezone

from axes.attempts import get_cool_off_threshold
from axes.conf import settings
from axes.deidentification import hash_identifier
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
    AccessBase,
    AccessFailureLog,
    AccessLog,
)
from axes.signals import user_locked_out

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
        ip_or_username: bool = False,
    ) -> int:
        attempts = AccessAttempt.objects.all()

        ip_filter, username_filter = self._identifier_filters(
            ip_address=ip_address, username=username
        )

        if ip_or_username:
            attempts = attempts.filter(Q(**ip_filter) | Q(**username_filter))
        else:
            if ip_address:
                attempts = attempts.filter(**ip_filter)
            if username:
                attempts = attempts.filter(**username_filter)

        count, _ = attempts.delete()
        log.info("AXES: Reset %d access attempts from database.", count)

        return count

    @staticmethod
    def _identifier_filters(
        *, ip_address: Optional[str] = None, username: Optional[str] = None
    ) -> tuple:
        """Build cleartext or hash lookups depending on the active policy."""

        if settings.AXES_DEIDENTIFY_ENABLED:
            return (
                {"ip_address_hash": hash_identifier(ip_address, "ip_address")},
                {"username_hash": hash_identifier(username, "username")},
            )
        return (
            {"ip_address": ip_address},
            {"username": username},
        )

    @staticmethod
    def _identifier_fields(request: HttpRequest, username: Optional[str]) -> dict:
        """
        Return the identifier columns for a new record.

        Under de-identification the direct identifier columns are stored as
        ``None`` and only their deterministic hashes are persisted, so the
        raw username / IP / user agent never reach the database.
        """

        if settings.AXES_DEIDENTIFY_ENABLED:
            return {
                "username": None,
                "ip_address": None,
                "user_agent": None,
                "username_hash": hash_identifier(username, "username"),
                "ip_address_hash": hash_identifier(
                    request.axes_ip_address, "ip_address"
                ),
                "user_agent_hash": hash_identifier(
                    request.axes_user_agent, "user_agent"
                ),
            }
        return {
            "username": username,
            "ip_address": request.axes_ip_address,
            "user_agent": request.axes_user_agent,
            "username_hash": None,
            "ip_address_hash": None,
            "user_agent_hash": None,
        }

    @staticmethod
    def _deidentified_metadata() -> dict:
        """Timestamp new records as de-identified when the policy is active."""

        if settings.AXES_DEIDENTIFY_ENABLED:
            return {"deidentified_at": timezone.now()}
        return {}

    def _attempt_lookup_and_defaults(
        self,
        request: HttpRequest,
        username: Optional[str],
        get_data: str,
        post_data: str,
    ) -> tuple:
        """
        Build the lookup and default values for get_or_create of an attempt.

        De-identified attempts are keyed on the hash columns; legacy attempts
        keep using the cleartext unique key.
        """

        common_defaults = {
            "get_data": get_data,
            "post_data": post_data,
            "http_accept": request.axes_http_accept,
            "path_info": request.axes_path_info,
            "failures_since_start": 1,
            "attempt_time": request.axes_attempt_time,
        }

        if settings.AXES_DEIDENTIFY_ENABLED:
            lookup = {
                "username_hash": hash_identifier(username, "username"),
                "ip_address_hash": hash_identifier(
                    request.axes_ip_address, "ip_address"
                ),
                "user_agent_hash": hash_identifier(
                    request.axes_user_agent, "user_agent"
                ),
            }
            defaults = {
                **common_defaults,
                "username": None,
                "ip_address": None,
                "user_agent": None,
                "deidentified_at": timezone.now(),
            }
            return lookup, defaults

        lookup = {
            "username": username,
            "ip_address": request.axes_ip_address,
            "user_agent": request.axes_user_agent,
        }
        defaults = {**common_defaults, "deidentified_at": None}
        return lookup, defaults

    def convert_legacy_records(self, *, batch_size: int = 500) -> int:
        """
        Convert cleartext audit records to de-identified markers in batches.

        The conversion is safe to run while new failures are being recorded and
        can be re-run any number of times:

        * only records that still hold cleartext identifiers are touched
          (``deidentified_at IS NULL``), so already converted records are
          skipped;
        * hashes are deterministic, so a record converted now and a fresh
          failure for the same account resolve to the same markers;
        * when a de-identified ``AccessAttempt`` for the same markers already
          exists the legacy row is merged into it, adding its failure count
          instead of creating a duplicate. The threshold for the account is
          therefore never reset or inflated.

        Returns the number of legacy records that were processed.
        """

        if not settings.AXES_DEIDENTIFY_ENABLED:
            log.info(
                "AXES: Skipping de-identification migration because "
                "AXES_DEIDENTIFY_ENABLED is False."
            )
            return 0

        processed = 0
        for model in (AccessAttempt, AccessFailureLog, AccessLog):
            processed += self._convert_model_batches(model, batch_size)
        return processed

    def _convert_model_batches(self, model, batch_size: int) -> int:
        processed = 0
        while True:
            legacy_ids = list(
                model.objects.filter(deidentified_at__isnull=True)
                .order_by("pk")
                .values_list("pk", flat=True)[:batch_size]
            )
            if not legacy_ids:
                break

            for instance in model.objects.filter(pk__in=legacy_ids):
                self._convert_instance(instance)
                processed += 1
        return processed

    def _convert_instance(self, instance: AccessBase) -> None:
        with transaction.atomic(using=router.db_for_write(type(instance))):
            # Lock the row so a concurrent failure cannot update it mid-flight.
            locked = (
                type(instance)
                .objects.select_for_update()
                .filter(pk=instance.pk)
                .first()
            )
            if locked is None or locked.deidentified_at is not None:
                # Another worker already converted this row; nothing to do.
                return

            hashes = {
                "username_hash": hash_identifier(locked.username, "username"),
                "ip_address_hash": hash_identifier(
                    locked.ip_address, "ip_address"
                ),
                "user_agent_hash": hash_identifier(
                    locked.user_agent, "user_agent"
                ),
            }

            if isinstance(locked, AccessAttempt):
                self._merge_or_pseudonymize_attempt(locked, hashes)
            else:
                locked.username = None
                locked.ip_address = None
                locked.user_agent = None
                for field_name, digest in hashes.items():
                    setattr(locked, field_name, digest)
                locked.deidentified_at = timezone.now()
                locked.save()

    @staticmethod
    def _merge_or_pseudonymize_attempt(
        attempt: AccessAttempt, hashes: dict
    ) -> None:
        existing = (
            AccessAttempt.objects.select_for_update()
            .exclude(pk=attempt.pk)
            .filter(**hashes)
            .first()
        )

        if existing is None:
            # No live de-identified row yet: pseudonymize this row in place,
            # preserving its failure count and attempt window untouched.
            attempt.username = None
            attempt.ip_address = None
            attempt.user_agent = None
            for field_name, digest in hashes.items():
                setattr(attempt, field_name, digest)
            attempt.deidentified_at = timezone.now()
            attempt.save()
            return

        # A de-identified row for the same account already exists (created by a
        # failure that arrived after the switch). Merge the legacy failure count
        # into it so the window keeps the true cumulative number of failures.
        existing.failures_since_start = (
            F("failures_since_start") + attempt.failures_since_start
        )
        # Keep the most recent activity so the cool-off window is not shortened.
        if attempt.attempt_time > existing.attempt_time:
            existing.attempt_time = attempt.attempt_time
        if hasattr(attempt, "expiration") and attempt.expiration is not None:
            if not hasattr(existing, "expiration") or existing.expiration is None:
                AccessAttemptExpiration.objects.create(
                    access_attempt=existing,
                    expires_at=attempt.expiration.expires_at,
                )
            else:
                existing.expiration.expires_at = max(
                    existing.expiration.expires_at,
                    attempt.expiration.expires_at,
                )
                existing.expiration.save()
        existing.save()
        # Deleting the legacy row also cascades its expiration row.
        attempt.delete()

    def clean_expired_deidentified_records(self) -> int:
        """
        Hard-delete de-identified audit records past the retention period.

        The retention cutoff is measured against ``attempt_time`` so that the
        real failure window, not the conversion timestamp, drives deletion.
        Running this repeatedly yields the same end state: once the expired
        records are gone the second run simply has nothing to delete.
        """

        retention_days = settings.AXES_DEIDENTIFY_RETENTION_DAYS
        if retention_days is None:
            log.debug(
                "AXES: Skipping de-identified retention cleanup because "
                "AXES_DEIDENTIFY_RETENTION_DAYS is not set."
            )
            return 0

        cutoff = timezone.now() - timedelta(days=retention_days)
        count = 0
        for model in (AccessAttempt, AccessFailureLog, AccessLog):
            deleted, _ = model.objects.filter(
                deidentified_at__isnull=False, attempt_time__lte=cutoff
            ).delete()
            count += deleted
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
            log.info("AXES: Reset all %d access failure logs from database.", count)
        else:
            limit = timezone.now() - timedelta(days=age_days)
            count, _ = AccessFailureLog.objects.filter(attempt_time__lte=limit).delete()
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
        if settings.AXES_DEIDENTIFY_ENABLED:
            failures = AccessFailureLog.objects.filter(
                username_hash=hash_identifier(username, "username")
            )
        else:
            failures = AccessFailureLog.objects.filter(username=username)
        out_of_limit_failures_logs = failures.count() - limit
        if out_of_limit_failures_logs > 0:
            for failure in failures[:out_of_limit_failures_logs]:
                failure.delete()
                count += 1
        return count

    def get_failures(self, request, credentials: Optional[dict] = None) -> int:
        attempts_list = self.get_user_attempts(request, credentials)
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

        # 2. database query: Get or create access record with the new failure data
        lockout_parameters = get_lockout_parameters(request, credentials)
        if lockout_parameters == ["username"] and username is None:
            log.warning(
                "AXES: Username is None and username is the only one lockout parameter, new record will NOT be created."
            )
        else:
            with transaction.atomic(using=router.db_for_write(AccessAttempt)):
                lookup, defaults = self._attempt_lookup_and_defaults(
                    request, username, get_data, post_data
                )
                (
                    attempt,
                    created,
                ) = AccessAttempt.objects.select_for_update().get_or_create(
                    **lookup,
                    defaults=defaults,
                )

                # Record failed attempt with all the relevant information.
                # Filtering based on username, IP address and user agent handled elsewhere,
                # and this handler just records the available information for further use.
                if created:
                    log.warning(
                        "AXES: New login failure by %s. Created new record in the database.",
                        client_str,
                    )

                # 3. database query if there were previous attempts in the database
                # Update failed attempt information but do not touch the username, IP address, or user agent fields,
                # because attackers can request the site with multiple different configurations
                # in order to bypass the defense mechanisms that are used by the site.
                else:
                    separator = "\n---------\n"

                    attempt.get_data = Concat("get_data", Value(separator + get_data))
                    attempt.post_data = Concat(
                        "post_data", Value(separator + post_data)
                    )
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
        if settings.AXES_ENABLE_ACCESS_FAILURE_LOG:
            with transaction.atomic(using=router.db_for_write(AccessFailureLog)):
                AccessFailureLog.objects.create(
                    **self._identifier_fields(request, username),
                    http_accept=request.axes_http_accept,
                    path_info=request.axes_path_info,
                    attempt_time=request.axes_attempt_time,
                    locked_out=request.axes_locked_out,
                    **self._deidentified_metadata(),
                )
                self.remove_out_of_limit_failure_logs(username=username)

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
                **self._identifier_fields(request, username),
                http_accept=request.axes_http_accept,
                path_info=request.axes_path_info,
                attempt_time=request.axes_attempt_time,
                # evaluate session hash here to ensure having the correct
                # value which is stored on the backend
                session_hash=get_client_session_hash(request),
                **self._deidentified_metadata(),
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
            if settings.AXES_DEIDENTIFY_ENABLED:
                username_filter = {
                    "username_hash": hash_identifier(username, "username")
                }
            else:
                username_filter = {"username": username}
            AccessLog.objects.filter(
                **username_filter,
                logout_time__isnull=True,
                # update only access log for given session
                session_hash=get_client_session_hash(request),
            ).update(logout_time=request.axes_attempt_time)

    def filter_user_attempts(
        self, request: HttpRequest, credentials: Optional[dict] = None
    ) -> List[QuerySet]:
        """
        Return a list querysets of AccessAttempts that match the given request and credentials.
        """

        username = get_client_username(request, credentials)

        filter_kwargs_list = get_client_parameters(
            username,
            request.axes_ip_address,
            request.axes_user_agent,
            request,
            credentials,
        )
        attempts_list = [
            AccessAttempt.objects.filter(**filter_kwargs)
            for filter_kwargs in filter_kwargs_list
        ]
        return attempts_list

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
