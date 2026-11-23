from logging import getLogger

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.core.signals import setting_changed
from django.db.models.signals import post_save, post_delete
from django.dispatch import Signal
from django.dispatch import receiver

from axes.attempt_identity import (
    OBSERVED_REQUEST_ATTRIBUTE,
    REQUEST_ATTRIBUTE,
    get_attempt_identifier,
)
from axes.handlers.proxy import AxesProxyHandler
from axes.models import AccessAttempt

log = getLogger(__name__)


# This signal provides the following arguments to any listeners:
# request - The current Request object.
# username - The username of the User who has been locked out.
# ip_address - The IP of the user who has been locked out.
user_locked_out = Signal()


@receiver(user_login_failed)
def handle_user_login_failed(sender, credentials, request=None, **kwargs):
    """
    Report a failed authentication attempt to the configured handler exactly
    once per real authentication attempt.

    Different layers of a project (e.g. a login form and a separate call to
    ``django.contrib.auth.authenticate``) can observe the same password
    check and emit ``user_login_failed`` more than once. Attempts that share
    the same attempt identity describe the same real failure and must only
    consume a single lockout score point, so duplicate reports are skipped.

    Signals without an attempt identity are forwarded untouched to preserve
    the behaviour of entry points that do not start an Axes-tracked attempt.
    """

    identifier = get_attempt_identifier(request)
    if identifier is not None and request is not None:
        observed = getattr(request, OBSERVED_REQUEST_ATTRIBUTE, None)
        if not isinstance(observed, set):
            observed = set()
            setattr(request, OBSERVED_REQUEST_ATTRIBUTE, observed)

        if identifier in observed:
            log.info(
                "AXES: Ignoring duplicate user_login_failed report for attempt %s.",
                identifier,
            )
            return

        observed.add(identifier)
        setattr(request, REQUEST_ATTRIBUTE, identifier)

    AxesProxyHandler.user_login_failed(
        sender, credentials=credentials, request=request, **kwargs
    )


@receiver(user_logged_in)
def handle_user_logged_in(*args, **kwargs):
    AxesProxyHandler.user_logged_in(*args, **kwargs)


@receiver(user_logged_out)
def handle_user_logged_out(*args, **kwargs):
    AxesProxyHandler.user_logged_out(*args, **kwargs)


@receiver(post_save, sender=AccessAttempt)
def handle_post_save_access_attempt(*args, **kwargs):
    AxesProxyHandler.post_save_access_attempt(*args, **kwargs)


@receiver(post_delete, sender=AccessAttempt)
def handle_post_delete_access_attempt(*args, **kwargs):
    AxesProxyHandler.post_delete_access_attempt(*args, **kwargs)


@receiver(setting_changed)
def handle_setting_changed(
    sender, setting, value, enter, **kwargs
):  # pylint: disable=unused-argument
    """
    Reinitialize handler implementation if a relevant setting changes
    in e.g. application reconfiguration or during testing.
    """

    if setting == "AXES_HANDLER":
        AxesProxyHandler.get_implementation(force=True)
