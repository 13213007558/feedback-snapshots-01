from typing import Optional
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.http import HttpRequest

from axes.attempt_identity import (
    REQUEST_ATTRIBUTE,
    begin_attempt_identifier,
    mark_attempt_non_countable,
)
from axes.exceptions import (
    AxesBackendPermissionDenied,
    AxesBackendRequestParameterRequired,
    AxesBusinessRuleDenied,
)
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_credentials, get_lockout_message, toggleable


class AxesStandaloneBackend:
    """
    Authentication backend class that forbids login attempts for locked out users.

    Use this class as the first item of ``AUTHENTICATION_BACKENDS`` to
    prevent locked out users from being logged in by the Django authentication flow.

    .. note:: This backend does not log your user in. It monitors login attempts.
              It also does not run any permissions checks at all.
              Authentication is handled by the following backends that are configured in ``AUTHENTICATION_BACKENDS``.
    """

    @toggleable
    def authenticate(
        self,
        request: HttpRequest,
        username: Optional[str] = None,
        password: Optional[str] = None,
        **kwargs: dict,
    ):
        """
        Checks user lockout status and raises an exception if user is not allowed to log in.

        Every call to this method represents one real authentication attempt
        and receives a fresh attempt identifier. The identifier is shared with
        the ``user_login_failed`` signal receivers through a context variable
        and the request, so duplicate failure reports for this exact password
        check are counted only once while two explicit authenticate calls on
        the same request get distinct identifiers and are counted separately.

        This method interrupts the login flow and inserts  error message directly to the
        ``response_context`` attribute that is supplied as a keyword argument.

        :keyword response_context: kwarg that will be have its ``error`` attribute updated with context.
        :raises AxesBackendRequestParameterRequired: if request parameter is not passed.
        :raises AxesBackendPermissionDenied: if user is already locked out.
        :raises AxesBusinessRuleDenied: if a project business rule rejects the attempt.
        """

        if request is None:
            raise AxesBackendRequestParameterRequired(
                "AxesBackend requires a request as an argument to authenticate"
            )

        identifier = begin_attempt_identifier()
        setattr(request, REQUEST_ATTRIBUTE, identifier)

        credentials = get_credentials(username=username, password=password, **kwargs)

        business_rule_reason = self.check_business_rules(request, credentials)
        if business_rule_reason is not None:
            mark_attempt_non_countable(request, business_rule_reason)
            raise AxesBusinessRuleDenied(business_rule_reason)

        if AxesProxyHandler.is_allowed(request, credentials):
            return

        # Locked out, don't try to authenticate, just update response_context and return.
        # Its a bit weird to pass a context and expect a response value but its nice to get a "why" back.

        error_msg = get_lockout_message()
        response_context = kwargs.get("response_context", {})
        response_context["error"] = error_msg

        # This flag can be used later to check if it was Axes that denied the login attempt.
        if not settings.AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT:
            request.axes_locked_out = True

        # Raise an error that stops the authentication flows at django.contrib.auth.authenticate.
        # This error stops bubbling up at the authenticate call which catches backend PermissionDenied errors.
        # After this error is caught by authenticate it emits a signal indicating user login failed,
        # which is processed by axes.signals.log_user_login_failed which logs and flags the failed request.
        # The axes.middleware.AxesMiddleware further processes the flagged request into a readable response.

        raise AxesBackendPermissionDenied(
            "AxesBackend detected that the given user is locked out"
        )

    def check_business_rules(
        self, request: HttpRequest, credentials: dict
    ) -> Optional[str]:
        """
        Hook for project specific login rules that are not password checks.

        Return a human readable reason string to reject the authentication
        without consuming Axes lockout score, or ``None`` to let the normal
        lockout and credential checks run. Override this method in a subclass
        to implement rules such as disabled accounts or pending verifications.
        """

        return None


class AxesBackend(AxesStandaloneBackend, ModelBackend):
    """
    Axes authentication backend that also inherits from ModelBackend,
    and thus also performs other functions of ModelBackend such as permissions checks.

    Use this class as the first item of ``AUTHENTICATION_BACKENDS`` to
    prevent locked out users from being logged in by the Django authentication flow.

    .. note:: This backend does not log your user in. It monitors login attempts.
              Authentication is handled by the following backends that are configured in ``AUTHENTICATION_BACKENDS``.
    """
