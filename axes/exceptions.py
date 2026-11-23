from django.core.exceptions import PermissionDenied


class AxesBackendPermissionDenied(PermissionDenied):
    """
    Raised by authentication backend on locked out requests to stop the Django authentication flow.
    """


class AxesBackendRequestParameterRequired(ValueError):
    """
    Raised by authentication backend on invalid or missing request parameter value.
    """


class AxesBusinessRuleDenied(PermissionDenied):
    """
    Raised when a login is rejected by a business rule instead of a wrong password.

    Unlike credential failures these rejections never consume Axes lockout
    score. The ``reason`` is surfaced on the request so views can explain to
    the user why the login was refused.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)
