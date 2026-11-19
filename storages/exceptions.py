from django.core.exceptions import PermissionDenied


class OperationNotAllowed(PermissionDenied, PermissionError):
    """
    Raised when a storage alias does not declare the capability required for
    the requested operation.

    It subclasses both Django's ``PermissionDenied`` (the natural exception
    for an authorization failure) and the builtin ``PermissionError`` (which
    file-oriented callers commonly catch).
    """
