from __future__ import annotations


class Error(Exception):
    pass


class ReferenceNotFoundError(Error):
    pass


class InvalidDatabaseError(Error):
    pass


class InheritanceError(Error):
    """Raised when a class inheritance chain cannot be resolved.

    This covers cycles in the derivation chain as well as references to a
    super class that is not present in the namespace. The offending class is
    recorded so the problem can be traced back to its origin.
    """

    def __init__(self, message: str, class_name: str | None = None, super_class_name: str | None = None):
        super().__init__(message)
        self.class_name = class_name
        self.super_class_name = super_class_name


class UnmappedPageError(Error):
    pass
