from __future__ import annotations


class Error(Exception):
    pass


class ObjectPathError(Error, ValueError):
    """Base class for errors raised while parsing a textual object path."""


class ObjectPathSyntaxError(ObjectPathError):
    """Raised when a textual object path is syntactically invalid."""

    def __init__(self, message: str, path: str | None = None, position: int | None = None):
        self.reason = message
        self.path = path
        self.position = position

        if path is not None and position is not None:
            message = f"{message} at position {position} in {path!r}"

        super().__init__(message)


class UnsupportedHostError(ObjectPathError):
    """Raised when an object path refers to a remote host.

    Only local paths are supported. This module never performs network requests.
    """


class InvalidInstancePathError(ObjectPathSyntaxError):
    """Raised when the key part of an instance path is malformed."""


class ReferenceNotFoundError(Error):
    pass


class InstanceNotFoundError(ReferenceNotFoundError, IndexError):
    """Raised when an instance path does not resolve to an instance."""


class AmbiguousInstanceError(ReferenceNotFoundError):
    """Raised when an instance path resolves to more than one instance."""


class InvalidDatabaseError(Error):
    pass


class UnmappedPageError(Error):
    pass
