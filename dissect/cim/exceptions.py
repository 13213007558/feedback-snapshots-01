from __future__ import annotations


class Error(Exception):
    pass


class InvalidObjectPathError(Error, ValueError):
    """The textual object path is syntactically invalid.

    The ``position`` attribute is the zero-based character offset in the input where the problem was found.
    """

    def __init__(self, reason: str, path: str | None = None, position: int | None = None):
        self.reason = reason
        self.path = path
        self.position = position

        message = "Invalid object path"
        if position is not None:
            message += f" at position {position}"
        message += f": {reason}"
        if path is not None:
            message += f" ({path!r})"

        super().__init__(message)


class UnsupportedHostError(Error, ValueError):
    """A remote host was used in an object path.

    Only local object paths are supported. No network requests are made for remote hosts.
    """

    def __init__(self, hostname: str):
        self.hostname = hostname
        super().__init__(f"Unsupported hostname {hostname!r}: only local object paths can be queried")


class InstanceNotFoundError(Error, IndexError):
    """A syntactically valid object path did not match an instance in the database."""


class ReferenceNotFoundError(Error):
    pass


class InvalidDatabaseError(Error):
    pass


class UnmappedPageError(Error):
    pass
