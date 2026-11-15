from __future__ import annotations


class Error(Exception):
    pass


class VolumeNotAvailableError(Error):
    pass


class InvalidHeader(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class NotAnRDMFileError(Error):
    pass


class InvalidResourceError(Error):
    """Raised when an address does not reference a valid resource in a resource file."""
