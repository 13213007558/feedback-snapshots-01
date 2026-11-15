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


class InvalidPointerBlockError(Error):
    """Raised when a pointer block (PB/PB2) contains a malformed or truncated pointer array."""

    pass
