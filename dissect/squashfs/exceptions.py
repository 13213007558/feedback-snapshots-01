from __future__ import annotations


class Error(Exception):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAFileError(Error):
    pass


class NotASymlinkError(Error):
    pass


class XattrError(Error, ValueError):
    """Raised when an extended attribute table entry cannot be decoded safely."""
