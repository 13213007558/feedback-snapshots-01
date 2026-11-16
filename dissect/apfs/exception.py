from __future__ import annotations


class Error(Exception):
    pass


class CheckpointError(Error):
    """Raised when no consistent APFS checkpoint can be selected."""


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass
