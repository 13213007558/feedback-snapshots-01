from __future__ import annotations


class Error(Exception):
    pass


class InvalidBTreeNode(Error, ValueError):
    """Raised when a B-tree node violates the APFS on-disk layout."""


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass
