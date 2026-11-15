from __future__ import annotations


class Error(Exception):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class InvalidChunkTable(Error, ValueError):
    """Related to AD1: the chunk table of a file entry is malformed or out of bounds."""


class DecompressionBudgetExceeded(Error):
    """Related to AD1: reading a file entry would exceed its decompression budget."""


class InvalidSnapshot(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class InvalidBlock(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class UnsupportedVersion(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""
