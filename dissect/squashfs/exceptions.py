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


class CompressionError(Error, ValueError):
    """A compressed block could not be decoded according to the block contract.

    Backends raise different exception types (``zlib.error``, ``lzma.LZMAError``,
    ``ValueError`` or ``CorruptDataError``), so the compression layer normalizes them
    to this exception. It is also a ``ValueError`` for backwards compatibility.
    """
