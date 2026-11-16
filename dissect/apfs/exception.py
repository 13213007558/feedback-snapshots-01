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


class InvalidObjectError(Error):
    """Raised when a block cannot be validated as an APFS object under any available interpretation.

    The message records why each candidate interpretation (the block as stored, and the block after
    decryption when a cipher was provided) was rejected, so the failure is attributed to the object
    interpretation/selection stage rather than surfacing later as a crash in a deep field parse.
    """
