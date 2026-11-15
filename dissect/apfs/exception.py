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


class DecmpfsError(Error):
    """Base class for decmpfs (compressed file) integrity failures."""


class DecmpfsBlockTableError(DecmpfsError):
    """The block table in a compressed resource fork is malformed.

    Raised for non-monotonic or duplicate offsets, entries that point outside the
    fork, zero-length entries or a table that does not describe every block.
    """


class DecmpfsPayloadError(DecmpfsError):
    """A compressed block cannot be decoded, or decodes to an unexpected length."""


class DecmpfsLogicalLengthError(DecmpfsError):
    """The declared logical length is inconsistent with the stored blocks.

    Raised when the inode-reported size contradicts the decmpfs header, the header
    size cannot be represented by inline data, or a decoded block does not cover the
    logical length it is responsible for.
    """
