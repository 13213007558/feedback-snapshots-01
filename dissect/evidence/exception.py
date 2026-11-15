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


class InvalidSnapshot(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class InvalidBlock(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class UnsupportedVersion(Error):
    """Related to ASDF (Acquire Snapshot Data Format)."""


class VerificationError(Error):
    """Base class for AD1 file content verification errors."""


class MissingDigestError(VerificationError):
    """No declared digest is available to verify the file content against."""


class InvalidDigestError(VerificationError):
    """A declared digest is malformed or has an unsupported format."""


class DigestMismatchError(VerificationError):
    """The reassembled logical file content does not match the declared digest."""


class IncompleteReadError(VerificationError):
    """Not all declared logical file bytes could be read and processed."""


AD1VerificationError = VerificationError
AD1MissingDigestError = MissingDigestError
AD1InvalidDigestError = InvalidDigestError
AD1DigestMismatchError = DigestMismatchError
AD1IncompleteReadError = IncompleteReadError
