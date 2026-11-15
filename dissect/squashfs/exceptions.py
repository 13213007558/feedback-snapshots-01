from __future__ import annotations


class Error(Exception):
    pass


class MetadataError(Error):
    """Raised when a metadata block chain cannot be parsed.

    The ``block`` and ``offset`` attributes record the physical metadata frame position and the
    logical (uncompressed) offset inside that frame at which the chain could no longer make
    progress, so callers can report exactly where a malformed chain broke down.
    """

    def __init__(self, message: str, block: int, offset: int):
        super().__init__(message)
        self.block = block
        self.offset = offset


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
