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


class OutOfBoundsError(Error):
    """A filesystem structure references bytes outside of the sub-image region.

    The offending reference is described by ``reference`` (the kind of table or structure that supplied the
    pointer) and ``offset`` (the pointer interpreted relative to the start of the filesystem). ``limit`` is the
    boundary the reference crossed.

    Args:
        reference: The kind of table or structure that produced the out-of-bounds reference.
        offset: The referenced offset, relative to the start of the filesystem.
        limit: The boundary that the offset must stay within.
        length: The number of bytes that were referenced, if known.
    """

    def __init__(self, reference: str, offset: int, limit: int, length: int | None = None):
        self.reference = reference
        self.offset = offset
        self.limit = limit
        self.length = length

        extent = f"offset {offset}"
        if length is not None:
            extent = f"offset {offset}, length {length}"

        super().__init__(f"{reference} references bytes outside of the sub-image region ({extent}, limit {limit})")
