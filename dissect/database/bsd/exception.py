from __future__ import annotations

from dissect.database.exception import Error


class CorruptRecordError(Error, ValueError):
    """A record could not be read completely from a (possibly corrupt) Berkeley DB page.

    Args:
        issue: The structural issue that made the record incomplete.
        partial: Bytes that could be read before the corruption was encountered.
        pages: Overflow pages that were part of the (partial) value.
    """

    def __init__(
        self,
        issue: object,
        partial: bytes = b"",
        pages: tuple[int, ...] = (),
    ):
        self.issue = issue
        self.partial = partial
        self.pages = pages
        super().__init__(str(issue))
