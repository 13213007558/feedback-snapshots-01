from __future__ import annotations

from dissect.database.exception import Error


class InvalidPageError(Error):
    """A page could not be parsed or is of an unexpected type."""

    def __init__(self, pgno: int, message: str):
        self.pgno = pgno
        super().__init__(f"page {pgno}: {message}")


class InvalidEntryError(Error):
    """An entry (slot) on a page could not be parsed."""

    def __init__(self, pgno: int, index: int, message: str):
        self.pgno = pgno
        self.index = index
        super().__init__(f"page {pgno} slot {index}: {message}")


class OverflowChainError(Error):
    """An overflow chain is broken.

    Carries the partial data read from the chain so far. The partial data only
    ever consists of bytes belonging to this chain, never of neighbouring items.
    """

    def __init__(self, pgno: int, message: str, partial: bytes = b""):
        self.pgno = pgno
        self.partial = partial
        super().__init__(f"overflow chain at page {pgno}: {message}")
