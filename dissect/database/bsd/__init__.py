from __future__ import annotations

from dissect.database.bsd.db import DB, Record
from dissect.database.bsd.exception import InvalidEntryError, InvalidPageError, OverflowChainError

__all__ = [
    "DB",
    "InvalidEntryError",
    "InvalidPageError",
    "OverflowChainError",
    "Record",
]
