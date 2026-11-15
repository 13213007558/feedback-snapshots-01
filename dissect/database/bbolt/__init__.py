from __future__ import annotations

from dissect.database.bbolt.bbolt import Bbolt
from dissect.database.bbolt.exception import InvalidDatabase
from dissect.database.bbolt.meta import MetaCandidate, MetaSelection, select_meta

BoltDB = Bbolt
"""Alias Bbolt to BoltDB."""

__all__ = [
    "Bbolt",
    "BoltDB",
    "InvalidDatabase",
    "MetaCandidate",
    "MetaSelection",
    "select_meta",
]
