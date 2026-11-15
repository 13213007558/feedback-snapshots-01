from __future__ import annotations

from dissect.database.bbolt.bbolt import Bbolt, Entry

BoltDB = Bbolt
"""Alias Bbolt to BoltDB."""

__all__ = ["Bbolt", "BoltDB", "Entry"]
