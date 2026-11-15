from __future__ import annotations

from dissect.database.bbolt.bbolt import Bbolt, Entry, EntryType

BoltDB = Bbolt
"""Alias Bbolt to BoltDB."""

__all__ = ["Bbolt", "BoltDB", "Entry", "EntryType"]
