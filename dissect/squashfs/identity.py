"""Identity table resolution for SquashFS inodes.

SquashFS stores 16-bit indexes in each inode header.  Those indexes address
entries in the filesystem-wide id table, which is itself stored as chained
metadata blocks.  An inode's on-disk ``uid``/``guid`` field is therefore an
index, not a numeric user or group ID.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdLookup:
    """The result of resolving one id-table index.

    A lookup either has a numeric ``resolved_id`` or records why the identity
    is unknown.  Unknown identities deliberately do not use ``0`` as a
    sentinel: uid/gid 0 is a valid identity (root) and must only be reported
    when the id table actually maps an index to 0.
    """

    table: str
    index: int
    raw_field: str
    resolved_id: int | None = None
    reason: str | None = None
    detail: str | None = None
    pointer_index: int | None = None
    metadata_block: int | None = None
    metadata_offset: int | None = None
    metadata_length: int | None = None

    @property
    def known(self) -> bool:
        """Whether the index was successfully mapped to a numeric ID."""
        return self.resolved_id is not None

    @property
    def status(self) -> str:
        """Human-readable resolution status."""
        return "resolved" if self.known else "unknown"

    @property
    def is_root(self) -> bool | None:
        """Whether this identity is numerically 0, or ``None`` if unknown."""
        if self.resolved_id is None:
            return None
        return self.resolved_id == 0

    @property
    def label(self) -> str:
        """A local-account-name-free label for this identity."""
        if self.resolved_id is None:
            return "unknown"
        if self.resolved_id == 0:
            return "root"
        return f"{self.table}:{self.resolved_id}"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable representation with source evidence."""
        return {
            "table": self.table,
            "raw_field": self.raw_field,
            "index": self.index,
            "resolved_id": self.resolved_id,
            "status": self.status,
            "known": self.known,
            "is_root": self.is_root,
            "reason": self.reason,
            "detail": self.detail,
            "id_pointer_index": self.pointer_index,
            "id_metadata_block": self.metadata_block,
            "id_metadata_offset": self.metadata_offset,
            "id_metadata_length": self.metadata_length,
        }
