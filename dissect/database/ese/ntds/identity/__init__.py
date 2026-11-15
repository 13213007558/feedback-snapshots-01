"""Object identity and display-path handling for offline NTDS snapshots.

This package deliberately separates two concepts that are easy to conflate when working from
offline database dumps:

- **Database-internal identity**: the row-level locator (DNT), the stable object GUID, the
  mutable RDN/name and the parent reference (PDNT). These are kept as independent fields on
  :class:`ObjectIdentity` so a rename, deletion or reused DNT cannot silently change identity.
- **Display paths**: the human-readable distinguished name produced by walking parent links.
  A :class:`DisplayPath` is presentation only: it carries diagnostics for missing parents,
  missing RDNs and cycles, and preserves every resolved segment so the path can be retraced
  through the original records.

Phantom and deleted records are never upgraded into normal live objects; their
:class:`ObjectState` travels with the identity.
"""

from __future__ import annotations

from dissect.database.ese.ntds.identity.builder import DisplayPathBuilder
from dissect.database.ese.ntds.identity.compare import Relation, RelationKind, SnapshotComparison, compare_snapshots
from dissect.database.ese.ntds.identity.escaping import escape_rdn_value, render_rdn
from dissect.database.ese.ntds.identity.exceptions import PathBuildError, PathIssue, PathIssueKind
from dissect.database.ese.ntds.identity.model import (
    DisplayPath,
    ObjectIdentity,
    ObjectState,
    PathSegment,
    identity_from_mapping,
)
from dissect.database.ese.ntds.identity.ntds_source import NTDSObjectSource
from dissect.database.ese.ntds.identity.report import render_comparison
from dissect.database.ese.ntds.identity.snapshot import InMemoryObjectSource, Snapshot
from dissect.database.ese.ntds.identity.source import ObjectSource

__all__ = [
    "DisplayPath",
    "DisplayPathBuilder",
    "InMemoryObjectSource",
    "NTDSObjectSource",
    "ObjectIdentity",
    "ObjectSource",
    "ObjectState",
    "PathBuildError",
    "PathIssue",
    "PathIssueKind",
    "PathSegment",
    "Relation",
    "RelationKind",
    "Snapshot",
    "SnapshotComparison",
    "compare_snapshots",
    "escape_rdn_value",
    "identity_from_mapping",
    "render_comparison",
    "render_rdn",
]
