from __future__ import annotations

from dissect.evidence.asdf.asdf import FILE_MAGIC, AsdfSnapshot, AsdfStream, AsdfWriter
from dissect.evidence.asdf.identity import (
    EvidenceExtent,
    EvidenceIndex,
    IdentityStrength,
    SourceClaim,
    StreamDeclaration,
    StreamIdentity,
    StreamRole,
    StreamRun,
    write_identity_manifest,
)

__all__ = [
    "FILE_MAGIC",
    "AsdfSnapshot",
    "AsdfStream",
    "AsdfWriter",
    "EvidenceExtent",
    "EvidenceIndex",
    "IdentityStrength",
    "SourceClaim",
    "StreamDeclaration",
    "StreamIdentity",
    "StreamRole",
    "StreamRun",
    "write_identity_manifest",
]
