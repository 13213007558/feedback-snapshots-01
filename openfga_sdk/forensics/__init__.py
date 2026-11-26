"""
Shareable forensics reports for OpenFGA Expand responses.

Public entry points:

* :class:`ForensicsBuilder` / :func:`build_forensics_report` turn an already
  fetched Expand response plus evidence tuples into a public-safe report.
* :class:`ExpandEvidenceCollector` drives Expand, Read and
  ReadAuthorizationModel calls and records the relations it read.
* :class:`InternalInvestigation` pairs the shareable report with the raw Expand
  response and an internal-only subject mapping.
"""

from openfga_sdk.forensics.builder import (
    ForensicsBuilder,
    build_forensics_report,
)
from openfga_sdk.forensics.collector import ExpandEvidenceCollector
from openfga_sdk.forensics.identifiers import (
    SubjectRegistry,
    evidence_identifier,
    public_identifier,
)
from openfga_sdk.forensics.models import (
    REPORT_SCHEMA_VERSION,
    EvidenceRecord,
    ForensicsReport,
    InternalInvestigation,
)


__all__ = [
    "ForensicsBuilder",
    "build_forensics_report",
    "ExpandEvidenceCollector",
    "SubjectRegistry",
    "public_identifier",
    "evidence_identifier",
    "EvidenceRecord",
    "ForensicsReport",
    "InternalInvestigation",
    "REPORT_SCHEMA_VERSION",
]
