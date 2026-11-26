"""
Data containers for shareable Expand forensics reports.

The containers intentionally hold plain, JSON-serializable data so reports can
be exported directly and compared byte-for-byte after canonical sorting.
"""

from dataclasses import dataclass, field
from typing import Any


REPORT_SCHEMA_VERSION = "forensics.expand/v1"


@dataclass
class EvidenceRecord:
    """Public-safe view of a stored relationship tuple supporting a node."""

    evidence_id: str
    public_tuple: dict[str, str]
    observed_at: str | None
    status: str
    record: dict[str, Any] = field(default_factory=dict)


@dataclass
class ForensicsReport:
    """
    Shareable, public-safe representation of an Expand investigation.

    ``tree`` preserves the userset dependency structure with canonical node
    ordering, ``evidence`` preserves source tuples, and ``unconfirmed_branches``
    lists branches whose evidence could not be established.
    """

    schema_version: str
    report_id: str
    generated_at: str
    request: dict[str, Any]
    authorization_model: dict[str, Any]
    relations_read: list[dict[str, Any]]
    tree: dict[str, Any]
    evidence: list[dict[str, Any]]
    subjects: list[dict[str, Any]]
    unconfirmed_branches: list[dict[str, Any]]
    display_name_collisions: list[dict[str, Any]]
    redaction: dict[str, Any]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "request": self.request,
            "authorization_model": self.authorization_model,
            "relations_read": self.relations_read,
            "tree": self.tree,
            "evidence": self.evidence,
            "subjects": self.subjects,
            "unconfirmed_branches": self.unconfirmed_branches,
            "display_name_collisions": self.display_name_collisions,
            "redaction": self.redaction,
            "summary": self.summary,
        }


@dataclass
class InternalInvestigation:
    """
    Complete investigation bundle retained for internal review only.

    ``raw_expand`` is the untouched Expand response and ``subject_mapping``
    allows re-identification. Neither field is part of the shareable report.
    """

    report: ForensicsReport
    raw_expand: dict[str, Any]
    raw_evidence: list[dict[str, Any]]
    subject_mapping: dict[str, str]

    def public_report(self) -> dict[str, Any]:
        return self.report.to_dict()
