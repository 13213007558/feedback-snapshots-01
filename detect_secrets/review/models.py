"""Data types for the structured-config review pipeline.

The pipeline has two mutually exclusive parse paths:

* ``structured``: the input parsed into a normalized, easy-to-audit shape.
  Normalization can merge same-name fields, re-order lines and shift rows, so
  every normalized entry keeps a pointer back to its *original* location.
* ``text``: a fallback used when structured parsing fails. The original text is
  reviewed line by line without any re-ordering.

Two visibility tiers are kept separate on purpose:

* :class:`PublicFinding` / :class:`PublicReport` are safe to share. They only
  reference original locations and non-sensitive evidence descriptors.
* :class:`ReviewResult` is the internal, machine-local record. It additionally
  holds restricted config values, normalized-only coordinates and the raw text
  of parse exceptions. These never appear in the public report.
"""
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


class ParsePath(str, Enum):
    """Which representation a finding was actually produced from."""

    STRUCTURED = 'structured'
    TEXT = 'text'


class Representation(str, Enum):
    """Which representation a coordinate belongs to."""

    ORIGINAL = 'original'
    NORMALIZED = 'normalized'


@dataclass(frozen=True)
class SourceLocation:
    """A coordinate tied to one explicit representation.

    ``line`` is 1-based. A normalized-only coordinate must never be labelled as
    an original coordinate: callers use :attr:`representation` to tell them
    apart so that normalized line numbers are not pasted back onto the input.
    """

    line: int
    representation: Representation
    column: Optional[int] = None
    path: Tuple[str, ...] = field(default_factory=tuple)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            'line': self.line,
            'column': self.column,
            'representation': self.representation.value,
            'path': list(self.path),
        }


@dataclass(frozen=True)
class NormalizedEntry:
    """A single row in the normalized representation.

    The normalized row lives at :attr:`normalized_line` inside the rendered
    normalized text. :attr:`original_locations` are the rows it was derived
    from in the raw input (one entry, or several when same-name fields merged).
    """

    logical_path: Tuple[str, ...]
    value: Optional[str]
    normalized_line: int
    original_locations: Tuple[SourceLocation, ...]
    occurrence_count: int
    occurrence_values: Tuple[Optional[str], ...] = ()

    def render(self) -> str:
        key = '.'.join(self.logical_path)
        rendered_value = '' if self.value is None else self.value
        return f'{key} = {rendered_value}'


@dataclass(frozen=True)
class Finding:
    """An internal finding with full provenance.

    ``original_location`` and ``normalized_location`` are both stored, but they
    are labelled with their representation. The public tier only exposes the
    original location plus :attr:`evidence`, never the restricted value.
    """

    rule_id: str
    parse_path: ParsePath
    original_location: SourceLocation
    normalized_location: Optional[SourceLocation]
    evidence: Dict[str, str]
    restricted_value: Optional[str]
    fingerprint: str
    normalized_index: Optional[int] = None

    def to_public(self) -> 'PublicFinding':
        return PublicFinding(
            rule_id=self.rule_id,
            parse_path=self.parse_path.value,
            location=self.original_location.to_public_dict(),
            evidence=dict(self.evidence),
            fingerprint=self.fingerprint,
        )


@dataclass(frozen=True)
class PublicFinding:
    """The shareable projection of a finding."""

    rule_id: str
    parse_path: str
    location: Dict[str, Any]
    evidence: Dict[str, str]
    fingerprint: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'parse_path': self.parse_path,
            'location': self.location,
            'evidence': dict(self.evidence),
            'fingerprint': self.fingerprint,
        }


@dataclass(frozen=True)
class ParseDiagnostic:
    """Restricted detail about why structured parsing fell back to text."""

    error_type: str
    message: str
    problem_line: Optional[int]
    problem_column: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'error_type': self.error_type,
            'message': self.message,
            'problem_line': self.problem_line,
            'problem_column': self.problem_column,
        }


@dataclass(frozen=True)
class PublicReport:
    """Safe-to-publish output. No values, exception text or normalized rows."""

    filename: str
    parse_path: str
    findings: Tuple[PublicFinding, ...]
    parse_failed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'filename': self.filename,
            'parse_path': self.parse_path,
            'parse_failed': self.parse_failed,
            'findings': [finding.to_dict() for finding in self.findings],
        }


@dataclass
class ReviewResult:
    """The complete, machine-local result of one review run."""

    filename: str
    parse_path: ParsePath
    findings: List[Finding] = field(default_factory=list)
    normalized_entries: List[NormalizedEntry] = field(default_factory=list)
    normalized_lines: List[str] = field(default_factory=list)
    original_text: str = ''
    diagnostic: Optional[ParseDiagnostic] = None

    @property
    def parse_failed(self) -> bool:
        return self.diagnostic is not None

    def public_report(self) -> PublicReport:
        return PublicReport(
            filename=self.filename,
            parse_path=self.parse_path.value,
            parse_failed=self.parse_failed,
            findings=tuple(finding.to_public() for finding in self.findings),
        )

    def internal_record(self) -> Dict[str, Any]:
        """Full record, including restricted data. Stays on the local machine."""
        return {
            'filename': self.filename,
            'parse_path': self.parse_path.value,
            'original_text': self.original_text,
            'normalized_lines': list(self.normalized_lines),
            'diagnostic': self.diagnostic.to_dict() if self.diagnostic else None,
            'findings': [
                {
                    'rule_id': finding.rule_id,
                    'parse_path': finding.parse_path.value,
                    'fingerprint': finding.fingerprint,
                    'original_location': finding.original_location.to_public_dict(),
                    'normalized_location': (
                        finding.normalized_location.to_public_dict()
                        if finding.normalized_location
                        else None
                    ),
                    'normalized_index': finding.normalized_index,
                    'evidence': dict(finding.evidence),
                    'restricted_value': finding.restricted_value,
                }
                for finding in self.findings
            ],
        }
