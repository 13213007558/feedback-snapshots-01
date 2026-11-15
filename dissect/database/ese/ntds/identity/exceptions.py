from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


class PathIssueKind(IntEnum):
    """Ways in which a displayed path can deviate from a complete directory path.

    A path may carry more than one issue. Issues never cause a record to be "repaired" into
    a normal live object; they only describe why a fully resolvable display path could not be
    produced.
    """

    MISSING_PARENT = 1
    """The parent DNT referenced by the object does not exist in the snapshot."""

    MISSING_RDN = 2
    """The object (or one of its ancestors) has no usable RDN attribute type and/or name."""

    CYCLE = 3
    """Walking the parent chain revisits a DNT, so the chain can never reach a root."""

    MULTI_VALUED_RDN = 4
    """An RDN contains multiple attribute value assertions (AVAs), rendered with ``+``."""

    ROOT_REACHED = 5
    """The chain ended at the database root object instead of a naming-context head."""


class PathBuildError(Exception):
    """Raised in strict mode when a display path cannot be fully constructed.

    Args:
        dnt: The DNT for which the path was being built.
        issues: The diagnostics collected while walking the parent chain.
    """

    def __init__(self, dnt: int, issues: Sequence[PathIssue]):
        self.dnt = dnt
        self.issues = list(issues)
        summary = ", ".join(f"{issue.kind.name}@DNT{issue.dnt}: {issue.detail}" for issue in self.issues)
        super().__init__(f"Incomplete display path for DNT {dnt}: {summary}")


class PathIssue:
    """A single diagnostic recorded while constructing a display path.

    Args:
        kind: The category of the problem.
        dnt: The DNT of the object at which the problem was observed.
        detail: A human-readable explanation of the problem.
    """

    __slots__ = ("detail", "dnt", "kind")

    def __init__(self, kind: PathIssueKind, dnt: int, detail: str):
        self.kind = kind
        self.dnt = dnt
        self.detail = detail

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PathIssue):
            return NotImplemented
        return self.kind == other.kind and self.dnt == other.dnt and self.detail == other.detail

    def __repr__(self) -> str:
        return f"PathIssue(kind={self.kind.name}, dnt={self.dnt}, detail={self.detail!r})"
