from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from dissect.database.ese.ntds.identity.exceptions import PathBuildError, PathIssue, PathIssueKind
from dissect.database.ese.ntds.identity.model import DisplayPath, PathSegment, render_identity_rdn

if TYPE_CHECKING:
    from dissect.database.ese.ntds.identity.source import ObjectSource


class DisplayPathBuilder:
    """Construct display paths by iteratively walking parent DNT links.

    The walk is iterative with an explicit visited set, so a parent-chain cycle produces a
    :class:`PathIssue` (and, in strict mode, a :class:`PathBuildError`) instead of exhausting
    the recursion limit. Parent rows that do not exist are reported rather than fabricated.

    Args:
        source: The snapshot's identity provider.
        strict: When true, :meth:`build` raises :class:`PathBuildError` on any structural
            issue instead of returning a partial path.
        cache_size: Number of built paths to cache; ``0`` disables caching.
    """

    def __init__(self, source: ObjectSource, *, strict: bool = False, cache_size: int = 4096):
        self.source = source
        self.strict = strict
        if cache_size > 0:
            # Bound the wrapper to keep the public signature keyword-only friendly.
            self.build = lru_cache(cache_size)(self._build)
        else:
            self.build = self._build

    def _build(self, dnt: int) -> DisplayPath:
        issues: list[PathIssue] = []
        segments: list[PathSegment] = []
        visited: set[int] = set()
        current = dnt

        while True:
            if current in visited:
                issues.append(
                    PathIssue(
                        PathIssueKind.CYCLE,
                        current,
                        f"parent chain revisits DNT {current}; chain so far: {[segment.dnt for segment in segments]}",
                    )
                )
                break
            visited.add(current)

            identity = self.source.get_identity(current)
            if identity is None:
                issues.append(
                    PathIssue(
                        PathIssueKind.MISSING_PARENT,
                        current,
                        f"referenced DNT {current} has no record in this snapshot",
                    )
                )
                break

            is_root_terminus = identity.pdnt in (None, 0)
            if is_root_terminus and not identity.has_rdn:
                # The database root object (for example $ROOT_OBJECT$) legitimately has no RDN;
                # it is a chain terminus, not a malformed object.
                rdn = None
                issues.append(
                    PathIssue(
                        PathIssueKind.ROOT_REACHED,
                        current,
                        "chain ends at the database root object; the root has no RDN",
                    )
                )
            else:
                rdn, rdn_issue = render_identity_rdn(identity)
                if rdn_issue is not None:
                    issues.append(rdn_issue)
            segments.append(PathSegment(current, rdn, identity))

            parent_dnt = identity.pdnt
            if parent_dnt is None or parent_dnt == 0:
                break
            current = parent_dnt

        path = DisplayPath(dnt, segments, issues)
        if self.strict and not path.is_complete:
            raise PathBuildError(dnt, issues)
        return path
