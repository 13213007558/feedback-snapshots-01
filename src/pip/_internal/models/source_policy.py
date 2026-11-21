"""Rules describing which sources packages may be installed from."""

from __future__ import annotations

import os
from collections.abc import Iterable
from urllib.parse import urlsplit

from pip._vendor.packaging.utils import NormalizedName, canonicalize_name

from pip._internal.utils.urls import path_to_url


def _normalize_source(source: str) -> str:
    """Normalize an approved source to a URL suitable for prefix matching.

    Local paths are converted to absolute ``file:`` URLs. Directories get a
    trailing slash so that only links located below them match.
    """
    if os.path.exists(source):
        url = path_to_url(os.path.abspath(source))
        if os.path.isdir(source) and not url.endswith("/"):
            url += "/"
        return url
    if urlsplit(source).scheme:
        return source
    # A local path that does not exist (yet); still treat it as a path so
    # that relative entries are anchored to the current directory.
    return path_to_url(os.path.abspath(source))


class SourcePolicy:
    """Decide which links pip may install packages from.

    :param approved_sources: URLs or local paths that packages must be
        obtained from. A link is approved when it matches a source exactly
        or is located below it. When empty, no restriction applies.
    :param approved_build_tools: Names of vetted build tools that are
        exempt from the approved source restriction.
    """

    def __init__(
        self,
        approved_sources: Iterable[str] = (),
        approved_build_tools: Iterable[str] = (),
    ) -> None:
        self.approved_sources: tuple[str, ...] = tuple(
            _normalize_source(source) for source in approved_sources
        )
        self.approved_build_tools: frozenset[NormalizedName] = frozenset(
            canonicalize_name(name) for name in approved_build_tools
        )

    @property
    def enforced(self) -> bool:
        """Whether any source restriction is in effect."""
        return bool(self.approved_sources)

    def allows(self, project_name: str, url: str) -> bool:
        """Return whether a link for ``project_name`` may be used."""
        if not self.approved_sources:
            return True
        if canonicalize_name(project_name) in self.approved_build_tools:
            return True
        for source in self.approved_sources:
            if url == source:
                return True
            prefix = source if source.endswith("/") else source + "/"
            if url.startswith(prefix):
                return True
        return False
