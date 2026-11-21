"""Approval-safe provenance summaries for an installation plan.

The regular installation report (see
:mod:`pip._internal.models.installation_report`) is a faithful, PEP 610 based
description of where every artifact comes from.  It is useful for tooling that
re-runs the installation, but it is not fit to be stored as an *approval*
artifact: the URLs it carries can embed access credentials, and a local
``file://`` source reveals the machine's filesystem layout.

This module derives a redacted summary from the same requirements that keeps
only what an approver can verify:

* the kind of source a package came from (``source_type``), which also lets
  internal troubleshooting tell an index, a local file, a direct URL or a VCS
  checkout apart;
* the package name and, when known, its version;
* content evidence, i.e. the hashes recorded for an archive or, for VCS
  checkouts, the resolved commit id.

Nothing produced here ever contains a URL, a netloc, a filesystem path or
credentials.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pip._vendor.packaging.utils import canonicalize_name

from pip._internal.models.link import Link
from pip._internal.req.req_install import InstallRequirement

#: Resolved through a package index or ``--find-links`` rather than given as an
#: explicit URL.
SOURCE_TYPE_INDEX = "index"

#: Points at a file on the local machine (``file://`` URL or path).
SOURCE_TYPE_LOCAL_FILE = "local_file"

#: An explicit remote URL to a downloadable archive.
SOURCE_TYPE_DIRECT_URL = "direct_url"

#: An explicit version control reference.
SOURCE_TYPE_VCS = "vcs"


class ProvenanceSummaryError(Exception):
    """Raised when an approval-safe provenance entry cannot be built."""


def _selected_link(ireq: InstallRequirement) -> Link | None:
    """The link that best represents the selected source.

    ``source_link`` survives wheel-cache substitution, so it is preferred over
    ``link``, which may have been rewritten to a cached local wheel.
    """
    return ireq.source_link or ireq.link


def _classify_source_type(ireq: InstallRequirement) -> str:
    """Return the coarse, non-sensitive kind of source for ``ireq``.

    Only the link *scheme* and whether the requirement was a direct reference
    are inspected, so no part of the URL is copied into the result.
    """
    link = _selected_link(ireq)
    if link is None:
        # A requirement without a link is satisfied from an index: there is no
        # user-provided location to describe.
        return SOURCE_TYPE_INDEX
    if link.is_vcs:
        return SOURCE_TYPE_VCS
    if link.is_file:
        return SOURCE_TYPE_LOCAL_FILE
    if ireq.is_direct:
        return SOURCE_TYPE_DIRECT_URL
    return SOURCE_TYPE_INDEX


def _archive_hashes(ireq: InstallRequirement) -> dict[str, str]:
    """Return recorded archive hashes without touching any location data."""
    download_info = ireq.download_info
    if (
        download_info is not None
        and download_info.archive_info is not None
        and download_info.archive_info.hashes
    ):
        return dict(download_info.archive_info.hashes)

    link = _selected_link(ireq)
    if link is not None and link.has_hash and link.hash_name and link.hash:
        return {link.hash_name: link.hash}

    return {}


def _vcs_evidence(ireq: InstallRequirement) -> dict[str, str] | None:
    download_info = ireq.download_info
    if download_info is None or download_info.vcs_info is None:
        return None
    return {
        "vcs": download_info.vcs_info.vcs,
        "commit_id": download_info.vcs_info.commit_id,
    }


def _resolved_version(ireq: InstallRequirement) -> str | None:
    """Best-effort resolved version, never derived from a URL or path."""
    try:
        version = ireq.get_dist().version
    except (AssertionError, AttributeError):
        return None
    if version is None:
        return None
    return str(version)


def build_provenance_entry(ireq: InstallRequirement) -> dict[str, Any]:
    """Build a single approval-safe provenance entry.

    The mapping only ever contains the source type, the package identity and
    content evidence.  Fields that could carry credentials or a machine-specific
    location are deliberately omitted.
    """
    name = ireq.name
    if name is None:
        raise ProvenanceSummaryError(
            "Cannot summarize a requirement without a package name."
        )

    entry: dict[str, Any] = {
        "name": canonicalize_name(name),
        "source_type": _classify_source_type(ireq),
    }

    version = _resolved_version(ireq)
    if version is not None:
        entry["version"] = version

    evidence: dict[str, Any] = {}
    hashes = _archive_hashes(ireq)
    if hashes:
        evidence["hashes"] = hashes
    vcs_info = _vcs_evidence(ireq)
    if vcs_info is not None:
        evidence["vcs_info"] = vcs_info
    if evidence:
        entry["content_evidence"] = evidence

    return entry


class ProvenanceSummary:
    """A redacted view of an installation plan, safe to store for approval.

    Unlike
    :class:`~pip._internal.models.installation_report.InstallationReport`, this
    never serializes download URLs or local paths, so credentials embedded in a
    URL and the host's filesystem layout cannot reach the approval material.
    """

    def __init__(self, install_requirements: Sequence[InstallRequirement]):
        self._entries = [build_provenance_entry(ireq) for ireq in install_requirements]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "1",
            # Rebuild primitive copies so callers cannot mutate the summary
            # through the returned structure.
            "packages": [dict(entry) for entry in self._entries],
        }

    def to_text(self) -> str:
        """Render a stable, one-line-per-package human-readable summary.

        Limited to the same safe fields as :meth:`to_dict`, so it can appear in
        error output without re-introducing a location or credential leak.
        """
        lines = []
        for entry in self._entries:
            parts = [f"{entry['name']} ({entry['source_type']})"]
            if "version" in entry:
                parts.append(f"version={entry['version']}")
            evidence = entry.get("content_evidence", {})
            if evidence.get("hashes"):
                hash_text = ",".join(
                    f"{name}={digest}"
                    for name, digest in sorted(evidence["hashes"].items())
                )
                parts.append(f"hashes={hash_text}")
            if evidence.get("vcs_info"):
                parts.append(
                    "vcs={vcs}:commit={commit_id}".format(**evidence["vcs_info"])
                )
            lines.append(" ".join(parts))
        return "\n".join(lines)


def describe_link_for_diagnostics(
    link: Link, ireq: InstallRequirement | None = None
) -> str:
    """Describe a :class:`Link` for internal diagnostics without its location.

    Returns only the source type and the non-sensitive file name when one can
    be derived, never the full URL, netloc, path or credentials. When
    ``ireq`` is given, its index/direct distinction is taken into account so an
    artifact fetched through an index is not mislabeled as a direct URL.
    """
    if link.is_vcs:
        source_type = SOURCE_TYPE_VCS
    elif link.is_file:
        source_type = SOURCE_TYPE_LOCAL_FILE
    elif ireq is not None and not ireq.is_direct:
        source_type = SOURCE_TYPE_INDEX
    else:
        source_type = SOURCE_TYPE_DIRECT_URL
    # Drop any VCS revision suffix (``repo.git@deadbeef`` -> ``repo.git``): the
    # resolved commit is already reported as content evidence, and keeping the
    # separator out guarantees no ``@`` character reaches the diagnostic text.
    filename = str(link.filename).split("@", 1)[0]
    if filename:
        return f"{source_type}:{filename}"
    return source_type
