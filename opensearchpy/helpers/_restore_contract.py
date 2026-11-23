# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

"""
Disaster recovery restore contract.

This module implements the *optional* preflight/approval layer that sits on
top of the untouched native ``snapshot.restore`` API. A recovery program is only
allowed to restore an *approved* snapshot into *temporary* indices, and there
is a time gap between approval and execution. The contract therefore:

* resolves the snapshot identity and the filtered source indices at preflight;
* computes every rename target up-front, so an approver sees exact destinations;
* freezes the exact restore parameters at approval time; and
* re-derives the same parameters at execution time and refuses to restore when
  anything has drifted (catalog, configuration or request).

The module contains no transport or ``await`` code. The synchronous and
asynchronous entry points fetch the snapshot listing and then call the same
functions here, which keeps their approval semantics identical. Patterns that
cannot be explained deterministically raise a preflight error before any
restore request is built.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..exceptions import (
    ApprovalStaleError,
    RestorePatternError,
    SnapshotIdentityError,
)

__all__ = [
    "SnapshotView",
    "IndexRename",
    "RestorePlan",
    "RestoreRequest",
    "RestoreReceipt",
    "build_restore_plan",
    "revalidate_plan",
    "ensure_approved",
    "build_receipt",
]


@dataclass(frozen=True)
class SnapshotView:
    """Identity and contained indices of a single snapshot."""

    repository: str
    snapshot: str
    uuid: Optional[str]
    version: Optional[Any]
    indices: Tuple[str, ...]
    state: Optional[str] = None

    @classmethod
    def from_response(
        cls, repository: str, response: Mapping[str, Any], snapshot_name: str
    ) -> "SnapshotView":
        snapshots = response.get("snapshots") if response is not None else None
        if not isinstance(snapshots, Sequence) or isinstance(snapshots, (str, bytes)):
            raise SnapshotIdentityError(
                "Snapshot response does not contain a 'snapshots' list for "
                f"repository {repository!r}."
            )
        matches = [item for item in snapshots if isinstance(item, Mapping)]
        if snapshot_name not in (None, "*", "_all"):
            matches = [item for item in matches if item.get("snapshot") == snapshot_name]

        if not matches:
            raise SnapshotIdentityError(
                f"Snapshot {snapshot_name!r} was not found in repository "
                f"{repository!r}."
            )
        if len(matches) > 1:
            raise SnapshotIdentityError(
                f"Snapshot name {snapshot_name!r} resolved to {len(matches)} "
                "snapshots; an exact snapshot identity is required for approval."
            )

        data = matches[0]
        raw_indices = data.get("indices", ())
        if isinstance(raw_indices, Mapping):
            indices = tuple(raw_indices.keys())
        elif isinstance(raw_indices, Sequence) and not isinstance(
            raw_indices, (str, bytes)
        ):
            indices = tuple(raw_indices)
        else:
            raise SnapshotIdentityError(
                f"Snapshot {snapshot_name!r} does not expose a readable index list."
            )

        return cls(
            repository=repository,
            snapshot=data.get("snapshot", snapshot_name),
            uuid=data.get("uuid"),
            version=data.get("version"),
            indices=tuple(indices),
            state=data.get("state"),
        )


@dataclass(frozen=True)
class IndexRename:
    """A single approved source -> temporary target mapping."""

    source: str
    target: str


@dataclass(frozen=True)
class RestoreRequest:
    """The exact, frozen parameters sent to ``snapshot.restore``."""

    repository: str
    snapshot: str
    method: str
    path: str
    body: Dict[str, Any]
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RestorePlan:
    """
    The approved contract. ``fingerprint`` captures every value that was
    checked at approval time; a different fingerprint on revalidation means the
    target needs re-approval.
    """

    repository: str
    snapshot: str
    snapshot_uuid: Optional[str]
    snapshot_version: Optional[Any]
    renames: Tuple[IndexRename, ...]
    request: RestoreRequest
    fingerprint: str

    @property
    def source_indices(self) -> Tuple[str, ...]:
        return tuple(rename.source for rename in self.renames)

    @property
    def target_indices(self) -> Tuple[str, ...]:
        return tuple(rename.target for rename in self.renames)

    def describe(self) -> Dict[str, Any]:
        """Serializable summary a caller can persist next to the approval."""
        return {
            "repository": self.repository,
            "snapshot": self.snapshot,
            "snapshot_uuid": self.snapshot_uuid,
            "source_indices": list(self.source_indices),
            "target_indices": list(self.target_indices),
            "renames": [
                {"source": rename.source, "target": rename.target}
                for rename in self.renames
            ],
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class RestoreReceipt:
    """Result of an executed restore, locating source and destination."""

    repository: str
    snapshot: str
    snapshot_uuid: Optional[str]
    request: RestoreRequest
    renames: Tuple[IndexRename, ...]
    raw_response: Any

    @property
    def mappings(self) -> Tuple[IndexRename, ...]:
        return self.renames

    @property
    def source_indices(self) -> Tuple[str, ...]:
        return tuple(rename.source for rename in self.renames)

    @property
    def target_indices(self) -> Tuple[str, ...]:
        return tuple(rename.target for rename in self.renames)


def _validate_literal(name: str, value: str, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise RestorePatternError(f"{what} must be a non-empty string, got {value!r}.")
    if any(token in value for token in ("*", "?", ",", "/")):
        raise RestorePatternError(
            f"{what} {value!r} contains a wildcard or separator; the recovery "
            "contract only approves concrete names so every target is known."
        )
    return value


def _validate_prefix(prefix: str) -> str:
    if not isinstance(prefix, str) or not prefix:
        raise RestorePatternError(
            f"Temporary index prefix must be a non-empty string, got {prefix!r}."
        )
    if any(token in prefix for token in ("*", "?", ",", "/", "_all")):
        raise RestorePatternError(
            f"Temporary index prefix {prefix!r} contains an unsupported pattern."
        )
    return prefix


def _filter_indices(
    available: Sequence[str],
    include: Optional[Sequence[str]],
    exclude: Optional[Sequence[str]],
    strict: bool = True,
) -> List[str]:
    exclude_set = set(exclude or ())
    if include is None:
        selected = [name for name in available if name not in exclude_set]
    else:
        include_set = set(include)
        selected = [
            name
            for name in available
            if name in include_set and name not in exclude_set
        ]
        unknown = sorted(include_set - set(available))
        if strict and unknown:
            raise RestorePatternError(
                "Requested source indices are not present in the approved "
                f"snapshot: {unknown}."
            )
    if not selected:
        if strict:
            raise RestorePatternError(
                "The index selection filtered out every index in the snapshot; "
                "nothing can be approved for restore."
            )
        return []
    return selected


def _build_renames(
    sources: Sequence[str],
    target_prefix: str,
    rename_map: Optional[Mapping[str, str]],
    strict: bool = True,
) -> List[IndexRename]:
    rename_map = dict(rename_map or {})
    unknown = sorted(set(rename_map) - set(sources))
    if strict and unknown:
        raise RestorePatternError(
            f"Explicit rename targets reference unknown source indices: {unknown}."
        )

    renames: List[IndexRename] = []
    seen_targets: Dict[str, str] = {}
    for source in sources:
        if source in rename_map:
            target = _validate_literal("target", rename_map[source], "Rename target")
        else:
            target = f"{target_prefix}{source}"
        if target in seen_targets:
            raise RestorePatternError(
                f"Source indices {seen_targets[target]!r} and {source!r} both "
                f"resolve to temporary target {target!r}."
            )
        seen_targets[target] = source
        renames.append(IndexRename(source=source, target=target))
    return renames


def _fingerprint(
    view: SnapshotView,
    renames: Sequence[IndexRename],
    body: Mapping[str, Any],
    params: Mapping[str, Any],
) -> str:
    import hashlib
    import json

    payload = {
        "identity": [view.repository, view.snapshot, view.uuid, view.version],
        "renames": [[rename.source, rename.target] for rename in renames],
        "body": body,
        "params": params,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_restore_plan(
    view: SnapshotView,
    *,
    target_prefix: str,
    include_indices: Optional[Sequence[str]] = None,
    exclude_indices: Optional[Sequence[str]] = None,
    rename_map: Optional[Mapping[str, str]] = None,
    include_global_state: bool = False,
    extra_body: Optional[Mapping[str, Any]] = None,
    params: Optional[Mapping[str, Any]] = None,
    headers: Optional[Mapping[str, str]] = None,
    strict: bool = True,
) -> RestorePlan:
    """
    Resolve and freeze an approved restore plan from a snapshot view.

    Only concrete index names and a concrete temporary prefix are accepted, so
    the filtered source set and every rename target can be explained and shown
    to an approver before execution. ``strict`` is only relaxed internally when
    re-validating an existing approval against a changed catalog.
    """
    repository = _validate_literal("repository", view.repository, "Repository")
    snapshot_name = _validate_literal("snapshot", view.snapshot, "Snapshot")
    prefix = _validate_prefix(target_prefix)

    for index in list(include_indices or ()) + list(exclude_indices or ()):
        _validate_literal("index", index, "Index selection")

    sources = _filter_indices(
        view.indices, include_indices, exclude_indices, strict=strict
    )
    renames = _build_renames(sources, prefix, rename_map, strict=strict)

    # Every destination is expressed as an explicit source -> target mapping and
    # frozen into the request. This avoids relying on a server-side regex whose
    # effect the approver cannot see, so the body always restores into the exact
    # temporary targets that were reviewed.
    body: Dict[str, Any] = {
        "indices": [rename.source for rename in renames],
        "include_global_state": include_global_state,
        "index_renames": [
            {"source_index": rename.source, "target_index": rename.target}
            for rename in renames
        ],
    }

    if extra_body:
        conflicting = set(extra_body).intersection(
            {"indices", "index_renames", "include_global_state"}
        )
        if conflicting:
            raise RestorePatternError(
                "extra_body must not override contract-managed keys: "
                f"{sorted(conflicting)}."
            )
        body.update(extra_body)

    frozen_params = dict(params or {})
    frozen_headers = dict(headers or {})
    request = RestoreRequest(
        repository=repository,
        snapshot=snapshot_name,
        method="POST",
        path=f"/_snapshot/{repository}/{snapshot_name}/_restore",
        body=body,
        params=frozen_params,
        headers=frozen_headers,
    )

    return RestorePlan(
        repository=repository,
        snapshot=snapshot_name,
        snapshot_uuid=view.uuid,
        snapshot_version=view.version,
        renames=tuple(renames),
        request=request,
        fingerprint=_fingerprint(view, renames, body, frozen_params),
    )


def revalidate_plan(plan: RestorePlan, current: SnapshotView) -> List[str]:
    """
    Re-derive the contract against a fresh snapshot view.

    Returns a list of human-readable drift reasons. An empty list means the
    approval is still valid. No restore request is issued by this function.
    """
    reasons: List[str] = []

    if current.repository != plan.repository:
        reasons.append(
            f"repository changed {plan.repository!r} -> {current.repository!r}"
        )
    if current.snapshot != plan.snapshot:
        reasons.append(
            f"snapshot name changed {plan.snapshot!r} -> {current.snapshot!r}"
        )
    if plan.snapshot_uuid is not None and current.uuid != plan.snapshot_uuid:
        reasons.append(
            f"snapshot uuid changed {plan.snapshot_uuid!r} -> {current.uuid!r}"
        )

    observed = set(current.indices)
    missing = [name for name in plan.source_indices if name not in observed]
    if missing:
        reasons.append(f"approved source indices no longer in snapshot: {missing}")

    # Rebuild the plan from the current catalog using the same selection that was
    # approved. Every target is re-derived from the frozen rename map, so any
    # directory/config/request change surfaces as a different fingerprint.
    rebuilt = build_restore_plan(
        current,
        target_prefix=_plan_prefix(plan),
        include_indices=list(plan.source_indices),
        rename_map=_plan_rename_map(plan),
        include_global_state=plan.request.body.get("include_global_state", False),
        extra_body=_plan_extra_body(plan),
        params=plan.request.params,
        headers=plan.request.headers,
        strict=False,
    )
    if rebuilt.fingerprint != plan.fingerprint:
        changed = _diff_renames(plan.renames, rebuilt.renames)
        if changed:
            detail = f"targets requiring re-approval: {changed}"
        else:
            detail = "snapshot identity or restore parameters changed"
        reasons.append(
            "frozen restore parameters no longer match the current catalog; "
            + detail
        )
    return reasons


def _plan_prefix(plan: RestorePlan) -> str:
    # All targets are explicit in index_renames; the prefix is only a fallback
    # argument required by the builder and never affects the frozen targets.
    return "dr-"


def _plan_rename_map(plan: RestorePlan) -> Dict[str, str]:
    return {
        entry["source_index"]: entry["target_index"]
        for entry in plan.request.body["index_renames"]
    }


def _plan_extra_body(plan: RestorePlan) -> Dict[str, Any]:
    managed = {"indices", "index_renames", "include_global_state"}
    return {key: val for key, val in plan.request.body.items() if key not in managed}


def _diff_renames(
    approved: Sequence[IndexRename], current: Sequence[IndexRename]
) -> List[str]:
    current_map = {rename.source: rename.target for rename in current}
    changed: List[str] = []
    for rename in approved:
        observed_target = current_map.get(rename.source)
        if observed_target != rename.target:
            changed.append(
                f"{rename.source}: {rename.target!r} -> {observed_target!r}"
            )
    return changed


def ensure_approved(plan: RestorePlan, current: SnapshotView) -> RestoreRequest:
    """
    Guard the native restore call behind a valid approval.

    Re-derives the contract against a fresh snapshot view and returns the exact
    frozen request only when there is no drift. A stale approval raises
    :class:`ApprovalStaleError`; the caller must not issue any restore request
    in that case. The returned :class:`RestoreRequest` carries the parameters
    captured at approval time, never values re-derived from the current catalog.
    """
    reasons = revalidate_plan(plan, current)
    if reasons:
        raise ApprovalStaleError(
            "Approval is no longer valid; re-approve the following targets "
            f"before restoring: {reasons}"
        )
    return plan.request


def build_receipt(plan: RestorePlan, raw_response: Any) -> RestoreReceipt:
    """Wrap a native restore response with the approved source/destination map."""
    return RestoreReceipt(
        repository=plan.repository,
        snapshot=plan.snapshot,
        snapshot_uuid=plan.snapshot_uuid,
        request=plan.request,
        renames=plan.renames,
        raw_response=raw_response,
    )
